using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EasyCryptography
{
    /// <summary>
    /// EasyCryptography is an easy-to-use wrapper around built-in .NET cryptography,
    /// providing a clean and simple API, and safe default settings for all
    /// algorithms and data sizes.
    ///
    /// For more detailed information please see the README.
    /// </summary>
    public static class Crypto
    {
        #region Default settings

        /// <summary>
        /// Global singleton settings instance. To customize your settings,
        /// adjust individual values, or provide a new custom instance.
        ///
        /// Please note that you must use the same settings when encrypting/decrypting
        /// or signing/verifying your data, otherwise the operations will fail.
        /// </summary>
        public static CryptoSettings Settings = new CryptoSettings();

        #endregion


        #region Hashing and Randomness API

        /// <summary>
        /// Computes the hash of input data.
        /// The length of the hash depends on the chosen algorithm.
        /// By default, it uses SHA256 and produces a 32-byte long hash.
        /// </summary>
        public static Hash Hash (byte[] data) {
            using var hash = HashAlgorithm.Create(Settings.HashAlgorithmID);
            return ByteArray<Hash>.CopyFrom(hash.ComputeHash(data));
        }

        /// <summary>
        /// Encodes the string as UTF8 and computes its hash.
        /// The length of the hash depends on the chosen algorithm.
        /// By default, it uses SHA256 and produces a 32-byte long hash.
        /// </summary>
        public static Hash Hash (string text) => Hash(Encoding.UTF8.GetBytes(text));

        /// <summary>
        /// Generates a byte array filled with random numbers from a
        /// cryptographically-strong random number generator.
        /// </summary>
        public static byte[] Random (int bytecount) {
            using var rng = new RNGCryptoServiceProvider();
            var bytes = new byte[bytecount];
            rng.GetBytes(bytes);
            return bytes;
        }

        /// <summary>
        /// Creates a new, random secret key for use in encryption.
        /// </summary>
        /// <returns></returns>
        public static SecretKey CreateSecretKeyRandom () {
            using var aes = NewAes();
            var results = ByteArray<SecretKey>.CopyFrom(aes.Key);

            aes.Clear();
            return results;
        }

        /// <summary>
        /// Creates a new secret key from the given string password and salt.
        /// This process uses a password derivation function, to convert
        /// a text password of any length into a random-looking secret key
        /// of the correct length for encryption.
        ///
        /// Caller can pass in different salts in order to produce different
        /// keys for the same password (e.g. for different applications).
        ///
        /// Calling this function several times with the same password and salt
        /// will always produce the same key.
        /// </summary>
        public static SecretKey CreateKeyFromPassword (string password, string salt) =>
            CreateKeyFromPassword(password, Hash(salt).Data);

        private static SecretKey CreateKeyFromPassword (string password, byte[] salt) {
            using var hash = HashAlgorithm.Create(Settings.HashAlgorithmID);
            using var pbkdf2 = new Rfc2898DeriveBytes(
                password,
                hash.HashSize / 8,
                Settings.PBKDF2Iterations,
                new HashAlgorithmName(Settings.HashAlgorithmID));

            if (salt != null) { pbkdf2.Salt = salt; }

            var bytes = pbkdf2.GetBytes(Settings.AESKeySize / 8);
            return ByteArray<SecretKey>.CopyFrom(bytes);
        }

        /// <summary>
        /// Encrypts provided data, using provided secret key, and a random initialization vector.
        ///
        /// The input data is plain data to be encrypted, and the key is a secret key that will be
        /// used for decryption as well. 
        ///
        /// If the sign flag is true, the result will also be signed with the encryption key,
        /// which allows for tampering detection, at the cost of slightly increased output size.
        /// This implementation uses HMAC in Encrypt-then-MAC mode, with hash strength specified in settings.
        /// 
        /// Encrypting the same data with the same key will produce different result bytes each time,
        /// because the initialization vector is being randomized on each call. However, each of those
        /// results can be decrypted with the same key, as expected.
        /// </summary>
        public static Encrypted Encrypt (byte[] data, SecretKey key, bool sign = true) =>
            Encrypt(data, key, null, sign);


        /// <summary>
        /// Encrypts provided data, using provided secret key, and initialization vector.
        ///
        /// The input data is plain data to be encrypted, and the key is a secret key that will be
        /// used for decryption as well. Initialization vector is a random starting point for encryption -
        /// it's not secret, and it doesn't really matter what the value is, as long as it's random. 
        ///
        /// If the sign flag is true, the result will also be signed with the encryption key,
        /// which allows for tampering detection, at the cost of output size increased by 16 bytes by default.
        /// This implementation uses HMAC in Encrypt-then-MAC mode, with hash size specified in settings.
        /// 
        /// Encrypting the same data with the same key and initialization vector will always
        /// produce the same bytes in result. However, calling code can pass in a null initialization vector,
        /// in which case a new one will be generated randomly.
        /// </summary>
        public static Encrypted Encrypt (byte[] data, SecretKey key, InitializationVector iv, bool sign = true) {
            // verify key length as expected
            if (key.Data.Length != Settings.AESKeySize / 8) {
                throw new ArgumentException("Unexpected key size", nameof(key));
            }

            using var aes = NewAes(key, iv);
            using var transform = aes.CreateEncryptor();

            var encrypted = TransformData(data, transform);

            // please note that we're using the same secret key for both encryption and signature.
            // some sources claim this could introduce weaknesses given some specific combinations
            // of encryption and mac algorithms. however, we are using AES for encryption and
            // HMAC-SHA256 for hashing, and this combination has no such known weaknesses
            // (for discussion see: https://crypto.stackexchange.com/questions/8081/ )

            var signature = sign ? Sign(encrypted, key).Data : new byte[0];

            var results = new Encrypted {
                IV = ByteArray<InitializationVector>.CopyFrom(aes.IV),
                Data = ByteArray<EncryptedBytes>.CopyFrom(encrypted),
                Signature = ByteArray<Signature>.CopyFrom(signature),
            };

            aes.Clear();
            return results;
        }

        /// <summary>
        /// Decrypts provided data using provided secret key. Data must contain both the encrypted
        /// bytes and the initialization vector used during encryption (and optionally, a signature),
        /// while the key is the secret key is the same one that was used previously for encryption.
        ///
        /// If a signature is present in the data, it will be checked before returning the results.
        /// If the signature is present and matches the data, the validated flag will be returned as true,
        /// otherwise it will be returned as false.
        /// </summary>
        public static Decrypted Decrypt (Encrypted encrypted, SecretKey key) {
            // verify key length as expected
            if (key.Data.Length != Settings.AESKeySize / 8) {
                throw new ArgumentException("Unexpected key size", nameof(key));
            }

            // check signature
            var hasSig = encrypted.Signature.Data.Length > 0;
            var verified = Verify(encrypted.Signature, encrypted.Data.Data, key);
            var result =
                verified ? SignatureValidationResult.SignatureValid :
                hasSig ? SignatureValidationResult.SignatureInvalid :
                SignatureValidationResult.SignatureMissing;

            // note: to avoid timing attacks, we always decrypt the data even if signature doesn't match
            using var aes = NewAes(key, encrypted.IV);
            using var transform = aes.CreateDecryptor();
            var decrypted = TransformData(encrypted.Data.Data, transform);
            aes.Clear();

            return new Decrypted { Data = decrypted, Result = result };
        }

        /// <summary>
        /// Creates a signature (authentication tag) for the given data, using the given secret key.
        /// The resulting signature will be unique to both the data and the key, and it can be
        /// used to confirm that a given key signed the data, and to detect data modification.
        ///
        /// Signatures work similarly to hashes, but are much more resistant to tampering (for example,
        /// the chosen-prefix collision attack) at the cost of slightly slower execution time.
        /// This implementation uses HMAC with strength specified in settings.
        /// </summary>
        public static Signature Sign (byte[] data, SecretKey key) {
            using var hmac = HMAC.Create(Settings.HMACAlgorithmID);
            hmac.Key = key.Data;
            var hash = hmac.ComputeHash(data);
            var result = ByteArray<Signature>.CopyFrom(hash);

            hmac.Clear();
            return result;
        }

        /// <summary>
        /// Verifies a previously generated signature (authentication tag) for given data and secret key.
        /// 
        /// This is done by generating a new signature for the given data and key, and comparing it
        /// to the provided signature. The function returns true if the signature matches the data and key,
        /// or false if it does not match, for example because the data or the key are not the same
        /// as those used to create the provided signature.
        /// </summary>
        public static bool Verify (Signature signature, byte[] data, SecretKey key) {
            var computed = Sign(data, key);
            return Check.BytewiseEquals(computed, signature);
        }

        #endregion


        #region Implementation details

        // helper function, generates a new AES instance with given parameters
        private static Aes NewAes (SecretKey key = null, InitializationVector iv = null) {
            var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.KeySize = Settings.AESKeySize;

            if (key != null) { aes.Key = key.Data; }
            if (iv != null) { aes.IV = iv.Data; }
            return aes;
        }

        // helper function for encrypting or decrypting via memory streams
        private static byte[] TransformData (byte[] bytes, ICryptoTransform transform) {
            using var memory = new MemoryStream();
            using var crypto = new CryptoStream(memory, transform, CryptoStreamMode.Write);
            crypto.Write(bytes, 0, bytes.Length);
            crypto.FlushFinalBlock();
            return memory.ToArray();
        }

        #endregion
    }



}
