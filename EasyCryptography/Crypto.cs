using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EasyCryptography
{
    #region Settings

    /// <summary>
    /// Settings used by all EasyCryptography operations.
    ///
    /// Symmetric encryption uses AES only, with configurable key size.
    /// Hashing can use a variety of algorithms, but SHA256 and larger are recommended.
    ///
    /// Please note that you must use the same settings when encrypting/decrypting
    /// or signing/verifying your data. 
    /// </summary>
    public class CryptoSettings
    {
        /// <summary>
        /// Hash algorithm string must be one of the allowed .NET hash names,
        /// such as "SHA256", "SHA512" and so on.
        /// </summary>
        public string HashAlgorithmID;

        /// <summary>
        /// Hash digest size is the size of the result of hashing, in bits.
        /// For example, SHA256 produces 256-bit hashes.
        /// </summary>
        public int HashDigestSize;

        /// <summary>
        /// HMAC algorithm string must be one of the allowed .NET HMAC names,
        /// such as "HMACSHA256", "HMACSHA512", etc.
        /// </summary>
        public string HMACAlgorithmID;

        /// <summary>
        /// HMAC digest size is the size of the result of hashing, in bits.
        /// For example, SHA256 produces 256-bit hashes.
        /// </summary>
        public int HMACDigestSize;

        /// <summary>
        /// AES key size is the size of the data array containing encryption
        /// key, in bits. To encrypt using AES-128, specify a 128-bit key size.
        /// </summary>
        public int AESKeySize;

        /// <summary>
        /// Iteration count is the number of hashing iterations performed
        /// by the public key derivation function. NIST recommends
        /// using as large of a value as feasible, to make brute-force
        /// cracking difficult. In our experience, iteration count of
        /// 100,000 is a good default, it means generating each new password
        /// will take several milliseconds on commodity hardware.
        /// For more complex situations this can be adjusted as needed,
        /// and values of 10,000 or larger will make this tough to brute-force.
        /// </summary>
        public int PBKDF2Iterations;

        /// <summary>
        /// Helper function that expresses hash digest size in bytes instead if bits.
        /// </summary>
        public int HashDigestSizeBytes => HashDigestSize / 8;

        /// <summary>
        /// Helper function that expresses HMAC hash digest size in bytes instead if bits.
        /// </summary>
        public int HMACDigestSizeBytes => HMACDigestSize / 8;

        /// <summary>
        /// Helper function that expresses AES key size in bytes instead if bits.
        /// </summary>
        public int AESKeySizeBytes => AESKeySize / 8;
    }

    #endregion


    /// <summary>
    /// EasyCryptography is an easy-to-use wrapper around built-in .NET cryptography,
    /// providing a clean and simple API, and safe default settings for all
    /// algorithms and data sizes. For more detailed information please see the README.
    /// </summary>
    public static class Crypto
    {

        #region Default settings

        /// <summary>
        /// These default settings provide good basic cryptography settings.
        /// By default the library will use AES-128 for symmetric encryption,
        /// SHA-256 for hashing and HMAC, and 100,000 rounds of SHA-256 for PBKDF2.
        /// </summary>
        public static readonly CryptoSettings DefaultSettings = new CryptoSettings() {
            HashAlgorithmID = "SHA256",
            HashDigestSize = 256,
            HMACAlgorithmID = "HMACSHA256",
            HMACDigestSize = 256,
            AESKeySize = 128,
            PBKDF2Iterations = 100_000,
        };

        /// <summary>
        /// Global singleton settings instance. To customize your settings,
        /// set this field to a new instance with different values.
        ///
        /// Please note that you must use the same settings when encrypting/decrypting
        /// or signing/verifying your data. 
        /// </summary>
        public static CryptoSettings Settings = DefaultSettings;

        #endregion


        #region Public API

        /// <summary>
        /// Computes the hash of input data.
        /// By default, it uses SHA256 and produces a 32-byte long hash.
        /// </summary>
        public static Hash Hash (byte[] data) {
            using var hash = HashAlgorithm.Create(Settings.HashAlgorithmID);
            return new Hash(hash.ComputeHash(data));
        }

        /// <summary>
        /// Encodes the string as UTF8 and computes its hash.
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
        public static SecretKey CreateKeyRandom () {
            using var aes = NewAes();
            var results = new SecretKey(aes.Key);

            aes.Clear();
            return results;
        }

        /// <summary>
        /// Creates a new secret key from the given string password.
        /// This process uses a password derivation function, to convert
        /// a text password of any length into a random-looking secret key
        /// of the correct length for encryption.
        ///
        /// Calling this function several times with the same password
        /// will always produce the same key.
        /// </summary>
        public static SecretKey CreateKeyFromPasswordNoSalt (string password) =>
            CreateKeyFromPassword(password, Hash(password).Bytes);

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
            CreateKeyFromPassword(password, Hash(salt).Bytes);

        public static SecretKey CreateKeyFromPassword (string password, byte[] salt) {
            using var pbkdf2 = new Rfc2898DeriveBytes(
                password,
                Settings.HashDigestSizeBytes,
                Settings.PBKDF2Iterations,
                new HashAlgorithmName(Settings.HashAlgorithmID));

            if (salt != null) { pbkdf2.Salt = salt; }

            var bytes = pbkdf2.GetBytes(Settings.AESKeySizeBytes);
            return new SecretKey(bytes);
        }

        /// <summary>
        /// Encrypts provided data, using provided secret key, and a random initialization vector.
        ///
        /// The input data is plain data to be encrypted, and the key is a secret key that will be
        /// used for decryption as well. 
        ///
        /// Encrypting the same data with the same key will produce different result bytes each time,
        /// because the initialization vector is being randomized on each call. However, each of those
        /// results can be decrypted with the same key, as expected.
        /// </summary>
        public static EncryptResult Encrypt (byte[] data, SecretKey key) =>
            Encrypt(data, key, null);


        /// <summary>
        /// Encrypts provided data, using provided secret key, and initialization vector.
        ///
        /// The input data is plain data to be encrypted, and the key is a secret key that will be
        /// used for decryption as well. Initialization vector is a random starting point for encryption -
        /// it's not secret, and it doesn't really matter what the value is, as long as it's random. 
        ///
        /// Encrypting the same data with the same key and initialization vector will always
        /// produce the same bytes in result. However, calling code can pass in a null initialization vector,
        /// in which case a new one will be generated randomly.
        /// </summary>
        public static EncryptResult Encrypt (byte[] data, SecretKey key, InitializationVector iv) {
            // verify key length as expected
            if (key.Bytes.Length != Settings.AESKeySizeBytes) {
                throw new ArgumentException("Unexpected key size", nameof(key));
            }

            using var aes = NewAes(key, iv);
            using var transform = aes.CreateEncryptor();

            var encrypted = TransformData(data, transform);
            var results = new EncryptResult {
                Init = new InitializationVector(aes.IV),
                Encrypted = new EncryptedData(encrypted),
            };

            aes.Clear();
            return results;
        }

        /// <summary>
        /// Decrypts provided data using provided secret key. Data contains both the encrypted
        /// bytes and the initialization vector bytes, while the key is the secret key used
        /// previously for encryption.
        ///
        /// If the key and initialization vector match, the result will be the plain data before
        /// encryption, otherwise the result will be a sequence of bytes of similar length as
        /// plain data but randomized content.
        /// </summary>
        public static DecryptResult Decrypt (EncryptResult encrypted, SecretKey key) {
            // verify key length as expected
            if (key.Bytes.Length != Settings.AESKeySizeBytes) {
                throw new ArgumentException("Unexpected key size", nameof(key));
            }

            using var aes = NewAes(key, encrypted.Init);
            using var transform = aes.CreateDecryptor();

            var decrypted = TransformData(encrypted.Encrypted.Bytes, transform);
            var results = new DecryptResult { Decrypted = decrypted };

            aes.Clear();
            return results;
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
            hmac.Key = key.Bytes;
            var hash = hmac.ComputeHash(data);
            var result = new Signature(hash);

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
            return ByteArray.BytewiseEquals(computed, signature);
        }


        /// <summary>
        /// Encrypts provided data with the provided secret key, and then signs the result using that key.
        /// The results can be used to verify later on, to make sure that encrypted data was not modified.
        ///
        /// This implementation uses HMAC in Encrypt-then-MAC mode, with hash strength specified in settings.
        /// </summary>
        public static EncryptAndSignResult EncryptAndSign (byte[] data, SecretKey key) {

            // please note that we're using the same secret key for both encryption and signature.
            // some sources claim this could introduce weaknesses given some specific combinations
            // of encryption and mac algorithms. however, we are using AES for encryption and
            // HMAC-SHA256 for hashing, and this combination has no such known weaknesses
            // (for discussion see: https://crypto.stackexchange.com/questions/8081/ )

            var encrypted = Encrypt(data, key);
            var signature = Sign(encrypted.Encrypted.Bytes, key);

            return new EncryptAndSignResult {
                Init = encrypted.Init,
                Encrypted = encrypted.Encrypted,
                Signature = signature,
            };
        }

        /// <summary>
        /// Takes encrypted data along with its signature, verifies that the encrypted data was signed correctly
        /// by the provided key, and decrypts the data (encrypted bytes and initialization vector).
        ///
        /// The results contain a boolean that specifies whether the signature was valid. If signature was valid,
        /// the resulting boolean will be true and data will contain the original plain data that was encrypted.
        /// Otherwise the resulting boolean will be false, and data will be a null reference.
        /// </summary>
        public static DecryptAndVerifyResult DecryptAndVerify (EncryptAndSignResult results, SecretKey key) {

            // to get ahead of timing attacks, we always decrypt the data even if signature doesn't match
            var encresults = new EncryptResult { Encrypted = results.Encrypted, Init = results.Init };
            var decrypted = Decrypt(encresults, key);
            var valid = Verify(results.Signature, results.Encrypted.Bytes, key);

            return new DecryptAndVerifyResult {
                IsSignatureValid = valid,
                Decrypted = valid ? decrypted.Decrypted : null,
            };
        }

        #endregion


        #region Implementation details

        // helper function, generates a new AES instance with given parameters
        private static Aes NewAes (SecretKey key = null, InitializationVector iv = null) {
            var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.KeySize = Settings.AESKeySize;

            if (key != null) { aes.Key = key.Bytes; }
            if (iv != null) { aes.IV = iv.Bytes; }
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



    #region Data containers

    /// <summary>
    /// Abstract wrapper around byte[], parent of multiple strongly-typed classes that describe
    /// byte arrays with various semantics (secret key, encrypted data, signature, etc.)
    ///
    /// Because C# doesn't have facilities similar to `typedef` in C++, we do this by
    /// wrapping byte[] in a helper class and providing strongly typed subclasses.
    /// </summary>
    public abstract class ByteArray
    {
        public byte[] Bytes { get; set; }

        protected ByteArray (byte[] source) { 
            Bytes = new byte[source.Length];
            Array.Copy(source, Bytes, source.Length);
        }

        /// <summary>
        /// Returns true if the two byte arrays are either both null or both have the same bytes.
        /// </summary>
        public static bool BytewiseEquals (ByteArray a, ByteArray b) => BytewiseEquals(a?.Bytes, b?.Bytes);

        /// <summary>
        /// Returns true if the two byte arrays are either both null or both have the same bytes.
        /// </summary>
        public static bool BytewiseEquals (byte[] a, byte[] b) {

            if (a == null && b == null) { return true; }  // both null
            if (a == null || b == null) { return false; } // one null but not the other

            if (a.Length != b.Length) { return false; }

            for (int i = 0, count = a.Length; i < count; i++) {
                if (a[i] != b[i]) { return false; }
            }

            return true;
        }
    }

    /// <summary>
    /// Wrapper around a secret key used for encryption and signatures. Secret keys should be
    /// treated as secret, and not saved along with encrypted data.
    /// </summary>
    public class SecretKey : ByteArray {
        public SecretKey (byte[] source) : base(source) { }
    }

    /// <summary>
    /// Wrapper around a byte array containing the results of encryption. To recover original
    /// data from encrypted data, one also needs initialization vector and secret key.
    /// </summary>
    public class EncryptedData : ByteArray {
        public EncryptedData (byte[] source) : base(source) { }
    }

    /// <summary>
    /// Wrapper around a byte array containing the initialization vector for some encrypted data.
    /// This vector matches encrypted data and together they are needed during decryption.
    /// </summary>
    public class InitializationVector : ByteArray {
        public InitializationVector (byte[] source) : base(source) { }
    }

    /// <summary>
    /// Wrapper around a byte array containing the hash of some input data given some key.
    /// </summary>
    public class Hash : ByteArray {
        public Hash (byte[] source) : base(source) { }
    }

    /// <summary>
    /// Wrapper around a byte array containing the signature (aka authentication code or
    /// authentication tag) for some input data given some key.
    ///
    /// Signatures work similarly to hashes, but are much more resistant to tampering (for example,
    /// the chosen-prefix collision attack) at the cost of slightly slower execution time.
    /// </summary>
    public class Signature : ByteArray {
        public Signature (byte[] source) : base(source) { }
    }

    /// <summary>
    /// Wrapper for encryption result, which contains both the encrypted data and initialization vector.
    /// Both need to be presented for decryption, along with the secret key.
    /// </summary>
    public class EncryptResult
    {
        public EncryptedData Encrypted;
        public InitializationVector Init;
    }

    /// <summary>
    /// Wrapper for decryption result, which is just the byte array that was originally encrypted.
    /// </summary>
    public class DecryptResult
    {
        public byte[] Decrypted;
    }

    /// <summary>
    /// Wrapper for encrypt and sign result, which contains both encryption result (broken down to
    /// encrypted data and initialization vector) and the signature of encrypted data.
    /// All three pieces need to be presented when trying to verify the signature and decrypt.
    /// </summary>
    public class EncryptAndSignResult
    {
        public InitializationVector Init;
        public EncryptedData Encrypted;
        public Signature Signature;
    }

    /// <summary>
    /// Results of trying to decrypt and verify the signature of some encrypted data.
    /// It contains a boolean which is true if the signature was valid, and a byte array
    /// which, if the signature was valid, is filled with the results of decryption or,
    /// if the signature was not valid, is set to null.
    /// </summary>
    public class DecryptAndVerifyResult
    {
        public byte[] Decrypted;
        public bool IsSignatureValid;
    }

    #endregion
}
