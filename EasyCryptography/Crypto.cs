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
            return ByteArray<Hash>.CopyFrom(hash.ComputeHash(data));
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
            var results = ByteArray<SecretKey>.CopyFrom(aes.Key);

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

        private static SecretKey CreateKeyFromPassword (string password, byte[] salt) {
            using var pbkdf2 = new Rfc2898DeriveBytes(
                password,
                Settings.HashDigestSizeBytes,
                Settings.PBKDF2Iterations,
                new HashAlgorithmName(Settings.HashAlgorithmID));

            if (salt != null) { pbkdf2.Salt = salt; }

            var bytes = pbkdf2.GetBytes(Settings.AESKeySizeBytes);
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
        public static Encrypted Encrypt (byte[] data, SecretKey key, bool sign) =>
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
        public static Encrypted Encrypt (byte[] data, SecretKey key, InitializationVector iv, bool sign) {
            // verify key length as expected
            if (key.Bytes.Length != Settings.AESKeySizeBytes) {
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

            var signature = sign ? Sign(encrypted, key).Bytes : new byte[0];

            var results = new Encrypted {
                Init = ByteArray<InitializationVector>.CopyFrom(aes.IV),
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
            if (key.Bytes.Length != Settings.AESKeySizeBytes) {
                throw new ArgumentException("Unexpected key size", nameof(key));
            }

            // check signature
            var hasSig = encrypted.Signature.Bytes.Length > 0;
            var verified = Verify(encrypted.Signature, encrypted.Data.Bytes, key);
            var result =
                verified ? SignatureValidationResult.SignatureValid :
                hasSig ? SignatureValidationResult.SignatureInvalid :
                SignatureValidationResult.SignatureMissing;

            // note: to avoid timing attacks, we always decrypt the data even if signature doesn't match
            using var aes = NewAes(key, encrypted.Init);
            using var transform = aes.CreateDecryptor();
            var decrypted = TransformData(encrypted.Data.Bytes, transform);
            aes.Clear();

            return new Decrypted { Bytes = decrypted, Result = result };
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
            return BytewiseEquals(computed, signature);
        }

        /// <summary>
        /// Returns true if the two byte arrays are either both null or both have the same bytes.
        /// </summary>
        public static bool BytewiseEquals<T> (ByteArray<T> a, ByteArray<T> b) where T : ByteArray<T>, new()
            => BytewiseEquals(a?.Bytes, b?.Bytes);

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



        #region Binary reader and writer utils

        internal static T Deserialize<T> (byte[] bytes) where T : ByteArray<T>, new() {
            using var mem = new MemoryStream(bytes);
            using var reader = new BinaryReader(mem);
            return Deserialize<T>(reader);
        }

        internal static T Deserialize<T> (BinaryReader reader) where T : ByteArray<T>, new() {
            int len = reader.ReadInt32();
            var bytes = reader.ReadBytes(len);
            return new T() { Bytes = bytes };
        }

        internal static void Serialize<T> (ByteArray<T> data, BinaryWriter writer) where T : ByteArray<T>, new() {
            int len = data.Bytes.Length;
            writer.Write(len);
            writer.Write(data.Bytes);
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
    public abstract class ByteArray<T> where T : ByteArray<T>, new()
    {
        public byte[] Bytes;

        /// <summary> Serializes this object into a length-prefixed byte array </summary>
        public byte[] Save () {
            using var mem = new MemoryStream();
            using var writer = new BinaryWriter(mem);
            Crypto.Serialize(this, writer);
            return mem.ToArray();
        }

        /// <summary> Makes a new object from a copy of the source array </summary>
        public static T CopyFrom (byte[] source) {
            var bytes = new byte[source.Length];
            Array.Copy(source, bytes, source.Length);
            return new T() { Bytes = bytes };
        }
    }

    /// <summary>
    /// Wrapper around a secret key used for encryption and signatures. Secret keys should be
    /// treated as secret, and not saved along with encrypted data.
    /// </summary>
    public class SecretKey : ByteArray<SecretKey>
    {
        /// <summary> Deserializes this object from a length-prefixed byte array </summary>
        public static SecretKey Load (byte[] bytes) => Crypto.Deserialize<SecretKey>(bytes);
    }

    /// <summary>
    /// Wrapper around a byte array containing the results of encryption. To recover original
    /// data from encrypted data, one also needs initialization vector and secret key.
    /// </summary>
    public class EncryptedBytes : ByteArray<EncryptedBytes>
    {
        /// <summary> Deserializes this object from a length-prefixed byte array </summary>
        public static EncryptedBytes Load (byte[] bytes) => Crypto.Deserialize<EncryptedBytes>(bytes);
    }

    /// <summary>
    /// Wrapper around a byte array containing the initialization vector for some encrypted data.
    /// This vector matches encrypted data and together they are needed during decryption.
    /// </summary>
    public class InitializationVector : ByteArray<InitializationVector>
    {
        /// <summary> Deserializes this object from a length-prefixed byte array </summary>
        public static InitializationVector Load (byte[] bytes) => Crypto.Deserialize<InitializationVector>(bytes);
    }

    /// <summary>
    /// Wrapper around a byte array containing the hash of some input data given some key.
    /// </summary>
    public class Hash : ByteArray<Hash>
    {
        /// <summary> Deserializes this object from a length-prefixed byte array </summary>
        public static Hash Load (byte[] bytes) => Crypto.Deserialize<Hash>(bytes);
    }

    /// <summary>
    /// Wrapper around a byte array containing the signature (aka authentication code or
    /// authentication tag) for some input data given some key.
    ///
    /// Signatures work similarly to hashes, but are much more resistant to tampering (for example,
    /// the chosen-prefix collision attack) at the cost of slightly slower execution time.
    /// </summary>
    public class Signature : ByteArray<Signature>
    {
        /// <summary> Deserializes this object from a length-prefixed byte array </summary>
        public static Signature Load (byte[] bytes) => Crypto.Deserialize<Signature>(bytes);
    }

    /// <summary>
    /// Represents the result of signature validation.
    /// </summary>
    public enum SignatureValidationResult
    {
        SignatureMissing = -1,
        SignatureInvalid = 0,
        SignatureValid = 1,
    }

    /// <summary>
    /// Wrapper for encrypt and sign result, which contains both encryption result (broken down to
    /// encrypted data and initialization vector) and the signature of encrypted data.
    /// All three pieces need to be presented when trying to verify the signature and decrypt.
    /// </summary>
    public class Encrypted
    {
        public EncryptedBytes Data;
        public InitializationVector Init;
        public Signature Signature;

        /// <summary> Serializes this object into a byte array </summary>
        public byte[] Save () {
            using var mem = new MemoryStream();
            {
                using var writer = new BinaryWriter(mem);
                Crypto.Serialize(Data, writer);
                Crypto.Serialize(Init, writer);
                Crypto.Serialize(Signature, writer);
            }
            return mem.ToArray();
        }

        /// <summary> Deserializes this object from a byte array </summary>
        public static Encrypted Load (byte[] bytes) {
            using var mem = new MemoryStream(bytes);
            using var reader = new BinaryReader(mem);
            var encr = Crypto.Deserialize<EncryptedBytes>(reader);
            var init = Crypto.Deserialize<InitializationVector>(reader);
            var sign = Crypto.Deserialize<Signature>(reader);
            return new Encrypted { Data = encr, Init = init, Signature = sign };
        }
    }

    /// <summary>
    /// Wrapper for decrypt results and signature verification.
    /// </summary>
    public class Decrypted
    {
        /// <summary>
        /// Byte array that contains the decrypted data
        /// </summary>
        public byte[] Bytes;

        /// <summary>
        /// This flag specifies whether a signature was present and/or checked
        /// </summary>
        public SignatureValidationResult Result;

        /// <summary>
        /// Returns true if the data was never signed, so its accuracy is unknown.
        /// </summary>
        public bool IsNotSigned => Result == SignatureValidationResult.SignatureMissing;

        /// <summary>
        /// Returns true if the data was signed, and it matches the provided signature,
        /// showing that the encrypted data was not modified between encryption and decryption.
        /// </summary>
        public bool IsSignatureValid => Result == SignatureValidationResult.SignatureValid;

        /// <summary>
        /// Returns true if the data was signed, but it does not match the provided signature,
        /// suggesting that a modification happened sometime between encryption and decryption.
        /// </summary>
        public bool IsSignatureNotValid => Result == SignatureValidationResult.SignatureInvalid;

    }

    #endregion
}
