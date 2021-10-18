using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EasyCryptography
{
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

    /// <summary>
    /// EasyCryptography is an easy-to-use wrapper around built-in .NET cryptography,
    /// providing a clean and simple API, and safe default settings for all
    /// algorithms and data sizes. For more detailed information please see the README.
    /// </summary>
    public static class Crypto
    {
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


        /// <summary>
        /// Computes the hash of input data.
        /// By default, it uses SHA256 and produces a 32-byte long hash.
        /// </summary>
        public static Hash Hash (byte[] bytes) {
            using var hash = HashAlgorithm.Create(Settings.HashAlgorithmID);
            return new Hash { Bytes = hash.ComputeHash(bytes) };
        }

        /// <summary>
        /// Encodes the string as UTF8 and computes its hash.
        /// By default, it uses SHA256 and produces a 32-byte long hash.
        /// </summary>
        public static Hash Hash (string text) => Hash(Encoding.UTF8.GetBytes(text));

        /// <summary>
        /// Computes the hash of input data.
        /// By default, it uses SHA256 and produces a 32-byte long hash.
        /// </summary>
        public static Hash Hash (Data data) => Hash(data.Bytes);


        /// <summary>
        /// Generates a byte array filled with random numbers from a
        /// cryptographically-strong random number generator.
        /// </summary>
        public static PlainData Random (int bytecount) {
            using var rng = new RNGCryptoServiceProvider();
            var bytes = new byte[bytecount];
            rng.GetBytes(bytes);
            return new PlainData { Bytes = bytes };
        }

        /// <summary>
        /// Creates a new, random secret key for use in encryption.
        /// </summary>
        /// <returns></returns>
        public static SecretKey CreateKeyRandom () {
            using var aes = NewAes();
            var results = Data.Copy<SecretKey>(aes.Key);

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
            return Data.Wrap<SecretKey>(bytes);
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
        public static EncryptResults Encrypt (PlainData data, SecretKey key) =>
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
        public static EncryptResults Encrypt (PlainData data, SecretKey key, InitializationVector iv) {
            // verify key length as expected
            if (key.Bytes.Length != Settings.AESKeySizeBytes) {
                throw new ArgumentException("Unexpected key size", nameof(key));
            }

            using var aes = NewAes(key, iv);
            using var transform = aes.CreateEncryptor();

            var encrypted = TransformData(data.Bytes, transform);
            var results = new EncryptResults {
                Init = Data.Copy<InitializationVector>(aes.IV),
                Encrypted = Data.Copy<EncryptedData>(encrypted),
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
        public static DecryptResults Decrypt (EncryptResults encrypted, SecretKey key) {
            // verify key length as expected
            if (key.Bytes.Length != Settings.AESKeySizeBytes) {
                throw new ArgumentException("Unexpected key size", nameof(key));
            }

            using var aes = NewAes(key, encrypted.Init);
            using var transform = aes.CreateDecryptor();

            var decrypted = TransformData(encrypted.Encrypted.Bytes, transform);
            var results = new DecryptResults { Decrypted = Data.Copy<PlainData>(decrypted) };

            aes.Clear();
            return results;
        }



        /// <summary>
        /// Creates a signature (authentication code) for the given data, using the given secret key.
        /// The resulting signature will be unique to both the data and the key, and so it can be
        /// used to confirm that a given key signed the data, and to detect data tampering.
        ///
        /// This implementation uses HMAC with strength specified in settings.
        /// </summary>
        public static Signature Sign (Data data, SecretKey key) {
            using var hash = HMAC.Create(Settings.HMACAlgorithmID);
            hash.Key = key.Bytes;
            var result = hash.ComputeHash(data.Bytes);
            return Data.Wrap<Signature>(result);
        }

        /// <summary>
        /// Verifies a previously generated signature (authentication code) for given data and secret key.
        /// This is done by generating a new signature for the given data and key, and comparing it
        /// to the provided signature. The function returns true if the signature matches the data and key,
        /// or false if it does not match, for example because the data or the key are not the same
        /// as those used to create the provided signature.
        /// </summary>
        public static bool Verify (Signature signature, Data data, SecretKey key) {
            var computed = Sign(data, key);
            return computed.BytewiseEquals(signature);
        }


        /// <summary>
        /// Encrypts provided data with the provided secret key, and then signs the result using that key.
        /// The results can be used to verify later on, to make sure that encrypted data was not modified.
        ///
        /// This implementation uses HMAC in Encrypt-then-MAC mode, with hash strength specified in settings.
        /// </summary>
        public static EncryptAndSignResult EncryptAndSign (PlainData data, SecretKey key) {

            // please note that we're using the same secret key for both encryption and signature.
            // some sources claim this could introduce weaknesses given some specific combinations
            // of encryption and mac algorithms. however, we are using AES for encryption and
            // HMAC-SHA256 for hashing, and this combination has no such known weaknesses
            // (for discussion see: https://crypto.stackexchange.com/questions/8081/ )

            var encrypted = Encrypt(data, key);
            var signature = Sign(encrypted.Encrypted, key);

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
        public static DecryptAndVerifyResults DecryptAndVerify (EncryptAndSignResult results, SecretKey key) {

            // to get ahead of timing attacks, we always decrypt the data even if signature doesn't match
            var encresults = new EncryptResults { Encrypted = results.Encrypted, Init = results.Init };
            var decrypted = Decrypt(encresults, key);
            var valid = Verify(results.Signature, results.Encrypted, key);

            return new DecryptAndVerifyResults {
                IsSignatureValid = valid,
                Decrypted = valid ? decrypted.Decrypted : null,
            };
        }

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
    }


    public abstract class Data
    {
        public byte[] Bytes { get; set; }

        public bool BytewiseEquals (Data other) => BytewiseEquals(other.Bytes);

        public bool BytewiseEquals (byte[] other) {
            if (other == null) { throw new ArgumentNullException(nameof(other)); }

            if (other.Length != Bytes.Length) { return false; }

            for (int i = 0, count = other.Length; i < count; i++) {
                if (other[i] != Bytes[i]) { return false; }
            }

            return true;
        }

        public void FillWith (byte value) => Array.Fill(Bytes, value);

        public void FillWithRandom () {
            using var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(Bytes);
        }


        public static T MakeFilled<T> (int bytes, byte fill) where T : Data, new() {
            var result = Wrap<T>(new byte[bytes]);
            result.FillWith(fill);
            return result;
        }

        public static T MakeRandom<T> (int bytes) where T : Data, new() {
            var result = Wrap<T>(new byte[bytes]);
            result.FillWithRandom();
            return result;
        }

        public static T Wrap<T> (byte[] bytes) where T : Data, new() =>
            new T() { Bytes = bytes };

        public static T Copy<T> (byte[] bytes) where T : Data, new() {
            var destination = new byte[bytes.Length];
            Array.Copy(bytes, destination, bytes.Length);
            return Wrap<T>(destination);
        }
    }

    public class SecretKey : Data { }
    public class PlainData : Data { }
    public class EncryptedData : Data { }
    public class InitializationVector : Data { }
    public class Hash : Data { }
    public class Signature : Data { }

    public class EncryptResults
    {
        public InitializationVector Init;
        public EncryptedData Encrypted;
    }

    public class DecryptResults
    {
        public PlainData Decrypted;
    }

    public class EncryptAndSignResult
    {
        public InitializationVector Init;
        public EncryptedData Encrypted;
        public Signature Signature;
    }

    public class DecryptAndVerifyResults
    {
        public PlainData Decrypted;
        public bool IsSignatureValid;
    }

}
