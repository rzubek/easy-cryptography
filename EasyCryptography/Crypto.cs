using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EasyCryptography
{
    public class Settings
    {
        public static readonly Settings DefaultSettings = new Settings() {
            HashAlgorithmID = "SHA256",
            HashDigestSize = 256,
            HMACAlgorithmID = "HMACSHA256",
            HMACDigestSize = 256,
            AESKeySize = 128,
            AESBlockSize = 128,
            PBKDF2Iterations = 10_000,
        };

        public static Settings Instance = DefaultSettings;

        public string HashAlgorithmID;
        public int HashDigestSize;
        public string HMACAlgorithmID;
        public int HMACDigestSize;

        public int AESKeySize;
        public int AESBlockSize;
        public int PBKDF2Iterations;

        public int HashDigestSizeBytes => HashDigestSize / 8;
        public int HMACDigestSizeBytes => HMACDigestSize / 8;
        public int AESKeySizeBytes => AESKeySize / 8;
        public int AESBlockSizeBytes => AESBlockSize / 8;
    }


    public static class Crypto
    {
        public static Hash Hash (string text) => Hash(Encoding.UTF8.GetBytes(text));
        public static Hash Hash (Data data) => Hash(data.Bytes);

        public static Hash Hash (byte[] bytes) {
            using var hash = HashAlgorithm.Create(Settings.Instance.HashAlgorithmID);
            return new Hash { Bytes = hash.ComputeHash(bytes) };
        }


        public static PlainData CreateBytesRandom (int bytecount) {
            using var rng = new RNGCryptoServiceProvider();
            var bytes = new byte[bytecount];
            rng.GetBytes(bytes);
            return new PlainData { Bytes = bytes };
        }

        public static SecretKey CreateKeyRandom () {
            using var aes = NewAes();
            var results = Data.Copy<SecretKey>(aes.Key);

            aes.Clear();
            return results;
        }

        public static SecretKey CreateKeyFromPasswordNoSalt (string password) =>
            CreateKeyFromPassword(password, Hash(password).Bytes);

        public static SecretKey CreateKeyFromPassword (string password, string salt) =>
            CreateKeyFromPassword(password, Hash(salt).Bytes);

        public static SecretKey CreateKeyFromPassword (string password, byte[] salt) {
            using var pbkdf2 = new Rfc2898DeriveBytes(
                password,
                Settings.Instance.HashDigestSizeBytes,
                Settings.Instance.PBKDF2Iterations,
                new HashAlgorithmName(Settings.Instance.HashAlgorithmID));

            if (salt != null) { pbkdf2.Salt = salt; }

            var bytes = pbkdf2.GetBytes(Settings.Instance.AESKeySizeBytes);
            return Data.Wrap<SecretKey>(bytes);
        }


        
        public static EncryptResults Encrypt (PlainData data, SecretKey key, InitializationVector iv = null) {
            // verify key length as expected
            if (key.Bytes.Length != Settings.Instance.AESKeySizeBytes) {
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

        public static DecryptResults Decrypt (EncryptResults encrypted, SecretKey key) {
            // verify key length as expected
            if (key.Bytes.Length != Settings.Instance.AESKeySizeBytes) {
                throw new ArgumentException("Unexpected key size", nameof(key));
            }

            using var aes = NewAes(key, encrypted.Init);
            using var transform = aes.CreateDecryptor();

            var decrypted = TransformData(encrypted.Encrypted.Bytes, transform);
            var results = new DecryptResults { Decrypted = Data.Copy<PlainData>(decrypted) };

            aes.Clear();
            return results;
        }


        // https://crypto.stackexchange.com/questions/8081/

        public static Signature Sign (Data original, SecretKey key) {
            using var hash = HMAC.Create(Settings.Instance.HMACAlgorithmID);
            hash.Key = key.Bytes;
            var result = hash.ComputeHash(original.Bytes);
            return Data.Wrap<Signature>(result);
        }

        public static bool Verify (Data original, Signature signature, SecretKey key) {
            var computed = Sign(original, key);
            return computed.BytewiseEquals(signature);
        }


        public static EncryptAndSignResult EncryptAndSign (PlainData data, SecretKey key) {
            var encrypted = Encrypt(data, key);
            var signature = Sign(encrypted.Encrypted, key);

            return new EncryptAndSignResult {
                Init = encrypted.Init,
                Encrypted = encrypted.Encrypted,
                Signature = signature,
            };
        }

        public static DecryptAndVerifyResults DecryptAndVerify (EncryptAndSignResult results, SecretKey key) {
            var encresults = new EncryptResults { Encrypted = results.Encrypted, Init = results.Init };
            var decrypted = Decrypt(encresults, key);
            var valid = Verify(results.Encrypted, results.Signature, key);
            return new DecryptAndVerifyResults { Decrypted = decrypted.Decrypted, IsSignatureValid = valid };
        }


        private static Aes NewAes (SecretKey key = null, InitializationVector iv = null) {
            var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.KeySize = Settings.Instance.AESKeySize;
            aes.BlockSize = Settings.Instance.AESBlockSize;

            if (key != null) { aes.Key = key.Bytes; }
            if (iv != null) { aes.IV = iv.Bytes; }
            return aes;
        }

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
