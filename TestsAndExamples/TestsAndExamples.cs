using NUnit.Framework;
using System;
using System.Text;

namespace EasyCryptography
{
    public class Tests
    {
        public byte[] plainData = MakeFilled(512, 42);
        public SecretKey key = Crypto.CreateKeyRandom();

        [Test]
        public void HashExamples () {

            // here's how to compute simple hashes
            var hash1 = Crypto.Hash("hello");
            var hash2 = Crypto.Hash(Encoding.UTF8.GetBytes("hello"));

            AssertBytesEqual(hash1, hash2);
        }

        [Test]
        public void SignatureExamples () {

            // here's how to sign and check a plain encrypted byte array
            var signature = Crypto.Sign(plainData, key);
            var isSignatureValid = Crypto.Verify(signature, plainData, key);

            Assert.IsTrue(isSignatureValid);
        }

        [Test]
        public void RandomnessExamples () {

            // just some cryptographically random bytes, they won't be equal of course
            var random1 = Crypto.Random(32);
            var random2 = Crypto.Random(32);

            AssertBytesDiffer(random1, random2);
        }

        [Test]
        public void EncryptionExamples () {

            // let's encrypt and decrypt some data
            var encrypted = Crypto.Encrypt(plainData, key);
            var decrypted = Crypto.Decrypt(encrypted, key);

            AssertBytesEqual(plainData, decrypted.Decrypted);

            // if we mess with encrypted data, we'll get a mess back
            var copyEncryptedData = new EncryptedData(encrypted.Encrypted.Bytes);
            copyEncryptedData.Bytes[0] = copyEncryptedData.Bytes[1] = 0;
            var test = new EncryptResult { Encrypted = copyEncryptedData, Init = encrypted.Init };
            decrypted = Crypto.Decrypt(test, key);

            AssertBytesDiffer(plainData, decrypted.Decrypted);

            // alternatively if we mess with the initialization vector, we'll also get a mess back
            var copyInitVector = new InitializationVector(encrypted.Init.Bytes);
            copyInitVector.Bytes[0] = copyInitVector.Bytes[1] = 0;
            test = new EncryptResult { Encrypted = encrypted.Encrypted, Init = copyInitVector };
            decrypted = Crypto.Decrypt(test, key);

            AssertBytesDiffer(plainData, decrypted.Decrypted);
        }

        [Test]
        public void SignedEncryptionExamples () {

            // let's encrypt and sign some data
            var encryptedSigned = Crypto.EncryptAndSign(plainData, key);
            var decryptedSigned = Crypto.DecryptAndVerify(encryptedSigned, key);

            Assert.IsTrue(decryptedSigned.IsSignatureValid);
            Assert.IsNotNull(decryptedSigned.Decrypted);
            AssertBytesEqual(plainData, decryptedSigned.Decrypted);

            // now if we mess with encrypted data, we'll get a null back instead
            // so we know the data has been tampered with
            encryptedSigned.Encrypted.Bytes[0] = encryptedSigned.Encrypted.Bytes[1] = 0;
            decryptedSigned = Crypto.DecryptAndVerify(encryptedSigned, key);

            Assert.IsFalse(decryptedSigned.IsSignatureValid);
            Assert.IsNull(decryptedSigned.Decrypted);
        }

        [Test]
        public void InitializationVectorExamples () {
            // let's encrypt and decrypt some data
            var encrypted = Crypto.Encrypt(plainData, key);
            var decrypted = Crypto.Decrypt(encrypted, key);

            // if we encrypt it again with the same key, we will *NOT* get the same cyphertext!
            // but we will of course get the same plaintext after decryption
            var encryptedAgain = Crypto.Encrypt(plainData, key);
            var decryptedAgain = Crypto.Decrypt(encryptedAgain, key);

            AssertBytesEqual(decrypted.Decrypted, decryptedAgain.Decrypted);
            AssertBytesDiffer(encryptedAgain.Encrypted, encrypted.Encrypted);

            // but if we re-encrypt with the same initialization vector,
            // the ciphertexts will match, and plaintexts will match
            encryptedAgain = Crypto.Encrypt(plainData, key, encrypted.Init);
            decryptedAgain = Crypto.Decrypt(encryptedAgain, key);

            AssertBytesEqual(decrypted.Decrypted, decryptedAgain.Decrypted);
            AssertBytesEqual(encryptedAgain.Encrypted, encrypted.Encrypted);
        }

        [Test]
        public void CreateSecretKeyExamples () {

            // some random keys, they're different of course
            var key1 = Crypto.CreateKeyRandom();
            var key2 = Crypto.CreateKeyRandom();
            var key3 = Crypto.CreateKeyRandom();

            Assert.IsFalse(ByteArray.BytewiseEquals(key1, key2));
            Assert.IsFalse(ByteArray.BytewiseEquals(key2, key3));

            // keys created from the same salt/password should be the same,
            // but if we change the salt, they should change
            var passkey1a = Crypto.CreateKeyFromPassword("foo", "salt1");
            var passkey1b = Crypto.CreateKeyFromPassword("foo", "salt1");

            AssertBytesEqual(passkey1a, passkey1b);

            var passkey2a = Crypto.CreateKeyFromPassword("foo", "salt2");

            AssertBytesDiffer(passkey1a, passkey2a);

            // multiple keys created intentionally without salt should be the same
            var nosaltkey1 = Crypto.CreateKeyFromPasswordNoSalt("foo");
            var nosaltkey2 = Crypto.CreateKeyFromPasswordNoSalt("foo");

            AssertBytesEqual(nosaltkey1, nosaltkey2);
        }

        private void AssertBytesEqual (byte[] a, byte[] b) => Assert.IsTrue(ByteArray.BytewiseEquals(a, b));
        private void AssertBytesDiffer (byte[] a, byte[] b) => Assert.IsFalse(ByteArray.BytewiseEquals(a, b));

        private void AssertBytesEqual (ByteArray a, ByteArray b) => Assert.IsTrue(ByteArray.BytewiseEquals(a, b));
        private void AssertBytesDiffer (ByteArray a, ByteArray b) => Assert.IsFalse(ByteArray.BytewiseEquals(a, b));

        private static byte[] MakeFilled (int bytes, byte fill) {
            var result = new byte[bytes];
            Array.Fill(result, fill);
            return result;
        }
    }
}