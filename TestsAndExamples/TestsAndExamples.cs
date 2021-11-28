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
        public void UnsignedEncryptionExamples () {

            // let's encrypt and decrypt some data
            var encrypted = Crypto.Encrypt(plainData, key, false);
            var decrypted = Crypto.Decrypt(encrypted, key);

            Assert.IsTrue(decrypted.IsNotSigned);
            AssertBytesEqual(plainData, decrypted.Bytes);

            // if we mess with encrypted data, we'll get a mess back
            var copyenc = ByteArray<EncryptedBytes>.CopyFrom(encrypted.Data.Bytes);
            copyenc.Bytes[0] = copyenc.Bytes[1] = 0;
            var test = new Encrypted { Data = copyenc, Init = encrypted.Init, Signature = encrypted.Signature };
            decrypted = Crypto.Decrypt(test, key);

            Assert.IsTrue(decrypted.IsNotSigned);
            AssertBytesDiffer(plainData, decrypted.Bytes);

            // alternatively if we mess with the initialization vector, we'll also get a mess back
            var copyiv = ByteArray<InitializationVector>.CopyFrom(encrypted.Init.Bytes);
            copyiv.Bytes[0] = copyiv.Bytes[1] = 0;
            test = new Encrypted { Data = encrypted.Data, Init = copyiv, Signature = encrypted.Signature };
            decrypted = Crypto.Decrypt(test, key);

            Assert.IsTrue(decrypted.IsNotSigned);
            AssertBytesDiffer(plainData, decrypted.Bytes);
        }

        [Test]
        public void SignedEncryptionExamples () {

            // let's encrypt and sign some data
            var encrypted = Crypto.Encrypt(plainData, key, true);
            var decrypted = Crypto.Decrypt(encrypted, key);

            Assert.IsTrue(decrypted.IsSignatureValid);
            AssertBytesEqual(plainData, decrypted.Bytes);

            // now if we mess with encrypted data, we'll get invalid flag back instead
            // so we know the data has been tampered with
            encrypted.Data.Bytes[0] = encrypted.Data.Bytes[1] = 0;
            decrypted = Crypto.Decrypt(encrypted, key);

            Assert.IsTrue(decrypted.IsSignatureNotValid);
            AssertBytesDiffer(plainData, decrypted.Bytes);
        }

        [Test]
        public void InitializationVectorExamples () {
            // let's encrypt and decrypt some data
            var encrypted = Crypto.Encrypt(plainData, key, false);
            var decrypted = Crypto.Decrypt(encrypted, key).Bytes;

            // if we encrypt it again with the same key, we will *NOT* get the same cyphertext!
            // but we will of course get the same plaintext after decryption
            var encryptedAgain = Crypto.Encrypt(plainData, key, false);
            var decryptedAgain = Crypto.Decrypt(encryptedAgain, key).Bytes;

            AssertBytesEqual(decrypted, decryptedAgain);
            AssertBytesDiffer(encryptedAgain.Data, encrypted.Data);

            // but if we re-encrypt with the same initialization vector,
            // the ciphertexts will match, and plaintexts will match
            encryptedAgain = Crypto.Encrypt(plainData, key, encrypted.Init, false);
            decryptedAgain = Crypto.Decrypt(encryptedAgain, key).Bytes;

            AssertBytesEqual(decrypted, decryptedAgain);
            AssertBytesEqual(encryptedAgain.Data, encrypted.Data);
        }

        [Test]
        public void CreateSecretKeyExamples () {

            // some random keys, they're different of course
            var key1 = Crypto.CreateKeyRandom();
            var key2 = Crypto.CreateKeyRandom();
            var key3 = Crypto.CreateKeyRandom();

            Assert.IsFalse(Crypto.BytewiseEquals(key1, key2));
            Assert.IsFalse(Crypto.BytewiseEquals(key2, key3));

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

        [Test]
        public void TestSerialization () {

            // test simple ByteArray subtypes - they all work the same

            {
                var key2bytes = key.Save();
                var keyloaded = SecretKey.Load(key2bytes);

                AssertBytesEqual(key, keyloaded);
            }

            {
                var signature = Crypto.Sign(plainData, key);
                var sig2bytes = signature.Save();
                var sigloaded = Signature.Load(sig2bytes);
                var isSignatureValid = Crypto.Verify(sigloaded, plainData, key);

                Assert.IsTrue(isSignatureValid);
            }

            // test encryption results 

            {
                var encrypted = Crypto.Encrypt(plainData, key, false);
                var enc2bytes = encrypted.Save();

                var encloaded = Encrypted.Load(enc2bytes);
                var decrypted = Crypto.Decrypt(encloaded, key);

                Assert.IsTrue(decrypted.IsNotSigned);
                AssertBytesEqual(plainData, decrypted.Bytes);
            }

            {
                var encsigned = Crypto.Encrypt(plainData, key, true);
                var enc2bytes = encsigned.Save();

                var encloaded = Encrypted.Load(enc2bytes);
                var decrypted = Crypto.Decrypt(encloaded, key);

                Assert.IsTrue(decrypted.IsSignatureValid);
                AssertBytesEqual(plainData, decrypted.Bytes);
            }
        }

        private void AssertBytesEqual (byte[] a, byte[] b) =>
            Assert.IsTrue(Crypto.BytewiseEquals(a, b));

        private void AssertBytesDiffer (byte[] a, byte[] b) =>
            Assert.IsFalse(Crypto.BytewiseEquals(a, b));

        private void AssertBytesEqual<T> (ByteArray<T> a, ByteArray<T> b) where T : ByteArray<T>, new() =>
            Assert.IsTrue(Crypto.BytewiseEquals(a, b));

        private void AssertBytesDiffer<T> (ByteArray<T> a, ByteArray<T> b) where T : ByteArray<T>, new() =>
            Assert.IsFalse(Crypto.BytewiseEquals(a, b));

        private static byte[] MakeFilled (int bytes, byte fill) {
            var result = new byte[bytes];
            Array.Fill(result, fill);
            return result;
        }
    }
}