using NUnit.Framework;
using System.Text;

namespace EasyCryptography
{
    public class Tests
    {
        public PlainData plainData = Data.MakeFilled<PlainData>(512, 42);
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
            var isSignatureValid = Crypto.Verify(plainData, signature, key);
            Assert.IsTrue(isSignatureValid);
        }

        [Test]
        public void RandomnessExamples () {

            // just some cryptographically random bytes, they won't be equal of course
            var random1 = Crypto.CreateBytesRandom(32);
            var random2 = Crypto.CreateBytesRandom(32);
            AssertBytesDiffer(random1, random2);
        }

        [Test]
        public void EncryptionExamples () {

            // let's encrypt and decrypt some data
            var encrypted = Crypto.Encrypt(plainData, key);
            var decrypted = Crypto.Decrypt(encrypted, key);
            AssertBytesEqual(plainData, decrypted.Decrypted);

            // if we mess with encrypted data, we'll get a mess back
            encrypted.Encrypted.Bytes[0] = encrypted.Encrypted.Bytes[1] = 0;
            decrypted = Crypto.Decrypt(encrypted, key);
            AssertBytesDiffer(plainData, decrypted.Decrypted);
        }

        [Test]
        public void SignedEncryptionExamples () {

            // let's encrypt and sing some data
            var encryptedSigned = Crypto.EncryptAndSign(plainData, key);
            var decryptedSigned = Crypto.DecryptAndVerify(encryptedSigned, key);
            Assert.IsTrue(decryptedSigned.IsSignatureValid);
            AssertBytesEqual(plainData, decryptedSigned.Decrypted);

            // now if we mess with encrypted data, we'll get a null back instead
            // so we know the data has been tampered with
            encryptedSigned.Encrypted.Bytes[0] = encryptedSigned.Encrypted.Bytes[1] = 0;
            decryptedSigned = Crypto.DecryptAndVerify(encryptedSigned, key);
            Assert.IsFalse(decryptedSigned.IsSignatureValid);
            AssertBytesDiffer(plainData, decryptedSigned.Decrypted);
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
            Assert.IsFalse(key1.BytewiseEquals(key2));
            Assert.IsFalse(key2.BytewiseEquals(key3));

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


        private void AssertBytesEqual (Data a, Data b) => Assert.IsTrue(a.BytewiseEquals(b));
        private void AssertBytesDiffer (Data a, Data b) => Assert.IsFalse(a.BytewiseEquals(b));
    }
}