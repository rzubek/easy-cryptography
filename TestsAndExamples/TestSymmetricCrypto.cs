using NUnit.Framework;

namespace EasyCryptography
{
    public class TestSymmetricCrypto : TestClass
    {
        [Test]
        public void SignatureExamples () {

            // here's how to sign and check a plain encrypted byte array
            var signature = Crypto.Sign(plainData, testKey);
            var isSignatureValid = Crypto.Verify(signature, plainData, testKey);

            Assert.IsTrue(isSignatureValid);
        }

        [Test]
        public void SymmetricEncryptionExamples () {

            // let's encrypt and decrypt some data
            var encrypted = Crypto.Encrypt(plainData, testKey, false);
            var decrypted = Crypto.Decrypt(encrypted, testKey);

            Assert.IsTrue(decrypted.IsSignatureMissing);
            AssertBytesEqual(plainData, decrypted.Data);

            // if we mess with encrypted data, we'll get a mess back
            var copyenc = ByteArray<EncryptedBytes>.CopyFrom(encrypted.Data.Data);
            copyenc.Data[0] = copyenc.Data[1] = 0;
            var test = new Encrypted { Data = copyenc, IV = encrypted.IV, Signature = encrypted.Signature };
            decrypted = Crypto.Decrypt(test, testKey);

            Assert.IsTrue(decrypted.IsSignatureMissing);
            AssertBytesDiffer(plainData, decrypted.Data);

            // alternatively if we mess with the initialization vector, we'll also get a mess back
            var copyiv = ByteArray<InitializationVector>.CopyFrom(encrypted.IV.Data);
            copyiv.Data[0] = copyiv.Data[1] = 0;
            test = new Encrypted { Data = encrypted.Data, IV = copyiv, Signature = encrypted.Signature };
            decrypted = Crypto.Decrypt(test, testKey);

            Assert.IsTrue(decrypted.IsSignatureMissing);
            AssertBytesDiffer(plainData, decrypted.Data);
        }

        [Test]
        public void SymmetricSignedEncryptionExamples () {

            // let's encrypt and sign some data
            var encrypted = Crypto.Encrypt(plainData, testKey);
            var decrypted = Crypto.Decrypt(encrypted, testKey);

            Assert.IsTrue(decrypted.IsSignatureValid);
            Assert.IsFalse(decrypted.IsSignatureInvalid);
            AssertBytesEqual(plainData, decrypted.Data);

            // now if we mess with encrypted data, we'll get invalid flag back instead
            // so we know the data has been tampered with
            encrypted.Data.Data[0] = encrypted.Data.Data[1] = 0;
            decrypted = Crypto.Decrypt(encrypted, testKey);

            Assert.IsFalse(decrypted.IsSignatureValid);
            Assert.IsTrue(decrypted.IsSignatureInvalid);
            AssertBytesDiffer(plainData, decrypted.Data);
        }

        [Test]
        public void RandomInitializationVectorExamples () {
            // let's encrypt and decrypt some data
            var encrypted = Crypto.Encrypt(plainData, testKey, false);
            var decrypted = Crypto.Decrypt(encrypted, testKey).Data;

            // if we encrypt it again with the same key, we will *NOT* get the same cyphertext!
            // but we will of course get the same plaintext after decryption
            var encryptedAgain = Crypto.Encrypt(plainData, testKey, false);
            var decryptedAgain = Crypto.Decrypt(encryptedAgain, testKey).Data;

            AssertBytesEqual(decrypted, decryptedAgain);
            AssertBytesDiffer(encryptedAgain.Data, encrypted.Data);

            // but if we re-encrypt with the same initialization vector,
            // the ciphertexts will match, and plaintexts will match
            encryptedAgain = Crypto.Encrypt(plainData, testKey, encrypted.IV, false);
            decryptedAgain = Crypto.Decrypt(encryptedAgain, testKey).Data;

            AssertBytesEqual(decrypted, decryptedAgain);
            AssertBytesEqual(encryptedAgain.Data, encrypted.Data);
        }

        [Test]
        public void CreateSecretKeyExamples () {

            // some random keys, they're different of course
            var key1 = Crypto.CreateSecretKeyRandom();
            var key2 = Crypto.CreateSecretKeyRandom();
            var key3 = Crypto.CreateSecretKeyRandom();

            Assert.IsFalse(Check.BytewiseEquals(key1, key2));
            Assert.IsFalse(Check.BytewiseEquals(key2, key3));

            // keys created from the same salt/password should be the same,
            // but if we change the salt, they should change
            var passkey1a = Crypto.CreateKeyFromPassword("foo", "salt1");
            var passkey1b = Crypto.CreateKeyFromPassword("foo", "salt1");

            AssertBytesEqual(passkey1a, passkey1b);

            var passkey2a = Crypto.CreateKeyFromPassword("foo", "salt2");

            AssertBytesDiffer(passkey1a, passkey2a);

            // multiple keys created intentionally without salt should be the same
            var nosaltkey1 = Crypto.CreateKeyFromPassword("foo", "");
            var nosaltkey2 = Crypto.CreateKeyFromPassword("foo", "");

            AssertBytesEqual(nosaltkey1, nosaltkey2);
        }
    }
}