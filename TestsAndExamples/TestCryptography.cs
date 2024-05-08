using NUnit.Framework;

namespace EasyCryptography
{
    public class TestCryptography : TestClass
    {
        [Test]
        public void SignatureExamples () {

            // here's how to sign and check a plain encrypted byte array
            var signature = EasyCryptography.Sign(plainData, testKey);
            var isSignatureValid = EasyCryptography.Verify(signature, plainData, testKey);

            Assert.That(isSignatureValid, Is.True);
        }

        [Test]
        public void SymmetricEncryptionExamples () {

            // let's encrypt and decrypt some data
            var encrypted = EasyCryptography.Encrypt(plainData, testKey, false);
            var decrypted = EasyCryptography.Decrypt(encrypted, testKey);

            Assert.That(decrypted.IsSignatureMissing, Is.True);
            AssertBytesEqual(plainData, decrypted.Data);

            // if we mess with encrypted data, we'll get a mess back
            var copyenc = EncryptedBytes.RawCopyFrom(encrypted.Data.Data);
            copyenc.Data[0] = copyenc.Data[1] = 0;
            var test = new Encrypted(copyenc, encrypted.IV, encrypted.Signature);
            decrypted = EasyCryptography.Decrypt(test, testKey);

            Assert.That(decrypted.IsSignatureMissing, Is.True);
            AssertBytesDiffer(plainData, decrypted.Data);

            // alternatively if we mess with the initialization vector, we'll also get a mess back
            var copyiv = InitializationVector.RawCopyFrom(encrypted.IV.Data);
            copyiv.Data[0] = copyiv.Data[1] = 0;
            test = new Encrypted(encrypted.Data, copyiv, encrypted.Signature);
            decrypted = EasyCryptography.Decrypt(test, testKey);

            Assert.That(decrypted.IsSignatureMissing, Is.True);
            AssertBytesDiffer(plainData, decrypted.Data);
        }

        [Test]
        public void SymmetricSignedEncryptionExamples () {

            // let's encrypt and sign some data
            var encrypted = EasyCryptography.Encrypt(plainData, testKey);
            var decrypted = EasyCryptography.Decrypt(encrypted, testKey);

            Assert.That(decrypted.IsSignatureValid, Is.True);
            Assert.That(decrypted.IsSignatureInvalid, Is.False);
            AssertBytesEqual(plainData, decrypted.Data);

            // now if we mess with encrypted data, we'll get invalid flag back instead
            // so we know the data has been tampered with
            encrypted.Data.Data[0] = encrypted.Data.Data[1] = 0;
            decrypted = EasyCryptography.Decrypt(encrypted, testKey);

            Assert.That(decrypted.IsSignatureValid, Is.False);
            Assert.That(decrypted.IsSignatureInvalid, Is.True);
            AssertBytesDiffer(plainData, decrypted.Data);
        }

        [Test]
        public void RandomInitializationVectorExamples () {
            // let's encrypt and decrypt some data
            var encrypted = EasyCryptography.Encrypt(plainData, testKey, false);
            var decrypted = EasyCryptography.Decrypt(encrypted, testKey).Data;

            // if we encrypt it again with the same key, we will *NOT* get the same cyphertext!
            // but we will of course get the same plaintext after decryption
            var encryptedAgain = EasyCryptography.Encrypt(plainData, testKey, false);
            var decryptedAgain = EasyCryptography.Decrypt(encryptedAgain, testKey).Data;

            AssertBytesEqual(decrypted, decryptedAgain);
            AssertBytesDiffer(encryptedAgain.Data, encrypted.Data);

            // but if we re-encrypt with the same initialization vector,
            // the ciphertexts will match, and plaintexts will match
            encryptedAgain = EasyCryptography.Encrypt(plainData, testKey, encrypted.IV, false);
            decryptedAgain = EasyCryptography.Decrypt(encryptedAgain, testKey).Data;

            AssertBytesEqual(decrypted, decryptedAgain);
            AssertBytesEqual(encryptedAgain.Data, encrypted.Data);
        }

        [Test]
        public void CreateSecretKeyExamples () {

            // some random keys, they're different of course
            var key1 = EasyCryptography.CreateSecretKeyRandom();
            var key2 = EasyCryptography.CreateSecretKeyRandom();
            var key3 = EasyCryptography.CreateSecretKeyRandom();

            Assert.That(Check.BytewiseEquals(key1, key2), Is.False);
            Assert.That(Check.BytewiseEquals(key2, key3), Is.False);

            // keys created from the same salt/password should be the same,
            // but if we change the salt, they should change
            var passkey1a = EasyCryptography.CreateKeyFromPassword("foo", "salt1");
            var passkey1b = EasyCryptography.CreateKeyFromPassword("foo", "salt1");

            AssertBytesEqual(passkey1a, passkey1b);

            var passkey2a = EasyCryptography.CreateKeyFromPassword("foo", "salt2");

            AssertBytesDiffer(passkey1a, passkey2a);

            // multiple keys created intentionally without salt should be the same
            var nosaltkey1 = EasyCryptography.CreateKeyFromPassword("foo", "");
            var nosaltkey2 = EasyCryptography.CreateKeyFromPassword("foo", "");

            AssertBytesEqual(nosaltkey1, nosaltkey2);
        }
    }
}