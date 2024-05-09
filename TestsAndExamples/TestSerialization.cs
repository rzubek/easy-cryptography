using NUnit.Framework;

namespace EasyCryptography
{
    public class TestSerialization : TestClass
    {
        [Test]
        public void TestSaveAndLoad () {

            // test simple ByteArray subtypes - they all work the same
            {
                var key2bytes = testKey.ToBytes();
                var keyloaded = SecretKey.FromBytes(key2bytes);

                AssertBytesEqual(testKey, keyloaded);
            }

            {
                var signature = EasyCryptography.Sign(plainData, testKey);
                var sig2bytes = signature.ToBytes();
                var sigloaded = Signature.FromBytes(sig2bytes);
                var isSignatureValid = EasyCryptography.Verify(sigloaded, plainData, testKey);

                Assert.That(isSignatureValid, Is.True);
            }
        }

        [Test]
        public void TestEncryptionResults () {

            // test encryption results 
            {
                var encrypted = EasyCryptography.Encrypt(plainData, testKey, false);
                var enc2bytes = encrypted.ToBytes();

                var encloaded = EncryptedData.FromBytes(enc2bytes);
                var decrypted = EasyCryptography.Decrypt(encloaded, testKey);

                Assert.That(decrypted.IsSignatureMissing, Is.True);
                AssertBytesEqual(plainData, decrypted.Data);
            }

            {
                var encsigned = EasyCryptography.Encrypt(plainData, testKey);
                var enc2bytes = encsigned.ToBytes();

                var encloaded = EncryptedData.FromBytes(enc2bytes);
                var decrypted = EasyCryptography.Decrypt(encloaded, testKey);

                Assert.That(decrypted.IsSignatureValid, Is.True);
                AssertBytesEqual(plainData, decrypted.Data);
            }
        }
    }
}