using NUnit.Framework;

namespace EasyCryptography
{
    public class TestSerialization : TestClass
    {
        [Test]
        public void TestSimpleSerialization () {

            // test simple ByteArray subtypes - they all work the same
            {
                var key2bytes = testKey.ToBytes();
                var keyloaded = SecretKey.FromBytes(key2bytes);

                AssertBytesEqual(testKey, keyloaded);
            }

            {
                var signature = Crypto.Sign(plainData, testKey);
                var sig2bytes = signature.ToBytes();
                var sigloaded = Signature.FromBytes(sig2bytes);
                var isSignatureValid = Crypto.Verify(sigloaded, plainData, testKey);

                Assert.IsTrue(isSignatureValid);
            }
        }

        [Test]
        public void TestEncryptionResults () {

            // test encryption results 
            {
                var encrypted = Crypto.Encrypt(plainData, testKey, false);
                var enc2bytes = encrypted.ToBytes();

                var encloaded = Encrypted.FromBytes(enc2bytes);
                var decrypted = Crypto.Decrypt(encloaded, testKey);

                Assert.IsTrue(decrypted.IsSignatureMissing);
                AssertBytesEqual(plainData, decrypted.Data);
            }

            {
                var encsigned = Crypto.Encrypt(plainData, testKey);
                var enc2bytes = encsigned.ToBytes();

                var encloaded = Encrypted.FromBytes(enc2bytes);
                var decrypted = Crypto.Decrypt(encloaded, testKey);

                Assert.IsTrue(decrypted.IsSignatureValid);
                AssertBytesEqual(plainData, decrypted.Data);
            }
        }
    }
}