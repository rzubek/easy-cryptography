using NUnit.Framework;
using System.Text;

namespace EasyCryptography
{
    public class TestHashingAndRandomness : TestClass
    {
        [Test]
        public void HashExamples () {

            // here's how to compute simple hashes
            var hash1 = EasyCryptography.Hash("hello");
            var hash2 = EasyCryptography.Hash(Encoding.UTF8.GetBytes("hello"));

            AssertBytesEqual(hash1, hash2);
        }

        [Test]
        public void RandomnessExamples () {

            // just some cryptographically random bytes, they won't be equal of course
            var random1 = EasyCryptography.Random(32);
            var random2 = EasyCryptography.Random(32);

            AssertBytesDiffer(random1, random2);
        }
    }
}