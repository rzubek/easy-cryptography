using NUnit.Framework;
using System;

namespace EasyCryptography
{
    public abstract class TestClass
    {
        public byte[] plainData = MakeFilled(512, 42);
        public SecretKey testKey = Crypto.CreateSecretKeyRandom();

        protected void AssertBytesEqual (byte[] a, byte[] b) =>
            Assert.IsTrue(Check.BytewiseEquals(a, b));

        protected void AssertBytesDiffer (byte[] a, byte[] b) =>
            Assert.IsFalse(Check.BytewiseEquals(a, b));

        protected void AssertBytesEqual<T> (ByteArray<T> a, ByteArray<T> b) where T : ByteArray<T>, new() =>
            Assert.IsTrue(Check.BytewiseEquals(a, b));

        protected void AssertBytesDiffer<T> (ByteArray<T> a, ByteArray<T> b) where T : ByteArray<T>, new() =>
            Assert.IsFalse(Check.BytewiseEquals(a, b));

        protected static byte[] MakeFilled (int bytes, byte fill) {
            var result = new byte[bytes];
            Array.Fill(result, fill);
            return result;
        }
    }
}