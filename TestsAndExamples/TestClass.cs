using NUnit.Framework;
using System;

namespace EasyCryptography
{
    public abstract class TestClass
    {
        public byte[] plainData = MakeFilled(512, 42);
        public SecretKey testKey = EasyCryptography.CreateSecretKeyRandom();

        protected static void AssertBytesEqual (byte[] a, byte[] b) =>
            Assert.That(Check.BytewiseEquals(a, b), Is.True);

        protected static void AssertBytesDiffer (byte[] a, byte[] b) =>
            Assert.That(Check.BytewiseEquals(a, b), Is.False);

        protected static void AssertBytesEqual<T> (ByteArray<T> a, ByteArray<T> b) where T : ByteArray<T>, new() =>
            Assert.That(Check.BytewiseEquals(a, b), Is.True);

        protected static void AssertBytesDiffer<T> (ByteArray<T> a, ByteArray<T> b) where T : ByteArray<T>, new() =>
            Assert.That(Check.BytewiseEquals(a, b), Is.False);

        protected static byte[] MakeFilled (int bytes, byte fill) {
            var result = new byte[bytes];
            Array.Fill(result, fill);
            return result;
        }
    }
}