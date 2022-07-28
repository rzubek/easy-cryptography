using System;
using System.IO;

namespace EasyCryptography
{
    /// <summary>
    /// Abstract wrapper around byte[], parent of multiple strongly-typed classes that describe
    /// byte arrays with various semantics (secret key, encrypted data, signature, etc.)
    ///
    /// Because C# doesn't have facilities similar to `typedef` in C++, we do this by
    /// wrapping byte[] in a helper class and providing strongly typed subclasses.
    /// </summary>
    public abstract class ByteArray<T> where T : ByteArray<T>, new()
    {
        public byte[] Data;

        /// <summary> Serializes this object into a length-prefixed byte array </summary>
        public byte[] ToBytes () {
            using var mem = new MemoryStream();
            using var writer = new BinaryWriter(mem);
            Serialize(writer);
            return mem.ToArray();
        }

        /// <summary> Deserializes an instance of this class from a length-prefixed byte array </summary>
        public static T FromBytes (byte[] bytes) {
            using var mem = new MemoryStream(bytes);
            using var reader = new BinaryReader(mem);
            return Deserialize(reader);
        }

        /// <summary> Makes a new object from a copy of the source array </summary>
        public static T CopyFrom (byte[] source) {
            var bytes = new byte[source.Length];
            Array.Copy(source, bytes, source.Length);
            return new T() { Data = bytes };
        }

        #region Binary reader and writer utils

        public void Serialize (BinaryWriter writer) {
            writer.Write(Data.Length);
            writer.Write(Data);
        }

        internal static T Deserialize (BinaryReader reader) {
            int len = reader.ReadInt32();
            var bytes = reader.ReadBytes(len);
            return new T() { Data = bytes };
        }

        #endregion

    }

    /// <summary>
    /// Wrapper around a secret key used for encryption and signatures. Secret keys should be
    /// treated as secret, and not saved along with encrypted data.
    /// </summary>
    public class SecretKey : ByteArray<SecretKey> { }

    /// <summary>
    /// Wrapper around a byte array containing the results of encryption. To recover original
    /// data from encrypted data, one also needs initialization vector and secret key.
    /// </summary>
    public class EncryptedBytes : ByteArray<EncryptedBytes> { }

    /// <summary>
    /// Wrapper around a byte array containing the initialization vector for some encrypted data.
    /// This vector matches encrypted data and together they are needed during decryption.
    /// </summary>
    public class InitializationVector : ByteArray<InitializationVector> { }

    /// <summary>
    /// Wrapper around a byte array containing the hash of some input data given some key.
    /// </summary>
    public class Hash : ByteArray<Hash> { }

    /// <summary>
    /// Wrapper around a byte array containing the signature (aka authentication code or
    /// authentication tag) for some input data given some key.
    ///
    /// Signatures work similarly to hashes, but are much more resistant to tampering (for example,
    /// the chosen-prefix collision attack) at the cost of slightly slower execution time.
    /// </summary>
    public class Signature : ByteArray<Signature> { }

    /// <summary>
    /// Represents the result of signature validation.
    /// </summary>
    public enum SignatureValidationResult
    {
        SignatureMissing = -1,
        SignatureInvalid = 0,
        SignatureValid = 1,
    }

    /// <summary>
    /// Wrapper for encrypt result, which contains both encryption result (broken down to
    /// encrypted data and initialization vector) and the signature of encrypted data.
    /// All three pieces need to be presented when trying to verify the signature and decrypt.
    /// </summary>
    public class Encrypted
    {
        public EncryptedBytes Data;
        public InitializationVector IV;
        public Signature Signature;

        /// <summary> Serializes this object into a byte array </summary>
        public byte[] ToBytes () {
            using var mem = new MemoryStream();
            using var writer = new BinaryWriter(mem);
            Data.Serialize(writer);
            IV.Serialize(writer);
            Signature.Serialize(writer);
            return mem.ToArray();
        }

        /// <summary> Deserializes this object from a byte array </summary>
        public static Encrypted FromBytes (byte[] bytes) {
            using var mem = new MemoryStream(bytes);
            using var reader = new BinaryReader(mem);
            var encr = EncryptedBytes.Deserialize(reader);
            var init = InitializationVector.Deserialize(reader);
            var sign = Signature.Deserialize(reader);
            return new Encrypted { Data = encr, IV = init, Signature = sign };
        }
    }

    /// <summary>
    /// Wrapper for decrypt results and signature verification.
    /// </summary>
    public class Decrypted
    {
        /// <summary>
        /// Byte array that contains the decrypted data
        /// </summary>
        public byte[] Data;

        /// <summary>
        /// This flag specifies whether a signature was present and/or checked
        /// </summary>
        public SignatureValidationResult Result;

        /// <summary>
        /// Returns true if the data was never signed, so its accuracy is unknown.
        /// </summary>
        public bool IsSignatureMissing => Result == SignatureValidationResult.SignatureMissing;

        /// <summary>
        /// Returns true if the data was signed, and it matches the provided signature,
        /// showing that the encrypted data was not modified between encryption and decryption.
        /// </summary>
        public bool IsSignatureValid => Result == SignatureValidationResult.SignatureValid;

        /// <summary>
        /// Returns true if the data was signed, but it does not match the provided signature,
        /// suggesting that a modification happened sometime between encryption and decryption.
        /// </summary>
        public bool IsSignatureInvalid => Result == SignatureValidationResult.SignatureInvalid;

    }


    public static class Check
    {
        /// <summary>
        /// Returns true if the two byte arrays are either both null or both have the same bytes.
        /// </summary>
        public static bool BytewiseEquals<T> (ByteArray<T> a, ByteArray<T> b) where T : ByteArray<T>, new()
            => BytewiseEquals(a?.Data, b?.Data);

        /// <summary>
        /// Returns true if the two byte arrays are either both null or both have the same bytes.
        /// </summary>
        public static bool BytewiseEquals (byte[] a, byte[] b) {

            if (a == null && b == null) { return true; }  // both null
            if (a == null || b == null) { return false; } // one null but not the other

            if (a.Length != b.Length) { return false; }

            for (int i = 0, count = a.Length; i < count; i++) {
                if (a[i] != b[i]) { return false; }
            }

            return true;
        }

    }
}
