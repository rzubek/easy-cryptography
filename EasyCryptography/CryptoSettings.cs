namespace EasyCryptography
{
    /// <summary>
    /// Settings used by all cryptography operations.
    ///
    /// Symmetric encryption uses AES, with configurable key size.
    /// Hashing algorithms are configurable, SHA256 or larger is recommended.
    ///
    /// Default settings provide good general-use cryptography settings,
    /// please see description of each property for details.
    /// </summary>
    public class CryptoSettings
    {
        /// <summary>
        /// AES key size is the size of the data array containing encryption
        /// key, in bits. To encrypt using AES-128, specify a 128-bit key size.
        /// </summary>
        public int AESKeySize = 128;

        /// <summary>
        /// Hash algorithm string must be one of the allowed .NET hash names,
        /// such as "SHA256", "SHA512" and so on.
        ///
        /// The default algorithm is SHA-256, which produces 32-byte hashes.
        /// SHA-256 is recommended by NIST FIPS 180-3 standard and later.
        /// </summary>
        public string HashAlgorithmID = "SHA256";

        /// <summary>
        /// HMAC algorithm string must be one of the allowed .NET HMAC names,
        /// such as "HMACSHA256", "HMACSHA512", etc.
        ///
        /// The default algorithm is HMAC SHA-256, which produces 32-byte hashes.
        /// </summary>
        public string HMACAlgorithmID = "HMACSHA256";

        /// <summary>
        /// Iteration count is the number of hashing iterations performed
        /// by the public key derivation function. NIST recommends
        /// using as large of a value as feasible, to make brute-force
        /// cracking difficult, but at least 10,000 iterations.
        /// (https://pages.nist.gov/800-63-3/sp800-63b.html#memsecretver)
        /// </summary>
        public int PBKDF2Iterations = 10_000;
    }
}
