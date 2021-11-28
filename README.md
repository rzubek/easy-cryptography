# Easy Cryptography

Easy, simple C# API for common cryptography operations. 

Based on built-in .NET crypto libraries, but with very simple API with safe defaults.



## What? Why?

Because sometimes we just need a simple library to `Encrypt()`, `Decrypt()`, `Sign()` and `Verify()` 
without a lot of research into correct settings and arcane flags.

This library came out of personal need to do similar data protection operations on several projects,
and getting tired of the boilerplate, and of trying to remember how to set up the same settings every time.




## What it provides

This library wraps the built-in crossplatform .NET System.Security.Cryptography libraries, in the following way:

  * Provides *safe, modern defaults* for all algorithms
  * Provides *easy API with typed containers* instead of plain byte arrays, to prevent common mistakes (see below)
  * Provides initialization, boilerplate, and teardown for all operations
  * Hides legacy algorithms 
  * Hides configuration options
  * Single-file implementation that can be embedded in projects

Some API highlights:

  * `Encrypt()` and `Decrypt()` functions to encrypt/decrypt data with a given secret key 
  * `EncryptAndSign()` and `DecryptAndVerify()` provide encryption and also detects third-party tampering
  * `Sign()` and `Verify()` functions just compute/check anti-tampering signatures of any data
  * `CreateKey*()` functions securely generate encryption keys (from string passwords, from byte array sources,
    or completely random)
  * `Hash()` computes strong hashes of any byte array 
  * `Random()` computes cryptographically random sequence of bytes

Finally, the built-in .NET cryptography APIs can be tricky, with many configuration options, variously operating on streams
and at other times on byte arrays, or relying on disposable classes for even simplest operations.
This API standardizes access and hides those implementation details.


## Examples

Here are some usage examples:

```csharp

// we can make the key completely random, or from some specific password

var key = Crypto.CreateKeyFromPassword("password", "salt"); // salt optional
// or: var key = Crypto.CreateKeyRandom();

// let's encrypt and decrypt some data
// encrypted includes both the ciphertext and init vector

var encrypted = Crypto.Encrypt(plainData, key);
var decrypted = Crypto.Decrypt(encrypted, key);

AssertBytesEqual(plainData, decrypted.Decrypted);

// decryption by itself doesn't know if encrypted data might be invalid
// or modified, so we have functions to both encrypt and sign the result,
// which will detect any tampering or accidental changes.

var encryptedSigned = Crypto.EncryptAndSign(plainData, key);
var decryptedSigned = Crypto.DecryptAndVerify(encryptedSigned, key);

Assert.IsTrue(decryptedSigned.IsSignatureValid);
AssertBytesEqual(plainData, decryptedSigned.Decrypted);

// we can also just sign any kind of a byte array and then verify
// that it hasn't been changed

var signature = Crypto.Sign(plainData, key);
var isValid = Crypto.Verify(signature, plainData, key);

Assert.IsTrue(isValid);

// finally just a simple wrapper around strong hash 
// and random number generator

var random = Crypto.Random(32);

var hash1 = Crypto.Hash("hello");
var hash2 = Crypto.Hash(Encoding.UTF8.GetBytes("hello"));

AssertBytesEqual(hash1, hash2);
```

### Default settings

Settings are user-configurable, but the defaults are:
  * Encrypt/decrypt: AES 128-bit in CRC mode (default in .NET)
  * Sign/verify: HMAC using SHA256 in EtM mode
  * Create key: PBKDF2 using SHA256 and 100k iterations
  * Hash: SHA256

#### Typesafe wrappers

In order to prevent accidental reuse of data in wrong contexts, or conversions
from string to byte arrays without going through appropriate steps, the library
uses the following strongly typed wrappers around `byte[]` byte arrays:
  * ByteArray - what cryptographers would call "plaintext", i.e. bytes before encryption
  * SecretKey - key used for symmetric encryption. The API makes it easy to create from a string
    password and (optional) salt via PBKDF, or from a strong random number generator.
  * EncryptResult - contains two elements that need to be persisted for future decryption:
    * EncryptedData - what cryptographers call "ciphertext", just the encrypted results.
    * InitializationVector - initial random state that must be persisted for decryption. 
      Init vector is not secret, but it needs be re-randomized each time we encrypt something.
  * EncryptAndSignResult - contains three elements that need to be persisted for decryption and checking:
    * EncryptedData - as above
    * InitializationVector - as above
    * Signature - byte array containing the cryptographic signature of the encrypted data,
      to detect if EncryptedData array was accidentally or intentionally modified after encryption.
  * DecryptResult - plaintext from decrypting ciphertext.
  * DecryptAndVerifyResult - plaintext and results of verification.



## What are the common mistakes this prevents?

Implementing simple encryption or authenticity checking can be frustrating - there's a large number
of algorithms, tuning values, or implementation choices. This is great for advanced users aware of 
correct usage and tradeoffs, but unnecessary for new users, or users who want simple encryption with sane defaults.

On the other hand, when new users turn to web search or Stack Overflow to get started,
they can find many examples of problematic or incorrect answers, which haven't been
corrected or updated:

  * Some examples convert user passwords into encryption keys by just grabbing the byte array of the string. 
    This is a common mistake, but very serious because strings don't have nearly enough randomness to be secure. 
    We have password derivation functions for that.
  * Some examples reuse IVs (initialization vectors), for example by declaring them as global constants.
    This can lead to vulnerabilities, because IVs are meant to be regenerated for each encryption operation -
    but they also need to be retained for use in decryption. Our implementation handles this.
  * Some examples implement anti-tampering by simply hashing data with some salt and comparing hashes. 
    This is vulnerable to spoofing, and instead we have signing API that provides HMAC authentication.
  * Some examples use old, legacy algorithms such as SHA1 for hashing, or AES-ECB for encryption. 
    .NET provides many compatibility options, but unfortunately very little guidance, 
    and the alphabet soup makes this decision difficult for new users.
  * Some cases of .NET documentation about encryption leads the user into trying to implement enterprise key management,
    storing keys in secure storage, and so on. This is appropriate for enterprise deployments, but is entirely
    inappropriate for small-scale projects, and can lead to data loss if the user mis-configures secure storage
    and loses access to their keys. This project side-steps all this, and lets the user handle keys just like other data.

This library aims to relieve these kinds of problems by making some very opinionated choices
(but still letting the user override default values with their own choices), 
and hiding as many implementation details as possible:

  * Secret keys can be loaded from a byte array, generated from a string password (which will automatically 
    invoke a strong derivation function), or generated uniquely from random data.
  * IV gets regenerated during each encryption, and persisted in EncryptResult
  * Encrypted results are signed with HMAC which is resistant to modification, extension attacks, etc.
  * Encryption and signing algorithms are set to use modern and secure defaults
  * Keys are stored and loaded from byte arrays, without making any assumptions about 
    storing the keys inside any kind of enterprise key management systems.
    Users can load them from environment variables, temp settings files, or some other method.



