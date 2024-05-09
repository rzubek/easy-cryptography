# Easy Cryptography

Greatly simplified C# API wrapper for common symmetric cryptography operations. 

- *Single-file library* that's ready to be dropped into other projects
- Robust API with *safe defaults*
- *Pure C#* implementation based on built-in .NET crypto libraries
- Compatible with *.NET Core 8.0*


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

  * `Encrypt()` function will encrypt some data with a given secret key, and add a signature to detect tampering
    * Signatures are optional and can be skipped without affecting encryption
  * `Decrypt()` function will decrypt data, and if a signature is present, check it and report whether it matches
  * `Sign()` and `Verify()` functions just compute/check anti-tampering signatures of any byte array
  * `CreateKey*()` functions securely generate encryption keys (from string passwords, from byte array sources,
    or completely random)
  * `Hash()` computes strong hashes of any byte array 
  * `Random()` computes cryptographically random sequence of bytes
  * `*.Save()` and `*.Load()` function for persisting encrypted data to a flat byte array, and loading it back up

Finally, the built-in .NET cryptography APIs can be tricky, with many configuration options, variously operating on streams
and at other times on byte arrays, or relying on disposable classes for even simplest operations.
This API standardizes access and hides those implementation details.


## Examples

Here are some usage examples:

```csharp

// we can make the key completely random, or from some specific password

var key = EasyCryptography.CreateKeyFromPassword("password", "salt"); // salt optional
// or: var key = EasyCryptography.CreateKeyRandom();

// let's encrypt and decrypt some data
// encrypted result includes both the ciphertext and init vector

// encryption by itself doesn't know if encrypted data might've been modified,
// so by default we include extra cryptographic signature to detect if data
// might have been tampered with between encryption and decryption

var encrypted = EasyCryptography.Encrypt(plainData, key);
var decrypted = EasyCryptography.Decrypt(encrypted, key);

AssertBytesEqual(plainData, decrypted.Bytes);
Assert.IsTrue(decrypted.IsSignatureValid);

// optionally we can skip signing and save ourselves 16 bytes 

var encrypted = EasyCryptography.Encrypt(plainData, key, false);
var decrypted = EasyCryptography.Decrypt(encrypted, key);

AssertBytesEqual(plainData, decrypted.Bytes);
Assert.IsTrue(decrypted.IsNotSigned);

// encryption results can be easily serialized into a byte array and back

byte[] encbytes = EasyCryptography.Encrypt(plainData, key).ToBytes();
var decrypted = EasyCryptography.Decrypt(Encrypted.FromBytes(encbytes), key);

Assert.IsTrue(decrypted.IsSignatureValid);
AssertBytesEqual(plainData, decrypted.Bytes);


// we can also just sign any kind of a byte array and then verify
// that it hasn't been changed

var signature = EasyCryptography.Sign(plainData, key);
var validated = EasyCryptography.Verify(signature, plainData, key);

Assert.IsTrue(validated);

// finally just a simple wrapper around strong hash 
// and random number generator

var random = EasyCryptography.Random(32);

var hash1 = EasyCryptography.Hash("hello");
var hash2 = EasyCryptography.Hash(Encoding.UTF8.GetBytes("hello"));

AssertBytesEqual(hash1, hash2);
```

### Default settings

Settings are user-configurable, but the defaults are:
  * Encrypt/decrypt: AES 128-bit in CRC mode (default in .NET)
  * Sign/verify: HMAC using SHA256 in EtM mode
  * Create key: PBKDF2 using SHA256 and 10k iterations
  * Hash: SHA256


### Typesafe wrappers

In order to prevent accidental reuse of data in wrong contexts, or conversions
from string to byte arrays without going through appropriate steps, the library
uses the following strongly typed wrappers around `byte[]` byte arrays:
  * SecretKey - key used for symmetric encryption. The API makes it easy to create one from a string
    password and (optional) salt via PBKDF, or from a strong random number generator.
  * EncryptedData - contains three elements that need to be persisted for decryption and checking:
    * EncryptedPayload - the encrypted results, i.e. the ciphertext produced by encryption
    * InitializationVector - initial random state that must be persisted for decryption 
    * Signature - byte array containing the cryptographic signature of the encrypted data,
      to detect if EncryptedData array was accidentally or intentionally modified after encryption
  * DecryptedData - contains two elements produced by decryption
    * byte[] Data - byte array that contains the result of decryption, and
    * SignatureValidationResult - flag that specifies whether the signature was valid / invalid / not present
  * Signature - byte array that is the cryptographic signature of some data using a secret key
  * Hash - byte array that is the hash (specifically secure HMAC) of some input data




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
  * Some examples ignore tampering issues. Decryption does not know whether someone tampered with encrypted bytes,
    so an explicit signature is necessary on any data that might be modified by end-users.
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
  * Encryption produces and checks anti-tampering signatures by default, but it can be turned off
  * Encrypted results are signed with HMAC which is resistant to modification, extension attacks, etc.
  * Encryption and signing algorithms are set to use modern and secure defaults
  * Keys are stored and loaded from byte arrays, without making any assumptions about 
    storing the keys inside any kind of enterprise key management systems.
    Users can load them from environment variables, temp settings files, or some other method.



