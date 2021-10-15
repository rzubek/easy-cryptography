# Easy Cryptography

Easy, simple C# API for common cryptography operations. 

Based on built-in .NET crypto libraries, but with very simple API with safe defaults.



# What? Why?

Because sometimes we just need a simple library to `Encrypt()`, `Decrypt()`, `Sign()` and `Verify()` 
without a lot of research into correct settings and arcane flags.

This library came out of personal need to do similar data protection operations on several projects,
and getting tired of the boilerplate, and of trying to remember how to set up the same settings every time.


## What it provides

This library wraps the built-in crossplatform .NET System.Security.Cryptography libraries, in the following way:

  * Provides safe, modern defaults for all algorithms
  * Provides easy API with typed containers instead of plain byte arrays, to prevent common mistakes (see below)
  * Provides initialization, boilerplate, and teardown for all operations
  * Hides legacy algorithms 
  * Hides configuration options

Some API highlights:

  * `Encrypt()` and `Decrypt()` functions to encrypt/decrypt data with a given secret key 
  * `EncryptAndSign()` and `DecryptAndVerify()` provide encryption and also detects third-party tampering
  * `Sign()` and `Verify()` functions just compute/check anti-tampering signatures of any data
  * `CreateKey*()` functions securely generate encryption keys (from string passwords, from byte array sources,
    or completely random), using PBKDF2 with SHA256 and a large number of iterations.
  * `Hash()` computes hashes of any byte array using SHA256
  * `CreateBytesRandom()` computes cryptographically random sequence of bytes

Finally, the .NET cryptography APIs can be frustratingly tricky, sometimes operating on streams
and at other times on byte arrays, or relying on disposable classes for even simplest operations.
This API standardizes access and hides those implementation details.


### What are the common mistakes this prevents?

There are many mistakes on Stack Overflow and even in some documentation, 
sometimes stemming from wanting to showcase some particular functionality, 
but which are inappropriate for use in production. 

Specific example:
  * Converting passwords into encryption keys by just grabbing the byte array of the string. 
    This is a common mistake, but crucial to avoid because strings don't have nearly enough randomness. 
    We have password derivation functions for that.
  * Reusing IVs (initialization vectors), for example by declaring them as global constants.
    This can lead to vulnerabilities, because IVs are meant to be regenerated for each encryption operation -
    but they also need to be retained for use in decryption. Our implementation handles this transparently.
  * Implementing anti-tampering by hashing data with some salt and comparing hashes. 
    This is vulnerable to spoofing, and we have signing API that provides HMAC authentication instead.
  * Using old, legacy algorithms such as SHA1 for hashing, or AES-ECB for encryption. 
    .NET provides many compatibility options, but unfortunately very little guidance, 
    and the alphabet soup makes this decision difficult for new users.


### Default settings

Settings are user-configurable, but the defaults are:
  * Encrypt/decrypt: AES 128-bit in CRC mode (default in .NET)
  * Sign/verify: HMAC using SHA256
  * Create key: PBKDF2 using SHA256 and 10k iterations
  * Hash: SHA256

