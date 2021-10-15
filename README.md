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


### What are the common mistakes this prevents?

Implementing simple encryption or authenticity checking can be frustrating - there's a large number
of algorithms, tuning values, or implementation choices. This is great for advanced users aware of 
correct usage and tradeoffs, but not ideal for new users, or users who want simple encryption with sane defaults.

On the other hand, when new users turn to web search or Stack Overflow to get started,
they can find many examples of suboptimal or just flat-out problematic answers,
which may be okay for illustration purposes but not for production use.

Some specific example:
  * Some examples show how to converting passwords into encryption keys by just grabbing the byte array of the string. 
    This is a common mistake, but quite serious because strings don't have nearly enough randomness to be secure. 
    We have password derivation functions for that.
  * Some examples reuse IVs (initialization vectors), for example by declaring them as global constants.
    This can lead to vulnerabilities, because IVs are meant to be regenerated for each encryption operation -
    but they also need to be retained for use in decryption. Our implementation handles this.
  * Some examples implement anti-tampering by hashing data with some salt and comparing hashes. 
    This is vulnerable to spoofing, and we have signing API that provides HMAC authentication instead.
  * Some examples use old, legacy algorithms such as SHA1 for hashing, or AES-ECB for encryption. 
    .NET provides many compatibility options, but unfortunately very little guidance, 
    and the alphabet soup makes this decision difficult for new users.
  * Some cases of .NET documentation about encryption leads the user into trying to understand enterprise key management,
    storing keys in secure storage, and so on. This is appropriate for enterprise deployments, but is entirely
    inappropriate for small-scale projects, and can lead to data loss if the user mis-configures secure storage
    and loses access to their keys. This project side-steps all this, and lets the user handle keys just like other data.

This library aims to relieve these kinds of problems by making some very opinionated choices
(but still letting the user override default values with their own choices), 
and hiding as many implementation details as possible.

### Default settings

Settings are user-configurable, but the defaults are:
  * Encrypt/decrypt: AES 128-bit in CRC mode (default in .NET)
  * Sign/verify: HMAC using SHA256
  * Create key: PBKDF2 using SHA256 and 10k iterations
  * Hash: SHA256

