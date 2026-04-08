# Security

## Threat Model

This library is designed to protect against:

- **Signature forgery**: GOST R 34.10-2012 signatures are produced via OpenSSL's gost-engine, which implements the standard elliptic curve operations. Forging a signature requires solving the discrete logarithm problem on the curve.
- **Key theft via memory inspection**: The `Zeroize()` method securely wipes private key material and frees the underlying OpenSSL EVP_PKEY. A GC finalizer provides a safety net, but explicit cleanup is strongly recommended.
- **Key theft via swap**: Symmetric cipher keys (Kuznechik, Magma, MGM) are protected with `mlock()` to prevent the OS from swapping key material to disk. If `mlock()` is not available (insufficient privileges), the library degrades gracefully.
- **Tampering detection**: Signature verification rejects any modification to the signed message or signature bytes.
- **Authenticated encryption**: Both Kuznechik-MGM and Magma-MGM provide AEAD (authenticated encryption with associated data), detecting any ciphertext or AAD modification.

## What This Library Does NOT Protect Against

- **Side-channel attacks in application code**: The library delegates to OpenSSL for constant-time operations, but application-level code (key handling, logging, serialization) is not hardened against timing or cache side-channels.
- **Compromised random number generator**: Key generation and nonce selection rely on `crypto/rand` (which uses the OS CSPRNG). If the system RNG is compromised, all generated keys and signatures are weakened.
- **Physical attacks**: Hardware-level attacks (power analysis, electromagnetic emanation, fault injection) are out of scope for a software library.
- **Compromised build environment**: If the OpenSSL installation or gost-engine binary is tampered with, all cryptographic guarantees are void.

## Security Assumptions

1. **CSPRNG**: `crypto/rand.Reader` provides cryptographically secure random bytes from the operating system.
2. **Constant-time operations**: OpenSSL's gost-engine performs elliptic curve scalar multiplication and modular arithmetic in constant time, preventing timing side-channels in the core crypto.
3. **OpenSSL correctness**: The underlying OpenSSL 3.0+ and gost-engine v3.0.3+ implementations are correct and free of critical vulnerabilities.
4. **Memory isolation**: The Go runtime and operating system provide process-level memory isolation.

## Known Limitations

- **cgo dependency**: All cryptographic operations cross the cgo boundary. This adds overhead and prevents pure-Go compilation. The `CGO_ENABLED=1` flag is required.
- **No FIPS certification**: This library is NOT FIPS-certified and has NOT been certified by the Russian Federal Security Service (FSB). It should not be used in contexts that require such certification.
- **gost-engine version dependency**: The library is tested with gost-engine v3.0.3. Other versions may behave differently or lack support for certain operations.
- **No formal audit**: This code has not undergone a formal security audit by an independent third party.

## Memory Protection

### Zeroization

Private key material is held in OpenSSL's `EVP_PKEY` structures, allocated on the C heap (outside Go's garbage collector).

- **`Zeroize()` must be called explicitly** by the application when a private key is no longer needed. This frees the EVP_PKEY and nils the handle, ensuring the key cannot be used again.
- **GC finalizer is a safety net only**: A Go runtime finalizer calls `EVP_PKEY_free` if the `KeyHandle` is garbage collected without explicit cleanup. However, finalizer timing is non-deterministic and should not be relied upon for timely zeroization.
- **After `Zeroize()`**, any operation on the key (including `Bytes()`, `Sign()`, or `Verify()` via the derived public key) will return an error.
- **`PubKey` shares the handle** with its originating `PrivKey`. Do not use a `PubKey` after the `PrivKey` has been zeroized.
- **KDF intermediate values** (PRK, iteration outputs) are zeroized with `OPENSSL_cleanse` after use to prevent key material leakage from derived key operations.

### Memory Locking (mlock)

Symmetric cipher keys in `Kuznechik`, `Magma`, `MGM`, and `Magma-MGM` are locked in physical memory via `mlock()` to prevent the operating system from swapping them to disk.

- **mlock is best-effort**: If `mlock()` fails (insufficient privileges, `RLIMIT_MEMLOCK` exceeded), the library continues without memory locking. Use `openssl.MlockAvailable()` to check whether locking is active.
- **`Zeroize()` calls `munlock()`** after wiping the key, releasing the physical memory reservation.
- For maximum protection on Linux, run the application with `CAP_IPC_LOCK` capability or increase `RLIMIT_MEMLOCK`.

### Hash Input Buffering

The Streebog `hash.Hash` implementation keeps all written data in an in-memory buffer (no disk spill). This avoids the side-channel risk of writing sensitive data to temporary files. For very large inputs, memory usage scales linearly with input size.

Recommended pattern:

```go
priv, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
if err != nil {
    // handle error
}
defer priv.Zeroize() // always clean up

pub := priv.PublicKey()
sig, err := gostcrypto.Sign(priv, message)
// ... use sig and pub ...
```

## Vulnerability Disclosure

If you discover a security vulnerability in this library:

1. **Do NOT open a public GitHub issue.**
2. **Email**: Send details to the repository maintainers via the email listed in the GitHub profile.
3. **GitHub Security Advisories**: Alternatively, use [GitHub Security Advisories](https://docs.github.com/en/code-security/security-advisories) to report the vulnerability privately.

### Response Timeline

- **72 hours**: Acknowledgement of the report.
- **7 days**: Patch developed and tested.
- **30 days**: Public disclosure (coordinated with the reporter).

We follow responsible disclosure practices and will credit reporters (unless anonymity is requested).
