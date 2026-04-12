# API Reference

Complete API reference for gost-crypto.

Backend: **CryptoPro CSP (CAPILite) + CryptoPro CAdES**.

[README](../README.md) | [README (Russian)](README.ru.md)

---

## Table of Contents

- [Root Package (gostcrypto)](#root-package-gostcrypto)
- [pkg/gost3410](#pkggost3410-package)
- [pkg/gost3411](#pkggost3411-package)
- [pkg/gost3412](#pkggost3412-package)
- [pkg/gost3413](#pkggost3413-package)
- [pkg/cms](#pkgcms-package)
- [pkg/gostx509](#pkggostx509-package)
- [pkg/kdf](#pkgkdf-package)
- [pkg/hd](#pkghd-package)
- [Error Handling](#error-handling)
- [Thread Safety](#thread-safety)

---

## Root Package (gostcrypto)

`import gostcrypto "github.com/rekurt/gost-crypto"`

High-level facade that re-exports types from `pkg/gost3410` and provides convenient Sign/Verify/Hash/Agree functions.

### Types

```go
type Curve = gost3410.Curve
type PrivKey = gost3410.PrivKey
type PubKey = gost3410.PubKey
```

### Functions

#### `GenerateKey(c Curve) (*PrivKey, error)`

Generates a new GOST R 34.10-2012 key pair for the given curve.

#### `LoadPrivKey(c Curve, raw []byte) (*PrivKey, error)`

Creates a private key from raw big-endian bytes. The raw bytes must be exactly the key size (32 for 256-bit curves, 64 for 512-bit curves).

#### `Sign(priv *PrivKey, msg []byte) ([]byte, error)`

Hashes `msg` with Streebog (auto-selected based on curve size) and signs with GOST R 34.10-2012. Returns signature as `r||s`.

#### `Verify(pub *PubKey, msg, sig []byte) (bool, error)`

Hashes `msg` with Streebog and verifies the GOST R 34.10-2012 signature.

#### `HashSum256(data []byte) [32]byte`

Returns the Streebog-256 digest of data.

#### `HashSum512(data []byte) [64]byte`

Returns the Streebog-512 digest of data.

#### `Agree(priv *PrivKey, pub *PubKey, ukm []byte) ([]byte, error)`

Performs VKO key agreement. Returns shared secret. Symmetric: `Agree(A, pubB, ukm) == Agree(B, pubA, ukm)`.

#### `AllCurves() []Curve`

Returns all 8 TC26 parameter sets.

### Sentinel Errors

```go
var (
    ErrUnknownCurve
    ErrPointNotOnCurve
    ErrInvalidKeySize
    ErrInvalidSignature
    ErrNilKey
    ErrCurveMismatch
    ErrEmptyUKM
)
```

---

## pkg/gost3410 Package

`import "github.com/rekurt/gost-crypto/pkg/gost3410"`

Low-level GOST R 34.10-2012 operations backed by CryptoPro CSP (CAPILite).

### Curve Type

```go
type Curve int

const (
    CurveTC26_256_A Curve = iota // id-tc26-gost-3410-2012-256-paramSetA
    CurveTC26_256_B              // CryptoPro-A
    CurveTC26_256_C              // CryptoPro-B
    CurveTC26_256_D              // CryptoPro-C
    CurveTC26_512_A
    CurveTC26_512_B
    CurveTC26_512_C
    CurveTC26_512_D              // test
)
```

### Functions

#### `GenerateKey(c Curve) (*PrivKey, error)`

Generates a random key pair for the given curve.

#### `LoadPrivKey(c Curve, raw []byte) (*PrivKey, error)`

Creates a private key from raw bytes via CryptoPro CSP.

#### `SignDigest(priv *PrivKey, digest []byte) ([]byte, error)`

Signs a pre-computed digest. Digest must be exactly key size bytes.

#### `VerifyDigest(pub *PubKey, digest, sig []byte) (bool, error)`

Verifies a signature over a pre-computed digest.

#### `VKO(priv *PrivKey, pub *PubKey, ukm []byte) ([]byte, error)`

Performs VKO key agreement (RFC 7836).

#### `AllCurves() []Curve`

Returns all 8 TC26 parameter sets.

### PrivKey Methods

- `Bytes() ([]byte, error)` -- returns raw private key bytes (sensitive!)
- `Curve() Curve` -- returns the curve parameter set
- `PublicKey() *PubKey` -- derives the public key
- `Public() crypto.PublicKey` -- implements `crypto.Signer`
- `Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)` -- implements `crypto.Signer`
- `MarshalBinary() ([]byte, error)` -- implements `encoding.BinaryMarshaler` (format: `[curve_id][raw_key]`)
- `UnmarshalBinary(data []byte) error` -- implements `encoding.BinaryUnmarshaler`
- `Zeroize()` -- securely wipes key material and frees CryptoPro handle
- `Handle()` -- returns the underlying CryptoPro CSP handle

### PubKey Methods

- `Bytes() ([]byte, error)` -- returns public key as a PUBLICKEYBLOB (CryptoPro format)
- `Curve() Curve` -- returns the curve parameter set
- `Validate() error` -- checks that the point lies on the curve
- `MarshalBinary() ([]byte, error)` -- implements `encoding.BinaryMarshaler`
- `Handle()` -- returns the underlying CryptoPro CSP handle

---

## pkg/gost3411 Package

`import "github.com/rekurt/gost-crypto/pkg/gost3411"`

GOST R 34.11-2012 Streebog hash functions via CryptoPro CSP.

### Hash Constructors

#### `New256() hash.Hash`

Returns a Streebog-256 hasher implementing `hash.Hash`.

#### `New512() hash.Hash`

Returns a Streebog-512 hasher implementing `hash.Hash`.

### One-Shot Hashing

#### `Sum256(data []byte) [32]byte`

Computes Streebog-256 digest in one call.

#### `Sum512(data []byte) [64]byte`

Computes Streebog-512 digest in one call.

### HMAC

#### `NewHMAC256(key []byte) hash.Hash`

Returns HMAC-Streebog-256 with the given key.

#### `NewHMAC512(key []byte) hash.Hash`

Returns HMAC-Streebog-512 with the given key.

### Hash Constants

```go
const (
    HashStreebog256 crypto.Hash = 100
    HashStreebog512 crypto.Hash = 101
)
```

These constants are **not** registered with `crypto.RegisterHash`. They are set above the standard library's `maxHash` to avoid collisions with built-in hash identifiers. You **cannot** use `crypto.Hash.New()` with them; use `gost3411.New256()` and `gost3411.New512()` directly instead.

---

## pkg/gost3412 Package

`import "github.com/rekurt/gost-crypto/pkg/gost3412"`

GOST R 34.12-2015 block ciphers via CryptoPro CSP.

### Constants

```go
const (
    KuznechikKeySize   = 32
    KuznechikBlockSize = 16
    MagmaKeySize       = 32
    MagmaBlockSize     = 8
)
```

### Interfaces

```go
type Zeroizable interface {
    Zeroize()
}
```

Implemented by all cipher objects. Securely wipes key material when called.

### Functions

#### `NewKuznechik(key []byte) (cipher.Block, error)`

Creates a Kuznechik (Grasshopper) cipher block. Key must be 32 bytes. Block size is 16 bytes (128 bits).

#### `NewMagma(key []byte) (cipher.Block, error)`

Creates a Magma cipher block. Key must be 32 bytes. Block size is 8 bytes (64 bits).

---

## pkg/gost3413 Package

`import "github.com/rekurt/gost-crypto/pkg/gost3413"`

GOST R 34.13-2015 block cipher modes of operation via CryptoPro CSP.

### AEAD (MGM -- Multilinear Galois Mode)

#### `NewKuznechikMGMFromKey(key []byte) (cipher.AEAD, error)`

Creates a Kuznechik-MGM AEAD. Nonce: 16 bytes, tag: 16 bytes.

#### `NewMagmaMGMFromKey(key []byte) (cipher.AEAD, error)`

Creates a Magma-MGM AEAD. Nonce: 8 bytes, tag: 8 bytes.

#### `NewMGMFromKey(key []byte) (cipher.AEAD, error)`

**Deprecated.** Alias for `NewKuznechikMGMFromKey`.

### CBC (Cipher Block Chaining)

#### `NewKuznechikCBC(key []byte) (*CBC, error)`
#### `NewMagmaCBC(key []byte) (*CBC, error)`

Plaintext must be block-aligned. No padding is applied.

**CBC methods:**

- `Encrypt(iv, plaintext []byte) ([]byte, error)`
- `Decrypt(iv, ciphertext []byte) ([]byte, error)`
- `BlockSize() int`
- `Zeroize()`

### CTR (Counter Mode)

#### `NewKuznechikCTR(key []byte) (*CTR, error)`
#### `NewMagmaCTR(key []byte) (*CTR, error)`

**CTR methods:**

- `Encrypt(iv, plaintext []byte) ([]byte, error)`
- `Decrypt(iv, ciphertext []byte) ([]byte, error)`
- `Stream(iv []byte) cipher.Stream` -- returns a `cipher.Stream` for use with streaming wrappers
- `Zeroize()`

### CFB (Cipher Feedback)

#### `NewKuznechikCFB(key []byte) (*CFB, error)`
#### `NewMagmaCFB(key []byte) (*CFB, error)`

**CFB methods:**

- `Encrypt(iv, plaintext []byte) ([]byte, error)`
- `Decrypt(iv, ciphertext []byte) ([]byte, error)`
- `StreamEncrypter(iv []byte) cipher.Stream` -- returns an encrypting `cipher.Stream`
- `StreamDecrypter(iv []byte) cipher.Stream` -- returns a decrypting `cipher.Stream`
- `Zeroize()`

### OFB (Output Feedback)

#### `NewKuznechikOFB(key []byte) (*OFB, error)`
#### `NewMagmaOFB(key []byte) (*OFB, error)`

**OFB methods:**

- `Encrypt(iv, plaintext []byte) ([]byte, error)`
- `Decrypt(iv, ciphertext []byte) ([]byte, error)`
- `Stream(iv []byte) cipher.Stream` -- returns a `cipher.Stream` for use with streaming wrappers
- `Zeroize()`

### CMAC (OMAC1)

#### `NewKuznechikCMAC(key []byte) (*CMAC, error)`
#### `NewMagmaCMAC(key []byte) (*CMAC, error)`

**CMAC methods:**

- `MAC(message []byte) ([]byte, error)` -- returns a MAC tag of block-size bytes
- `Zeroize()`

### Streaming io.Reader Wrappers

#### `EncryptReader(stream cipher.Stream, src io.Reader) (io.ReadCloser, error)`

Wraps `src` so that bytes read are encrypted through the given `cipher.Stream`.

#### `DecryptReader(stream cipher.Stream, src io.Reader) (io.ReadCloser, error)`

Wraps `src` so that bytes read are decrypted through the given `cipher.Stream`.

**Usage example:**

```go
ctr, _ := gost3413.NewKuznechikCTR(key)
stream := ctr.Stream(iv)
rc, _ := gost3413.EncryptReader(stream, plainReader)
defer rc.Close()
io.Copy(dst, rc)
```

---

## pkg/cms Package

`import "github.com/rekurt/gost-crypto/pkg/cms"`

CMS (Cryptographic Message Syntax) SignedData operations via CryptoPro CAdES.

### Types

```go
type SignOptions struct {
    Detached bool // if true, signed data is not embedded in the CMS structure
}

type VerifyOptions struct {
    NoCertVerify bool // if true, skip certificate chain validation
}

type SignedData struct { /* opaque */ }
```

### Functions

#### `Sign(priv *gost3410.PrivKey, cert *gostx509.Certificate, data []byte, opts SignOptions) (*SignedData, error)`

Creates a CMS SignedData structure. Uses the private key and certificate to produce a GOST R 34.10-2012 signature over the data.

#### `ParseDER(der []byte) (*SignedData, error)`

Parses a DER-encoded CMS SignedData structure.

### SignedData Methods

- `Verify(data []byte, opts VerifyOptions) error` -- verifies the signature. For detached signatures, pass the original data; for attached signatures, `data` may be nil.
- `DER() ([]byte, error)` -- returns the DER-encoded CMS structure
- `PEM() ([]byte, error)` -- returns the PEM-encoded CMS structure
- `Free()` -- releases the underlying CryptoPro handle

---

## pkg/gostx509 Package

`import "github.com/rekurt/gost-crypto/pkg/gostx509"`

X.509 certificate operations for GOST keys via CryptoPro CSP.

### Types

```go
type Subject struct {
    CommonName         string
    Organization       string
    OrganizationalUnit string
    Country            string
    Province           string
    Locality           string
}

type CertOptions struct {
    SerialNumber *big.Int
    NotBefore    time.Time
    NotAfter     time.Time
}

type Certificate struct { /* opaque */ }
type CertificateRequest struct { /* opaque */ }
```

### Functions

#### `CreateSelfSigned(priv *gost3410.PrivKey, subject Subject, opts CertOptions) (*Certificate, error)`

Creates a self-signed X.509 certificate with a GOST R 34.10-2012 signature.

#### `CreateCSR(priv *gost3410.PrivKey, subject Subject) (*CertificateRequest, error)`

**Not implemented.** Currently returns an error unconditionally. Reserved for future use.

#### `ParseDER(der []byte) (*Certificate, error)`

Parses a DER-encoded X.509 certificate.

#### `ParsePEM(pem []byte) (*Certificate, error)`

Parses a PEM-encoded X.509 certificate.

### Certificate Methods

- `DER() ([]byte, error)` -- returns the DER-encoded certificate
- `PEM() ([]byte, error)` -- returns the PEM-encoded certificate
- `SubjectCN() string` -- returns the subject Common Name
- `IssuerCN() string` -- returns the issuer Common Name
- `Verify(pub *gost3410.PubKey) error` -- verifies the certificate signature against the given public key
- `VerifySelfSigned() error` -- verifies that the certificate is validly self-signed
- `Free()` -- releases the underlying CryptoPro handle

### CertificateRequest Methods

- `DER() ([]byte, error)` -- returns the DER-encoded CSR
- `PEM() ([]byte, error)` -- returns the PEM-encoded CSR
- `Free()` -- releases the underlying CryptoPro handle

---

## pkg/kdf Package

`import "github.com/rekurt/gost-crypto/pkg/kdf"`

Key derivation functions based on GOST primitives.

### HKDF (RFC 5869)

#### `HKDF256(salt, ikm, info []byte, length int) []byte`

Derives `length` bytes using HKDF with HMAC-Streebog-256.

#### `HKDF512(salt, ikm, info []byte, length int) []byte`

Derives `length` bytes using HKDF with HMAC-Streebog-512.

#### `HKDFExtract256(salt, ikm []byte) []byte`

HKDF-Extract phase only (Streebog-256).

#### `HKDFExtract512(salt, ikm []byte) []byte`

HKDF-Extract phase only (Streebog-512).

#### `HKDFExpand256(prk, info []byte, length int) []byte`

HKDF-Expand phase only (Streebog-256).

#### `HKDFExpand512(prk, info []byte, length int) []byte`

HKDF-Expand phase only (Streebog-512).

### KDF_GOSTR3411 (R 50.1.113-2016)

#### `KDF_GOSTR3411_256(key, label, seed []byte) []byte`

Russian national KDF per R 50.1.113-2016. Output: 32 bytes.

#### `KDF_GOSTR3411_512(key, label, seed []byte) []byte`

Russian national KDF per R 50.1.113-2016. Output: 64 bytes.

### PBKDF2 (RFC 8018)

#### `PBKDF2_256(password, salt []byte, iterations, keyLen int) []byte`

PBKDF2 with HMAC-Streebog-256.

#### `PBKDF2_512(password, salt []byte, iterations, keyLen int) []byte`

PBKDF2 with HMAC-Streebog-512.

---

## pkg/hd Package

`import "github.com/rekurt/gost-crypto/pkg/hd"`

Hierarchical deterministic key derivation using HKDF-Streebog.

### Functions

#### `Master(seed []byte, c Curve) (*DerivedKey, error)`

Derives a master key from a seed (minimum 16 bytes). Both chain code and private key are deterministically derived via HKDF-Streebog.

#### `Derive(parent *DerivedKey, path string, c Curve) (*DerivedKey, error)`

Derives a child key along the given BIP-32 style path. Supports hardened (`'` or `h` suffix) and normal derivation.

#### `ParsePath(path string) ([]PathComponent, error)`

Parses a BIP-32 path string (e.g. `m/44'/0'/0'/0/0`) into components.

### Types

```go
type DerivedKey struct {
    Key       *PrivKey  // GOST R 34.10-2012 private key
    ChainCode []byte    // 32-byte chain code for further derivation
}
```

- `Zeroize()` -- securely wipes key and chain code

```go
type PathComponent struct {
    Index    uint32
    Hardened bool
}
```

---

## Error Handling

All operations return errors rather than panicking. Common sentinel errors:

| Error | When |
|-------|------|
| `ErrNilKey` | nil or zeroized key passed |
| `ErrInvalidKeySize` | digest/key size mismatch |
| `ErrInvalidSignature` | wrong signature length |
| `ErrUnknownCurve` | invalid curve identifier |
| `ErrPointNotOnCurve` | public key point not on curve |
| `ErrCurveMismatch` | VKO with keys on different curves |
| `ErrEmptyUKM` | VKO without User Keying Material |

---

## Thread Safety

- Key generation and signing are thread-safe (CryptoPro handles locking internally).
- A single `*PrivKey` or `*PubKey` should not be shared across goroutines without synchronization.
- `Zeroize()` invalidates both the private key and any derived public keys.
- `Free()` on CMS and certificate objects is not thread-safe; do not call concurrently.
