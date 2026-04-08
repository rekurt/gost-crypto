# API Reference

Complete API reference for gost-crypto.

[README](../README.md) | [README (Russian)](README.ru.md)

---

## Table of Contents

- [Root Package (gostcrypto)](#root-package-gostcrypto)
- [pkg/gost3410](#pkggost3410-package)
- [pkg/gost3411](#pkggost3411-package)
- [pkg/gost3412](#pkggost3412-package)
- [pkg/gost3413](#pkggost3413-package)
- [pkg/hd](#pkghd-package)
- [pkg/kdf](#pkgkdf-package)
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

### Constants

```go
const (
    CurveTC26_256_A  // id-tc26-gost-3410-2012-256-paramSetA
    CurveTC26_256_B  // CryptoPro-A
    CurveTC26_256_C  // CryptoPro-B
    CurveTC26_256_D  // CryptoPro-C
    CurveTC26_512_A
    CurveTC26_512_B
    CurveTC26_512_C
    CurveTC26_512_D  // test
)
```

### Functions

#### `GenerateKey(c Curve) (*PrivKey, error)`

Generates a new GOST R 34.10-2012 key pair for the given curve.

#### `LoadPrivKey(c Curve, raw []byte) (*PrivKey, error)`

Creates a private key from raw big-endian bytes. The raw bytes must be exactly the key size (32 for 256-bit, 64 for 512-bit).

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

Low-level GOST R 34.10-2012 operations backed by OpenSSL gost-engine.

### `GenerateKey(c Curve) (*PrivKey, error)`

Generates a random key pair for the given curve.

### `LoadPrivKey(c Curve, raw []byte) (*PrivKey, error)`

Creates a private key from raw bytes via OpenSSL.

### `SignDigest(priv *PrivKey, digest []byte) ([]byte, error)`

Signs a pre-computed digest. Digest must be exactly key size bytes.

### `VerifyDigest(pub *PubKey, digest, sig []byte) (bool, error)`

Verifies a signature over a pre-computed digest.

### `VKO(priv *PrivKey, pub *PubKey, ukm []byte) ([]byte, error)`

Performs VKO key agreement.

### PrivKey Methods

- `Bytes() ([]byte, error)` — returns raw private key bytes (sensitive!)
- `Curve() Curve` — returns the curve parameter set
- `PublicKey() *PubKey` — derives the public key
- `Public() crypto.PublicKey` — implements `crypto.Signer`
- `Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)` — implements `crypto.Signer`
- `MarshalBinary() ([]byte, error)` — implements `encoding.BinaryMarshaler` (format: `[curve_id][raw_key]`)
- `UnmarshalBinary(data []byte) error` — implements `encoding.BinaryUnmarshaler`
- `Zeroize()` — securely wipes key material and frees OpenSSL handle

### PubKey Methods

- `Bytes() ([]byte, error)` — returns raw public key bytes (SPKI DER or raw X||Y)
- `Curve() Curve` — returns the curve parameter set
- `Validate() error` — checks that the point lies on the curve
- `MarshalBinary() ([]byte, error)` — implements `encoding.BinaryMarshaler`

---

## pkg/gost3411 Package

`import "github.com/rekurt/gost-crypto/pkg/gost3411"`

GOST R 34.11-2012 Streebog hash functions via OpenSSL gost-engine.

### `New256() hash.Hash`

Returns a Streebog-256 hasher implementing `hash.Hash`.

### `New512() hash.Hash`

Returns a Streebog-512 hasher implementing `hash.Hash`.

### `Sum256(data []byte) [32]byte`

Computes Streebog-256 digest in one call.

### `Sum512(data []byte) [64]byte`

Computes Streebog-512 digest in one call.

### `NewHMAC256(key []byte) hash.Hash`

Returns HMAC-Streebog-256 with the given key.

### `NewHMAC512(key []byte) hash.Hash`

Returns HMAC-Streebog-512 with the given key.

### Hash Constants

```go
const (
    HashStreebog256 crypto.Hash = 100  // registered via crypto.RegisterHash
    HashStreebog512 crypto.Hash = 101
)
```

These are registered with `crypto.RegisterHash` in `init()`, enabling standard Go `crypto.Hash` lookup.

---

## pkg/gost3412 Package

`import "github.com/rekurt/gost-crypto/pkg/gost3412"`

GOST R 34.12-2015 block ciphers via OpenSSL gost-engine.

### `NewKuznechik(key []byte) (cipher.Block, error)`

Creates a Kuznechik cipher block. Key must be 32 bytes. Block size is 16 bytes (128 bits).

### `NewMagma(key []byte) (cipher.Block, error)`

Creates a Magma cipher block. Key must be 32 bytes. Block size is 8 bytes (64 bits).

---

## pkg/gost3413 Package

`import "github.com/rekurt/gost-crypto/pkg/gost3413"`

GOST R 34.13-2015 block cipher modes of operation via OpenSSL gost-engine.

### AEAD (Authenticated Encryption)

#### `NewMGMFromKey(key []byte) (cipher.AEAD, error)`
Creates a Kuznechik-MGM AEAD. Nonce: 16 bytes, tag: 16 bytes.

#### `NewMagmaMGMFromKey(key []byte) (cipher.AEAD, error)`
Creates a Magma-MGM AEAD. Nonce: 8 bytes, tag: 8 bytes.

### CTR (Counter Mode)

#### `NewKuznechikCTR(key []byte) (*CTR, error)`
#### `NewMagmaCTR(key []byte) (*CTR, error)`
Methods: `Encrypt(iv, plaintext) ([]byte, error)`, `Decrypt(iv, ciphertext) ([]byte, error)`, `Zeroize()`.

### CBC (Cipher Block Chaining)

#### `NewKuznechikCBC(key []byte) (*CBC, error)`
#### `NewMagmaCBC(key []byte) (*CBC, error)`
Plaintext must be block-aligned. No padding. Methods: `Encrypt`, `Decrypt`, `BlockSize`, `Zeroize`.

### CFB (Cipher Feedback)

#### `NewKuznechikCFB(key []byte) (*CFB, error)`
#### `NewMagmaCFB(key []byte) (*CFB, error)`
Stream cipher mode. Methods: `Encrypt`, `Decrypt`, `Zeroize`.

### OFB (Output Feedback)

#### `NewKuznechikOFB(key []byte) (*OFB, error)`
#### `NewMagmaOFB(key []byte) (*OFB, error)`
Synchronous stream cipher. Methods: `Encrypt`, `Decrypt`, `Zeroize`.

### CMAC (OMAC1)

#### `NewKuznechikCMAC(key []byte) (*CMAC, error)`
#### `NewMagmaCMAC(key []byte) (*CMAC, error)`
Methods: `MAC(message []byte) ([]byte, error)`, `Zeroize()`. Output: block-size bytes.

### Streaming io.Reader Wrappers

```go
NewCTREncryptReader(ctr *CTR, iv []byte, r io.Reader) io.Reader
NewCTRDecryptReader(ctr *CTR, iv []byte, r io.Reader) io.Reader
NewCFBEncryptReader(cfb *CFB, iv []byte, r io.Reader) io.Reader
NewCFBDecryptReader(cfb *CFB, iv []byte, r io.Reader) io.Reader
NewOFBEncryptReader(ofb *OFB, iv []byte, r io.Reader) io.Reader
NewOFBDecryptReader(ofb *OFB, iv []byte, r io.Reader) io.Reader
```

---

## pkg/hd Package

`import "github.com/rekurt/gost-crypto/pkg/hd"`

Hierarchical deterministic key derivation using HKDF-Streebog.

### `Master(seed []byte, c Curve) (*DerivedKey, error)`

Derives a master key from a seed (minimum 16 bytes). Both chain code and private key are deterministically derived via HKDF-Streebog.

### `Derive(parent *DerivedKey, path string, c Curve) (*DerivedKey, error)`

Derives a child key along the given BIP-32 style path. Supports hardened (`'` or `h` suffix) and normal derivation.

### `ParsePath(path string) ([]PathComponent, error)`

Parses a BIP-32 path string into components.

### DerivedKey

```go
type DerivedKey struct {
    Key       *PrivKey  // GOST R 34.10-2012 private key
    ChainCode []byte    // 32-byte chain code for further derivation
}
```

- `Zeroize()` — securely wipes key and chain code

---

## pkg/kdf Package

`import "github.com/rekurt/gost-crypto/pkg/kdf"`

Key derivation functions based on GOST primitives.

### HKDF (RFC 5869)

#### `HKDF256(salt, ikm, info []byte, length int) []byte`
Derives `length` bytes using HKDF with HMAC-Streebog-256.

#### `HKDF512(salt, ikm, info []byte, length int) []byte`
Derives `length` bytes using HKDF with HMAC-Streebog-512.

#### `HKDFExtract256(salt, ikm []byte) []byte` / `HKDFExtract512`
HKDF-Extract phase only.

#### `HKDFExpand256(prk, info []byte, length int) []byte` / `HKDFExpand512`
HKDF-Expand phase only.

### KDF_GOSTR3411 (R 50.1.113-2016)

#### `KDF_GOSTR3411_256(key, label, seed []byte) []byte`
Russian national KDF. Output: 32 bytes.

#### `KDF_GOSTR3411_512(key, label, seed []byte) []byte`
Output: 64 bytes.

### PBKDF2 (RFC 8018)

#### `PBKDF2_256(password, salt []byte, iterations, keyLen int) []byte`
PBKDF2 with HMAC-Streebog-256.

#### `PBKDF2_512(password, salt []byte, iterations, keyLen int) []byte`
PBKDF2 with HMAC-Streebog-512.

---

## Error Handling

All operations return errors rather than panicking. Common error types:

| Error | When |
|-------|------|
| `ErrNilKey` | nil or zeroized key passed |
| `ErrInvalidKeySize` | digest/key size mismatch |
| `ErrInvalidSignature` | wrong signature length |
| `ErrUnknownCurve` | invalid curve identifier |
| `ErrCurveMismatch` | VKO with keys on different curves |
| `ErrEmptyUKM` | VKO without User Keying Material |

---

## Thread Safety

- Key generation and signing are thread-safe (OpenSSL handles locking internally)
- A single `*PrivKey` or `*PubKey` should not be shared across goroutines without synchronization
- `Zeroize()` invalidates both the private key and any derived public keys
