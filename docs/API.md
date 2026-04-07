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
- `Zeroize()` — securely wipes key material and frees OpenSSL handle

### PubKey Methods

- `Curve() Curve` — returns the curve parameter set
- `Validate() error` — checks that the point lies on the curve

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

---

## pkg/gost3412 Package

`import "github.com/rekurt/gost-crypto/pkg/gost3412"`

GOST R 34.12-2015 Kuznechik block cipher via OpenSSL gost-engine.

### `NewCipher(key []byte) (cipher.Block, error)`

Creates a Kuznechik cipher block. Key must be 32 bytes. Block size is 16 bytes.

---

## pkg/gost3413 Package

`import "github.com/rekurt/gost-crypto/pkg/gost3413"`

GOST R 34.13-2015 MGM authenticated encryption via OpenSSL gost-engine.

### `NewMGM(block cipher.Block) (cipher.AEAD, error)`

Creates an MGM AEAD from a Kuznechik cipher block.

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

Key derivation functions based on HKDF-Streebog.

### `HKDF256(salt, ikm, info []byte, length int) []byte`

Derives `length` bytes using HKDF with Streebog-256.

### `HKDF512(salt, ikm, info []byte, length int) []byte`

Derives `length` bytes using HKDF with Streebog-512.

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
