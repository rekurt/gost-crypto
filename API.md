# API Reference

Complete API reference for gost-crypto.

[README](README.md) | [README (Russian)](README.ru.md) | [Examples](_examples/EXAMPLES.md)

---

## Table of Contents

- [streebog](#streebog-package)
- [gost3410](#gost3410-package)
- [gostcrypto](#gostcrypto-package)
- [kdf/hd](#kdfhd-package)
- [Error Handling](#error-handling)
- [Constants](#constants)
- [Thread Safety](#thread-safety)

---

## streebog Package

GOST R 34.11-2012 Streebog hash functions.

### `Sum256(data []byte) [32]byte`

Computes a 256-bit Streebog hash.

```go
hash := streebog.Sum256([]byte("message"))
```

### `Sum512(data []byte) [64]byte`

Computes a 512-bit Streebog hash.

```go
hash := streebog.Sum512([]byte("message"))
```

---

## gost3410 Package

GOST R 34.10-2012 elliptic curve signatures and key management.

### Types

#### `Curve`

Identifies a TC26 elliptic curve parameter set.

```go
const (
    TC26_256_A Curve = iota
    TC26_256_B
    TC26_256_C
    TC26_256_D
    TC26_512_A
    TC26_512_B
    TC26_512_C
    TC26_512_D
)
```

The `Size()` method returns the key size in bytes (32 for 256-bit curves, 64 for 512-bit curves).

#### `HashID`

Selects the hash algorithm for signing operations.

```go
const (
    HashAuto    HashID = iota // Zero value: infer from key size
    Streebog256               // 256-bit Streebog
    Streebog512               // 512-bit Streebog
)
```

#### `PrivKey`

Private key for GOST R 34.10-2012 signatures.

**Fields:**
- `D []byte` — private key scalar (32 bytes for 256-bit curves, 64 bytes for 512-bit)

#### `PubKey`

Public key for GOST R 34.10-2012 signatures.

**Fields:**
- `X []byte` — X coordinate (32 or 64 bytes)
- `Y []byte` — Y coordinate (32 or 64 bytes)

---

### Key Generation

#### `NewPrivKey(curve Curve) (*PrivKey, error)`

Generates a random private key for the specified curve.

```go
privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
```

#### `FromRawPriv(curve Curve, d []byte) (*PrivKey, error)`

Creates a private key from raw bytes. The byte slice must match the curve's key size.

```go
raw, _ := hex.DecodeString("7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28")
privKey, err := gost3410.FromRawPriv(gost3410.TC26_256_A, raw)
```

#### `(pk *PrivKey) Public() (*PubKey, error)`

Derives the corresponding public key.

```go
pubKey, err := privKey.Public()
```

---

### Signing and Verification

#### `(pk *PrivKey) Sign(digest []byte, hash HashID) ([]byte, error)`

Signs a pre-computed digest. The digest size must match the hash algorithm (32 bytes for Streebog256, 64 bytes for Streebog512).

**Returns:** signature bytes (`r || s`; 64 bytes for 256-bit curves, 128 bytes for 512-bit).

```go
digest := streebog.Sum256(message)
sig, err := privKey.Sign(digest[:], gost3410.Streebog256)
```

#### `(pk *PubKey) Verify(digest, signature []byte, hash HashID) (bool, error)`

Verifies a signature against a pre-computed digest.

```go
valid, err := pubKey.Verify(digest[:], signature, gost3410.Streebog256)
```

---

### Key Serialization

#### `(pk *PubKey) ToCompressed(withPrefix bool) []byte`

Serializes the public key in compressed format.

- With prefix: `0x02` (even Y) or `0x03` (odd Y) followed by X coordinate
- Without prefix: X coordinate only

| Curve type | With prefix | Without prefix |
|------------|-------------|----------------|
| 256-bit | 33 bytes | 32 bytes |
| 512-bit | 65 bytes | 64 bytes |

```go
compressed := pubKey.ToCompressed(true)
```

#### `(pk *PubKey) ToUncompressed(withPrefix bool) []byte`

Serializes the public key in uncompressed format.

- With prefix: `0x04` followed by X and Y coordinates
- Without prefix: X and Y coordinates concatenated

| Curve type | With prefix | Without prefix |
|------------|-------------|----------------|
| 256-bit | 65 bytes | 64 bytes |
| 512-bit | 129 bytes | 128 bytes |

```go
uncompressed := pubKey.ToUncompressed(true)
```

#### `FromCompressed(curve Curve, data []byte, hasPrefix bool) (*PubKey, error)`

Recovers a public key from compressed format. Reconstructs the Y coordinate from the X coordinate and curve equation.

```go
recovered, err := gost3410.FromCompressed(gost3410.TC26_256_A, compressed, true)
```

#### `FromUncompressed(curve Curve, data []byte, hasPrefix bool) (*PubKey, error)`

Recovers a public key from uncompressed format.

```go
recovered, err := gost3410.FromUncompressed(gost3410.TC26_256_A, uncompressed, true)
```

---

## gostcrypto Package

High-level facade that combines Streebog hashing with GOST R 34.10-2012 signing in a single call.

### Types

#### `Options`

Controls hash algorithm selection.

```go
type Options struct {
    Hash gost3410.HashID
}
```

If `Hash` is `HashAuto` (zero value) or `Options` is nil, the hash algorithm is inferred from the key size: Streebog256 for 256-bit keys, Streebog512 for 512-bit keys.

### Functions

#### `Sign(privKey *gost3410.PrivKey, message []byte, opts *Options) ([]byte, error)`

Hashes the message with Streebog and signs the resulting digest.

```go
opts := &gostcrypto.Options{Hash: gost3410.Streebog256}
sig, err := gostcrypto.Sign(privKey, message, opts)
```

#### `Verify(pubKey *gost3410.PubKey, message, signature []byte, opts *Options) (bool, error)`

Hashes the message with Streebog and verifies the signature against the resulting digest.

```go
valid, err := gostcrypto.Verify(pubKey, message, signature, opts)
```

---

## kdf/hd Package

Hierarchical deterministic key derivation using HKDF with Streebog.

### Functions

#### `Master(seed []byte, hash gost3410.HashID) (*gost3410.PrivKey, []byte, error)`

Generates a master private key and chain code from a seed.

**Parameters:**
- `seed` — random seed (recommended: 32+ bytes)
- `hash` — Streebog256 or Streebog512

**Returns:** master private key, chain code (32 bytes), error.

```go
masterKey, chainCode, err := hd.Master(seed, gost3410.Streebog256)
```

#### `Derive(parentKey *gost3410.PrivKey, parentChain []byte, path string, hash gost3410.HashID) (*gost3410.PrivKey, []byte, error)`

Derives a child key at the specified BIP32-style path.

**Path format:**
- Must start with `m/`
- Normal derivation: `m/0/1/2`
- Hardened derivation: `m/0'/1'/2'`
- Mixed: `m/44'/283'/0'/0/0`

```go
childKey, childChain, err := hd.Derive(masterKey, chainCode, "m/44'/283'/0'/0/0", gost3410.Streebog256)
```

---

## Error Handling

| Error | Cause |
|-------|-------|
| `ErrInvalidKeySize` | Key byte length does not match the curve |
| `ErrInvalidDigestSize` | Digest length does not match the hash algorithm (expected 32 or 64 bytes) |
| `ErrInvalidSignatureSize` | Signature length is incorrect for the curve |
| `ErrInvalidCurve` | Curve is not supported by the backend |
| `ErrKeyRecoveryFailed` | Public key cannot be reconstructed from the provided data |
| `ErrDerivationFailed` | Key derivation failed (invalid path or parent key) |

---

## Constants

```go
// Hash output sizes
Streebog256HashSize = 32  // bytes
Streebog512HashSize = 64  // bytes

// Signature sizes (r || s)
TC26_256_SignatureSize = 64   // bytes
TC26_512_SignatureSize = 128  // bytes

// Compressed public key sizes
TC26_256_CompressedSize   = 33  // with prefix
TC26_256_CompressedSizeNP = 32  // without prefix
TC26_512_CompressedSize   = 65  // with prefix
TC26_512_CompressedSizeNP = 64  // without prefix

// Uncompressed public key sizes
TC26_256_UncompressedSize   = 65   // with prefix
TC26_256_UncompressedSizeNP = 64   // without prefix
TC26_512_UncompressedSize   = 129  // with prefix
TC26_512_UncompressedSizeNP = 128  // without prefix
```

---

## Thread Safety

- `PrivKey` and `PubKey` are immutable after creation and safe for concurrent reads
- `Sign` and `Verify` are safe for concurrent use with distinct key instances
- `Master` and `Derive` are safe for concurrent use with independent inputs
