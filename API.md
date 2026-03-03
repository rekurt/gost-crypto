# API Reference

Complete API documentation for the gost-crypto library.

**[📖 README (English)](README.md)** | **[📖 README (Russian)](README.ru.md)** | **[📚 Documentation Index](DOCUMENTATION.md)** | **[💡 Advanced Examples](EXAMPLES.md)** 

## Table of Contents

- [streebog Package](#streebog-package)
- [gost3410 Package](#gost3410-package)
- [gostcrypto Package](#gostcrypto-package)
- [kdf/hd Package](#kdfhd-package)

## streebog Package

Hash implementation for GOST R 34.11-2012 Streebog.

### Functions

#### `Sum256(data []byte) [32]byte`

Computes a 256-bit Streebog hash of the input data.

**Parameters:**
- `data []byte` - Input data to hash

**Returns:**
- `[32]byte` - 256-bit hash result

**Example:**
```go
message := []byte("Hello, World!")
hash := streebog.Sum256(message)
```

#### `Sum512(data []byte) [64]byte`

Computes a 512-bit Streebog hash of the input data.

**Parameters:**
- `data []byte` - Input data to hash

**Returns:**
- `[64]byte` - 512-bit hash result

**Example:**
```go
message := []byte("Hello, World!")
hash := streebog.Sum512(message)
```

---

## gost3410 Package

GOST R 34.10-2012 elliptic curve signatures and key management.

### Types

#### `Curve`

Enumeration of supported elliptic curves.

**Values:**
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

#### `HashID`

Hash algorithm selector.

**Values:**
```go
const (
    HashAuto    HashID = iota // Zero value; infer hash from key size
    Streebog256               // GOST R 34.11-2012 with 256-bit output
    Streebog512               // GOST R 34.11-2012 with 512-bit output
)
```

#### `PrivKey`

Private key structure for elliptic curve signatures.

**Fields:**
- `D []byte` - Private key scalar (32 bytes for 256-bit curves, 64 bytes for 512-bit curves)

**Methods:**

##### `func NewPrivKey(curve Curve) (*PrivKey, error)`

Generates a new random private key for the given curve.

**Parameters:**
- `curve Curve` - Elliptic curve to use

**Returns:**
- `*PrivKey` - Generated private key
- `error` - Error if key generation failed

**Example:**
```go
privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
if err != nil {
    log.Fatal(err)
}
```

##### `func FromRawPriv(curve Curve, d []byte) (*PrivKey, error)`

Creates a private key from raw bytes.

**Parameters:**
- `curve Curve` - Elliptic curve to use
- `d []byte` - Private key scalar (32 bytes for 256-bit, 64 bytes for 512-bit)

**Returns:**
- `*PrivKey` - Private key
- `error` - Error if key is invalid

**Example:**
```go
keyBytes, _ := hex.DecodeString("7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28")
privKey, err := gost3410.FromRawPriv(gost3410.TC26_256_A, keyBytes)
```

##### `func (pk *PrivKey) Public() (*PubKey, error)`

Derives the public key from the private key.

**Returns:**
- `*PubKey` - Corresponding public key
- `error` - Error if derivation failed

**Example:**
```go
pubKey, err := privKey.Public()
```

##### `func (pk *PrivKey) Sign(digest []byte, hash HashID) ([]byte, error)`

Signs a message digest.

**Parameters:**
- `digest []byte` - Pre-computed message digest (32 bytes for Streebog256, 64 bytes for Streebog512)
- `hash HashID` - Hash algorithm used (for format consistency)

**Returns:**
- `[]byte` - Signature (64 bytes for 256-bit curves, 128 bytes for 512-bit curves)
- `error` - Error if signing failed

**Example:**
```go
digest := streebog.Sum256(message)
sig, err := privKey.Sign(digest[:], gost3410.Streebog256)
```

#### `PubKey`

Public key structure for elliptic curve signatures.

**Fields:**
- `X []byte` - X coordinate (32 bytes for 256-bit curves, 64 bytes for 512-bit curves)
- `Y []byte` - Y coordinate (32 bytes for 256-bit curves, 64 bytes for 512-bit curves)

**Methods:**

##### `func (pk *PubKey) Verify(digest, signature []byte, hash HashID) (bool, error)`

Verifies a signature on a message digest.

**Parameters:**
- `digest []byte` - Pre-computed message digest
- `signature []byte` - Signature to verify
- `hash HashID` - Hash algorithm used

**Returns:**
- `bool` - True if signature is valid
- `error` - Error if verification failed

**Example:**
```go
valid, err := pubKey.Verify(digest[:], signature, gost3410.Streebog256)
if err == nil && valid {
    fmt.Println("Signature is valid")
}
```

##### `func (pk *PubKey) ToCompressed(withPrefix bool) []byte`

Serializes the public key in compressed format.

**Parameters:**
- `withPrefix bool` - Include prefix byte (0x02/0x03 for even/odd Y)

**Returns:**
- `[]byte` - Compressed public key (33 bytes for 256-bit with prefix, 32 without)

**Example:**
```go
compressed := pubKey.ToCompressed(true)
fmt.Printf("Compressed key: %s\n", hex.EncodeToString(compressed))
```

##### `func (pk *PubKey) ToUncompressed(withPrefix bool) []byte`

Serializes the public key in uncompressed format.

**Parameters:**
- `withPrefix bool` - Include prefix byte (0x04)

**Returns:**
- `[]byte` - Uncompressed public key (65 bytes for 256-bit with prefix, 64 without)

**Example:**
```go
uncompressed := pubKey.ToUncompressed(true)
fmt.Printf("Uncompressed key: %s\n", hex.EncodeToString(uncompressed))
```

##### `func FromCompressed(curve Curve, data []byte, hasPrefix bool) (*PubKey, error)`

Recovers a public key from compressed format.

**Parameters:**
- `curve Curve` - Elliptic curve used
- `data []byte` - Compressed key data
- `hasPrefix bool` - Whether data includes prefix byte

**Returns:**
- `*PubKey` - Recovered public key
- `error` - Error if recovery failed

**Example:**
```go
recovered, err := gost3410.FromCompressed(gost3410.TC26_256_A, compressed, true)
```

##### `func FromUncompressed(curve Curve, data []byte, hasPrefix bool) (*PubKey, error)`

Recovers a public key from uncompressed format.

**Parameters:**
- `curve Curve` - Elliptic curve used
- `data []byte` - Uncompressed key data
- `hasPrefix bool` - Whether data includes prefix byte

**Returns:**
- `*PubKey` - Recovered public key
- `error` - Error if recovery failed

**Example:**
```go
recovered, err := gost3410.FromUncompressed(gost3410.TC26_256_A, uncompressed, true)
```

---

## gostcrypto Package

High-level facade combining hashing and signing operations.

### Types

#### `Options`

Configuration options for signing and verification.

**Fields:**
- `Hash HashID` - Hash algorithm to use (Streebog256 or Streebog512). If zero (HashAuto), inferred from key size.

**Example:**
```go
opts := &gostcrypto.Options{Hash: gost3410.Streebog256}
```

### Functions

#### `func Sign(privKey *gost3410.PrivKey, message []byte, opts *Options) ([]byte, error)`

Signs a message using the private key.

**Parameters:**
- `privKey *gost3410.PrivKey` - Private key for signing
- `message []byte` - Message to sign
- `opts *Options` - Signing options (if nil or Hash is HashAuto, hash is inferred from key size)

**Returns:**
- `[]byte` - Signature
- `error` - Error if signing failed

**Example:**
```go
opts := &gostcrypto.Options{Hash: gost3410.Streebog256}
sig, err := gostcrypto.Sign(privKey, message, opts)
```

#### `func Verify(pubKey *gost3410.PubKey, message, signature []byte, opts *Options) (bool, error)`

Verifies a signature on a message.

**Parameters:**
- `pubKey *gost3410.PubKey` - Public key for verification
- `message []byte` - Original message
- `signature []byte` - Signature to verify
- `opts *Options` - Verification options (if nil or Hash is HashAuto, hash is inferred from key size)

**Returns:**
- `bool` - True if signature is valid
- `error` - Error if verification failed

**Example:**
```go
opts := &gostcrypto.Options{Hash: gost3410.Streebog256}
valid, err := gostcrypto.Verify(pubKey, message, signature, opts)
if err == nil && valid {
    fmt.Println("Signature verified")
}
```

---

## kdf/hd Package

Hierarchical deterministic key derivation using HKDF.

### Functions

#### `func Master(seed []byte, hash gost3410.HashID) (*gost3410.PrivKey, []byte, error)`

Generates a master key and chain code from a seed.

**Parameters:**
- `seed []byte` - Random seed (recommended: 32+ bytes)
- `hash gost3410.HashID` - Hash algorithm (Streebog256 or Streebog512)

**Returns:**
- `*gost3410.PrivKey` - Master private key
- `[]byte` - Chain code for derivation (32 bytes)
- `error` - Error if generation failed

**Example:**
```go
seed := []byte("my secret seed phrase")
masterKey, chainCode, err := hd.Master(seed, gost3410.Streebog256)
```

#### `func Derive(parentKey *gost3410.PrivKey, parentChain []byte, path string, hash gost3410.HashID) (*gost3410.PrivKey, []byte, error)`

Derives a child key at the specified path.

**Parameters:**
- `parentKey *gost3410.PrivKey` - Parent private key
- `parentChain []byte` - Parent chain code
- `path string` - Derivation path (e.g., "m/0'/1/2'")
- `hash gost3410.HashID` - Hash algorithm

**Returns:**
- `*gost3410.PrivKey` - Derived child key
- `[]byte` - Child chain code
- `error` - Error if derivation failed

**Path Format:**
- `m/` - Root (required at start)
- `0-2147483647` - Normal derivation indices
- `n'` or `n H` - Hardened derivation (deprecated: H notation, use ' suffix)
- Examples: `m/0`, `m/0'/1`, `m/44'/283'/0'/0/0`

**Example:**
```go
childKey, childChain, err := hd.Derive(masterKey, chainCode, "m/0'/1/2'", gost3410.Streebog256)
```

---

## Error Handling

Common error types and their meanings:

| Error | Meaning | Action |
|-------|---------|--------|
| `ErrInvalidKeySize` | Key size doesn't match curve | Verify key was created for correct curve |
| `ErrInvalidDigestSize` | Digest size doesn't match hash algorithm | Ensure digest matches algorithm (32 or 64 bytes) |
| `ErrInvalidSignatureSize` | Signature size is incorrect | Verify signature source and format |
| `ErrInvalidCurve` | Unsupported elliptic curve | Use supported curve (256-A, 512-A/B/C) |
| `ErrKeyRecoveryFailed` | Cannot recover public key from data | Verify serialized key format |
| `ErrDerivationFailed` | Cannot derive key at path | Check path format and parent key validity |

---

## Constants

### Hash Algorithm Sizes

```go
Streebog256HashSize = 32  // bytes
Streebog512HashSize = 64  // bytes

// Signature sizes (r || s)
TC26_256_SignatureSize = 64  // bytes
TC26_512_SignatureSize = 128 // bytes

// Public key sizes
TC26_256_CompressedSize = 33   // bytes (with prefix)
TC26_256_CompressedSizeNP = 32 // bytes (without prefix)
TC26_256_UncompressedSize = 65   // bytes (with prefix)
TC26_256_UncompressedSizeNP = 64 // bytes (without prefix)

TC26_512_CompressedSize = 65    // bytes (with prefix)
TC26_512_CompressedSizeNP = 64  // bytes (without prefix)
TC26_512_UncompressedSize = 129  // bytes (with prefix)
TC26_512_UncompressedSizeNP = 128 // bytes (without prefix)
```

---

## Thread Safety

- **PrivKey/PubKey**: Immutable after creation, safe for concurrent reads
- **Master/Derive**: Thread-safe for concurrent calls with different paths
- **Sign/Verify**: Thread-safe for concurrent operations with different keys
- **KeyPool**: For high-concurrency scenarios, consider using a key pool pattern

---

## Performance Tips

1. **Reuse key objects**: Creating keys is expensive, reuse them
2. **Pre-compute hashes**: Hash once, sign multiple times if needed
3. **Batch operations**: Sign/verify multiple messages without key creation overhead
4. **HD derivation**: Cache parent chains if deriving many children
5. **Concurrent signing**: Each goroutine can safely use different key objects

---

## Compatibility Notes

- Signatures are deterministic (same message produces different signatures due to random k)
- Key formats are compatible with standard elliptic curve standards
- Big-endian byte order for all multi-byte values
- No ASN.1 encoding built-in; use external libraries for PEM/ASN.1 support
