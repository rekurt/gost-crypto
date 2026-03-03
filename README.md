# gost-crypto

[![CI](https://github.com/rekurt/gost-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/rekurt/gost-crypto/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/rekurt/gost-crypto)](https://goreportcard.com/report/github.com/rekurt/gost-crypto)
[![GoDoc](https://pkg.go.dev/badge/github.com/rekurt/gost-crypto)](https://pkg.go.dev/github.com/rekurt/gost-crypto)

Pure Go implementation of Russian GOST cryptographic standards: digital signatures (GOST R 34.10-2012), cryptographic hashing (GOST R 34.11-2012 Streebog), and key management for TC26 elliptic curves.

[API Reference](API.md) | [На русском](README.ru.md) | [Contributing](CONTRIBUTING.md)

## Features

- **GOST R 34.11-2012 Streebog** — 256-bit and 512-bit cryptographic hash functions
- **GOST R 34.10-2012** — elliptic curve digital signatures with TC26 parameter sets
- **Key serialization** — compressed and uncompressed public key encoding with optional prefix
- **Key recovery** — public key reconstruction from serialized forms
- **HD key derivation** — HKDF-based hierarchical deterministic derivation with BIP32-style paths
- **Batch operations** — signing and verification of multiple documents
- **High-level API** — facade combining hashing and signing in a single call

## Requirements

- Go 1.21 or later
- [ddulesov/gogost](https://github.com/ddulesov/gogost) v1.0.0 (resolved automatically via `go mod`)

## Installation

```bash
go get github.com/rekurt/gost-crypto
```

```go
import (
    "github.com/rekurt/gost-crypto/gostcrypto"
    "github.com/rekurt/gost-crypto/gost3410"
)
```

## Supported Curves

The library supports TC26 (ТК26 — Technical Committee 26) standardized elliptic curves:

| Curve | Key Size | Status |
|-------|----------|--------|
| TC26_256_A | 256-bit | Supported |
| TC26_256_B | 256-bit | Not available in gogost v1.0.0 |
| TC26_256_C | 256-bit | Not available in gogost v1.0.0 |
| TC26_256_D | 256-bit | Not available in gogost v1.0.0 |
| TC26_512_A | 512-bit | Supported |
| TC26_512_B | 512-bit | Supported |
| TC26_512_C | 512-bit | Supported |
| TC26_512_D | 512-bit | Not available in gogost v1.0.0 |

## Quick Start

### Signing and Verification

```go
package main

import (
    "fmt"
    "github.com/rekurt/gost-crypto/gost3410"
    "github.com/rekurt/gost-crypto/gostcrypto"
)

func main() {
    privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
    if err != nil {
        panic(err)
    }

    pubKey, err := privKey.PublicKey()
    if err != nil {
        panic(err)
    }

    message := []byte("Hello, GOST R 34.10-2012!")
    opts := &gostcrypto.Options{Hash: gost3410.Streebog256}

    signature, err := gostcrypto.Sign(privKey, message, opts)
    if err != nil {
        panic(err)
    }

    valid, err := gostcrypto.Verify(pubKey, message, signature, opts)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Signature valid: %v\n", valid)
}
```

### 512-bit Curves

```go
package main

import (
    "fmt"
    "github.com/rekurt/gost-crypto/gost3410"
    "github.com/rekurt/gost-crypto/gostcrypto"
)

func main() {
    privKey, err := gost3410.NewPrivKey(gost3410.TC26_512_A)
    if err != nil {
        panic(err)
    }

    pubKey, err := privKey.PublicKey()
    if err != nil {
        panic(err)
    }

    message := []byte("Secure message")
    opts := &gostcrypto.Options{Hash: gost3410.Streebog512}

    signature, err := gostcrypto.Sign(privKey, message, opts)
    if err != nil {
        panic(err)
    }

    valid, err := gostcrypto.Verify(pubKey, message, signature, opts)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Signature valid: %v\n", valid)
}
```

### Public Key Serialization

```go
package main

import (
    "encoding/hex"
    "fmt"
    "github.com/rekurt/gost-crypto/gost3410"
)

func main() {
    privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
    if err != nil {
        panic(err)
    }

    pubKey, err := privKey.PublicKey()
    if err != nil {
        panic(err)
    }

    // Compressed: prefix (0x02 or 0x03) + X coordinate (33 bytes total)
    compressed, err := pubKey.ToCompressed(true)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Compressed: %s (%d bytes)\n", hex.EncodeToString(compressed), len(compressed))

    // Uncompressed: prefix (0x04) + X + Y (65 bytes total)
    uncompressed := pubKey.ToUncompressed(true)
    fmt.Printf("Uncompressed: %s... (%d bytes)\n", hex.EncodeToString(uncompressed[:16]), len(uncompressed))

    // Without prefix (64 bytes)
    uncompressedNP := pubKey.ToUncompressed(false)
    fmt.Printf("Uncompressed (no prefix): %s... (%d bytes)\n", hex.EncodeToString(uncompressedNP[:16]), len(uncompressedNP))
}
```

### Key Recovery from Serialized Form

```go
package main

import (
    "fmt"
    "github.com/rekurt/gost-crypto/gost3410"
    "github.com/rekurt/gost-crypto/gostcrypto"
)

func main() {
    privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
    if err != nil {
        panic(err)
    }

    originalPubKey, err := privKey.PublicKey()
    if err != nil {
        panic(err)
    }

    message := []byte("Test message")
    opts := &gostcrypto.Options{Hash: gost3410.Streebog256}

    signature, err := gostcrypto.Sign(privKey, message, opts)
    if err != nil {
        panic(err)
    }

    // Serialize and recover
    compressed, err := originalPubKey.ToCompressed(true)
    if err != nil {
        panic(err)
    }
    recoveredPubKey, err := gost3410.FromCompressed(gost3410.TC26_256_A, compressed, true)
    if err != nil {
        panic(err)
    }

    // Verify with recovered key
    valid, err := gostcrypto.Verify(recoveredPubKey, message, signature, opts)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Recovered key verification: %v\n", valid)
}
```

### Batch Signing

```go
package main

import (
    "fmt"
    "github.com/rekurt/gost-crypto/gost3410"
    "github.com/rekurt/gost-crypto/gostcrypto"
)

func main() {
    privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
    if err != nil {
        panic(err)
    }

    pubKey, err := privKey.PublicKey()
    if err != nil {
        panic(err)
    }

    documents := []struct {
        name string
        data []byte
    }{
        {"Invoice 001", []byte("Invoice #001 Amount: 1000 RUB")},
        {"Invoice 002", []byte("Invoice #002 Amount: 2500 RUB")},
        {"Certificate", []byte("Certificate of authenticity GOST")},
    }

    opts := &gostcrypto.Options{Hash: gost3410.Streebog256}
    signatures := make([][]byte, len(documents))

    for i, doc := range documents {
        sig, err := gostcrypto.Sign(privKey, doc.data, opts)
        if err != nil {
            panic(err)
        }
        signatures[i] = sig
        fmt.Printf("Signed: %s\n", doc.name)
    }

    fmt.Println("\nVerification:")
    for i, doc := range documents {
        valid, err := gostcrypto.Verify(pubKey, doc.data, signatures[i], opts)
        if err != nil {
            panic(err)
        }
        fmt.Printf("  %s: %v\n", doc.name, valid)
    }
}
```

### HD Key Derivation

```go
package main

import (
    "encoding/hex"
    "fmt"
    "github.com/rekurt/gost-crypto/gost3410"
    "github.com/rekurt/gost-crypto/gostcrypto"
    "github.com/rekurt/gost-crypto/kdf/hd"
)

func main() {
    seed := []byte("my secret seed phrase for wallet")
    masterKey, chainCode, err := hd.Master(seed, gost3410.Streebog256)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Master key created, chain code: %s\n", hex.EncodeToString(chainCode))

    paths := []string{"m/0", "m/1", "m/0'/1'", "m/44'/283'/0'/0/0"}
    derivedKeys := make([]*gost3410.PrivKey, len(paths))

    for i, path := range paths {
        childKey, childChain, err := hd.Derive(masterKey, chainCode, path, gost3410.Streebog256)
        if err != nil {
            panic(err)
        }

        derivedKeys[i] = childKey
        pubKey, _ := childKey.PublicKey()
        fmt.Printf("Path %-20s chain=%s... pub=%s...\n",
            path, hex.EncodeToString(childChain[:8]), hex.EncodeToString(pubKey.X[:8]))
    }

    // Sign with derived keys
    message := []byte("HD wallet transaction")
    opts := &gostcrypto.Options{Hash: gost3410.Streebog256}

    for i, path := range paths {
        pubKey, _ := derivedKeys[i].PublicKey()
        signature, _ := gostcrypto.Sign(derivedKeys[i], message, opts)
        valid, _ := gostcrypto.Verify(pubKey, message, signature, opts)
        fmt.Printf("Path %s — signature valid: %v\n", path, valid)
    }
}
```

**Path format:**

| Syntax | Meaning |
|--------|---------|
| `m/` | Root (required) |
| `n` | Normal derivation at index `n` |
| `n'` | Hardened derivation at index `n` |

Examples: `m/0`, `m/0'`, `m/44'/283'/0'/0/0`

## Low-Level API

For direct control over hashing and signing:

```go
package main

import (
    "fmt"
    "github.com/rekurt/gost-crypto/gost3410"
    "github.com/rekurt/gost-crypto/streebog"
)

func main() {
    privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
    if err != nil {
        panic(err)
    }

    pubKey, err := privKey.PublicKey()
    if err != nil {
        panic(err)
    }

    // Hash manually
    message := []byte("Direct signing example")
    digest := streebog.Sum256(message)

    // Sign the digest
    signature, err := privKey.SignDigest(digest[:])
    if err != nil {
        panic(err)
    }

    // Verify
    valid, err := pubKey.Verify(digest[:], signature)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Signature valid: %v\n", valid)
}
```

### Creating Keys from Raw Bytes

```go
package main

import (
    "encoding/hex"
    "fmt"
    "github.com/rekurt/gost-crypto/gost3410"
)

func main() {
    raw, _ := hex.DecodeString(
        "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28")

    privKey, err := gost3410.FromRawPriv(gost3410.TC26_256_A, raw)
    if err != nil {
        panic(err)
    }

    pubKey, err := privKey.PublicKey()
    if err != nil {
        panic(err)
    }

    fmt.Printf("Public key X: %s...\n", hex.EncodeToString(pubKey.X[:16]))
    fmt.Printf("Public key Y: %s...\n", hex.EncodeToString(pubKey.Y[:16]))
}
```

## Package Structure

```
gost-crypto/
├── streebog/           # GOST R 34.11-2012 Streebog hash (256/512)
│   └── streebog.go
├── gost3410/           # GOST R 34.10-2012 elliptic curve signatures
│   ├── backend_gogost.go    # gogost backend integration
│   ├── hash.go              # HashID type and constants
│   ├── keys.go              # key generation, serialization, recovery
│   ├── sign.go              # SignDigest and Verify methods
│   ├── signer.go            # crypto.Signer interface
│   └── *_test.go
├── gostcrypto/         # High-level facade (hash + sign in one call)
│   ├── facade.go
│   └── *_test.go
├── kdf/hd/             # HD key derivation (HKDF, BIP32-style paths)
│   └── hd.go
└── _examples/          # Runnable examples
```

## Testing

```bash
# All tests
go test ./...

# Verbose
go test -v ./...

# Single package
go test -v ./gost3410
go test -v ./gostcrypto

# Coverage
go test -cover ./...

# Specific test
go test -run TestIntegrationSignVerifyWithSerialization256 ./gostcrypto
```

### Coverage

| Package | Coverage | Notes |
|---------|----------|-------|
| `streebog` | 100% | RFC 6986 test vectors |
| `gostcrypto` | 88.2% | Integration tests, auto hash selection |
| `kdf/hd` | 92.9% | Path parsing, hardened/normal derivation |
| `gost3410` | 86.2% | All supported curves, serialization roundtrips, crypto.Signer |

### What Is Tested

- **Streebog**: RFC 6986 vectors (M1, M2), empty input, large messages, incremental hashing
- **GOST R 34.10-2012**: Sign/verify roundtrip on all supported curves, property-based tests (100 iterations)
- **Key serialization**: Compressed/uncompressed with and without prefix, roundtrip recovery
- **HD derivation**: Path consistency, hardened/normal derivation, fuzz tests for path parsing
- **Error handling**: Corruption detection, cross-curve rejection, invalid inputs, nil arguments

## Technical Details

### Signature Format

Signatures use GOST OCTET STRING format: `r || s`, where each component is stored as big-endian bytes.

| Curve type | Component size | Total signature |
|------------|---------------|-----------------|
| 256-bit | 32 bytes | 64 bytes |
| 512-bit | 64 bytes | 128 bytes |

### Public Key Encoding

**Compressed** (X coordinate + parity bit):

| Curve type | With prefix | Without prefix |
|------------|-------------|----------------|
| 256-bit | 33 bytes (`0x02`/`0x03` + X) | 32 bytes |
| 512-bit | 65 bytes (`0x02`/`0x03` + X) | 64 bytes |

**Uncompressed** (both coordinates):

| Curve type | With prefix | Without prefix |
|------------|-------------|----------------|
| 256-bit | 65 bytes (`0x04` + X + Y) | 64 bytes |
| 512-bit | 129 bytes (`0x04` + X + Y) | 128 bytes |

### Byte Order

The public API uses big-endian byte order for keys and signatures. Conversion to little-endian for the gogost backend is handled internally.

## Security Notes

1. Each signature uses a cryptographically random nonce (k)
2. Private keys should never be logged or serialized to untrusted storage
3. All inputs are validated for expected sizes and formats
4. Verification uses constant-time comparison
5. Implementation follows GOST R 34.10-2012 as specified in RFC 7091

## Limitations

- **Curve availability**: TC26_256_B/C/D and TC26_512_D require gogost backend support not yet present in v1.0.0
- **No ASN.1/PEM**: Key serialization to ASN.1 or PEM formats is not built in; use external libraries if needed
- **No official test vectors**: Validation uses generated roundtrip vectors; official TK26 vectors are pending integration
- **Pure Go**: No hardware acceleration or assembly optimizations

## References

- [GOST R 34.10-2012](https://www.tc26.ru/) — Digital signature algorithm
- [GOST R 34.11-2012](https://www.tc26.ru/) — Streebog hash function
- [RFC 7091](https://datatracker.ietf.org/doc/html/rfc7091) — GOST R 34.10-2012 Digital Signature Algorithm
- [RFC 6986](https://datatracker.ietf.org/doc/html/rfc6986) — GOST R 34.11-2012 Hash Function
- [ddulesov/gogost](https://github.com/ddulesov/gogost) — Backend cryptographic implementation
- [TK26](http://www.tc26.ru/) — Technical Committee 26 (official specifications)

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas of interest:
- Additional TC26 curve support (requires gogost backend changes)
- ASN.1/PEM codec
- Official TK26 test vector integration

## License

MIT License. See [LICENSE](LICENSE) for details.
