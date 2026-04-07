# gost-crypto

[![CI](https://github.com/rekurt/gost-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/rekurt/gost-crypto/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/rekurt/gost-crypto)](https://goreportcard.com/report/github.com/rekurt/gost-crypto)
[![GoDoc](https://pkg.go.dev/badge/github.com/rekurt/gost-crypto)](https://pkg.go.dev/github.com/rekurt/gost-crypto)

Go implementation of Russian GOST cryptographic standards backed by OpenSSL gost-engine: digital signatures (GOST R 34.10-2012), cryptographic hashing (GOST R 34.11-2012 Streebog), block cipher (GOST R 34.12-2015 Kuznechik), authenticated encryption (GOST R 34.13-2015 MGM), VKO key agreement, and HD key derivation.

[API Reference](API.md) | [На русском](README.ru.md) | [Contributing](CONTRIBUTING.md)

## Features

- **GOST R 34.11-2012 Streebog** — 256-bit and 512-bit cryptographic hash functions
- **GOST R 34.10-2012** — elliptic curve digital signatures with all 8 TC26 parameter sets
- **GOST R 34.12-2015 Kuznechik** — 128-bit block cipher (cipher.Block interface)
- **GOST R 34.13-2015 MGM** — authenticated encryption (cipher.AEAD interface)
- **VKO key agreement** — GOST R 34.10-2012 ECDH-based shared secret derivation
- **HD key derivation** — deterministic hierarchical key derivation with BIP32-style paths
- **High-level API** — facade combining hashing and signing in a single call
- **Zero external Go dependencies** — only OpenSSL gost-engine via CGO

## Requirements

- Go 1.22 or later
- OpenSSL 3.x with gost-engine installed
- CGO enabled

## Installation

```bash
go get github.com/rekurt/gost-crypto
```

```go
import (
    gostcrypto "github.com/rekurt/gost-crypto"
)
```

## Supported Curves

All 8 TC26 (ТК26 — Technical Committee 26) standardized elliptic curves are supported:

| Curve | Key Size | OID |
|-------|----------|-----|
| CurveTC26_256_A | 256-bit | 1.2.643.7.1.2.1.1.1 |
| CurveTC26_256_B | 256-bit | 1.2.643.2.2.35.1 (CryptoPro-A) |
| CurveTC26_256_C | 256-bit | 1.2.643.2.2.35.2 (CryptoPro-B) |
| CurveTC26_256_D | 256-bit | 1.2.643.2.2.35.3 (CryptoPro-C) |
| CurveTC26_512_A | 512-bit | 1.2.643.7.1.2.1.2.1 |
| CurveTC26_512_B | 512-bit | 1.2.643.7.1.2.1.2.2 |
| CurveTC26_512_C | 512-bit | 1.2.643.7.1.2.1.2.3 |
| CurveTC26_512_D | 512-bit | 1.2.643.7.1.2.1.2.0 (test) |

## Quick Start

### Signing and Verification

```go
package main

import (
    "fmt"
    gostcrypto "github.com/rekurt/gost-crypto"
)

func main() {
    privKey, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
    if err != nil {
        panic(err)
    }
    defer privKey.Zeroize()

    pubKey := privKey.PublicKey()

    message := []byte("Hello, GOST R 34.10-2012!")

    // Sign (auto-selects Streebog-256 for 256-bit curve)
    signature, err := gostcrypto.Sign(privKey, message)
    if err != nil {
        panic(err)
    }

    // Verify
    valid, err := gostcrypto.Verify(pubKey, message, signature)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Signature valid: %v\n", valid)
}
```

### 512-bit Curves

```go
privKey, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_512_A)
if err != nil {
    panic(err)
}
defer privKey.Zeroize()

sig, _ := gostcrypto.Sign(privKey, []byte("Secure message"))
// sig is 128 bytes (64+64 for r||s)
```

### VKO Key Agreement

```go
privA, _ := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
privB, _ := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
defer privA.Zeroize()
defer privB.Zeroize()

ukm := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

// Shared secret is symmetric: Agree(A, pubB) == Agree(B, pubA)
secretAB, _ := gostcrypto.Agree(privA, privB.PublicKey(), ukm)
secretBA, _ := gostcrypto.Agree(privB, privA.PublicKey(), ukm)
// secretAB == secretBA
```

### HD Key Derivation

```go
package main

import (
    "fmt"
    gostcrypto "github.com/rekurt/gost-crypto"
    "github.com/rekurt/gost-crypto/pkg/hd"
)

func main() {
    seed := []byte("my secret seed phrase - at least 16 bytes")

    masterDK, err := hd.Master(seed, gostcrypto.CurveTC26_256_A)
    if err != nil {
        panic(err)
    }
    defer masterDK.Zeroize()

    // Derive child keys
    childDK, err := hd.Derive(masterDK, "m/44'/0'/0", gostcrypto.CurveTC26_256_A)
    if err != nil {
        panic(err)
    }
    defer childDK.Zeroize()

    // Sign with derived key
    sig, _ := gostcrypto.Sign(childDK.Key, []byte("HD wallet transaction"))
    fmt.Printf("Signature: %x...\n", sig[:16])
}
```

**Path format:**

| Syntax | Meaning |
|--------|---------|
| `m/` | Root (required) |
| `n` | Normal derivation at index `n` |
| `n'` or `nh` | Hardened derivation at index `n` |

### Low-Level Signing (pkg/gost3410)

```go
import (
    "github.com/rekurt/gost-crypto/pkg/gost3410"
    "github.com/rekurt/gost-crypto/pkg/gost3411"
)

priv, _ := gost3410.GenerateKey(gost3410.CurveTC26_256_A)
defer priv.Zeroize()

digest := gost3411.Sum256([]byte("Direct signing example"))

sig, _ := gost3410.SignDigest(priv, digest[:])

pub := priv.PublicKey()
valid, _ := gost3410.VerifyDigest(pub, digest[:], sig)
```

### Loading Keys from Raw Bytes

```go
raw := []byte{...} // 32 bytes for 256-bit curve

priv, err := gostcrypto.LoadPrivKey(gostcrypto.CurveTC26_256_A, raw)
if err != nil {
    panic(err)
}
defer priv.Zeroize()
```

## Package Structure

```
gost-crypto/
├── gostcrypto.go       # High-level facade: Sign, Verify, HashSum, Agree
├── keys.go             # GenerateKey, LoadPrivKey, PrivKey/PubKey aliases
├── curves.go           # Curve type, TC26 constants, AllCurves
├── errors.go           # Re-exported sentinel errors
├── pkg/
│   ├── gost3410/       # GOST R 34.10-2012 signatures (OpenSSL backend)
│   ├── gost3411/       # GOST R 34.11-2012 Streebog hash (OpenSSL backend)
│   ├── gost3412/       # GOST R 34.12-2015 Kuznechik cipher
│   ├── gost3413/       # GOST R 34.13-2015 MGM AEAD
│   ├── hd/             # HD key derivation (HKDF, BIP32-style paths)
│   └── kdf/            # Key derivation functions (HKDF-Streebog)
├── internal/openssl/   # CGO bindings for OpenSSL gost-engine
└── _examples/          # Runnable examples
```

## Testing

```bash
# All tests
go test ./...

# With race detection
go test -race ./...

# Benchmarks
go test -bench=. -benchmem ./pkg/gost3410/ ./pkg/gost3411/

# Coverage
go test -cover ./...

# Single package
go test -v ./pkg/gost3410/
```

### What Is Tested

- **Streebog**: RFC 6986 vectors (M1, M2), empty input, large messages, incremental hashing
- **GOST R 34.10-2012**: Sign/verify roundtrip on all 8 curves, property-based tests (100 iterations)
- **LoadPrivKey**: Generate-extract-load roundtrip on all curves, sign/verify with loaded keys
- **HD derivation**: Deterministic key derivation, path parsing, hardened/normal, fuzz tests
- **VKO**: Symmetric key agreement, different UKM values, cross-curve rejection
- **Error handling**: Corruption detection, cross-curve rejection, nil/zeroized keys, size mismatches

## Technical Details

### Signature Format

Signatures use GOST OCTET STRING format: `r || s`, both big-endian.

| Curve type | Component size | Total signature |
|------------|---------------|-----------------|
| 256-bit | 32 bytes | 64 bytes |
| 512-bit | 64 bytes | 128 bytes |

### Byte Order

The public API uses big-endian byte order for keys and signatures.

## Security Notes

1. Each signature uses a cryptographically random nonce (k) via OpenSSL
2. Private keys must be explicitly zeroized via `Zeroize()` when no longer needed
3. All inputs are validated for expected sizes and formats
4. Cryptographic operations are delegated to OpenSSL gost-engine
5. Implementation follows GOST R 34.10-2012 as specified in RFC 7091

## Limitations

- **OpenSSL required**: Requires OpenSSL 3.x with gost-engine and CGO; no pure-Go fallback
- **No ASN.1/PEM**: Key serialization to ASN.1 or PEM formats is not built in
- **Deprecated ENGINE API**: Uses OpenSSL ENGINE API (deprecated in 3.0); migration to provider API is planned

## References

- [GOST R 34.10-2012](https://www.tc26.ru/) — Digital signature algorithm
- [GOST R 34.11-2012](https://www.tc26.ru/) — Streebog hash function
- [RFC 7091](https://datatracker.ietf.org/doc/html/rfc7091) — GOST R 34.10-2012 Digital Signature Algorithm
- [RFC 6986](https://datatracker.ietf.org/doc/html/rfc6986) — GOST R 34.11-2012 Hash Function
- [TK26](http://www.tc26.ru/) — Technical Committee 26 (official specifications)

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas of interest:
- ASN.1/PEM codec for key serialization
- Migration from ENGINE API to OpenSSL 3.x provider API
- Official TK26 test vector integration

## License

MIT License. See [LICENSE](LICENSE) for details.
