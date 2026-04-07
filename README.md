# gost-crypto

[![CI](https://github.com/rekurt/gost-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/rekurt/gost-crypto/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/rekurt/gost-crypto)](https://goreportcard.com/report/github.com/rekurt/gost-crypto)
[![GoDoc](https://pkg.go.dev/badge/github.com/rekurt/gost-crypto)](https://pkg.go.dev/github.com/rekurt/gost-crypto)

Production-ready Go library for Russian GOST cryptographic standards, backed by OpenSSL gost-engine. Zero external Go dependencies — all cryptography is delegated to OpenSSL for constant-time operations and battle-tested implementations.

[API Reference](docs/API.md) | [Examples](docs/EXAMPLES.md) | [На русском](docs/README.ru.md) | [Contributing](docs/CONTRIBUTING.md)

## Features

- **GOST R 34.11-2012 Streebog** — 256-bit and 512-bit cryptographic hash functions
- **GOST R 34.10-2012** — elliptic curve digital signatures with all 8 TC26 parameter sets
- **GOST R 34.12-2015 Kuznechik** — 128-bit block cipher (`cipher.Block` interface)
- **GOST R 34.13-2015 MGM** — authenticated encryption (`cipher.AEAD` interface)
- **VKO key agreement** — GOST R 34.10-2012 ECDH-based shared secret derivation
- **HD key derivation** — deterministic hierarchical keys with BIP32-style paths
- **High-level API** — facade combining hashing and signing in a single call

## Requirements

- Go 1.22+
- OpenSSL 3.x with gost-engine ([installation guide](docs/DEPLOYMENT.md))
- CGO enabled

## Installation

```bash
go get github.com/rekurt/gost-crypto
```

## Quick Start

### Sign and Verify

```go
package main

import (
    "fmt"
    gostcrypto "github.com/rekurt/gost-crypto"
)

func main() {
    priv, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
    if err != nil {
        panic(err)
    }
    defer priv.Zeroize()

    sig, err := gostcrypto.Sign(priv, []byte("Hello, GOST!"))
    if err != nil {
        panic(err)
    }

    ok, err := gostcrypto.Verify(priv.PublicKey(), []byte("Hello, GOST!"), sig)
    if err != nil {
        panic(err)
    }
    fmt.Println("valid:", ok) // valid: true
}
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
// bytes.Equal(secretAB, secretBA) == true
```

More examples: [docs/EXAMPLES.md](docs/EXAMPLES.md) | [_examples/](_examples/)

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
│   └── kdf/            # Key derivation functions (HKDF-Streebog, KDF_GOSTR3411)
├── internal/openssl/   # CGO bindings for OpenSSL gost-engine
└── _examples/          # Runnable examples
```

## Documentation

| Document | Description |
|----------|-------------|
| [API Reference](docs/API.md) | Complete API for all packages |
| [Examples](docs/EXAMPLES.md) | Validated usage patterns |
| [Deployment](docs/DEPLOYMENT.md) | OpenSSL + gost-engine setup |
| [Migration v0→v1](docs/MIGRATION.md) | Breaking changes and migration path |
| [Threat Model](docs/THREAT_MODEL.md) | Security assumptions and limitations |

## Contributing

Contributions are welcome. See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

## License

MIT License. See [LICENSE](LICENSE) for details.
