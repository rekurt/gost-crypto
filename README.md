# gost-crypto

Go library for Russian GOST cryptographic standards, backed by OpenSSL 3.0+ and [gost-engine](https://github.com/gost-engine/engine).

Provides digital signatures (GOST R 34.10-2012), hashing (Streebog), symmetric encryption (Kuznechik), authenticated encryption (MGM), key agreement (VKO), and key derivation (KDF, HKDF, HD).

[![CI](https://github.com/rekurt/gost-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/rekurt/gost-crypto/actions/workflows/ci.yml)

## Quick Start

```go
package main

import (
    "fmt"
    "github.com/rekurt/gost-crypto"
)

func main() {
    // Generate a key pair on a 256-bit TC26 curve
    priv, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
    if err != nil {
        panic(err)
    }
    defer priv.Zeroize()

    // Sign a message (Streebog hash is selected automatically)
    msg := []byte("Hello, GOST!")
    sig, err := gostcrypto.Sign(priv, msg)
    if err != nil {
        panic(err)
    }

    // Verify
    ok, err := gostcrypto.Verify(priv.PublicKey(), msg, sig)
    if err != nil {
        panic(err)
    }
    fmt.Println("valid:", ok) // valid: true
}
```

## Supported Algorithms

| Algorithm | Standard | Package |
|-----------|----------|---------|
| Streebog-256 / Streebog-512 | GOST R 34.11-2012 | `pkg/gost3411` |
| GOST R 34.10-2012 (sign/verify) | GOST R 34.10-2012 | `pkg/gost3410` |
| VKO key agreement | GOST R 34.10-2012 Appendix B | `pkg/gost3410` |
| Kuznechik block cipher | GOST R 34.12-2015 | `pkg/gost3412` |
| MGM (AEAD) | GOST R 34.13-2015 | `pkg/gost3413` |
| GOST R KDF | GOST R 50.1.113-2016 | `pkg/kdf` |
| HKDF (Streebog-based) | RFC 5869 with Streebog | `pkg/kdf` |
| HD key derivation | BIP32-style with Streebog HMAC | `pkg/hd` |

All eight TC26 elliptic curve parameter sets are supported (256-bit: A/B/C/D, 512-bit: A/B/C/D).

## Package Structure

```
gost-crypto/
    doc.go, gostcrypto.go, keys.go, curves.go   # High-level facade
    internal/openssl/                             # cgo OpenSSL bindings
    pkg/
        gost3410/     # GOST R 34.10-2012 signatures + VKO
        gost3411/     # Streebog hash + HMAC
        gost3412/     # Kuznechik block cipher
        gost3413/     # MGM authenticated encryption
        kdf/          # GOST R KDF + HKDF
        hd/           # Hierarchical deterministic key derivation
```

## Requirements

- Go 1.22+
- OpenSSL 3.0+ with gost-engine v3.0.3+
- `CGO_ENABLED=1`
- C compiler (gcc or clang), CMake

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for detailed installation instructions on Linux, macOS, and Docker.

## Docker

The fastest way to get started:

```bash
docker build -f Dockerfile.ci -t gost-crypto-ci .
docker run --rm -v "$(pwd):/app" -w /app gost-crypto-ci go test ./... -count=1
```

## Documentation

- [Deployment Guide](docs/DEPLOYMENT.md) -- installing OpenSSL and gost-engine
- [Security](docs/SECURITY.md) -- threat model, assumptions, vulnerability disclosure
- [Migration Guide](docs/MIGRATION.md) -- upgrading from v0 (gogost-based) to v1

## Security Notice

This library has NOT been formally audited and is NOT certified by FSB (Federal Security Service of Russia). It is provided for educational and research use. If your application requires certified cryptography, use a certified implementation.

See [docs/SECURITY.md](docs/SECURITY.md) for the full threat model and vulnerability disclosure process.

## License

MIT
