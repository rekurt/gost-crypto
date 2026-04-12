# gost-crypto

[![CI](https://github.com/rekurt/gost-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/rekurt/gost-crypto/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/rekurt/gost-crypto)](https://goreportcard.com/report/github.com/rekurt/gost-crypto)
[![GoDoc](https://pkg.go.dev/badge/github.com/rekurt/gost-crypto)](https://pkg.go.dev/github.com/rekurt/gost-crypto)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/rekurt/gost-crypto)](go.mod)
[![codecov](https://codecov.io/gh/rekurt/gost-crypto/branch/master/graph/badge.svg)](https://codecov.io/gh/rekurt/gost-crypto)

Go library for Russian GOST cryptographic standards (GOST R 34.10-2012, GOST R 34.11-2012 Streebog, GOST R 34.12-2015 Kuznechik, GOST R 34.13-2015 MGM), powered by CryptoPro CSP (CAPILite) and CryptoPro CAdES. Digital signatures, hashing, encryption, key agreement, CMS/CAdES signing, and key derivation with zero external Go dependencies.

[API Reference](docs/API.md) | [Examples](docs/EXAMPLES.md) | [На русском](docs/README.ru.md) | [Contributing](docs/CONTRIBUTING.md)

## Why gost-crypto?

- **CryptoPro CSP backend** — GOST primitives (Streebog, GOST 34.10-2012 sign/verify/VKO, Kuznechik / Magma block ciphers, IMIT) are delegated to CryptoPro CSP 5.0+ via CAPILite; CMS / CAdES-BES signatures are produced by CryptoPro's CAdES library.
- **Complete GOST toolkit** — digital signatures, hashing, symmetric encryption, AEAD, key agreement, CAdES-BES CMS, and key derivation in a single library
- **Standard Go interfaces** — `hash.Hash`, `cipher.Block`, `cipher.AEAD` — drop-in compatible with Go's crypto ecosystem
- **Zero Go dependencies** — `go.mod` has no `require` directives; only CryptoPro CSP + CGO at build time
- **All 8 TC26 curves** — both 256-bit and 512-bit elliptic curve parameter sets
- **HD key derivation** — BIP32-style hierarchical deterministic keys for GOST curves

## Features

| Standard | Package | Description | Go Interface |
|----------|---------|-------------|--------------|
| GOST R 34.10-2012 | `pkg/gost3410` | Elliptic curve digital signatures | — |
| GOST R 34.11-2012 | `pkg/gost3411` | Streebog hash (256/512-bit) | `hash.Hash` |
| GOST R 34.12-2015 | `pkg/gost3412` | Kuznechik block cipher | `cipher.Block` |
| GOST R 34.13-2015 | `pkg/gost3413` | MGM authenticated encryption | `cipher.AEAD` |
| RFC 7836 | `pkg/gost3410` | VKO key agreement (ECDH) | — |
| R 50.1.113-2016 | `pkg/kdf` | KDF_GOSTR3411, HKDF-Streebog | — |
| BIP-32 style | `pkg/hd` | HD key derivation | — |

## Requirements

- Go 1.22+
- CryptoPro CSP 5.0+ for Linux installed under `/opt/cprocsp/` (with a
  valid CryptoPro licence). CAPILite libraries `libcapi10.so`,
  `libcapi20.so`, `libssp.so`, `librdrsup.so` and CryptoPro CAdES library
  `libcades.so` must be on the dynamic-linker path. See the
  [deployment guide](docs/DEPLOYMENT.md).
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

### Kuznechik Encryption (AEAD)

```go
import "github.com/rekurt/gost-crypto/pkg/gost3413"

aead, _ := gost3413.NewMGMFromKey(key) // 32-byte key

nonce := make([]byte, aead.NonceSize())
rand.Read(nonce)

ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
```

More examples: [docs/EXAMPLES.md](docs/EXAMPLES.md) | [_examples/](_examples/)

## Supported Curves

All 8 TC26 elliptic curve parameter sets are supported:

| Curve | Size | OID | Notes |
|-------|------|-----|-------|
| `CurveTC26_256_A` | 256-bit | 1.2.643.7.1.2.1.1.1 | Recommended |
| `CurveTC26_256_B` | 256-bit | 1.2.643.2.2.35.1 | CryptoPro-A |
| `CurveTC26_256_C` | 256-bit | 1.2.643.2.2.35.2 | CryptoPro-B |
| `CurveTC26_256_D` | 256-bit | 1.2.643.2.2.35.3 | CryptoPro-C |
| `CurveTC26_512_A` | 512-bit | 1.2.643.7.1.2.1.2.1 | |
| `CurveTC26_512_B` | 512-bit | 1.2.643.7.1.2.1.2.2 | |
| `CurveTC26_512_C` | 512-bit | 1.2.643.7.1.2.1.2.3 | |
| `CurveTC26_512_D` | 512-bit | 1.2.643.7.1.2.1.2.0 | Test curve |

## Package Structure

```
gost-crypto/
├── gostcrypto.go         # High-level facade: Sign, Verify, HashSum, Agree
├── keys.go               # GenerateKey, LoadPrivKey, PrivKey/PubKey aliases
├── curves.go             # Curve type, TC26 constants, AllCurves
├── errors.go             # Re-exported sentinel errors
├── pkg/
│   ├── gost3410/         # GOST R 34.10-2012 signatures (CryptoPro CSP)
│   ├── gost3411/         # GOST R 34.11-2012 Streebog hash  (CryptoPro CSP)
│   ├── gost3412/         # GOST R 34.12-2015 Kuznechik / Magma cipher
│   ├── gost3413/         # GOST R 34.13-2015 modes (CBC native, CTR/CFB/OFB/MGM in Go)
│   ├── cms/              # CMS / CAdES-BES signing via CryptoPro CAdES
│   ├── gostx509/         # X.509 certificate creation & verification
│   ├── hd/               # HD key derivation (HKDF, BIP32-style paths)
│   └── kdf/              # Key derivation functions (HKDF-Streebog, KDF_GOSTR3411)
├── internal/cryptopro/   # CGO bindings for CryptoPro CSP (CAPILite) + CAdES
└── _examples/            # Runnable examples
```

## Documentation

| Document | Description |
|----------|-------------|
| [API Reference](docs/API.md) | Complete API for all packages |
| [Examples](docs/EXAMPLES.md) | Validated usage patterns |
| [Deployment](docs/DEPLOYMENT.md) | CryptoPro CSP + CAdES setup |
| [Migration v0 to v1](docs/MIGRATION.md) | Breaking changes and migration path |
| [Threat Model](docs/THREAT_MODEL.md) | Security assumptions and limitations |
| [Security Policy](SECURITY.md) | Vulnerability disclosure |

## Standards Compliance

This library implements the following Russian and international standards:

- **GOST R 34.10-2012** / [RFC 7091](https://datatracker.ietf.org/doc/html/rfc7091) — Digital signature algorithm
- **GOST R 34.11-2012** / [RFC 6986](https://datatracker.ietf.org/doc/html/rfc6986) — Streebog hash function
- **GOST R 34.12-2015** — Kuznechik block cipher
- **GOST R 34.13-2015** — MGM authenticated encryption mode
- **RFC 7836** — VKO key agreement
- **R 50.1.113-2016** — KDF_GOSTR3411 key derivation
- **[TC26](http://www.tc26.ru/)** — All 8 standardized elliptic curve parameter sets

## Migration Status (OpenSSL → CryptoPro CSP)

This library was recently migrated from OpenSSL gost-engine to CryptoPro
CSP. The migration is **code-complete** but has the following known
limitations:

| Area | Status | Notes |
|------|--------|-------|
| GOST 34.10-2012 sign/verify | Implemented | Via `CryptSignHashA` / `CryptVerifySignatureA` |
| Streebog hash (256/512) | Implemented | Via `CryptCreateHash` / `CryptHashData` |
| Kuznechik / Magma ECB | Implemented | Via `CryptImportKey(PLAINTEXTKEYBLOB)` + `CryptEncrypt` |
| CBC / CTR / CFB / OFB modes | Implemented | Pure Go on top of raw block cipher |
| MGM (AEAD) | Implemented | Pure Go; **not yet validated with KAT vectors** |
| CMAC (IMIT) | Implemented | Via CryptoPro CSP native IMIT hash |
| VKO key agreement | Implemented | Via `CryptExportKey` + `CryptImportKey` + `KP_SV` |
| CMS / CAdES-BES signing | Implemented | Via `CadesSignMessage` / `CadesVerifyMessage` |
| X.509 certificates | Implemented | `CreateSelfSigned`, `ParseDER/PEM`, `Verify` |
| CSR creation | **Not implemented** | CAPILite lacks a GOST-compatible PKCS#10 builder |
| CI / Docker | **Stubbed** | Requires private base image with CryptoPro CSP |
| Build tag | Required | `-tags cryptopro` (CGO + Linux only) |

## Contributing

Contributions are welcome. See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

## License

MIT License. See [LICENSE](LICENSE) for details.
