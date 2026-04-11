# AGENTS.md

This file provides guidance to Codex / Claude Code agents when working
with code in this repository.

## Overview

This is a Go cryptography library implementing Russian GOST standards.
The project provides wrappers and utilities for digital signatures
(GOST R 34.10-2012) combined with Streebog hashing (GOST R 34.11-2012),
Kuznechik / Magma block ciphers (GOST R 34.12-2015), higher-level modes
(GOST R 34.13-2015 CBC / CTR / CFB / OFB / MGM / IMIT), VKO key
agreement, CMS / CAdES-BES signing, X.509 certificates, HD key
derivation and PBKDF2 / HKDF / KDF_GOSTR3411.

Primitive operations are delegated to **CryptoPro CSP 5.0+ for Linux**
(CAPILite API, libcapi10 / libcapi20) via CGO. CMS / CAdES operations
call into CryptoPro's **CAdES SDK** (libcades). Higher-level modes that
CAPILite does not expose natively (CTR / CFB / OFB / MGM) are
implemented in pure Go on top of the raw Kuznechik / Magma block cipher
provided by `pkg/gost3412`.

## Architecture

- **Root package (`gostcrypto`)** — high-level facade
  - `gostcrypto.go`: `Sign()`, `Verify()`, `HashSum256/512()`, `Agree()`
  - `keys.go`, `curves.go`, `errors.go` — type aliases + sentinels
  - Auto-selects correct Streebog variant (256/512) based on curve size

- **`pkg/gost3410/`** — GOST R 34.10-2012 signatures (CryptoPro CSP)
  - `curves.go`, `keys.go`, `func.go`, `vko.go`, `encoding.go`

- **`pkg/gost3411/`** — Streebog hash (CryptoPro CSP)
  - `streebog.go`: `hash.Hash` wrapper, `Sum256/512`
  - `hmac.go`: HMAC-Streebog via stdlib `crypto/hmac`

- **`pkg/gost3412/`** — Kuznechik / Magma raw block cipher (CryptoPro CSP ECB)
  - `kuznechik.go`, `magma.go`: `cipher.Block` interface

- **`pkg/gost3413/`** — GOST 34.13-2015 modes of operation
  - `cbc.go`, `ctr.go`, `cfb.go`, `ofb.go` — pure Go on top of
    `pkg/gost3412` (crypto/cipher standard mode wrappers)
  - `mgm.go`, `magma_mgm.go`, `mgm_core.go` — pure-Go MGM AEAD
  - `cmac.go` — dispatches to `cryptopro.CMAC` (CSP IMIT primitive)
  - `stream.go` — `cipher.Stream` → `io.ReadCloser` adapter

- **`pkg/cms/`** — CMS / CAdES-BES signing via CryptoPro CAdES (libcades)
- **`pkg/gostx509/`** — X.509 create / parse / verify via CAPILite CertXxx
- **`pkg/hd/`** — HD key derivation (pure Go on top of `pkg/gost3411`)
- **`pkg/kdf/`** — HKDF / KDF_GOSTR3411 / PBKDF2 (pure Go)

- **`internal/cryptopro/`** — CGO bindings for CryptoPro CSP + CAdES
  - `provider.go`: `CryptAcquireContextA` lifecycle
  - `key.go`, `gost3410.go`: HCRYPTKEY wrapper, keygen / sign / verify
  - `hash.go`: Streebog via `CryptCreateHash` / `CryptHashData`
  - `cipher.go`: raw ECB HCRYPTKEY wrapper
  - `cmac.go`: IMIT hash dispatch for CMAC
  - `vko.go`: VKO key agreement
  - `cades.go`: CAdES-BES sign / verify via `CadesSignMessage` / `CadesVerifyMessage`
  - `x509.go`: certificate create / parse / verify via `CryptSignAndEncodeCertificate` + `CertCreateCertificateContext`
  - `oids.go`: TC26 parameter-set OID table + CAPILite ALG_ID constants
  - `errors.go`: HRESULT / GetLastError mapping
  - `cleanse.go`, `mlock.go`: secure memory helpers

- **`_examples/`** — runnable examples (sign_verify, vko_agreement,
  encrypt_decrypt, batch_signing, hd_derivation, key_serialization)

### Key Data Flow

1. User calls `gostcrypto.Sign(privKey, message)` or `Verify(pubKey, message, sig)`
2. Root facade auto-selects Streebog-256 or -512 based on the key's curve
3. Message is hashed via `cryptopro.HashBytes` → CryptoPro CSP `CryptCreateHash`
4. Digest is signed via `cryptopro.SignDigestH` → CryptoPro CSP `CryptSignHashA`

## Development Tasks

### Build and Test

- **Build**: `CGO_ENABLED=1 go build ./...`
- **Test**: `CGO_ENABLED=1 go test -race -count=1 ./...`
- **Benchmarks**: `go test -bench=. -benchmem ./pkg/gost3410/ ./pkg/gost3411/`
- **Lint**: `golangci-lint run ./...` or `go vet ./...`

### Dependencies

- **Zero external Go dependencies** (go.mod has no `require` directives)
- **System requirements**: CryptoPro CSP 5.0+ for Linux under `/opt/cprocsp/`,
  including `libcapi10.so`, `libcapi20.so`, `libssp.so`, `librdrsup.so`,
  and CryptoPro CAdES `libcades.so`; CGO enabled
- **Licence**: library MIT; CryptoPro CSP requires a separate licence from cryptopro.ru

## Documentation Structure

```
README.md              # Quickstart and library pitch
SECURITY.md            # Vulnerability disclosure policy
docs/
├── API.md             # Complete API reference
├── CONTRIBUTING.md    # Contributing guidelines
├── DEPLOYMENT.md      # CryptoPro CSP + CAdES setup
├── EXAMPLES.md        # Usage examples
├── MIGRATION.md       # v0 → v1 migration guide
├── THREAT_MODEL.md    # Threat model and security design
└── (*.ru.md)          # Russian translations
```

## Signature Format

Signatures are r||s (little-endian), 64 bytes (256-bit curve) or 128
bytes (512-bit curve). This matches the native CryptoPro CSP wire
format and the historical gost-engine output — no transcoding is
necessary at any layer.

## Key Interfaces

- `Curve`: TC26 parameter set enumeration (all 8 curves)
- `PrivKey`: opaque private key with `Bytes()`, `Curve()`, `PublicKey()`,
  `Zeroize()`
- `PubKey`: opaque public key with `Curve()`, `Validate()`
- `DerivedKey`: HD-derived bundle with `Key` and `ChainCode`, `Zeroize()`

## Implementation Status

All core packages are implemented on the CryptoPro CSP backend:
- `pkg/gost3410`: all 8 TC26 curves, GenerateKey, LoadPrivKey, Sign/Verify, VKO
- `pkg/gost3411`: Streebog-256/512 hashing, HMAC-Streebog
- `pkg/gost3412`: Kuznechik / Magma block ciphers (`cipher.Block`)
- `pkg/gost3413`: CBC / CTR / CFB / OFB / MGM / CMAC (pure Go modes over CSP block cipher)
- `pkg/cms`: CAdES-BES sign / verify via libcades
- `pkg/gostx509`: X.509 certificate creation / parsing / verification
- `pkg/hd`, `pkg/kdf`: pure Go on top of `pkg/gost3411`

### Next Steps

- Migrate the CI workflow and Dockerfiles to a base image with
  CryptoPro CSP pre-installed (out of scope for the migration PR).
- Optional: CSR creation via CryptoPro CSP CertCreateSelfSignCertificate.
- Optional: ASN.1 / PEM key serialization sub-package.
