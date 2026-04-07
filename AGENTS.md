# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Overview

This is a Go cryptography library implementing Russian GOST standards. The project provides wrappers and utilities for digital signature operations using GOST R 34.10-2012 (elliptic curve signatures) combined with Streebog hashing (GOST R 34.11-2012), backed by OpenSSL gost-engine via CGO.

## Architecture

The codebase is organized into a root facade package and internal implementation packages:

### Package Structure

- **Root package (`gostcrypto`)** - High-level facade re-exporting types from `pkg/gost3410`
  - `gostcrypto.go`: `Sign()`, `Verify()`, `HashSum256()`, `HashSum512()`, `Agree()`
  - `keys.go`: `GenerateKey()`, `LoadPrivKey()`, type aliases for `PrivKey`, `PubKey`
  - `curves.go`: `Curve` type alias, all 8 TC26 curve constants, `AllCurves()`
  - `errors.go`: Re-exported sentinel errors
  - Auto-selects correct Streebog variant (256/512) based on curve key size

- **`pkg/gost3410/`** - GOST R 34.10-2012 elliptic curve operations (OpenSSL backend)
  - `curves.go`: `Curve` type with all 8 TC26 parameter sets (256-A/B/C/D, 512-A/B/C/D)
  - `keys.go`: `GenerateKey()`, `LoadPrivKey()`, `PrivKey`, `PubKey` types
  - `func.go`: `SignDigest()`, `VerifyDigest()` functions
  - `vko.go`: VKO key agreement with `Agree()`, `ErrCurveMismatch`, `ErrEmptyUKM`

- **`pkg/gost3411/`** - Streebog hashing (GOST R 34.11-2012) via OpenSSL
  - `streebog.go`: `New256()`, `New512()`, `Sum256()`, `Sum512()` (hash.Hash interface)
  - `hmac.go`: HMAC-Streebog

- **`pkg/gost3412/`** - Kuznechik cipher (GOST R 34.12-2015) via OpenSSL
  - `kuznechik.go`: `cipher.Block` interface

- **`pkg/gost3413/`** - MGM authenticated encryption (GOST R 34.13-2015) via OpenSSL
  - `mgm.go`: `cipher.AEAD` interface

- **`pkg/hd/`** - Hierarchical deterministic key derivation (BIP-32 style)
  - `hd.go`: `Master()`, `Derive()`, `ParsePath()`, `DerivedKey`
  - Deterministic: both chain codes and private keys are derived from seed via HKDF-Streebog

- **`pkg/kdf/`** - Key derivation functions
  - `kdf.go`: `HKDF256()`, `HKDF512()`

- **`internal/openssl/`** - CGO bindings for OpenSSL gost-engine
  - `engine.go`: Engine initialization
  - `evp_pkey.go`: Key generation, loading, signing, verification
  - `evp_md.go`: Hash operations
  - `key_handle.go`: Opaque key handle wrapper
  - `vko.go`: VKO key agreement

- **`_examples/`** - Runnable examples (sign_verify, vko_agreement, encrypt_decrypt, batch_signing, hd_derivation, key_serialization)

### Key Data Flow

1. User calls `gostcrypto.Sign(privKey, message)` or `Verify(pubKey, message, sig)`
2. Root package auto-selects correct Streebog variant (256/512) based on key's curve size
3. Message is hashed using Streebog via OpenSSL gost-engine
4. Digest is passed to GOST R 34.10-2012 signing/verification via OpenSSL

## Development Tasks

### Build and Test Commands

- **Build**: `go build ./...` - Compiles all packages (requires OpenSSL + gost-engine + CGO)
- **Run tests**: `go test ./...` - Runs all tests
- **Run with race detector**: `go test -race ./...`
- **Benchmarks**: `go test -bench=. -benchmem ./pkg/gost3410/ ./pkg/gost3411/`
- **Lint**: Use `golangci-lint run ./...` if available, or `go vet ./...` for basic checking

### Dependencies

- **Zero external Go dependencies** (go.mod has no `require` directives)
- **System requirements**: OpenSSL 3.x with gost-engine installed, CGO enabled
- **License**: MIT

## Documentation Structure

```
README.md              # Quickstart and library pitch
SECURITY.md            # Vulnerability disclosure policy
docs/
├── API.md             # Complete API reference
├── CONTRIBUTING.md    # Contributing guidelines
├── DEPLOYMENT.md      # OpenSSL + gost-engine setup
├── EXAMPLES.md        # Usage examples
├── MIGRATION.md       # v0 → v1 migration guide
├── THREAT_MODEL.md    # Threat model and security design
└── (*.ru.md)          # Russian translations
```

## Signature Format

The library uses GOST OCTET STRING format for signatures: `r || s`, where each component is `n` bytes (n=32 for 256-bit keys, n=64 for 512-bit keys).

## Key Interfaces

- `Curve`: Identifies TC26 parameter sets (all 8 curves: 256-A/B/C/D, 512-A/B/C/D)
- `PrivKey`: Opaque private key with `Bytes()`, `Curve()`, `PublicKey()`, `Zeroize()` methods
- `PubKey`: Opaque public key with `Curve()`, `Validate()` methods
- `DerivedKey`: HD-derived key bundle with `Key` and `ChainCode`, `Zeroize()` method

## Implementation Status

All core packages are fully implemented and tested:
- `pkg/gost3410`: All 8 TC26 curves, GenerateKey, LoadPrivKey, SignDigest, VerifyDigest, VKO
- `pkg/gost3411`: Streebog-256/512 hashing, HMAC-Streebog
- `pkg/gost3412`: Kuznechik block cipher
- `pkg/gost3413`: MGM authenticated encryption
- `pkg/hd`: Deterministic HD key derivation with HKDF-Streebog
- `pkg/kdf`: HKDF-256/512 key derivation
- Root `gostcrypto`: High-level facade with auto hash selection

### Next Steps

- Optional: ASN.1/PEM codec sub-package for key serialization
- Optional: Migrate from deprecated OpenSSL ENGINE API to provider API
