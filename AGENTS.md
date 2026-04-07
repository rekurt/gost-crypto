# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Overview

This is a Go cryptography library implementing Russian GOST standards. The project provides wrappers and utilities for digital signature operations using GOST R 34.10-2012 (elliptic curve signatures) combined with Streebog hashing (GOST R 34.11-2012).

## Architecture

The codebase is organized into four main packages:

### Package Structure

- **`gostcrypto/`** - High-level facade providing combined signing and verification operations
  - `facade.go`: Exposes `Sign()` and `Verify()` functions that handle both hashing (Streebog) and signing (GOST R 34.10-2012) in one call
  - Takes an `Options` struct to optionally override hash algorithm (defaults to inferring from key size)

- **`gost3410/`** - Low-level GOST R 34.10-2012 elliptic curve operations
  - `keys.go`: Defines `PrivKey` and `PubKey` structs and operations:
    - Key generation: `NewPrivKey()` generates random keys with `0 < d < q` range validation
    - Key conversion: `FromRawPriv()`, `FromRawPrivReduce()`, `ToRaw()`, `PublicKey()`
    - Public key encoding: `ToUncompressed()`, `ToCompressed()`, `FromUncompressed()`, `FromCompressed()`
  - `hash.go`: `HashID` type with `HashAuto`, `Streebog256`, `Streebog512` constants
  - `sign.go`: `SignDigest()` and `Verify()` methods - fully implemented
  - `signer.go`: `crypto.Signer` interface implementation (`Public()`, `Sign()`)
  - `backend_gogost.go`: Backend integration with `ddulesov/gogost` for `mulBase()`, `recoverY()`, `curveOrder()`
  - Supports 8 TC26 curve parameter sets: 4x 256-bit curves and 4x 512-bit curves

- **`streebog/`** - Wrapper for Streebog-256/512 hashing (GOST R 34.11-2012)
  - Thin wrapper around external `github.com/ddulesov/gogost` library
  - Provides convenient `Sum256()` and `Sum512()` functions (hashers via `New256()`, `New512()`)

- **`kdf/hd/`** - HD key derivation using HKDF
  - `hd.go`: Hierarchical deterministic key derivation with BIP32-style path parsing

- **`_examples/`** - Usage examples (sign_verify_256, sign_verify_512, batch_signing, hd_derivation, key_serialization)

- **Repo files**: `.github/workflows/ci.yml` (CI matrix: Go 1.21/1.22/latest), `SECURITY.md`, `CONTRIBUTING.md`

### Key Data Flow

1. User calls `gostcrypto.Sign(privKey, message, options)` or `Verify(pubKey, message, sig, options)`
2. Facade automatically selects correct Streebog variant (256 or 512) based on key size or options
3. Message is hashed using Streebog
4. Digest is passed to GOST R 34.10-2012 signing/verification

## Development Tasks

### Build and Test Commands

- **Build**: `go build ./...` - Compiles all packages
- **Run tests**: `go test ./...` - Runs all tests
- **Lint**: Use `golangci-lint run ./...` if available, or `go vet ./...` for basic checking

### Implementation Status

All core packages are fully implemented and tested:
- `gost3410`: Sign/Verify, key generation, serialization, crypto.Signer - all working (85.5% coverage)
- `gostcrypto`: High-level facade with auto hash selection - all working (88.2% coverage)
- `streebog`: Streebog-256/512 hashing - all working (100% coverage)
- `kdf/hd`: HD key derivation - all working (92.9% coverage)

### External Dependency

- Uses `github.com/ddulesov/gogost v1.0.0` for actual cryptographic operations
- The library provides implementations of Streebog hashing and GOST R 34.10-2012 elliptic curve operations

## Signature Format

The library uses GOST OCTET STRING format for signatures: `r || s`, where each component is `n` bytes (n=32 for 256-bit keys, n=64 for 512-bit keys).

Public keys can be encoded in:
- Uncompressed form: `0x04 || X || Y` (with prefix) or `X || Y` (without)
- Compressed form: `0x02/0x03 || X` (with prefix) or `X` with MSB as parity bit (without)

## Implementation Status (Updated)

**Completed**:
- `streebog` package - Full implementation (100% coverage)
- `gost3410/keys.go` - Complete key handling, serialization, range validation
- `gost3410/hash.go` - HashID type and constants
- `gost3410/signer.go` - crypto.Signer interface implementation
- `gost3410/backend_gogost.go` - Backend integration with ddulesov/gogost
- `gost3410/sign.go` - SignDigest and Verify methods (85.5% coverage)
- `gostcrypto` facade - Complete high-level API (88.2% coverage)
- `kdf/hd` - HKDF-based HD key derivation with hash/curve validation (92.9% coverage)

**Validated with**:
- RFC 6986 Streebog test vectors (M1, M2 messages)
- GOST R 34.10-2012 sign/verify roundtrip tests on all supported curves
- Property-based tests (100 iterations sign-then-verify on all curves)
- Fuzz tests for path parsing, compressed/uncompressed key serialization
- Edge case tests for error paths, corruption, and cross-curve rejection
- Benchmarks for Sign and Verify operations (256-bit and 512-bit)

**Not Yet Implemented**:
- Support for additional TC26 curves (256-B/C/D, 512-D) - backend ready, just needs registration
- ASN.1/PEM codec sub-package for key serialization (optional)

## Key Interfaces

- `Curve`: Identifies TC26 parameter sets (256-A, 512-A/B/C supported), supports `Size() (int, error)` method
- `Options`: Controls hash algorithm selection in facade functions (optional)
- `HashID`: Selects between Streebog256 and Streebog512 (HashAuto = zero value for auto-detection)
- `PrivKey`: Private key with `SignDigest()`, `PublicKey()`, `ToRaw()` methods; implements `crypto.Signer`
- `PubKey`: Public key with `Verify()` and serialization methods (`ToCompressed()`, `ToUncompressed()`, `FromCompressed()`, `FromUncompressed()`)

## Known Issues

All previously known issues have been resolved:

### Verify Method - Public Key Reconstruction
- **Status**: FIXED (commit 21427da)
- **Fix**: Corrected byte order in public key reconstruction - gogost expects X||Y (both reversed), not Y||X

### Bugs Fixed During Validation (2026-03-03)
- **NewPrivKey signature**: Changed to return `(*PrivKey, error)` with `0 < d < q` range validation via rejection sampling
- **Private key validation**: `FromRawPriv` rejects d == 0 and d >= q
- **padToSize**: Returns defensive copies; truncates when input exceeds target size
- **Options hash inference**: Fixed zero-value ambiguity by introducing `HashAuto` sentinel value (iota=0) so `Streebog256` and `Streebog512` are non-zero
- **Benchmark nil keys**: Fixed BenchmarkVerify256/512 to use real public keys via `privKey.PublicKey()`
- **ToCompressed**: Returns `([]byte, error)` — errors when `prefix=false` and `X[0] >= 0x80`
- **modSqrt**: Replaced custom Tonelli-Shanks with stdlib `big.Int.ModSqrt`
- **HashID moved**: Extracted to `gost3410/hash.go`; `h HashID` parameter removed from `SignDigest`/`Verify`
- **crypto.Signer**: `PrivKey` implements `crypto.Signer`; `Public()` returns `crypto.PublicKey`, `PublicKey()` returns `(*PubKey, error)`
- **HD derivation**: Hash/curve size mismatch validation; empty path segment detection

## Test Vectors and Standards

### Current Test Vector Status
- Streebog-256/512: RFC 6986 vectors (M1 63-byte, M2 72-byte), "abc", empty string, long message, incremental hashing
- GOST R 34.10-2012: Sign/verify roundtrip on all supported curves (256-A, 512-A/B/C)
- Property-based: 100-iteration sign-then-verify for each curve
- Edge cases: corruption detection, cross-curve rejection, invalid inputs

## Project Status

All core functionality is complete. Full TODO audit (33 items across 5 priority levels) has been completed — see `docs/plans/completed/2026-03-03-implement-todo-audit.md` for details.

### Next Steps

### Priority 1: Implement Remaining TC26 Curves
- **Effort**: Low
- **Support needed**: 256-B/C/D, 512-D curves
- **Status**: Curves defined in gost3410/keys.go, gogost backend ready
- **Action**: Add curve parameter sets to gogostCurves array

### Priority 2: Implement Optional ASN.1/PEM Codec
- **Effort**: Medium
- **Impact**: Key serialization to standard formats
- **Optional**: Not required for core functionality