# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **PKCS#8 / SPKI PEM encoding for GOST R 34.10-2012 keys**
  (`pkg/gost3410/pem.go`). New methods and functions:
  `(*PrivKey).MarshalPrivateKeyPEM`, `ParsePrivateKeyPEM`,
  `(*PubKey).MarshalPublicKeyPEM`, `ParsePublicKeyPEM`,
  `(*PubKey).ZeroizePublicKey`. Output is byte-compatible with
  `openssl pkey` from OpenSSL gost-engine and uses the RFC 4491 /
  RFC 7836 signing OIDs.
- **X.509 self-signed certificate example**
  (`_examples/x509-cert/main.go`) — end-to-end flow covering key
  generation, cert issuance, PEM round-trip on disk, and interop
  commands for `openssl x509` / `openssl pkey`.
- **Benchmarks** for previously uncovered packages:
  `pkg/gost3411` (HMAC-Streebog-256/512), `pkg/gost3412`
  (Kuznechik / Magma `NewCipher`, `Encrypt`, `Decrypt`),
  `pkg/gost3413` (CBC, CTR, CMAC, MGM over 1 KB payloads),
  `pkg/kdf` (`KDF_GOSTR3411`, `HKDF`, `PBKDF2`), `pkg/hd`
  (`Master`, `Derive` at depth 1 and 5, `ParsePath`).
- **Fuzz tests**:
  `pkg/gost3411` — `FuzzSum256`, `FuzzSum512` (determinism +
  streaming-equals-one-shot invariants);
  `pkg/hd` — `FuzzDerive` (seed + path, no panics);
  `pkg/gost3410` — `FuzzLoadPrivKey_512`, `FuzzUnmarshalBinary`.
- **RFC 7801 / RFC 8891 explicit test vectors** — new
  `TestKuznechik_RFC7801` and `TestMagma_RFC8891` cite the IETF
  publications of GOST R 34.12-2015 directly, and additionally
  exercise sequential encrypt/decrypt on a cached cipher handle to
  protect against regressions in EVP context reuse.

### Changed

- `ParsePrivateKeyPEM` / `ParsePublicKeyPEM` now recover the **exact**
  TC26 parameter set from the encoded key's AlgorithmIdentifier
  instead of collapsing 256-bit keys to `CurveTC26_256_A` and
  512-bit keys to `CurveTC26_512_A`. Curve identity round-trips for
  every paramSet (A/B/C/D × 256/512); unknown paramSet OIDs are
  rejected. Implemented via pure-Go `encoding/asn1` parsing of the
  PKCS#8 PrivateKeyInfo / SubjectPublicKeyInfo returned by
  OpenSSL's `i2d_PrivateKey` / `i2d_PUBKEY`, so the detection logic
  has deterministic unit test coverage even without gost-engine
  present (`TestCurveFromDER_AllParamSets`).
- `(*PubKey).ZeroizePublicKey` is now safe to call on **any**
  `PubKey` value. A new `ownsHandle` flag distinguishes a shared
  `PubKey` returned by `(*PrivKey).PublicKey()` (where the owning
  `PrivKey` controls lifetime) from a standalone `PubKey` returned
  by `ParsePublicKeyPEM`. Calling Zeroize on a shared handle is now
  a documented no-op rather than an invisible use-after-free that
  invalidated the owning `PrivKey`.
- `pkg/gost3413/stream.go`: explicitly ignore the error from the
  idempotent auto-close in `cipherStreamReader.Read` after EOF. The
  error has no surface to be returned on once the caller has already
  seen `io.EOF`, and ignoring it is now documented inline.

### Notes

- All new crypto-facing tests and benchmarks honour the existing
  `skipIfNoEngine` pattern, so they are skipped cleanly in
  environments where OpenSSL gost-engine is not installed.
- `MarshalPrivateKeyPEM` currently returns unencrypted PKCS#8.
  Password-protected PKCS#8 is not yet exposed.
