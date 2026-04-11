// Package cryptopro is the internal CGO backend that binds gost-crypto to
// CryptoPro CSP (CAPILite) and CryptoPro CAdES on Linux.
//
// This package replaces the former internal/openssl backend which used
// OpenSSL with gost-engine. The public package surface under pkg/* is
// unchanged — only the underlying primitive implementations move from
// EVP_* / ENGINE_* to CryptoPro CSP (CryptAcquireContextA,
// CryptCreateHash, CryptEncrypt, CryptSignHash, ...) and libcades
// (CadesSignMessage, CadesVerifyMessage, ...).
//
// # Runtime requirements
//
//   - CryptoPro CSP 5.0+ for Linux installed under /opt/cprocsp/
//   - libcapi10.so, libcapi20.so, libssp.so, librdrsup.so in
//     /opt/cprocsp/lib/amd64/
//   - CryptoPro CAdES library (libcades.so) in the same directory
//   - Valid CryptoPro licence (the CSP refuses to initialise without one)
//
// # Package layout
//
//   - provider.go — CryptAcquireContextA lifecycle, sync.Once guard
//   - key.go      — KeyHandle wrapping HCRYPTKEY
//   - gost3410.go — keygen / sign / verify / raw import-export
//   - hash.go     — Streebog-256/512 via CryptCreateHash
//   - cipher.go   — Kuznechik/Magma raw block cipher via HCRYPTKEY
//   - cmac.go     — IMIT (GOST MAC) via CryptCreateHash
//   - vko.go      — VKO (key agreement) via CryptImportKey + KP_SV
//   - cades.go    — CAdES-BES sign / verify via libcades
//   - x509.go     — X.509 certificate ops via CAPILite Cert* functions
//   - oids.go     — TC26 parameter-set OIDs and CryptoPro ALG_ID constants
//   - errors.go   — HRESULT / GetLastError mapping
//   - cleanse.go  — secure memory zeroing
//   - mlock.go    — mlock/munlock for key buffers
//
// # Thread safety
//
// Init() is idempotent and safe for concurrent callers (sync.Once). The
// global HCRYPTPROV handle is used only as a template for creating hash
// and cipher contexts; each operation creates its own context, so there
// is no per-operation locking.
package cryptopro
