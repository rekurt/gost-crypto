// Package gost3410 implements GOST R 34.10-2012 elliptic curve digital
// signatures using CryptoPro CSP (CAPILite).
//
// This package provides low-level signing and verification with all 8
// standardized TC26 elliptic curve parameter sets (256-bit and 512-bit).
// For most use cases, prefer the high-level [github.com/rekurt/gost-crypto.Sign]
// and [github.com/rekurt/gost-crypto.Verify] functions which handle hashing
// automatically.
//
// # Supported Curves
//
// 256-bit: [CurveTC26_256_A], [CurveTC26_256_B] (CryptoPro-A),
// [CurveTC26_256_C] (CryptoPro-B), [CurveTC26_256_D] (CryptoPro-C).
//
// 512-bit: [CurveTC26_512_A], [CurveTC26_512_B], [CurveTC26_512_C],
// [CurveTC26_512_D] (test curve).
//
// # Key Management
//
// Use [GenerateKey] to create a new random key pair, or [LoadPrivKey] to
// load an existing private key from raw bytes. Private keys must be
// explicitly zeroized with Zeroize() after use.
//
// # Signature Format
//
// Signatures are encoded as GOST OCTET STRING: r || s, both big-endian.
// 64 bytes for 256-bit curves, 128 bytes for 512-bit curves.
//
// # VKO Key Agreement
//
// The [VKO] function implements GOST R 34.10-2012 ECDH-based key agreement
// as defined in RFC 7836. Both parties derive the same shared secret.
//
// # Standards
//
// GOST R 34.10-2012, RFC 7091 (signatures), RFC 7836 (VKO key agreement).
package gost3410
