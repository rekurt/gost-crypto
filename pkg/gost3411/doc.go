// Package gost3411 implements the GOST R 34.11-2012 Streebog cryptographic
// hash function backed by CryptoPro CSP (CAPILite).
//
// Streebog is the Russian national standard hash function, providing
// 256-bit and 512-bit digest outputs. This package implements the
// standard [hash.Hash] interface for streaming use and provides
// convenience functions for one-shot hashing.
//
// # Hash Functions
//
//   - [New256] / [Sum256] for Streebog-256 (256-bit digest)
//   - [New512] / [Sum512] for Streebog-512 (512-bit digest)
//
// # HMAC
//
// HMAC-Streebog is available via [NewHMAC256] and [NewHMAC512],
// implementing the standard [hash.Hash] interface.
//
// # Standards
//
// GOST R 34.11-2012, RFC 6986 (Streebog hash function).
package gost3411
