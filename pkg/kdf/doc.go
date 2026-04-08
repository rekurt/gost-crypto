// Package kdf provides key derivation functions based on GOST Streebog,
// including HKDF (RFC 5869) and KDF_GOSTR3411 (R 50.1.113-2016).
//
// # HKDF
//
// [HKDF256] and [HKDF512] implement the standard HKDF construction
// (RFC 5869) using HMAC-Streebog-256 and HMAC-Streebog-512 respectively.
// Extract and Expand variants are also available for advanced use.
//
// # KDF_GOSTR3411
//
// [KDF_GOSTR3411_256] and [KDF_GOSTR3411_512] implement the Russian
// national standard KDF as defined in R 50.1.113-2016, using
// HMAC-Streebog as the underlying PRF.
//
// # Standards
//
// RFC 5869 (HKDF), R 50.1.113-2016 (KDF_GOSTR3411).
package kdf
