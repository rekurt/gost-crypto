// Package gost3412 implements the GOST R 34.12-2015 Kuznechik block cipher
// backed by OpenSSL gost-engine.
//
// Kuznechik is the Russian national standard block cipher with a 128-bit
// block size and 256-bit key. This package implements the standard
// [crypto/cipher.Block] interface, making it compatible with Go's
// cipher mode wrappers (CBC, CTR, etc.).
//
// For authenticated encryption, see [github.com/rekurt/gost-crypto/pkg/gost3413]
// which provides MGM mode ([crypto/cipher.AEAD]) on top of Kuznechik.
//
// # Standards
//
// GOST R 34.12-2015 (Kuznechik block cipher).
package gost3412
