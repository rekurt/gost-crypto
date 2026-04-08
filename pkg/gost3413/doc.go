// Package gost3413 implements GOST R 34.13-2015 MGM (Multilinear Galois Mode)
// authenticated encryption backed by OpenSSL gost-engine.
//
// MGM is the Russian national standard for authenticated encryption with
// associated data (AEAD), operating on top of the Kuznechik block cipher.
// This package implements the standard [crypto/cipher.AEAD] interface.
//
// # Usage
//
// Create an MGM cipher with [NewMGMFromKey] using a 32-byte Kuznechik key:
//
//	aead, err := gost3413.NewMGMFromKey(key)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	nonce := make([]byte, aead.NonceSize())
//	// fill nonce with random bytes...
//
//	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
//
// # Standards
//
// GOST R 34.13-2015 (MGM mode), GOST R 34.12-2015 (Kuznechik cipher).
package gost3413
