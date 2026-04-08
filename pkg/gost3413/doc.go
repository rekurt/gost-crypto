// Package gost3413 implements GOST R 34.13-2015 block cipher modes of operation
// backed by OpenSSL gost-engine.
//
// # Supported Modes
//
//   - [NewMGMFromKey] — MGM (Multilinear Galois Mode) authenticated encryption (AEAD)
//   - [NewMagmaMGMFromKey] — Magma-MGM authenticated encryption (AEAD)
//   - [NewKuznechikCTR], [NewMagmaCTR] — CTR (counter) mode
//   - [NewKuznechikCBC], [NewMagmaCBC] — CBC (cipher block chaining) mode
//   - [NewKuznechikCFB], [NewMagmaCFB] — CFB (cipher feedback) mode
//   - [NewKuznechikOFB], [NewMagmaOFB] — OFB (output feedback) mode
//   - [NewKuznechikCMAC], [NewMagmaCMAC] — CMAC (OMAC1) authentication
//   - [EncryptReader], [DecryptReader] — stateful io.Reader streaming wrappers
//
// All modes support both Kuznechik (128-bit block) and Magma (64-bit block)
// as the underlying block cipher.
//
// # Usage
//
// Create an MGM cipher with [NewMGMFromKey] using a 32-byte key:
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
// GOST R 34.13-2015 (modes of operation), GOST R 34.12-2015 (Kuznechik and Magma ciphers).
package gost3413
