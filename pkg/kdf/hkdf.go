package kdf

import (
	"hash"

	"github.com/rekurt/gost-crypto/internal/openssl"
	"github.com/rekurt/gost-crypto/pkg/gost3411"
)

// HKDF256 performs HKDF (RFC 5869) using HMAC-Streebog-256.
// Returns `length` bytes of derived key material.
// Panics if length > 255*32 (RFC 5869 §2.3 limit).
func HKDF256(salt, ikm, info []byte, length int) []byte {
	return hkdf(gost3411.NewHMAC256, salt, ikm, info, length, 32)
}

// HKDF512 performs HKDF (RFC 5869) using HMAC-Streebog-512.
// Returns `length` bytes of derived key material.
// Panics if length > 255*64 (RFC 5869 §2.3 limit).
func HKDF512(salt, ikm, info []byte, length int) []byte {
	return hkdf(gost3411.NewHMAC512, salt, ikm, info, length, 64)
}

// HKDFExtract256 performs HKDF-Extract with Streebog-256.
func HKDFExtract256(salt, ikm []byte) []byte {
	mac := gost3411.NewHMAC256(salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// HKDFExtract512 performs HKDF-Extract with Streebog-512.
func HKDFExtract512(salt, ikm []byte) []byte {
	mac := gost3411.NewHMAC512(salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// HKDFExpand256 performs HKDF-Expand with Streebog-256.
func HKDFExpand256(prk, info []byte, length int) []byte {
	return hkdfExpand(gost3411.NewHMAC256, prk, info, length, 32)
}

// HKDFExpand512 performs HKDF-Expand with Streebog-512.
func HKDFExpand512(prk, info []byte, length int) []byte {
	return hkdfExpand(gost3411.NewHMAC512, prk, info, length, 64)
}

func hkdf(newHMAC func([]byte) hash.Hash, salt, ikm, info []byte, length, hashSize int) []byte {
	// Extract
	if len(salt) == 0 {
		salt = make([]byte, hashSize)
	}
	mac := newHMAC(salt)
	mac.Write(ikm)
	prk := mac.Sum(nil)

	// Expand
	result := hkdfExpand(newHMAC, prk, info, length, hashSize)

	// Securely wipe the PRK — it is sensitive key material.
	openssl.CleanseBytes(prk)

	return result
}

func hkdfExpand(newHMAC func([]byte) hash.Hash, prk, info []byte, length, hashSize int) []byte {
	// RFC 5869 §2.3: L ≤ 255*HashLen
	maxLen := 255 * hashSize
	if length > maxLen {
		panic("kdf: HKDF output length exceeds 255*HashLen (RFC 5869 §2.3)")
	}
	if length <= 0 {
		return nil
	}
	n := (length + hashSize - 1) / hashSize
	result := make([]byte, 0, n*hashSize)
	var prev []byte

	for i := 1; i <= n; i++ {
		mac := newHMAC(prk)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{byte(i)})
		newPrev := mac.Sum(nil)
		// Wipe previous intermediate output — it is derived key material.
		if len(prev) > 0 {
			openssl.CleanseBytes(prev)
		}
		prev = newPrev
		result = append(result, prev...)
	}
	// Wipe the last prev (already copied into result).
	if len(prev) > 0 {
		openssl.CleanseBytes(prev)
	}

	return result[:length]
}
