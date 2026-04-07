package gost3411

import (
	"crypto/hmac"
	"hash"
)

// NewHMAC256 returns a hash.Hash computing HMAC-Streebog-256.
func NewHMAC256(key []byte) hash.Hash {
	return hmac.New(New256, key)
}

// NewHMAC512 returns a hash.Hash computing HMAC-Streebog-512.
func NewHMAC512(key []byte) hash.Hash {
	return hmac.New(New512, key)
}
