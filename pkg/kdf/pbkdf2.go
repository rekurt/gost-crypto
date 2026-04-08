package kdf

import (
	"crypto/hmac"
	"encoding/binary"
	"hash"

	"github.com/rekurt/gost-crypto/internal/openssl"
	"github.com/rekurt/gost-crypto/pkg/gost3411"
)

// PBKDF2_256 derives a key from a password using PBKDF2 (RFC 8018) with
// HMAC-Streebog-256 as the pseudorandom function.
//
// iterations is the cost parameter (recommended minimum: 10000).
// keyLen is the desired output key length in bytes.
func PBKDF2_256(password, salt []byte, iterations, keyLen int) []byte {
	return pbkdf2(password, salt, iterations, keyLen, gost3411.NewHMAC256, 32)
}

// PBKDF2_512 derives a key from a password using PBKDF2 (RFC 8018) with
// HMAC-Streebog-512 as the pseudorandom function.
//
// iterations is the cost parameter (recommended minimum: 10000).
// keyLen is the desired output key length in bytes.
func PBKDF2_512(password, salt []byte, iterations, keyLen int) []byte {
	return pbkdf2(password, salt, iterations, keyLen, gost3411.NewHMAC512, 64)
}

// pbkdf2 implements PBKDF2 per RFC 8018 §5.2.
func pbkdf2(password, salt []byte, iterations, keyLen int, newHMAC func([]byte) hash.Hash, hLen int) []byte {
	numBlocks := (keyLen + hLen - 1) / hLen
	dk := make([]byte, 0, numBlocks*hLen)

	for block := 1; block <= numBlocks; block++ {
		dk = append(dk, pbkdf2F(password, salt, iterations, block, newHMAC)...)
	}

	return dk[:keyLen]
}

// pbkdf2F computes F(Password, Salt, c, i) = U_1 ^ U_2 ^ ... ^ U_c
// where U_1 = PRF(Password, Salt || INT(i)).
func pbkdf2F(password, salt []byte, iterations, block int, newHMAC func([]byte) hash.Hash) []byte {
	// U_1 = PRF(Password, Salt || INT_32_BE(i))
	mac := hmac.New(func() hash.Hash { return newHMAC(password) }, password)

	mac.Write(salt)
	var blockBuf [4]byte
	binary.BigEndian.PutUint32(blockBuf[:], uint32(block))
	mac.Write(blockBuf[:])

	u := mac.Sum(nil)
	result := make([]byte, len(u))
	copy(result, u)

	// U_2 .. U_c
	for i := 2; i <= iterations; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(u[:0])

		for j := range result {
			result[j] ^= u[j]
		}
	}

	// Wipe intermediate U value — it is derived key material.
	openssl.CleanseBytes(u)

	return result
}
