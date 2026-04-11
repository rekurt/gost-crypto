// Package kdf implements key derivation functions for GOST cryptography.
package kdf

import (
	"encoding/binary"
	"hash"

	"github.com/rekurt/gost-crypto/internal/cryptopro"
	"github.com/rekurt/gost-crypto/pkg/gost3411"
)

// KDF_GOSTR3411_256 implements KDF from R 50.1.113-2016 using Streebog-256.
// Output is always 32 bytes.
// Formula: HMAC_Streebog256(key, 0x01 || label || 0x00 || seed || L)
// where L = output length in bits (big-endian 2 bytes).
func KDF_GOSTR3411_256(key, label, seed []byte) []byte {
	return kdfGOSTR3411(key, label, seed, 256, gost3411.NewHMAC256)
}

// KDF_GOSTR3411_512 implements KDF from R 50.1.113-2016 using Streebog-512.
// Output is always 64 bytes.
func KDF_GOSTR3411_512(key, label, seed []byte) []byte {
	return kdfGOSTR3411(key, label, seed, 512, gost3411.NewHMAC512)
}

func kdfGOSTR3411(key, label, seed []byte, bits int, newHMAC func([]byte) hash.Hash) []byte {
	// Build message: 0x01 || label || 0x00 || seed || L_be16
	msg := make([]byte, 0, 1+len(label)+1+len(seed)+2)
	msg = append(msg, 0x01)
	msg = append(msg, label...)
	msg = append(msg, 0x00)
	msg = append(msg, seed...)
	var lBuf [2]byte
	binary.BigEndian.PutUint16(lBuf[:], uint16(bits))
	msg = append(msg, lBuf[:]...)

	mac := newHMAC(key)
	mac.Write(msg)
	result := mac.Sum(nil)

	// Wipe the intermediate message buffer.
	cryptopro.CleanseBytes(msg)

	return result
}
