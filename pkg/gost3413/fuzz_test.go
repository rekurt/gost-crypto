package gost3413

import (
	"testing"

	"github.com/rekurt/gost-crypto/internal/cryptopro"
)

// FuzzMGMOpen exercises the MGM Open function with arbitrary ciphertexts
// to verify it never panics on invalid or corrupted input.
func FuzzMGMOpen(f *testing.F) {
	if err := cryptopro.Init(); err != nil {
		f.Skip("CryptoPro CSP not available:", err)
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	aead, err := NewMGMFromKey(key)
	if err != nil {
		f.Fatalf("NewMGMFromKey: %v", err)
	}

	nonce := make([]byte, aead.NonceSize())
	validCt := aead.Seal(nil, nonce, []byte("test plaintext!!"), []byte("aad"))

	f.Add(validCt)
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 16))   // exactly tag size
	f.Add(make([]byte, 1024)) // large random input

	f.Fuzz(func(t *testing.T, ct []byte) {
		// Open must not panic on any input, only return errors.
		_, _ = aead.Open(nil, nonce, ct, []byte("aad"))
	})
}
