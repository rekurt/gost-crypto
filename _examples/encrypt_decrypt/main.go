package main

import (
	"crypto/rand"
	"fmt"

	"github.com/rekurt/gost-crypto/pkg/gost3412"
	"github.com/rekurt/gost-crypto/pkg/gost3413"
)

func main() {
	fmt.Println("=== Kuznechik + MGM AEAD ===\n")

	// Generate a random 256-bit key
	key := make([]byte, gost3412.KuznechikKeySize)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}

	// Create AEAD cipher (Kuznechik-MGM)
	aead, err := gost3413.NewMGMFromKey(key)
	if err != nil {
		panic(err)
	}

	// Generate a unique nonce for each message
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	plaintext := []byte("Confidential GOST-encrypted message")
	aad := []byte("additional authenticated data")

	// Encrypt and authenticate
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	fmt.Printf("Plaintext:  %s\n", plaintext)
	fmt.Printf("Ciphertext: %d bytes (includes %d-byte auth tag)\n",
		len(ciphertext), aead.Overhead())

	// Decrypt and verify
	decrypted, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Decrypted:  %s\n\n", decrypted)

	// Tampered ciphertext is rejected
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[0] ^= 0xFF

	_, err = aead.Open(nil, nonce, tampered, aad)
	fmt.Printf("Tampered ciphertext rejected: %v\n", err != nil)
}
