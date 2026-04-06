package gost3413

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

func skipIfNoEngine(t *testing.T) {
	t.Helper()
	if err := openssl.Init(); err != nil {
		t.Skip("gost-engine not available:", err)
	}
}

func TestMGM_SealOpen_Roundtrip(t *testing.T) {
	skipIfNoEngine(t)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	aead, err := NewMGMFromKey(key)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("Hello, Kuznechik-MGM!")
	aad := []byte("additional data")

	sealed := aead.Seal(nil, nonce, plaintext, aad)
	if len(sealed) != len(plaintext)+mgmTagSize {
		t.Fatalf("sealed length = %d, want %d", len(sealed), len(plaintext)+mgmTagSize)
	}

	opened, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Errorf("roundtrip failed:\n  got  %x\n  want %x", opened, plaintext)
	}
}

func TestMGM_TamperedCiphertext(t *testing.T) {
	skipIfNoEngine(t)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	aead, err := NewMGMFromKey(key)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("tamper test data block!")
	aad := []byte("aad")

	sealed := aead.Seal(nil, nonce, plaintext, aad)

	// Tamper with the ciphertext (not the tag)
	tampered := make([]byte, len(sealed))
	copy(tampered, sealed)
	tampered[0] ^= 0xff

	_, err = aead.Open(nil, nonce, tampered, aad)
	if err == nil {
		t.Fatal("expected Open to fail on tampered ciphertext")
	}
}

func TestMGM_TamperedAAD(t *testing.T) {
	skipIfNoEngine(t)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	aead, err := NewMGMFromKey(key)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("aad tamper test!!")
	aad := []byte("original aad")

	sealed := aead.Seal(nil, nonce, plaintext, aad)

	// Open with different AAD
	_, err = aead.Open(nil, nonce, sealed, []byte("tampered aad"))
	if err == nil {
		t.Fatal("expected Open to fail on tampered AAD")
	}
}

func TestMGM_InvalidKeySize(t *testing.T) {
	skipIfNoEngine(t)
	_, err := NewMGMFromKey(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for 16-byte key")
	}
	_, err = NewMGMFromKey(make([]byte, 0))
	if err == nil {
		t.Fatal("expected error for empty key")
	}
	_, err = NewMGMFromKey(make([]byte, 64))
	if err == nil {
		t.Fatal("expected error for 64-byte key")
	}
}

func TestMGM_EmptyPlaintext(t *testing.T) {
	skipIfNoEngine(t)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	aead, err := NewMGMFromKey(key)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	aad := []byte("only authenticate this")

	// Seal with empty plaintext — output should be just the tag.
	sealed := aead.Seal(nil, nonce, nil, aad)
	if len(sealed) != mgmTagSize {
		t.Fatalf("sealed length = %d, want %d (tag only)", len(sealed), mgmTagSize)
	}

	// Open should return empty plaintext.
	opened, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if len(opened) != 0 {
		t.Errorf("expected empty plaintext, got %x", opened)
	}
}

func TestMGM_DifferentNonces(t *testing.T) {
	skipIfNoEngine(t)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	aead, err := NewMGMFromKey(key)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("same plaintext for both nonces!!")
	aad := []byte("same aad")

	nonce1 := make([]byte, aead.NonceSize())
	nonce2 := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce1); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(nonce2); err != nil {
		t.Fatal(err)
	}

	sealed1 := aead.Seal(nil, nonce1, plaintext, aad)
	sealed2 := aead.Seal(nil, nonce2, plaintext, aad)

	if bytes.Equal(sealed1, sealed2) {
		t.Error("different nonces produced identical ciphertext+tag")
	}
}
