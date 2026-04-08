package gost3413

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestMagmaMGM_SealOpen_Roundtrip(t *testing.T) {
	skipIfNoEngine(t)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	aead, err := NewMagmaMGMFromKey(key)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("Hello, Magma-MGM AEAD!")
	aad := []byte("additional data")

	sealed := aead.Seal(nil, nonce, plaintext, aad)
	if len(sealed) != len(plaintext)+magmaMGMTagSize {
		t.Fatalf("sealed length = %d, want %d", len(sealed), len(plaintext)+magmaMGMTagSize)
	}

	opened, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Errorf("roundtrip failed:\n  got  %x\n  want %x", opened, plaintext)
	}
}

func TestMagmaMGM_TamperedCiphertext(t *testing.T) {
	skipIfNoEngine(t)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	aead, err := NewMagmaMGMFromKey(key)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	sealed := aead.Seal(nil, nonce, []byte("tamper test!!!!!"), []byte("aad"))

	tampered := make([]byte, len(sealed))
	copy(tampered, sealed)
	tampered[0] ^= 0xff

	_, err = aead.Open(nil, nonce, tampered, []byte("aad"))
	if err == nil {
		t.Fatal("expected Open to fail on tampered ciphertext")
	}
}

func TestMagmaMGM_TamperedAAD(t *testing.T) {
	skipIfNoEngine(t)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	aead, err := NewMagmaMGMFromKey(key)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	sealed := aead.Seal(nil, nonce, []byte("aad tamper test!"), []byte("original"))

	_, err = aead.Open(nil, nonce, sealed, []byte("tampered"))
	if err == nil {
		t.Fatal("expected Open to fail on tampered AAD")
	}
}

func TestMagmaMGM_InvalidKeySize(t *testing.T) {
	skipIfNoEngine(t)
	_, err := NewMagmaMGMFromKey(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}

func TestMagmaMGM_EmptyPlaintext(t *testing.T) {
	skipIfNoEngine(t)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	aead, err := NewMagmaMGMFromKey(key)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	sealed := aead.Seal(nil, nonce, nil, []byte("auth only"))
	if len(sealed) != magmaMGMTagSize {
		t.Fatalf("sealed length = %d, want %d (tag only)", len(sealed), magmaMGMTagSize)
	}

	opened, err := aead.Open(nil, nonce, sealed, []byte("auth only"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if len(opened) != 0 {
		t.Errorf("expected empty plaintext, got %x", opened)
	}
}
