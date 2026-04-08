package gost3412

import (
	"bytes"
	"testing"
)

func TestMagma_BlockSize(t *testing.T) {
	skipIfNoEngine(t)
	key := make([]byte, MagmaKeySize)
	b, err := NewMagma(key)
	if err != nil {
		t.Fatal(err)
	}
	if b.BlockSize() != 8 {
		t.Errorf("BlockSize() = %d, want 8", b.BlockSize())
	}
}

func TestMagma_InvalidKeySize(t *testing.T) {
	skipIfNoEngine(t)
	_, err := NewMagma(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for 16-byte key")
	}
	_, err = NewMagma(make([]byte, 0))
	if err == nil {
		t.Fatal("expected error for empty key")
	}
	_, err = NewMagma(make([]byte, 64))
	if err == nil {
		t.Fatal("expected error for 64-byte key")
	}
}

func TestMagma_EncryptDecrypt_Roundtrip(t *testing.T) {
	skipIfNoEngine(t)
	key := []byte{
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
		0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
	}
	plaintext := []byte{
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	}

	b, err := NewMagma(key)
	if err != nil {
		t.Fatal(err)
	}

	ct := make([]byte, MagmaBlockSize)
	b.Encrypt(ct, plaintext)

	if bytes.Equal(ct, plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}

	recovered := make([]byte, MagmaBlockSize)
	b.Decrypt(recovered, ct)

	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("roundtrip failed:\n  got  %x\n  want %x", recovered, plaintext)
	}
}

func TestMagma_DifferentKeys(t *testing.T) {
	skipIfNoEngine(t)
	key1 := make([]byte, MagmaKeySize)
	key2 := make([]byte, MagmaKeySize)
	key2[0] = 0xff

	plaintext := make([]byte, MagmaBlockSize)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	b1, err := NewMagma(key1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := NewMagma(key2)
	if err != nil {
		t.Fatal(err)
	}

	ct1 := make([]byte, MagmaBlockSize)
	ct2 := make([]byte, MagmaBlockSize)
	b1.Encrypt(ct1, plaintext)
	b2.Encrypt(ct2, plaintext)

	if bytes.Equal(ct1, ct2) {
		t.Error("different keys produced identical ciphertext")
	}
}
