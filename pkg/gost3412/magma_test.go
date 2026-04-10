package gost3412

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestMagma_GOSTR3412_AppendixA verifies the normative test vector
// from GOST R 34.12-2015, Appendix A.2, also republished in
// RFC 8891 Appendix A (Test Vectors).
//
// Key:        ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
// Plaintext:  fedcba9876543210
// Ciphertext: 4ee901e5c2d8ca3d
func TestMagma_GOSTR3412_AppendixA(t *testing.T) {
	skipIfNoEngine(t)

	key := mustMagmaHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	plaintext := mustMagmaHex("fedcba9876543210")
	expectedCT := mustMagmaHex("4ee901e5c2d8ca3d")

	b, err := NewMagma(key)
	if err != nil {
		t.Fatal(err)
	}

	ct := make([]byte, MagmaBlockSize)
	b.Encrypt(ct, plaintext)

	if !bytes.Equal(ct, expectedCT) {
		t.Errorf("Magma encrypt mismatch (GOST R 34.12-2015 A.2):\n  got  %x\n  want %x", ct, expectedCT)
	}

	pt := make([]byte, MagmaBlockSize)
	b.Decrypt(pt, ct)

	if !bytes.Equal(pt, plaintext) {
		t.Errorf("Magma decrypt mismatch:\n  got  %x\n  want %x", pt, plaintext)
	}
}

// TestMagma_RFC8891 re-runs the RFC 8891 Appendix A encryption KAT
// and exercises sequential encrypt/decrypt on the same cipher handle
// to verify ECB statelessness between calls.
func TestMagma_RFC8891(t *testing.T) {
	skipIfNoEngine(t)

	// Normative vector: RFC 8891 Appendix A.
	key := mustMagmaHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	plaintext := mustMagmaHex("fedcba9876543210")
	expectedCT := mustMagmaHex("4ee901e5c2d8ca3d")

	b, err := NewMagma(key)
	if err != nil {
		t.Fatal(err)
	}

	ct1 := make([]byte, MagmaBlockSize)
	ct2 := make([]byte, MagmaBlockSize)
	b.Encrypt(ct1, plaintext)
	b.Encrypt(ct2, plaintext)

	if !bytes.Equal(ct1, expectedCT) {
		t.Errorf("Magma RFC 8891 first encrypt mismatch:\n  got  %x\n  want %x", ct1, expectedCT)
	}
	if !bytes.Equal(ct2, expectedCT) {
		t.Errorf("Magma RFC 8891 second encrypt mismatch:\n  got  %x\n  want %x", ct2, expectedCT)
	}

	pt1 := make([]byte, MagmaBlockSize)
	pt2 := make([]byte, MagmaBlockSize)
	b.Decrypt(pt1, expectedCT)
	b.Decrypt(pt2, expectedCT)

	if !bytes.Equal(pt1, plaintext) {
		t.Errorf("Magma RFC 8891 first decrypt mismatch:\n  got  %x\n  want %x", pt1, plaintext)
	}
	if !bytes.Equal(pt2, plaintext) {
		t.Errorf("Magma RFC 8891 second decrypt mismatch:\n  got  %x\n  want %x", pt2, plaintext)
	}
}

func mustMagmaHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("bad hex: " + err.Error())
	}
	return b
}

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
