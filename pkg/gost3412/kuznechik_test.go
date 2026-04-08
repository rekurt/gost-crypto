package gost3412

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

// mustHex decodes a hex string or panics.
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("bad hex: " + err.Error())
	}
	return b
}

// TestKuznechik_GOSTR3412_AppendixA verifies the normative test vector
// from GOST R 34.12-2015, Appendix A.1.
// Key:        8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
// Plaintext:  1122334455667700ffeeddccbbaa9988
// Ciphertext: 7f679d90bebc24305a468d42b9d4edcd
func TestKuznechik_GOSTR3412_AppendixA(t *testing.T) {
	skipIfNoEngine(t)

	key := mustHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	plaintext := mustHex("1122334455667700ffeeddccbbaa9988")
	expectedCT := mustHex("7f679d90bebc24305a468d42b9d4edcd")

	b, err := NewKuznechik(key)
	if err != nil {
		t.Fatal(err)
	}

	ct := make([]byte, KuznechikBlockSize)
	b.Encrypt(ct, plaintext)

	if !bytes.Equal(ct, expectedCT) {
		t.Errorf("Kuznechik encrypt mismatch (GOST R 34.12-2015 A.1):\n  got  %x\n  want %x", ct, expectedCT)
	}

	pt := make([]byte, KuznechikBlockSize)
	b.Decrypt(pt, ct)

	if !bytes.Equal(pt, plaintext) {
		t.Errorf("Kuznechik decrypt mismatch:\n  got  %x\n  want %x", pt, plaintext)
	}
}

func skipIfNoEngine(t *testing.T) {
	t.Helper()
	if err := openssl.Init(); err != nil {
		t.Skip("gost-engine not available:", err)
	}
}

func TestKuznechik_BlockSize(t *testing.T) {
	skipIfNoEngine(t)
	key := make([]byte, KuznechikKeySize)
	b, err := NewKuznechik(key)
	if err != nil {
		t.Fatal(err)
	}
	if b.BlockSize() != 16 {
		t.Errorf("BlockSize() = %d, want 16", b.BlockSize())
	}
}

func TestKuznechik_InvalidKeySize(t *testing.T) {
	skipIfNoEngine(t)
	_, err := NewKuznechik(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for 16-byte key")
	}
	_, err = NewKuznechik(make([]byte, 0))
	if err == nil {
		t.Fatal("expected error for empty key")
	}
	_, err = NewKuznechik(make([]byte, 64))
	if err == nil {
		t.Fatal("expected error for 64-byte key")
	}
}

func TestKuznechik_EncryptDecrypt_Roundtrip(t *testing.T) {
	skipIfNoEngine(t)
	key := []byte{
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	}
	plaintext := []byte{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
	}

	b, err := NewKuznechik(key)
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt
	ct := make([]byte, KuznechikBlockSize)
	b.Encrypt(ct, plaintext)

	// Ciphertext must differ from plaintext
	if bytes.Equal(ct, plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}

	// Decrypt
	recovered := make([]byte, KuznechikBlockSize)
	b.Decrypt(recovered, ct)

	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("roundtrip failed:\n  got  %x\n  want %x", recovered, plaintext)
	}
}

func TestKuznechik_DifferentKeys(t *testing.T) {
	skipIfNoEngine(t)
	key1 := make([]byte, KuznechikKeySize)
	key2 := make([]byte, KuznechikKeySize)
	key2[0] = 0xff

	plaintext := make([]byte, KuznechikBlockSize)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	b1, err := NewKuznechik(key1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := NewKuznechik(key2)
	if err != nil {
		t.Fatal(err)
	}

	ct1 := make([]byte, KuznechikBlockSize)
	ct2 := make([]byte, KuznechikBlockSize)
	b1.Encrypt(ct1, plaintext)
	b2.Encrypt(ct2, plaintext)

	if bytes.Equal(ct1, ct2) {
		t.Error("different keys produced identical ciphertext")
	}
}
