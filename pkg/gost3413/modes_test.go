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

// --- CTR mode tests ---

func TestKuznechikCTR_Roundtrip(t *testing.T) {
	skipIfNoEngine(t)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	ctr, err := NewKuznechikCTR(key)
	if err != nil {
		t.Fatal(err)
	}
	defer ctr.Zeroize()

	// Kuznechik-CTR typically uses an 8-byte IV in gost-engine.
	iv := make([]byte, 8)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("GOST R 34.13-2015 CTR mode test with Kuznechik cipher")

	ct, err := ctr.Encrypt(iv, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if bytes.Equal(ct, plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}

	recovered, err := ctr.Decrypt(iv, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("roundtrip failed:\n  got  %x\n  want %x", recovered, plaintext)
	}
}

func TestKuznechikCTR_InvalidKeySize(t *testing.T) {
	skipIfNoEngine(t)
	_, err := NewKuznechikCTR(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}

func TestMagmaCTR_Roundtrip(t *testing.T) {
	skipIfNoEngine(t)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	ctr, err := NewMagmaCTR(key)
	if err != nil {
		t.Fatal(err)
	}
	defer ctr.Zeroize()

	// Magma-CTR typically uses a 4-byte IV in gost-engine.
	iv := make([]byte, 4)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("Magma CTR mode test")

	ct, err := ctr.Encrypt(iv, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	recovered, err := ctr.Decrypt(iv, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("roundtrip failed:\n  got  %x\n  want %x", recovered, plaintext)
	}
}

// --- CBC mode tests ---

func TestKuznechikCBC_Roundtrip(t *testing.T) {
	skipIfNoEngine(t)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	cbc, err := NewKuznechikCBC(key)
	if err != nil {
		t.Fatal(err)
	}
	defer cbc.Zeroize()

	// Kuznechik CBC uses 16-byte IV.
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}

	// Plaintext must be a multiple of 16 bytes.
	plaintext := make([]byte, 48)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	ct, err := cbc.Encrypt(iv, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if bytes.Equal(ct, plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}

	recovered, err := cbc.Decrypt(iv, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("roundtrip failed:\n  got  %x\n  want %x", recovered, plaintext)
	}
}

func TestKuznechikCBC_NonBlockSize(t *testing.T) {
	skipIfNoEngine(t)

	key := make([]byte, 32)
	cbc, err := NewKuznechikCBC(key)
	if err != nil {
		t.Fatal(err)
	}
	defer cbc.Zeroize()

	iv := make([]byte, 16)
	_, err = cbc.Encrypt(iv, make([]byte, 13)) // not a multiple of 16
	if err == nil {
		t.Fatal("expected error for non-block-size plaintext")
	}
}

func TestMagmaCBC_Roundtrip(t *testing.T) {
	skipIfNoEngine(t)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	cbc, err := NewMagmaCBC(key)
	if err != nil {
		t.Fatal(err)
	}
	defer cbc.Zeroize()

	// Magma CBC uses 8-byte IV.
	iv := make([]byte, 8)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}

	// Plaintext must be a multiple of 8 bytes.
	plaintext := make([]byte, 24)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	ct, err := cbc.Encrypt(iv, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	recovered, err := cbc.Decrypt(iv, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("roundtrip failed:\n  got  %x\n  want %x", recovered, plaintext)
	}
}

// --- CFB mode tests ---

func TestKuznechikCFB_Roundtrip(t *testing.T) {
	skipIfNoEngine(t)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	cfb, err := NewKuznechikCFB(key)
	if err != nil {
		t.Fatal(err)
	}
	defer cfb.Zeroize()

	// Kuznechik CFB uses 16-byte IV.
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("CFB mode does not require block-aligned input")

	ct, err := cfb.Encrypt(iv, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if bytes.Equal(ct, plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}

	recovered, err := cfb.Decrypt(iv, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("roundtrip failed:\n  got  %x\n  want %x", recovered, plaintext)
	}
}

// --- OFB mode tests ---

func TestKuznechikOFB_Roundtrip(t *testing.T) {
	skipIfNoEngine(t)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	ofb, err := NewKuznechikOFB(key)
	if err != nil {
		t.Fatal(err)
	}
	defer ofb.Zeroize()

	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("OFB mode does not require block-aligned input!")

	ct, err := ofb.Encrypt(iv, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if bytes.Equal(ct, plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}

	recovered, err := ofb.Decrypt(iv, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("roundtrip failed:\n  got  %x\n  want %x", recovered, plaintext)
	}
}

func TestMagmaOFB_Roundtrip(t *testing.T) {
	skipIfNoEngine(t)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	ofb, err := NewMagmaOFB(key)
	if err != nil {
		t.Skip("magma-ofb not available:", err)
	}
	defer ofb.Zeroize()

	iv := make([]byte, 8)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("Magma OFB test")

	ct, err := ofb.Encrypt(iv, plaintext)
	if err != nil {
		t.Skip("magma-ofb not supported by gost-engine:", err)
	}

	recovered, err := ofb.Decrypt(iv, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("roundtrip failed:\n  got  %x\n  want %x", recovered, plaintext)
	}
}

func TestMagmaCFB_Roundtrip(t *testing.T) {
	skipIfNoEngine(t)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	cfb, err := NewMagmaCFB(key)
	if err != nil {
		t.Skip("magma-cfb not available:", err)
	}
	defer cfb.Zeroize()

	// Magma CFB uses 8-byte IV.
	iv := make([]byte, 8)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("Magma CFB test data")

	ct, err := cfb.Encrypt(iv, plaintext)
	if err != nil {
		t.Skip("magma-cfb not supported by gost-engine:", err)
	}

	recovered, err := cfb.Decrypt(iv, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("roundtrip failed:\n  got  %x\n  want %x", recovered, plaintext)
	}
}
