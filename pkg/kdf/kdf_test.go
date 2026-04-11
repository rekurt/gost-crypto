package kdf

import (
	"bytes"
	"testing"

	"github.com/rekurt/gost-crypto/internal/cryptopro"
)

func skipIfNoEngine(t *testing.T) {
	t.Helper()
	if err := cryptopro.Init(); err != nil {
		t.Skip("CryptoPro CSP not available:", err)
	}
}

func TestKDF_GOSTR3411_256_Deterministic(t *testing.T) {
	skipIfNoEngine(t)
	key := bytes.Repeat([]byte{0xAA}, 32)
	label := []byte("test-label")
	seed := []byte("test-seed")

	r1 := KDF_GOSTR3411_256(key, label, seed)
	r2 := KDF_GOSTR3411_256(key, label, seed)

	if len(r1) != 32 {
		t.Fatalf("output length = %d, want 32", len(r1))
	}
	if !bytes.Equal(r1, r2) {
		t.Error("KDF is not deterministic")
	}
}

func TestKDF_GOSTR3411_512_Deterministic(t *testing.T) {
	skipIfNoEngine(t)
	key := bytes.Repeat([]byte{0xBB}, 64)
	label := []byte("label-512")
	seed := []byte("seed-512")

	r1 := KDF_GOSTR3411_512(key, label, seed)
	r2 := KDF_GOSTR3411_512(key, label, seed)

	if len(r1) != 64 {
		t.Fatalf("output length = %d, want 64", len(r1))
	}
	if !bytes.Equal(r1, r2) {
		t.Error("KDF is not deterministic")
	}
}

func TestHKDF_DifferentLengths(t *testing.T) {
	skipIfNoEngine(t)
	salt := []byte("salt")
	ikm := []byte("input key material")
	info := []byte("context info")

	r32 := HKDF256(salt, ikm, info, 32)
	r64 := HKDF256(salt, ikm, info, 64)

	if len(r32) != 32 {
		t.Fatalf("HKDF(32) length = %d", len(r32))
	}
	if len(r64) != 64 {
		t.Fatalf("HKDF(64) length = %d", len(r64))
	}
	// First 32 bytes of r64 must equal r32 (HKDF expand property)
	if !bytes.Equal(r32, r64[:32]) {
		t.Error("HKDF(64)[:32] != HKDF(32) — violates HKDF expand property")
	}
}

func TestKDF_vs_HKDF_Different(t *testing.T) {
	skipIfNoEngine(t)
	key := bytes.Repeat([]byte{0xCC}, 32)
	label := []byte("label")
	seed := []byte("seed")

	kdfOut := KDF_GOSTR3411_256(key, label, seed)
	hkdfOut := HKDF256(key, seed, label, 32)

	if bytes.Equal(kdfOut, hkdfOut) {
		t.Error("KDF_GOSTR3411 and HKDF should produce different outputs (different algorithms)")
	}
}

func TestHKDF_LengthZero(t *testing.T) {
	skipIfNoEngine(t)
	result := HKDF256([]byte("salt"), []byte("ikm"), []byte("info"), 0)
	if result != nil {
		t.Errorf("HKDF(length=0) should return nil, got %v", result)
	}
}

func TestHKDF_OverflowPanics(t *testing.T) {
	skipIfNoEngine(t)
	defer func() {
		if r := recover(); r == nil {
			t.Error("HKDF with length > 255*HashLen should panic")
		}
	}()
	// 255*32 = 8160 is max for HKDF256; 8161 should panic
	HKDF256([]byte("salt"), []byte("ikm"), []byte("info"), 255*32+1)
}
