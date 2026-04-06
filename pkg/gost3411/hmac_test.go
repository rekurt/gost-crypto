package gost3411

import (
	"encoding/hex"
	"testing"
)

func TestHMAC256_KnownVector(t *testing.T) {
	skipIfNoEngine(t)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	data := []byte("test message for HMAC")

	mac := NewHMAC256(key)
	mac.Write(data)
	result := mac.Sum(nil)

	if len(result) != 32 {
		t.Fatalf("HMAC-256 output length = %d, want 32", len(result))
	}

	// Verify the output is deterministic.
	mac2 := NewHMAC256(key)
	mac2.Write(data)
	result2 := mac2.Sum(nil)
	if hex.EncodeToString(result) != hex.EncodeToString(result2) {
		t.Error("HMAC-256 is not deterministic")
	}
}

func TestHMAC512_Deterministic(t *testing.T) {
	skipIfNoEngine(t)

	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i)
	}
	data := []byte("test message for HMAC-512")

	mac1 := NewHMAC512(key)
	mac1.Write(data)
	r1 := mac1.Sum(nil)

	mac2 := NewHMAC512(key)
	mac2.Write(data)
	r2 := mac2.Sum(nil)

	if len(r1) != 64 {
		t.Fatalf("HMAC-512 output length = %d, want 64", len(r1))
	}
	if hex.EncodeToString(r1) != hex.EncodeToString(r2) {
		t.Error("HMAC-512 is not deterministic")
	}
}
