package gost3411

import (
	"crypto"
	"testing"
)

func TestHashRegistration(t *testing.T) {
	skipIfNoEngine(t)

	// Verify Streebog-256 is registered and produces correct size.
	if !HashStreebog256.Available() {
		t.Fatal("HashStreebog256 not registered with crypto.RegisterHash")
	}
	h256 := HashStreebog256.New()
	if h256.Size() != 32 {
		t.Errorf("HashStreebog256 size = %d, want 32", h256.Size())
	}

	// Verify Streebog-512 is registered and produces correct size.
	if !HashStreebog512.Available() {
		t.Fatal("HashStreebog512 not registered with crypto.RegisterHash")
	}
	h512 := HashStreebog512.New()
	if h512.Size() != 64 {
		t.Errorf("HashStreebog512 size = %d, want 64", h512.Size())
	}
}

func TestHashConstants_AreUnique(t *testing.T) {
	if HashStreebog256 == HashStreebog512 {
		t.Error("HashStreebog256 and HashStreebog512 have the same value")
	}
}

func TestHashConstants_DoNotConflict(t *testing.T) {
	// Verify our hash constants don't conflict with standard Go hashes.
	standardHashes := []crypto.Hash{
		crypto.MD5, crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512,
	}
	for _, h := range standardHashes {
		if HashStreebog256 == h || HashStreebog512 == h {
			t.Errorf("GOST hash constant %d conflicts with standard hash %d", HashStreebog256, h)
		}
	}
}
