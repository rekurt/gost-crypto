package kdf

import (
	"bytes"
	"testing"
)

func TestPBKDF2_256_Deterministic(t *testing.T) {
	skipIfNoEngine(t)

	password := []byte("password")
	salt := []byte("salt")

	dk1 := PBKDF2_256(password, salt, 1000, 32)
	dk2 := PBKDF2_256(password, salt, 1000, 32)

	if len(dk1) != 32 {
		t.Fatalf("output length = %d, want 32", len(dk1))
	}
	if !bytes.Equal(dk1, dk2) {
		t.Error("PBKDF2 is not deterministic")
	}
}

func TestPBKDF2_512_Deterministic(t *testing.T) {
	skipIfNoEngine(t)

	password := []byte("password")
	salt := []byte("salt")

	dk1 := PBKDF2_512(password, salt, 1000, 64)
	dk2 := PBKDF2_512(password, salt, 1000, 64)

	if len(dk1) != 64 {
		t.Fatalf("output length = %d, want 64", len(dk1))
	}
	if !bytes.Equal(dk1, dk2) {
		t.Error("PBKDF2 is not deterministic")
	}
}

func TestPBKDF2_DifferentPasswords(t *testing.T) {
	skipIfNoEngine(t)

	salt := []byte("salt")
	dk1 := PBKDF2_256([]byte("password1"), salt, 1000, 32)
	dk2 := PBKDF2_256([]byte("password2"), salt, 1000, 32)

	if bytes.Equal(dk1, dk2) {
		t.Error("different passwords produced identical output")
	}
}

func TestPBKDF2_DifferentSalts(t *testing.T) {
	skipIfNoEngine(t)

	password := []byte("password")
	dk1 := PBKDF2_256(password, []byte("salt1"), 1000, 32)
	dk2 := PBKDF2_256(password, []byte("salt2"), 1000, 32)

	if bytes.Equal(dk1, dk2) {
		t.Error("different salts produced identical output")
	}
}

func TestPBKDF2_DifferentIterations(t *testing.T) {
	skipIfNoEngine(t)

	password := []byte("password")
	salt := []byte("salt")
	dk1 := PBKDF2_256(password, salt, 1000, 32)
	dk2 := PBKDF2_256(password, salt, 2000, 32)

	if bytes.Equal(dk1, dk2) {
		t.Error("different iteration counts produced identical output")
	}
}

func TestPBKDF2_LongerOutput(t *testing.T) {
	skipIfNoEngine(t)

	password := []byte("password")
	salt := []byte("salt")
	dk := PBKDF2_256(password, salt, 1000, 64) // 64 > hLen=32, so two blocks

	if len(dk) != 64 {
		t.Fatalf("output length = %d, want 64", len(dk))
	}

	// First 32 bytes should equal single-block output.
	dk32 := PBKDF2_256(password, salt, 1000, 32)
	if !bytes.Equal(dk[:32], dk32) {
		t.Error("first block of 64-byte output differs from 32-byte output")
	}
}
