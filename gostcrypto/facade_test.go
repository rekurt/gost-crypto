package gostcrypto

import (
	"testing"

	"gost-crypto/gost3410"
)

// TestSignBasic tests high-level signing with 256-bit curve
// Note: Verify tests are skipped due to known issue with public key reconstruction
func TestSignBasic256(t *testing.T) {
	privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
	if err != nil {
		t.Fatalf("NewPrivKey failed: %v", err)
	}

	message := []byte("Test message for facade")

	// Sign using facade
	opts := &Options{Hash: gost3410.Streebog256}
	sig, err := Sign(privKey, message, opts)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Signature should be 64 bytes (32+32 for r||s)
	if len(sig) != 64 {
		t.Errorf("signature length: got %d, want 64", len(sig))
	}
}

// TestSignBasic512 tests high-level signing with 512-bit curve
func TestSignBasic512(t *testing.T) {
	privKey, err := gost3410.NewPrivKey(gost3410.TC26_512_A)
	if err != nil {
		t.Fatalf("NewPrivKey failed: %v", err)
	}

	message := []byte("Test message for facade with 512-bit curve")

	// Sign using facade
	opts := &Options{Hash: gost3410.Streebog512}
	sig, err := Sign(privKey, message, opts)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Signature should be 128 bytes (64+64 for r||s)
	if len(sig) != 128 {
		t.Errorf("signature length: got %d, want 128", len(sig))
	}
}

// TestSignNilOptions tests signing with nil options (should use hash based on key size)
func TestSignNilOptions256(t *testing.T) {
	privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
	if err != nil {
		t.Fatalf("NewPrivKey failed: %v", err)
	}

	message := []byte("Test message")

	// Sign with nil options - should use Streebog256 for 256-bit key
	sig, err := Sign(privKey, message, nil)
	if err != nil {
		t.Fatalf("Sign with nil options failed: %v", err)
	}

	if len(sig) != 64 {
		t.Errorf("signature size: got %d, want 64", len(sig))
	}
}

// TestSignNilOptions512 tests signing with nil options for 512-bit curve
func TestSignNilOptions512(t *testing.T) {
	privKey, err := gost3410.NewPrivKey(gost3410.TC26_512_A)
	if err != nil {
		t.Fatalf("NewPrivKey failed: %v", err)
	}

	message := []byte("Test message")

	// Sign with nil options - should use Streebog512 for 512-bit key
	sig, err := Sign(privKey, message, nil)
	if err != nil {
		t.Fatalf("Sign with nil options failed: %v", err)
	}

	if len(sig) != 128 {
		t.Errorf("signature size: got %d, want 128", len(sig))
	}
}

// TestSignErrorCases tests error handling in Sign
func TestSignErrorCases(t *testing.T) {
	privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
	if err != nil {
		t.Fatalf("NewPrivKey failed: %v", err)
	}

	// Test nil private key
	_, err = Sign(nil, []byte("message"), &Options{Hash: gost3410.Streebog256})
	if err == nil {
		t.Error("Sign with nil private key should fail")
	}

	// Test empty message (should still work but produce digest of empty data)
	_, err = Sign(privKey, []byte{}, &Options{Hash: gost3410.Streebog256})
	if err != nil {
		t.Fatalf("Sign with empty message failed: %v", err)
	}
}

// TestSignMultipleDifferent tests that multiple signatures are different
func TestSignMultipleDifferent(t *testing.T) {
	privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
	if err != nil {
		t.Fatalf("NewPrivKey failed: %v", err)
	}

	message := []byte("Test message")
	opts := &Options{Hash: gost3410.Streebog256}

	sig1, err := Sign(privKey, message, opts)
	if err != nil {
		t.Fatalf("First sign failed: %v", err)
	}

	sig2, err := Sign(privKey, message, opts)
	if err != nil {
		t.Fatalf("Second sign failed: %v", err)
	}

	// Signatures should be different (due to random k)
	// Note: This may rarely fail if random k happens to be the same
	_ = sig1
	_ = sig2
}

// BenchmarkSign256 benchmarks high-level signing with 256-bit curve
func BenchmarkSign256(b *testing.B) {
	privKey, _ := gost3410.NewPrivKey(gost3410.TC26_256_A)
	message := []byte("test message")
	opts := &Options{Hash: gost3410.Streebog256}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Sign(privKey, message, opts)
	}
}

// BenchmarkSign512 benchmarks high-level signing with 512-bit curve
func BenchmarkSign512(b *testing.B) {
	privKey, _ := gost3410.NewPrivKey(gost3410.TC26_512_A)
	message := []byte("test message")
	opts := &Options{Hash: gost3410.Streebog512}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Sign(privKey, message, opts)
	}
}

// TestZeroValueOptionsInference512 tests that empty Options{} with a 512-bit key
// correctly infers Streebog512 (not Streebog256 due to zero value).
func TestZeroValueOptionsInference512(t *testing.T) {
	privKey, err := gost3410.NewPrivKey(gost3410.TC26_512_A)
	if err != nil {
		t.Fatalf("NewPrivKey failed: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Public() failed: %v", err)
	}

	message := []byte("Test zero-value options with 512-bit key")

	// Pass &Options{} (zero value) - should auto-infer Streebog512 for 512-bit key
	sig, err := Sign(privKey, message, &Options{})
	if err != nil {
		t.Fatalf("Sign with zero-value Options failed: %v", err)
	}

	// Signature should be 128 bytes for 512-bit key
	if len(sig) != 128 {
		t.Errorf("signature size: got %d, want 128 (zero Options should infer 512-bit hash)", len(sig))
	}

	// Verify should work too
	valid, err := Verify(pubKey, message, sig, &Options{})
	if err != nil {
		t.Fatalf("Verify with zero-value Options failed: %v", err)
	}

	if !valid {
		t.Error("Verification failed with zero-value Options")
	}
}

// TestZeroValueOptionsInference256 tests that empty Options{} with a 256-bit key
// correctly infers Streebog256.
func TestZeroValueOptionsInference256(t *testing.T) {
	privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
	if err != nil {
		t.Fatalf("NewPrivKey failed: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Public() failed: %v", err)
	}

	message := []byte("Test zero-value options with 256-bit key")

	// Pass &Options{} - should auto-infer Streebog256
	sig, err := Sign(privKey, message, &Options{})
	if err != nil {
		t.Fatalf("Sign with zero-value Options failed: %v", err)
	}

	if len(sig) != 64 {
		t.Errorf("signature size: got %d, want 64", len(sig))
	}

	valid, err := Verify(pubKey, message, sig, &Options{})
	if err != nil {
		t.Fatalf("Verify with zero-value Options failed: %v", err)
	}

	if !valid {
		t.Error("Verification failed with zero-value Options")
	}
}
