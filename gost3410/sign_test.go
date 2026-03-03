package gost3410

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/rekurt/gost-crypto/streebog"
)

// TestSignVerify256 tests signing and verification with TC26_256_A curve
func TestSignVerify256(t *testing.T) {

	// Generate key pair
	privKey, err := NewPrivKey(TC26_256_A)
	if err != nil {
		t.Fatalf("NewPrivKey failed: %v", err)
	}

	// Derive public key
	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Public() failed: %v", err)
	}

	// Create message and digest
	message := []byte("Test message for GOST signature")
	digest := streebog.Sum256(message)

	// Sign
	sig, err := privKey.Sign(digest[:], Streebog256)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Signature should be 64 bytes (32+32 for r||s)
	if len(sig) != 64 {
		t.Errorf("signature length: got %d, want 64", len(sig))
	}

	// Verify with original public key
	valid, err := pubKey.Verify(digest[:], sig, Streebog256)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !valid {
		t.Error("signature verification failed for correct signature")
	}

	// Verify should fail with wrong message
	wrongMessage := []byte("Wrong message")
	wrongDigest := streebog.Sum256(wrongMessage)
	valid, err = pubKey.Verify(wrongDigest[:], sig, Streebog256)
	if err != nil {
		t.Fatalf("Verify with wrong message failed: %v", err)
	}

	if valid {
		t.Error("signature verification succeeded with wrong message - should have failed")
	}
}

// TestSignVerify512 tests signing and verification with TC26_512_A curve
func TestSignVerify512(t *testing.T) {

	// Generate key pair
	privKey, err := NewPrivKey(TC26_512_A)
	if err != nil {
		t.Fatalf("NewPrivKey failed: %v", err)
	}

	// Derive public key
	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Public() failed: %v", err)
	}

	// Create message and digest
	message := []byte("Test message for GOST 512-bit signature")
	digest := streebog.Sum512(message)

	// Sign
	sig, err := privKey.Sign(digest[:], Streebog512)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Signature should be 128 bytes (64+64 for r||s)
	if len(sig) != 128 {
		t.Errorf("signature length: got %d, want 128", len(sig))
	}

	// Verify with original public key
	valid, err := pubKey.Verify(digest[:], sig, Streebog512)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !valid {
		t.Error("signature verification failed for correct signature")
	}

	// Verify should fail with wrong message
	wrongMessage := []byte("Wrong message")
	wrongDigest := streebog.Sum512(wrongMessage)
	valid, err = pubKey.Verify(wrongDigest[:], sig, Streebog512)
	if err != nil {
		t.Fatalf("Verify with wrong message failed: %v", err)
	}

	if valid {
		t.Error("signature verification succeeded with wrong message - should have failed")
	}
}

// TestSignMultiple tests that multiple signatures over same message produce different results
func TestSignMultiple256(t *testing.T) {
	privKey, err := NewPrivKey(TC26_256_A)
	if err != nil {
		t.Fatalf("NewPrivKey failed: %v", err)
	}

	message := []byte("Test message")
	digest := streebog.Sum256(message)

	// Create two signatures
	sig1, err := privKey.Sign(digest[:], Streebog256)
	if err != nil {
		t.Fatalf("First sign failed: %v", err)
	}

	sig2, err := privKey.Sign(digest[:], Streebog256)
	if err != nil {
		t.Fatalf("Second sign failed: %v", err)
	}

	// Signatures should be different (due to random k)
	if bytes.Equal(sig1, sig2) {
		t.Error("two signatures of same message are identical - randomness issue")
	}
}

// TestSignErrorCases tests error handling in Sign
func TestSignErrorCases(t *testing.T) {
	privKey, err := NewPrivKey(TC26_256_A)
	if err != nil {
		t.Fatalf("NewPrivKey failed: %v", err)
	}

	// Test nil private key
	var nilKey *PrivKey
	_, err = nilKey.Sign(make([]byte, 32), Streebog256)
	if err == nil {
		t.Error("Sign with nil key should fail")
	}

	// Test wrong digest size
	wrongDigest := make([]byte, 16)
	_, err = privKey.Sign(wrongDigest, Streebog256)
	if err == nil {
		t.Error("Sign with wrong digest size should fail")
	}
}

// TestVerifyErrorCases tests error handling in Verify
func TestVerifyErrorCases(t *testing.T) {
	privKey, err := NewPrivKey(TC26_256_A)
	if err != nil {
		t.Fatalf("NewPrivKey failed: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Public() failed: %v", err)
	}

	// Test nil public key
	var nilKey *PubKey
	_, err = nilKey.Verify(make([]byte, 32), make([]byte, 64), Streebog256)
	if err == nil {
		t.Error("Verify with nil key should fail")
	}

	// Test wrong digest size
	wrongDigest := make([]byte, 16)
	_, err = pubKey.Verify(wrongDigest, make([]byte, 64), Streebog256)
	if err == nil {
		t.Error("Verify with wrong digest size should fail")
	}

	// Test wrong signature size
	wrongSig := make([]byte, 32)
	_, err = pubKey.Verify(make([]byte, 32), wrongSig, Streebog256)
	if err == nil {
		t.Error("Verify with wrong signature size should fail")
	}
}

// TestPrivKeyPublic tests public key derivation from private key
func TestPrivKeyPublic256(t *testing.T) {
	privKey, err := NewPrivKey(TC26_256_A)
	if err != nil {
		t.Fatalf("NewPrivKey failed: %v", err)
	}

	derivedPubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Public() failed: %v", err)
	}

	// Verify it's a valid public key
	if derivedPubKey == nil {
		t.Error("derived public key is nil")
	}
	if derivedPubKey.Curve != TC26_256_A {
		t.Error("derived public key curve mismatch")
	}
	if len(derivedPubKey.X) != 32 || len(derivedPubKey.Y) != 32 {
		t.Error("derived public key coordinate size mismatch")
	}
}

// TestPrivKeyPublic512 tests public key derivation from private key on 512-bit curve
func TestPrivKeyPublic512(t *testing.T) {
	privKey, err := NewPrivKey(TC26_512_A)
	if err != nil {
		t.Fatalf("NewPrivKey failed: %v", err)
	}

	derivedPubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Public() failed: %v", err)
	}

	// Verify it's a valid public key
	if derivedPubKey == nil {
		t.Error("derived public key is nil")
	}
	if derivedPubKey.Curve != TC26_512_A {
		t.Error("derived public key curve mismatch")
	}
	if len(derivedPubKey.X) != 64 || len(derivedPubKey.Y) != 64 {
		t.Error("derived public key coordinate size mismatch")
	}
}

// TestNewPrivKey256 tests private key generation for 256-bit curve
func TestNewPrivKey256(t *testing.T) {
	privKey, err := NewPrivKey(TC26_256_A)
	if err != nil {
		t.Fatalf("NewPrivKey failed: %v", err)
	}

	// Check private key size
	if len(privKey.D) != 32 {
		t.Errorf("private key size: got %d, want 32", len(privKey.D))
	}

	// Check curve matches
	if privKey.Curve != TC26_256_A {
		t.Error("private key curve mismatch")
	}

	// Check not all zeros
	allZeroD := true
	for _, b := range privKey.D {
		if b != 0 {
			allZeroD = false
			break
		}
	}
	if allZeroD {
		t.Error("private key is all zeros")
	}

	// Derive and check public key
	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Public() failed: %v", err)
	}

	if len(pubKey.X) != 32 {
		t.Errorf("public key X size: got %d, want 32", len(pubKey.X))
	}
	if len(pubKey.Y) != 32 {
		t.Errorf("public key Y size: got %d, want 32", len(pubKey.Y))
	}
	if pubKey.Curve != TC26_256_A {
		t.Error("public key curve mismatch")
	}
}

// TestNewPrivKey512 tests private key generation for 512-bit curve
func TestNewPrivKey512(t *testing.T) {
	privKey, err := NewPrivKey(TC26_512_A)
	if err != nil {
		t.Fatalf("NewPrivKey failed: %v", err)
	}

	// Check private key size
	if len(privKey.D) != 64 {
		t.Errorf("private key size: got %d, want 64", len(privKey.D))
	}

	// Check curve matches
	if privKey.Curve != TC26_512_A {
		t.Error("private key curve mismatch")
	}

	// Derive and check public key
	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Public() failed: %v", err)
	}

	if len(pubKey.X) != 64 {
		t.Errorf("public key X size: got %d, want 64", len(pubKey.X))
	}
	if len(pubKey.Y) != 64 {
		t.Errorf("public key Y size: got %d, want 64", len(pubKey.Y))
	}
	if pubKey.Curve != TC26_512_A {
		t.Error("public key curve mismatch")
	}
}

// TestFromRawPriv tests creating private key from raw bytes
func TestFromRawPriv256(t *testing.T) {
	// Generate random bytes for private key
	d := make([]byte, 32)
	_, err := rand.Read(d)
	if err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	privKey, err := FromRawPriv(TC26_256_A, d)
	if err != nil {
		t.Fatalf("FromRawPriv failed: %v", err)
	}

	// Check that key was created with correct curve and data
	if privKey.Curve != TC26_256_A {
		t.Error("curve mismatch")
	}
	if !bytes.Equal(privKey.D, d) {
		t.Error("private key data mismatch")
	}

	// Check that public key can be derived
	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Public() failed: %v", err)
	}

	if pubKey.Curve != TC26_256_A {
		t.Error("public key curve mismatch")
	}
	if len(pubKey.X) != 32 || len(pubKey.Y) != 32 {
		t.Error("public key size mismatch")
	}
}

// TestFromRawPriv512 tests creating private key from raw bytes on 512-bit curve
func TestFromRawPriv512(t *testing.T) {
	// Generate random bytes for private key
	d := make([]byte, 64)
	_, err := rand.Read(d)
	if err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	privKey, err := FromRawPriv(TC26_512_A, d)
	if err != nil {
		t.Fatalf("FromRawPriv failed: %v", err)
	}

	// Check that key was created with correct curve and data
	if privKey.Curve != TC26_512_A {
		t.Error("curve mismatch")
	}
	if !bytes.Equal(privKey.D, d) {
		t.Error("private key data mismatch")
	}

	// Check that public key can be derived
	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Public() failed: %v", err)
	}

	if pubKey.Curve != TC26_512_A {
		t.Error("public key curve mismatch")
	}
	if len(pubKey.X) != 64 || len(pubKey.Y) != 64 {
		t.Error("public key size mismatch")
	}
}

// TestKeySerializationRoundTrip tests public key serialization and deserialization
func TestKeySerializationRoundTrip256(t *testing.T) {

	privKey, err := NewPrivKey(TC26_256_A)
	if err != nil {
		t.Fatalf("NewPrivKey failed: %v", err)
	}

	originalPubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Public() failed: %v", err)
	}

	// Test Sign/Verify roundtrip with serialized key
	message := []byte("Test message")
	digest := streebog.Sum256(message)

	sig, err := privKey.Sign(digest[:], Streebog256)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify with original key
	valid, err := originalPubKey.Verify(digest[:], sig, Streebog256)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !valid {
		t.Error("signature verification failed with original key")
	}

	// Serialize and deserialize compressed key
	compressed := originalPubKey.ToCompressed(true)
	recoveredPubKey, err := FromCompressed(TC26_256_A, compressed, true)
	if err != nil {
		t.Fatalf("FromCompressed failed: %v", err)
	}

	// Verify with deserialized key
	valid, err = recoveredPubKey.Verify(digest[:], sig, Streebog256)
	if err != nil {
		t.Fatalf("Verify with recovered key failed: %v", err)
	}

	if !valid {
		t.Error("signature verification failed with recovered key")
	}
}

// BenchmarkSign256 benchmarks signing with 256-bit curve
func BenchmarkSign256(b *testing.B) {
	privKey, err := NewPrivKey(TC26_256_A)
	if err != nil {
		b.Fatalf("NewPrivKey failed: %v", err)
	}

	digest := streebog.Sum256([]byte("test message"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = privKey.Sign(digest[:], Streebog256)
	}
}

// BenchmarkVerify256 benchmarks verification with 256-bit curve
func BenchmarkVerify256(b *testing.B) {
	privKey, err := NewPrivKey(TC26_256_A)
	if err != nil {
		b.Fatalf("NewPrivKey failed: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		b.Fatalf("Public() failed: %v", err)
	}

	digest := streebog.Sum256([]byte("test message"))
	sig, err := privKey.Sign(digest[:], Streebog256)
	if err != nil {
		b.Fatalf("Sign failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pubKey.Verify(digest[:], sig, Streebog256)
	}
}

// BenchmarkSign512 benchmarks signing with 512-bit curve
func BenchmarkSign512(b *testing.B) {
	privKey, err := NewPrivKey(TC26_512_A)
	if err != nil {
		b.Fatalf("NewPrivKey failed: %v", err)
	}

	digest := streebog.Sum512([]byte("test message"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = privKey.Sign(digest[:], Streebog512)
	}
}

// BenchmarkVerify512 benchmarks verification with 512-bit curve
func BenchmarkVerify512(b *testing.B) {
	privKey, err := NewPrivKey(TC26_512_A)
	if err != nil {
		b.Fatalf("NewPrivKey failed: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		b.Fatalf("Public() failed: %v", err)
	}

	digest := streebog.Sum512([]byte("test message"))
	sig, err := privKey.Sign(digest[:], Streebog512)
	if err != nil {
		b.Fatalf("Sign failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pubKey.Verify(digest[:], sig, Streebog512)
	}
}
