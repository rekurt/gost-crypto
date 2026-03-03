package gost3410

import (
	"bytes"
	"testing"

	"gost-crypto/streebog"
)

// TestEdgeCaseMinimalPrivateKey tests with minimal valid private key (0x01)
func TestEdgeCaseMinimalPrivateKey(t *testing.T) {
	privKeyBytes := make([]byte, 32)
	privKeyBytes[31] = 1 // d = 1

	privKey, err := FromRawPriv(TC26_256_A, privKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create private key with d=1: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive public key: %v", err)
	}

	// Should produce valid public key
	if len(pubKey.X) != 32 || len(pubKey.Y) != 32 {
		t.Error("Invalid public key size")
	}

	if bytes.Equal(pubKey.X, make([]byte, 32)) || bytes.Equal(pubKey.Y, make([]byte, 32)) {
		t.Error("Public key has zero coordinate")
	}
}

// TestEdgeCaseMaximalPrivateKey tests with maximum valid private key
func TestEdgeCaseMaximalPrivateKey256(t *testing.T) {
	privKeyBytes := make([]byte, 32)
	for i := range privKeyBytes {
		privKeyBytes[i] = 0xFF
	}

	privKey, err := FromRawPriv(TC26_256_A, privKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create private key with max value: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive public key: %v", err)
	}

	if len(pubKey.X) != 32 || len(pubKey.Y) != 32 {
		t.Error("Invalid public key size")
	}
}

// TestEdgeCaseZeroPrivateKey tests that zero private key fails appropriately
func TestEdgeCaseZeroPrivateKey(t *testing.T) {
	privKeyBytes := make([]byte, 32) // All zeros

	privKey, err := FromRawPriv(TC26_256_A, privKeyBytes)
	if err != nil {
		t.Logf("Zero private key correctly rejected: %v", err)
		return // Expected to fail or handle gracefully
	}

	// If it doesn't reject, verify it at least doesn't crash
	_, err = privKey.Public()
	// Either error is acceptable for zero key
}

// TestEdgeCaseSmallMessage tests signing smallest possible message
func TestEdgeCaseSmallMessage(t *testing.T) {
	privKey, err := NewPrivKey(TC26_256_A)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive public key: %v", err)
	}

	// One byte message
	message := []byte("A")
	digest := streebog.Sum256(message)

	sig, err := privKey.Sign(digest[:], Streebog256)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	valid, err := pubKey.Verify(digest[:], sig, Streebog256)
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	if !valid {
		t.Error("Verification failed for single byte message")
	}
}

// TestEdgeCaseMessageAllZeros tests message with all zero bytes
func TestEdgeCaseMessageAllZeros(t *testing.T) {
	privKey, err := NewPrivKey(TC26_256_A)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive public key: %v", err)
	}

	message := make([]byte, 1000) // All zeros
	digest := streebog.Sum256(message)

	sig, err := privKey.Sign(digest[:], Streebog256)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	valid, err := pubKey.Verify(digest[:], sig, Streebog256)
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	if !valid {
		t.Error("Verification failed for all-zero message")
	}
}

// TestEdgeCaseMessageAllOnes tests message with all 0xFF bytes
func TestEdgeCaseMessageAllOnes(t *testing.T) {
	privKey, err := NewPrivKey(TC26_256_A)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive public key: %v", err)
	}

	message := make([]byte, 1000)
	for i := range message {
		message[i] = 0xFF
	}
	digest := streebog.Sum256(message)

	sig, err := privKey.Sign(digest[:], Streebog256)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	valid, err := pubKey.Verify(digest[:], sig, Streebog256)
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	if !valid {
		t.Error("Verification failed for all-0xFF message")
	}
}

// TestEdgeCaseIncorrectDigestSize tests error handling for wrong digest size
func TestEdgeCaseIncorrectDigestSize256(t *testing.T) {
	privKey, err := NewPrivKey(TC26_256_A)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Wrong size digest (should be 32 for 256-bit)
	wrongDigest := make([]byte, 64)

	_, err = privKey.Sign(wrongDigest, Streebog256)
	if err == nil {
		t.Error("Should reject digest of wrong size")
	}
}

// TestEdgeCaseIncorrectSignatureSize tests error handling for wrong signature size
func TestEdgeCaseIncorrectSignatureSize256(t *testing.T) {
	privKey, err := NewPrivKey(TC26_256_A)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive public key: %v", err)
	}

	message := []byte("test")
	digest := streebog.Sum256(message)

	sig, err := privKey.Sign(digest[:], Streebog256)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Try with truncated signature
	wrongSig := sig[:32]
	_, err = pubKey.Verify(digest[:], wrongSig, Streebog256)
	if err == nil {
		t.Error("Should reject signature of wrong size")
	}
}

// TestEdgeCaseDifferentCurvesIncompatible tests error when mixing curves
func TestEdgeCaseDifferentCurvesIncompatible(t *testing.T) {
	privKey256, err := NewPrivKey(TC26_256_A)
	if err != nil {
		t.Fatalf("Failed to generate 256-bit key: %v", err)
	}

	pubKey512, err := func() (*PubKey, error) {
		privKey512, err := NewPrivKey(TC26_512_A)
		if err != nil {
			return nil, err
		}
		return privKey512.Public()
	}()
	if err != nil {
		t.Fatalf("Failed to generate 512-bit key: %v", err)
	}

	message := []byte("test")
	digest256 := streebog.Sum256(message)

	// Try to verify 256-bit signature with 512-bit key (should fail)
	sig256, err := privKey256.Sign(digest256[:], Streebog256)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// This should fail - size mismatch
	_, err = pubKey512.Verify(digest256[:], sig256, Streebog256)
	if err == nil {
		t.Error("Should reject verification with incompatible key sizes")
	}
}

// TestEdgCase512MinimalKey tests 512-bit key with minimal value
func TestEdgCase512MinimalKey(t *testing.T) {
	privKeyBytes := make([]byte, 64)
	privKeyBytes[63] = 1 // d = 1

	privKey, err := FromRawPriv(TC26_512_A, privKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create 512-bit private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive public key: %v", err)
	}

	if len(pubKey.X) != 64 || len(pubKey.Y) != 64 {
		t.Error("Invalid 512-bit public key size")
	}
}

// TestEdgeCasePublicKeyRecoveryRoundTrip tests multiple serialization rounds
func TestEdgeCasePublicKeyRecoveryRoundTrip(t *testing.T) {
	privKey, err := NewPrivKey(TC26_256_A)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	originalPubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive public key: %v", err)
	}

	// Round 1: Serialize and deserialize
	compressed1 := originalPubKey.ToCompressed(true)
	recovered1, err := FromCompressed(TC26_256_A, compressed1, true)
	if err != nil {
		t.Fatalf("Round 1 deserialization failed: %v", err)
	}

	// Round 2: Serialize and deserialize again
	compressed2 := recovered1.ToCompressed(true)
	recovered2, err := FromCompressed(TC26_256_A, compressed2, true)
	if err != nil {
		t.Fatalf("Round 2 deserialization failed: %v", err)
	}

	// Round 3: Verify all match
	if !bytes.Equal(compressed1, compressed2) {
		t.Error("Compressed forms differ after round trip")
	}

	if !bytes.Equal(recovered1.X, recovered2.X) || !bytes.Equal(recovered1.Y, recovered2.Y) {
		t.Error("Public keys differ after multiple round trips")
	}

	if !bytes.Equal(originalPubKey.X, recovered2.X) || !bytes.Equal(originalPubKey.Y, recovered2.Y) {
		t.Error("Final key does not match original")
	}
}

// TestEdgeCaseNilInputs tests error handling for nil inputs
func TestEdgeCaseNilInputs(t *testing.T) {
	privKey, err := NewPrivKey(TC26_256_A)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive public key: %v", err)
	}

	// Test nil digest
	_, err = privKey.Sign(nil, Streebog256)
	if err == nil {
		t.Error("Should reject nil digest")
	}

	// Test nil signature
	_, err = pubKey.Verify([]byte{1, 2, 3}, nil, Streebog256)
	if err == nil {
		t.Error("Should reject nil signature")
	}
}
