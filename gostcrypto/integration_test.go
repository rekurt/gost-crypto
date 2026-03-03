package gostcrypto

import (
	"bytes"
	"testing"

	"github.com/rekurt/gost-crypto/gost3410"
	"github.com/rekurt/gost-crypto/kdf/hd"
)

// TestIntegrationSignVerifyWithSerialization tests complete workflow:
// key generation -> serialization -> deserialization -> sign -> verify
func TestIntegrationSignVerifyWithSerialization256(t *testing.T) {
	// Step 1: Generate key pair
	privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive public key: %v", err)
	}

	// Step 2: Serialize public key (compressed and uncompressed)
	compressedPub, err := pubKey.ToCompressed(true)
	if err != nil {
		t.Fatalf("ToCompressed failed: %v", err)
	}
	uncompressedPub := pubKey.ToUncompressed(true)

	if len(compressedPub) != 33 {
		t.Errorf("compressed size: got %d, want 33", len(compressedPub))
	}
	if len(uncompressedPub) != 65 {
		t.Errorf("uncompressed size: got %d, want 65", len(uncompressedPub))
	}

	// Step 3: Deserialize and verify formats match
	recoveredFromCompressed, err := gost3410.FromCompressed(gost3410.TC26_256_A, compressedPub, true)
	if err != nil {
		t.Fatalf("Failed to recover from compressed: %v", err)
	}

	if !bytes.Equal(recoveredFromCompressed.X, pubKey.X) || !bytes.Equal(recoveredFromCompressed.Y, pubKey.Y) {
		t.Error("Recovered compressed key does not match original")
	}

	recoveredFromUncompressed, err := gost3410.FromUncompressed(gost3410.TC26_256_A, uncompressedPub, true)
	if err != nil {
		t.Fatalf("Failed to recover from uncompressed: %v", err)
	}

	if !bytes.Equal(recoveredFromUncompressed.X, pubKey.X) || !bytes.Equal(recoveredFromUncompressed.Y, pubKey.Y) {
		t.Error("Recovered uncompressed key does not match original")
	}

	// Step 4: Sign message with facade
	message := []byte("Integration test message")
	opts := &Options{Hash: gost3410.Streebog256}
	sig, err := Sign(privKey, message, opts)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Step 5: Verify with original public key
	valid, err := Verify(pubKey, message, sig, opts)
	if err != nil {
		t.Fatalf("Failed to verify with original key: %v", err)
	}
	if !valid {
		t.Error("Verification failed with original key")
	}

	// Step 6: Verify with recovered public keys (both formats)
	valid, err = Verify(recoveredFromCompressed, message, sig, opts)
	if err != nil {
		t.Fatalf("Failed to verify with recovered compressed key: %v", err)
	}
	if !valid {
		t.Error("Verification failed with recovered compressed key")
	}

	valid, err = Verify(recoveredFromUncompressed, message, sig, opts)
	if err != nil {
		t.Fatalf("Failed to verify with recovered uncompressed key: %v", err)
	}
	if !valid {
		t.Error("Verification failed with recovered uncompressed key")
	}

	// Step 7: Negative test - verify should fail with different message
	wrongMessage := []byte("Different message")
	valid, err = Verify(pubKey, wrongMessage, sig, opts)
	if err != nil {
		t.Fatalf("Verify with wrong message failed: %v", err)
	}
	if valid {
		t.Error("Verification should fail with wrong message")
	}
}

// TestIntegrationHDKeyDerivationAndSigning tests HD wallet workflow
func TestIntegrationHDKeyDerivationAndSigning256(t *testing.T) {
	// Step 1: Create master key from seed
	seed := []byte("test seed for HD wallet")
	masterKey, chainCode, err := hd.Master(seed, gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Failed to create master key: %v", err)
	}

	// Step 2: Derive child keys at different paths
	paths := []string{"m/0", "m/1", "m/2/3", "m/0'/1'"}
	derivedKeys := make([]*gost3410.PrivKey, len(paths))

	for i, path := range paths {
		childKey, newChain, err := hd.Derive(masterKey, chainCode, path, gost3410.Streebog256)
		if err != nil {
			t.Fatalf("Failed to derive at %s: %v", path, err)
		}

		if len(newChain) != 32 {
			t.Errorf("chain code size at %s: got %d, want 32", path, len(newChain))
		}

		derivedKeys[i] = childKey
	}

	// Step 3: Verify all derived keys are different
	for i := 0; i < len(derivedKeys); i++ {
		for j := i + 1; j < len(derivedKeys); j++ {
			if bytes.Equal(derivedKeys[i].D, derivedKeys[j].D) {
				t.Errorf("Keys at paths %s and %s are identical", paths[i], paths[j])
			}
		}
	}

	// Step 4: Sign with each derived key
	message := []byte("HD wallet transaction")
	opts := &Options{Hash: gost3410.Streebog256}

	for i, childKey := range derivedKeys {
		pubKey, err := childKey.Public()
		if err != nil {
			t.Fatalf("Failed to derive public key at %s: %v", paths[i], err)
		}

		sig, err := Sign(childKey, message, opts)
		if err != nil {
			t.Fatalf("Failed to sign at %s: %v", paths[i], err)
		}

		valid, err := Verify(pubKey, message, sig, opts)
		if err != nil {
			t.Fatalf("Failed to verify at %s: %v", paths[i], err)
		}

		if !valid {
			t.Errorf("Verification failed at path %s", paths[i])
		}
	}
}

// TestIntegrationMultipleCurves tests sign/verify with different curves
func TestIntegrationMultipleCurves(t *testing.T) {
	curves256 := []gost3410.Curve{gost3410.TC26_256_A}
	curves512 := []gost3410.Curve{gost3410.TC26_512_A, gost3410.TC26_512_B, gost3410.TC26_512_C}

	message := []byte("Multi-curve test message")

	// Test 256-bit curves
	for _, curve := range curves256 {
		privKey, err := gost3410.NewPrivKey(curve)
		if err != nil {
			t.Fatalf("Failed to generate key for curve: %v", err)
		}

		pubKey, err := privKey.Public()
		if err != nil {
			t.Fatalf("Failed to derive public key: %v", err)
		}

		opts := &Options{Hash: gost3410.Streebog256}
		sig, err := Sign(privKey, message, opts)
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		valid, err := Verify(pubKey, message, sig, opts)
		if err != nil {
			t.Fatalf("Failed to verify: %v", err)
		}

		if !valid {
			t.Error("Verification failed for 256-bit curve")
		}
	}

	// Test 512-bit curves
	for _, curve := range curves512 {
		privKey, err := gost3410.NewPrivKey(curve)
		if err != nil {
			t.Fatalf("Failed to generate key for curve: %v", err)
		}

		pubKey, err := privKey.Public()
		if err != nil {
			t.Fatalf("Failed to derive public key: %v", err)
		}

		opts := &Options{Hash: gost3410.Streebog512}
		sig, err := Sign(privKey, message, opts)
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		valid, err := Verify(pubKey, message, sig, opts)
		if err != nil {
			t.Fatalf("Failed to verify: %v", err)
		}

		if !valid {
			t.Error("Verification failed for 512-bit curve")
		}
	}
}

// TestIntegrationLargeMessage tests signing/verifying large messages
func TestIntegrationLargeMessage(t *testing.T) {
	privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive public key: %v", err)
	}

	// Create large message (1 MB)
	largeMessage := make([]byte, 1024*1024)
	for i := range largeMessage {
		largeMessage[i] = byte(i % 256)
	}

	opts := &Options{Hash: gost3410.Streebog256}
	sig, err := Sign(privKey, largeMessage, opts)
	if err != nil {
		t.Fatalf("Failed to sign large message: %v", err)
	}

	valid, err := Verify(pubKey, largeMessage, sig, opts)
	if err != nil {
		t.Fatalf("Failed to verify large message: %v", err)
	}

	if !valid {
		t.Error("Verification failed for large message")
	}

	// Modify one byte and verify fails
	largeMessage[512000]++
	valid, err = Verify(pubKey, largeMessage, sig, opts)
	if err != nil {
		t.Fatalf("Verify with modified message failed: %v", err)
	}

	if valid {
		t.Error("Verification should fail with modified message")
	}
}

// TestIntegrationEmptyMessage tests edge case with empty message
func TestIntegrationEmptyMessage(t *testing.T) {
	privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive public key: %v", err)
	}

	emptyMessage := []byte("")

	opts := &Options{Hash: gost3410.Streebog256}
	sig, err := Sign(privKey, emptyMessage, opts)
	if err != nil {
		t.Fatalf("Failed to sign empty message: %v", err)
	}

	valid, err := Verify(pubKey, emptyMessage, sig, opts)
	if err != nil {
		t.Fatalf("Failed to verify empty message: %v", err)
	}

	if !valid {
		t.Error("Verification failed for empty message")
	}
}

// TestIntegrationConsistency tests that signing same message produces valid signatures
func TestIntegrationConsistency(t *testing.T) {
	privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive public key: %v", err)
	}

	message := []byte("Consistency test message")
	opts := &Options{Hash: gost3410.Streebog256}

	// Sign same message multiple times
	signatures := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		sig, err := Sign(privKey, message, opts)
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}
		signatures[i] = sig

		// Verify immediately
		valid, err := Verify(pubKey, message, sig, opts)
		if err != nil {
			t.Fatalf("Failed to verify: %v", err)
		}
		if !valid {
			t.Errorf("Verification failed on iteration %d", i)
		}
	}

	// Note: Signatures will be different due to random k, but all should verify
	// Verify that not all signatures are identical (randomness works)
	identical := true
	for i := 1; i < len(signatures); i++ {
		if !bytes.Equal(signatures[0], signatures[i]) {
			identical = false
			break
		}
	}

	if identical {
		t.Error("All signatures are identical - randomness may not be working properly")
	}
}
