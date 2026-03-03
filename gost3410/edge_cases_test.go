package gost3410

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/rekurt/gost-crypto/streebog"
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

// TestEdgeCaseMaximalPrivateKey tests that max-value (0xFF..FF) private key is rejected (>= curve order)
func TestEdgeCaseMaximalPrivateKey256(t *testing.T) {
	privKeyBytes := make([]byte, 32)
	for i := range privKeyBytes {
		privKeyBytes[i] = 0xFF
	}

	_, err := FromRawPriv(TC26_256_A, privKeyBytes)
	if err == nil {
		t.Fatal("FromRawPriv should reject d >= curve order")
	}
	t.Logf("Max-value private key correctly rejected: %v", err)
}

// TestEdgeCaseZeroPrivateKey tests that zero private key is rejected
func TestEdgeCaseZeroPrivateKey(t *testing.T) {
	privKeyBytes := make([]byte, 32) // All zeros

	_, err := FromRawPriv(TC26_256_A, privKeyBytes)
	if err == nil {
		t.Fatal("FromRawPriv should reject zero private key")
	}
	t.Logf("Zero private key correctly rejected: %v", err)
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
	compressed1, err := originalPubKey.ToCompressed(true)
	if err != nil {
		t.Fatalf("Round 1 ToCompressed failed: %v", err)
	}
	recovered1, err := FromCompressed(TC26_256_A, compressed1, true)
	if err != nil {
		t.Fatalf("Round 1 deserialization failed: %v", err)
	}

	// Round 2: Serialize and deserialize again
	compressed2, err := recovered1.ToCompressed(true)
	if err != nil {
		t.Fatalf("Round 2 ToCompressed failed: %v", err)
	}
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

// TestCrossCurveVerification tests that signature from one curve fails verification on another
func TestCrossCurveVerification(t *testing.T) {
	// Sign on 512-A, try to verify on 512-B (same key size, different curves)
	privKeyA, err := NewPrivKey(TC26_512_A)
	if err != nil {
		t.Fatalf("NewPrivKey 512-A failed: %v", err)
	}

	privKeyB, err := NewPrivKey(TC26_512_B)
	if err != nil {
		t.Fatalf("NewPrivKey 512-B failed: %v", err)
	}

	pubKeyB, err := privKeyB.Public()
	if err != nil {
		t.Fatalf("Public() 512-B failed: %v", err)
	}

	message := []byte("cross-curve test")
	digest := streebog.Sum512(message)

	sigA, err := privKeyA.Sign(digest[:], Streebog512)
	if err != nil {
		t.Fatalf("Sign on 512-A failed: %v", err)
	}

	// Verify signature from curve A with pubkey from curve B
	valid, err := pubKeyB.Verify(digest[:], sigA, Streebog512)
	if err != nil {
		// Error is also acceptable
		t.Logf("Cross-curve verify returned error (expected): %v", err)
		return
	}
	if valid {
		t.Error("Signature from 512-A should not verify with 512-B key")
	}
}

// TestPropertySignThenVerify runs 100 iterations of sign-then-verify with random keys
func TestPropertySignThenVerify(t *testing.T) {
	for i := 0; i < 100; i++ {
		privKey, err := NewPrivKey(TC26_256_A)
		if err != nil {
			t.Fatalf("Iteration %d: NewPrivKey failed: %v", i, err)
		}

		pubKey, err := privKey.Public()
		if err != nil {
			t.Fatalf("Iteration %d: Public() failed: %v", i, err)
		}

		message := make([]byte, 32)
		if _, err := rand.Read(message); err != nil {
			t.Fatalf("Iteration %d: rand.Read failed: %v", i, err)
		}
		digest := streebog.Sum256(message)

		sig, err := privKey.Sign(digest[:], Streebog256)
		if err != nil {
			t.Fatalf("Iteration %d: Sign failed: %v", i, err)
		}

		valid, err := pubKey.Verify(digest[:], sig, Streebog256)
		if err != nil {
			t.Fatalf("Iteration %d: Verify failed: %v", i, err)
		}
		if !valid {
			t.Fatalf("Iteration %d: sign-then-verify returned false", i)
		}
	}
}

// TestFromRawPrivWrongSize tests FromRawPriv with incorrect byte lengths
func TestFromRawPrivWrongSize(t *testing.T) {
	tests := []struct {
		name  string
		curve Curve
		size  int
	}{
		{"256-A too short", TC26_256_A, 16},
		{"256-A too long", TC26_256_A, 64},
		{"256-A empty", TC26_256_A, 0},
		{"512-A too short", TC26_512_A, 32},
		{"512-A too long", TC26_512_A, 128},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := make([]byte, tc.size)
			_, err := FromRawPriv(tc.curve, d)
			if err == nil {
				t.Errorf("FromRawPriv should reject %d bytes for %s", tc.size, tc.name)
			}
		})
	}
}

// TestFromRawPrivInvalidCurve tests FromRawPriv with an invalid curve
func TestFromRawPrivInvalidCurve(t *testing.T) {
	d := make([]byte, 32)
	_, err := FromRawPriv(Curve(99), d)
	if err == nil {
		t.Error("FromRawPriv should reject invalid curve")
	}
}

// TestFromCompressedInvalidData tests FromCompressed with various incorrect inputs
func TestFromCompressedInvalidData(t *testing.T) {
	tests := []struct {
		name   string
		curve  Curve
		data   []byte
		prefix bool
	}{
		{"wrong size with prefix 256", TC26_256_A, make([]byte, 16), true},
		{"wrong size without prefix 256", TC26_256_A, make([]byte, 16), false},
		{"wrong prefix byte 0x04", TC26_256_A, append([]byte{0x04}, make([]byte, 32)...), true},
		{"wrong prefix byte 0x00", TC26_256_A, append([]byte{0x00}, make([]byte, 32)...), true},
		{"wrong size with prefix 512", TC26_512_A, make([]byte, 32), true},
		{"wrong size without prefix 512", TC26_512_A, make([]byte, 32), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FromCompressed(tc.curve, tc.data, tc.prefix)
			if err == nil {
				t.Errorf("FromCompressed should reject invalid data: %s", tc.name)
			}
		})
	}
}

// TestFromUncompressedInvalidData tests FromUncompressed with various incorrect inputs
func TestFromUncompressedInvalidData(t *testing.T) {
	tests := []struct {
		name   string
		curve  Curve
		data   []byte
		prefix bool
	}{
		{"wrong size with prefix 256", TC26_256_A, make([]byte, 32), true},
		{"wrong size without prefix 256", TC26_256_A, make([]byte, 32), false},
		{"wrong prefix byte 0x03", TC26_256_A, append([]byte{0x03}, make([]byte, 64)...), true},
		{"wrong size with prefix 512", TC26_512_A, make([]byte, 64), true},
		{"wrong size without prefix 512", TC26_512_A, make([]byte, 64), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FromUncompressed(tc.curve, tc.data, tc.prefix)
			if err == nil {
				t.Errorf("FromUncompressed should reject invalid data: %s", tc.name)
			}
		})
	}
}

// TestFromCompressedInvalidCurve tests FromCompressed with invalid curve
func TestFromCompressedInvalidCurve(t *testing.T) {
	_, err := FromCompressed(Curve(99), make([]byte, 33), true)
	if err == nil {
		t.Error("FromCompressed should reject invalid curve")
	}
}

// TestFromUncompressedInvalidCurve tests FromUncompressed with invalid curve
func TestFromUncompressedInvalidCurve(t *testing.T) {
	_, err := FromUncompressed(Curve(99), make([]byte, 65), true)
	if err == nil {
		t.Error("FromUncompressed should reject invalid curve")
	}
}

// TestCurveSizeInvalid tests Curve.Size() with invalid curve values
func TestCurveSizeInvalid(t *testing.T) {
	tests := []struct {
		name  string
		curve Curve
	}{
		{"negative", Curve(-1)},
		{"out of range", Curve(99)},
		{"just past valid", Curve(8)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.curve.Size()
			if err == nil {
				t.Errorf("Size() should return error for invalid curve %d", tc.curve)
			}
		})
	}
}

// TestCurveSizeValid tests Curve.Size() returns correct sizes for all valid curves
func TestCurveSizeValid(t *testing.T) {
	tests := []struct {
		curve    Curve
		expected int
	}{
		{TC26_256_A, 32},
		{TC26_256_B, 32},
		{TC26_256_C, 32},
		{TC26_256_D, 32},
		{TC26_512_A, 64},
		{TC26_512_B, 64},
		{TC26_512_C, 64},
		{TC26_512_D, 64},
	}
	for _, tc := range tests {
		size, err := tc.curve.Size()
		if err != nil {
			t.Errorf("Size() for curve %d failed: %v", tc.curve, err)
		}
		if size != tc.expected {
			t.Errorf("Size() for curve %d = %d, want %d", tc.curve, size, tc.expected)
		}
	}
}

// TestNewPrivKeyInvalidCurve tests NewPrivKey with invalid curve
func TestNewPrivKeyInvalidCurve(t *testing.T) {
	_, err := NewPrivKey(Curve(99))
	if err == nil {
		t.Error("NewPrivKey should fail for invalid curve")
	}
}

// TestFromRawPrivRangeValidation tests private key range validation (0 < d < q)
func TestFromRawPrivRangeValidation(t *testing.T) {
	q, err := curveOrder(TC26_256_A)
	if err != nil {
		t.Fatalf("curveOrder failed: %v", err)
	}
	size := 32

	toBytes := func(v *big.Int) []byte {
		b := v.Bytes()
		if len(b) < size {
			padded := make([]byte, size)
			copy(padded[size-len(b):], b)
			return padded
		}
		return b
	}

	t.Run("d=0 rejected", func(t *testing.T) {
		_, err := FromRawPriv(TC26_256_A, make([]byte, size))
		if err == nil {
			t.Error("FromRawPriv should reject d=0")
		}
	})

	t.Run("d=q rejected", func(t *testing.T) {
		_, err := FromRawPriv(TC26_256_A, toBytes(q))
		if err == nil {
			t.Error("FromRawPriv should reject d=q")
		}
	})

	t.Run("d=q-1 accepted", func(t *testing.T) {
		qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
		pk, err := FromRawPriv(TC26_256_A, toBytes(qMinus1))
		if err != nil {
			t.Fatalf("FromRawPriv should accept d=q-1: %v", err)
		}
		_, err = pk.Public()
		if err != nil {
			t.Fatalf("Public() failed for d=q-1: %v", err)
		}
	})

	t.Run("d=1 accepted", func(t *testing.T) {
		pk, err := FromRawPriv(TC26_256_A, toBytes(big.NewInt(1)))
		if err != nil {
			t.Fatalf("FromRawPriv should accept d=1: %v", err)
		}
		_, err = pk.Public()
		if err != nil {
			t.Fatalf("Public() failed for d=1: %v", err)
		}
	})
}

// TestToRaw tests that ToRaw returns a copy of private key bytes
func TestToRaw(t *testing.T) {
	privKey, err := NewPrivKey(TC26_256_A)
	if err != nil {
		t.Fatalf("NewPrivKey failed: %v", err)
	}

	raw := privKey.ToRaw()
	if !bytes.Equal(raw, privKey.D) {
		t.Error("ToRaw should return identical bytes")
	}

	// Mutating the result should not affect the original
	raw[0] ^= 0xFF
	if bytes.Equal(raw, privKey.D) {
		t.Error("ToRaw should return a copy, not a reference")
	}
}

// TestSignWithUnsupportedCurve tests Sign with a curve that has no backend
func TestSignWithUnsupportedCurve(t *testing.T) {
	d := make([]byte, 32)
	d[31] = 1
	privKey := &PrivKey{D: d, Curve: TC26_256_B}
	_, err := privKey.Sign(make([]byte, 32), Streebog256)
	if err == nil {
		t.Error("Sign should fail for unsupported curve")
	}
}

// TestVerifyWithUnsupportedCurve tests Verify with a curve that has no backend
func TestVerifyWithUnsupportedCurve(t *testing.T) {
	pubKey := &PubKey{X: make([]byte, 32), Y: make([]byte, 32), Curve: TC26_256_B}
	_, err := pubKey.Verify(make([]byte, 32), make([]byte, 64), Streebog256)
	if err == nil {
		t.Error("Verify should fail for unsupported curve")
	}
}

// TestToCompressedHighBitError tests that ToCompressed(false) returns an error when X[0] >= 0x80
func TestToCompressedHighBitError(t *testing.T) {
	// Find a key where X[0] >= 0x80
	var pub *PubKey
	for scalar := byte(1); scalar < 255; scalar++ {
		d := make([]byte, 32)
		d[31] = scalar
		x, y, err := mulBase(TC26_256_A, d)
		if err != nil {
			t.Fatalf("mulBase failed: %v", err)
		}
		if x[0] >= 0x80 {
			pub = &PubKey{X: x, Y: y, Curve: TC26_256_A}
			break
		}
	}
	if pub == nil {
		t.Skip("could not find a key with X[0] >= 0x80 in first 254 scalars")
	}

	// prefix=true should still work
	_, err := pub.ToCompressed(true)
	if err != nil {
		t.Fatalf("ToCompressed(true) should work regardless of X[0]: %v", err)
	}

	// prefix=false should return error
	_, err = pub.ToCompressed(false)
	if err == nil {
		t.Fatal("ToCompressed(false) should return error when X[0] >= 0x80")
	}
	t.Logf("ToCompressed(false) correctly returned error: %v", err)
}

// TestToCompressedNoPrefixSuccess tests that ToCompressed(false) succeeds when X[0] < 0x80
func TestToCompressedNoPrefixSuccess(t *testing.T) {
	// Find a key where X[0] < 0x80
	var pub *PubKey
	for scalar := byte(1); scalar < 255; scalar++ {
		d := make([]byte, 32)
		d[31] = scalar
		x, y, err := mulBase(TC26_256_A, d)
		if err != nil {
			t.Fatalf("mulBase failed: %v", err)
		}
		if x[0] < 0x80 {
			pub = &PubKey{X: x, Y: y, Curve: TC26_256_A}
			break
		}
	}
	if pub == nil {
		t.Skip("could not find a key with X[0] < 0x80 in first 254 scalars")
	}

	compressed, err := pub.ToCompressed(false)
	if err != nil {
		t.Fatalf("ToCompressed(false) should succeed when X[0] < 0x80: %v", err)
	}

	// Roundtrip: verify deserialization recovers the same key
	recovered, err := FromCompressed(TC26_256_A, compressed, false)
	if err != nil {
		t.Fatalf("FromCompressed roundtrip failed: %v", err)
	}
	if !bytes.Equal(recovered.X, pub.X) || !bytes.Equal(recovered.Y, pub.Y) {
		t.Error("no-prefix compressed roundtrip failed: keys differ")
	}
}
