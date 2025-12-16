package gost3410

import (
	"bytes"
	"testing"
)

// TestMulBase256 tests scalar multiplication on 256-bit TC26 curve
func TestMulBase256(t *testing.T) {
	curve := TC26_256_A

	// Simple test: multiply by 1 (should return base point)
	d := make([]byte, 32)
	d[31] = 1 // d = 1 in big-endian

	x, y, err := mulBase(curve, d)
	if err != nil {
		t.Fatalf("mulBase failed: %v", err)
	}

	// Check sizes
	if len(x) != 32 {
		t.Errorf("x size: got %d, want 32", len(x))
	}
	if len(y) != 32 {
		t.Errorf("y size: got %d, want 32", len(y))
	}

	// Both should be non-zero
	if allZero(x) {
		t.Error("x is zero")
	}
	if allZero(y) {
		t.Error("y is zero")
	}
}

// TestMulBase512 tests scalar multiplication on 512-bit TC26 curve
func TestMulBase512(t *testing.T) {
	curve := TC26_512_A

	// Simple test: multiply by 1 (should return base point)
	d := make([]byte, 64)
	d[63] = 1 // d = 1 in big-endian

	x, y, err := mulBase(curve, d)
	if err != nil {
		t.Fatalf("mulBase failed: %v", err)
	}

	// Check sizes
	if len(x) != 64 {
		t.Errorf("x size: got %d, want 64", len(x))
	}
	if len(y) != 64 {
		t.Errorf("y size: got %d, want 64", len(y))
	}

	// Both should be non-zero
	if allZero(x) {
		t.Error("x is zero")
	}
	if allZero(y) {
		t.Error("y is zero")
	}
}

// TestRecoverY256 tests Y coordinate recovery on 256-bit TC26 curve
func TestRecoverY256(t *testing.T) {
	curve := TC26_256_A

	// Generate a point
	d := make([]byte, 32)
	d[31] = 42

	x, originalY, err := mulBase(curve, d)
	if err != nil {
		t.Fatalf("mulBase failed: %v", err)
	}

	// Recover Y from X
	recovered, err := recoverY(curve, x, isOddBytes(originalY))
	if err != nil {
		t.Fatalf("recoverY failed: %v", err)
	}

	// Recovered Y should match original
	if !bytes.Equal(recovered, originalY) {
		t.Errorf("recovered Y does not match original")
	}
}

// TestRecoverY512 tests Y coordinate recovery on 512-bit TC26 curve
func TestRecoverY512(t *testing.T) {
	curve := TC26_512_A

	// Generate a point
	d := make([]byte, 64)
	d[63] = 42

	x, originalY, err := mulBase(curve, d)
	if err != nil {
		t.Fatalf("mulBase failed: %v", err)
	}

	// Recover Y from X
	recovered, err := recoverY(curve, x, isOddBytes(originalY))
	if err != nil {
		t.Fatalf("recoverY failed: %v", err)
	}

	// Recovered Y should match original
	if !bytes.Equal(recovered, originalY) {
		t.Errorf("recovered Y does not match original")
	}
}

// TestPublicKeyRoundTrip tests public key serialization roundtrip
func TestPublicKeyRoundTrip256(t *testing.T) {
	curve := TC26_256_A

	// Generate a key pair
	d := make([]byte, 32)
	d[31] = 100

	x, y, err := mulBase(curve, d)
	if err != nil {
		t.Fatalf("mulBase failed: %v", err)
	}

	pub := &PubKey{X: x, Y: y, Curve: curve}

	// Test compressed with prefix
	compressed := pub.ToCompressed(true)
	if len(compressed) != 33 {
		t.Errorf("compressed with prefix size: got %d, want 33", len(compressed))
	}

	recovered, err := FromCompressed(curve, compressed, true)
	if err != nil {
		t.Fatalf("FromCompressed with prefix failed: %v", err)
	}

	if !bytes.Equal(recovered.X, pub.X) || !bytes.Equal(recovered.Y, pub.Y) {
		t.Error("compressed roundtrip failed")
	}

	// Test uncompressed with prefix
	uncompressed := pub.ToUncompressed(true)
	if len(uncompressed) != 65 {
		t.Errorf("uncompressed with prefix size: got %d, want 65", len(uncompressed))
	}

	recovered, err = FromUncompressed(curve, uncompressed, true)
	if err != nil {
		t.Fatalf("FromUncompressed with prefix failed: %v", err)
	}

	if !bytes.Equal(recovered.X, pub.X) || !bytes.Equal(recovered.Y, pub.Y) {
		t.Error("uncompressed roundtrip failed")
	}
}

// TestPublicKeyRoundTrip512 tests public key serialization roundtrip on 512-bit curves
func TestPublicKeyRoundTrip512(t *testing.T) {
	curve := TC26_512_A

	// Generate a key pair
	d := make([]byte, 64)
	d[63] = 100

	x, y, err := mulBase(curve, d)
	if err != nil {
		t.Fatalf("mulBase failed: %v", err)
	}

	pub := &PubKey{X: x, Y: y, Curve: curve}

	// Test compressed with prefix
	compressed := pub.ToCompressed(true)
	if len(compressed) != 65 {
		t.Errorf("compressed with prefix size: got %d, want 65", len(compressed))
	}

	recovered, err := FromCompressed(curve, compressed, true)
	if err != nil {
		t.Fatalf("FromCompressed with prefix failed: %v", err)
	}

	if !bytes.Equal(recovered.X, pub.X) || !bytes.Equal(recovered.Y, pub.Y) {
		t.Error("compressed roundtrip failed")
	}

	// Test uncompressed with prefix
	uncompressed := pub.ToUncompressed(true)
	if len(uncompressed) != 129 {
		t.Errorf("uncompressed with prefix size: got %d, want 129", len(uncompressed))
	}

	recovered, err = FromUncompressed(curve, uncompressed, true)
	if err != nil {
		t.Fatalf("FromUncompressed with prefix failed: %v", err)
	}

	if !bytes.Equal(recovered.X, pub.X) || !bytes.Equal(recovered.Y, pub.Y) {
		t.Error("uncompressed roundtrip failed")
	}
}

// TestTC26_512_B tests 512-B curve support (gogost available)
func TestTC26_512_B(t *testing.T) {
	curve := TC26_512_B

	// Generate a key pair
	d := make([]byte, 64)
	d[63] = 50

	x, y, err := mulBase(curve, d)
	if err != nil {
		t.Fatalf("mulBase failed for 512-B: %v", err)
	}

	// Check sizes
	if len(x) != 64 || len(y) != 64 {
		t.Errorf("512-B key size mismatch: x=%d, y=%d (expected 64,64)", len(x), len(y))
	}

	// Both should be non-zero
	if allZero(x) || allZero(y) {
		t.Error("512-B generated zero coordinates")
	}

	// Test public key operations
	pub := &PubKey{X: x, Y: y, Curve: curve}
	compressed := pub.ToCompressed(true)
	if len(compressed) != 65 {
		t.Errorf("512-B compressed size: got %d, want 65", len(compressed))
	}
}

// TestTC26_512_C tests 512-C curve support (gogost available)
func TestTC26_512_C(t *testing.T) {
	curve := TC26_512_C

	// Generate a key pair
	d := make([]byte, 64)
	d[63] = 75

	x, y, err := mulBase(curve, d)
	if err != nil {
		t.Fatalf("mulBase failed for 512-C: %v", err)
	}

	// Check sizes
	if len(x) != 64 || len(y) != 64 {
		t.Errorf("512-C key size mismatch: x=%d, y=%d (expected 64,64)", len(x), len(y))
	}

	// Both should be non-zero
	if allZero(x) || allZero(y) {
		t.Error("512-C generated zero coordinates")
	}

	// Test public key operations
	pub := &PubKey{X: x, Y: y, Curve: curve}
	compressed := pub.ToCompressed(true)
	if len(compressed) != 65 {
		t.Errorf("512-C compressed size: got %d, want 65", len(compressed))
	}
}

// TestUnsupportedCurves tests that unsupported curves return errors
// (256-B/C/D and 512-D not available in gogost v1.0.0)
func TestUnsupportedCurves(t *testing.T) {
	unsupported := []struct {
		name  string
		curve Curve
	}{
		{"256-B", TC26_256_B},
		{"256-C", TC26_256_C},
		{"256-D", TC26_256_D},
		{"512-D", TC26_512_D},
	}

	for _, tc := range unsupported {
		t.Run(tc.name, func(t *testing.T) {
			d := make([]byte, 32)
			if tc.curve >= TC26_512_A {
				d = make([]byte, 64)
			}
			d[len(d)-1] = 1

			_, _, err := mulBase(tc.curve, d)
			if err == nil {
				t.Errorf("Expected error for unsupported curve %s, got nil", tc.name)
			}
		})
	}
}

// Helper functions
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func isOddBytes(b []byte) bool {
	return b[len(b)-1]&1 == 1
}
