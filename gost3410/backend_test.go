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
	compressed, err := pub.ToCompressed(true)
	if err != nil {
		t.Fatalf("ToCompressed with prefix failed: %v", err)
	}
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
	compressed, err := pub.ToCompressed(true)
	if err != nil {
		t.Fatalf("ToCompressed with prefix failed: %v", err)
	}
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
	compressed, err := pub.ToCompressed(true)
	if err != nil {
		t.Fatalf("ToCompressed failed for 512-B: %v", err)
	}
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
	compressed, err := pub.ToCompressed(true)
	if err != nil {
		t.Fatalf("ToCompressed failed for 512-C: %v", err)
	}
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

// TestPadToSizeExact tests padToSize with exact size input
func TestPadToSizeExact(t *testing.T) {
	b := []byte{0x01, 0x02, 0x03, 0x04}
	result := padToSize(b, 4)
	if !bytes.Equal(result, b) {
		t.Errorf("padToSize exact: got %x, want %x", result, b)
	}
}

// TestPadToSizeShort tests padToSize with short input (needs padding)
func TestPadToSizeShort(t *testing.T) {
	b := []byte{0x01, 0x02}
	result := padToSize(b, 4)
	expected := []byte{0x00, 0x00, 0x01, 0x02}
	if !bytes.Equal(result, expected) {
		t.Errorf("padToSize short: got %x, want %x", result, expected)
	}
}

// TestPadToSizeLong tests padToSize with oversized input (needs truncation)
func TestPadToSizeLong(t *testing.T) {
	b := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	result := padToSize(b, 4)
	expected := []byte{0x01, 0x02, 0x03, 0x04}
	if !bytes.Equal(result, expected) {
		t.Errorf("padToSize long: got %x, want %x", result, expected)
	}
}

// TestPadToSizeEmpty tests padToSize with empty input
func TestPadToSizeEmpty(t *testing.T) {
	b := []byte{}
	result := padToSize(b, 4)
	expected := []byte{0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(result, expected) {
		t.Errorf("padToSize empty: got %x, want %x", result, expected)
	}
}

// TestSerialization512AllFormats tests all 4 serialization formats for 512-bit curves (A/B/C)
func TestSerialization512AllFormats(t *testing.T) {
	curves := []struct {
		name  string
		curve Curve
	}{
		{"512-A", TC26_512_A},
		{"512-B", TC26_512_B},
		{"512-C", TC26_512_C},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			// Find a scalar whose public key X[0] < 0x80 (needed for no-prefix compressed format)
			// The no-prefix format uses MSB of X[0] as parity bit, so X[0] must not have MSB set
			var pub *PubKey
			for scalar := byte(1); scalar < 255; scalar++ {
				d := make([]byte, 64)
				d[63] = scalar
				x, y, err := mulBase(tc.curve, d)
				if err != nil {
					t.Fatalf("mulBase failed: %v", err)
				}
				if x[0] < 0x80 {
					pub = &PubKey{X: x, Y: y, Curve: tc.curve}
					break
				}
			}
			if pub == nil {
				t.Fatal("could not find a suitable key with X[0] < 0x80")
			}

			// Format 1: compressed with prefix (0x02/0x03 || X)
			t.Run("compressed_with_prefix", func(t *testing.T) {
				enc, err := pub.ToCompressed(true)
				if err != nil {
					t.Fatalf("ToCompressed failed: %v", err)
				}
				if len(enc) != 65 {
					t.Fatalf("compressed with prefix size: got %d, want 65", len(enc))
				}
				if enc[0] != 0x02 && enc[0] != 0x03 {
					t.Fatalf("invalid prefix byte: 0x%02x", enc[0])
				}
				recovered, err := FromCompressed(tc.curve, enc, true)
				if err != nil {
					t.Fatalf("FromCompressed failed: %v", err)
				}
				if !bytes.Equal(recovered.X, pub.X) || !bytes.Equal(recovered.Y, pub.Y) {
					t.Error("compressed with prefix roundtrip failed")
				}
			})

			// Format 2: compressed without prefix (X with MSB parity)
			t.Run("compressed_without_prefix", func(t *testing.T) {
				enc, err := pub.ToCompressed(false)
				if err != nil {
					t.Fatalf("ToCompressed failed: %v", err)
				}
				if len(enc) != 64 {
					t.Fatalf("compressed without prefix size: got %d, want 64", len(enc))
				}
				recovered, err := FromCompressed(tc.curve, enc, false)
				if err != nil {
					t.Fatalf("FromCompressed failed: %v", err)
				}
				if !bytes.Equal(recovered.X, pub.X) || !bytes.Equal(recovered.Y, pub.Y) {
					t.Error("compressed without prefix roundtrip failed")
				}
			})

			// Format 3: uncompressed with prefix (0x04 || X || Y)
			t.Run("uncompressed_with_prefix", func(t *testing.T) {
				enc := pub.ToUncompressed(true)
				if len(enc) != 129 {
					t.Fatalf("uncompressed with prefix size: got %d, want 129", len(enc))
				}
				if enc[0] != 0x04 {
					t.Fatalf("invalid prefix byte: 0x%02x", enc[0])
				}
				recovered, err := FromUncompressed(tc.curve, enc, true)
				if err != nil {
					t.Fatalf("FromUncompressed failed: %v", err)
				}
				if !bytes.Equal(recovered.X, pub.X) || !bytes.Equal(recovered.Y, pub.Y) {
					t.Error("uncompressed with prefix roundtrip failed")
				}
			})

			// Format 4: uncompressed without prefix (X || Y)
			t.Run("uncompressed_without_prefix", func(t *testing.T) {
				enc := pub.ToUncompressed(false)
				if len(enc) != 128 {
					t.Fatalf("uncompressed without prefix size: got %d, want 128", len(enc))
				}
				recovered, err := FromUncompressed(tc.curve, enc, false)
				if err != nil {
					t.Fatalf("FromUncompressed failed: %v", err)
				}
				if !bytes.Equal(recovered.X, pub.X) || !bytes.Equal(recovered.Y, pub.Y) {
					t.Error("uncompressed without prefix roundtrip failed")
				}
			})
		})
	}
}

// TestRecoverYInvalidX tests recoverY with an X coordinate not on the curve
func TestRecoverYInvalidX(t *testing.T) {
	// Use X=0 which is unlikely to be on the curve
	x := make([]byte, 32)
	_, err := recoverY(TC26_256_A, x, false)
	if err == nil {
		t.Error("recoverY should fail for x=0 (not on curve)")
	}
}

// TestRecoverYInvalidX512 tests recoverY with an invalid X on 512-bit curve
func TestRecoverYInvalidX512(t *testing.T) {
	x := make([]byte, 64)
	_, err := recoverY(TC26_512_A, x, true)
	if err == nil {
		t.Error("recoverY should fail for x=0 on 512-bit curve")
	}
}

// TestRecoverYUnsupportedCurve tests recoverY with unsupported curve
func TestRecoverYUnsupportedCurve(t *testing.T) {
	x := make([]byte, 32)
	x[31] = 1
	_, err := recoverY(TC26_256_B, x, false)
	if err == nil {
		t.Error("recoverY should fail for unsupported curve")
	}
}

// TestGetModeInvalidCurve tests getMode with invalid curve value
func TestGetModeInvalidCurve(t *testing.T) {
	_, err := getMode(Curve(99))
	if err == nil {
		t.Error("getMode should fail for invalid curve")
	}
}

// TestGetCurveOutOfRange tests getCurve with out-of-range values
func TestGetCurveOutOfRange(t *testing.T) {
	_, err := getCurve(Curve(-1))
	if err == nil {
		t.Error("getCurve should fail for negative curve")
	}
	_, err = getCurve(Curve(100))
	if err == nil {
		t.Error("getCurve should fail for out-of-range curve")
	}
}

// TestPadToSizeReturnsCopy verifies that padToSize always returns a new slice,
// so modifications to the result don't affect the input.
func TestPadToSizeReturnsCopy(t *testing.T) {
	t.Run("exact size returns copy", func(t *testing.T) {
		original := []byte{0x01, 0x02, 0x03, 0x04}
		input := append([]byte(nil), original...)
		result := padToSize(input, 4)
		if !bytes.Equal(result, original) {
			t.Fatalf("padToSize exact: got %x, want %x", result, original)
		}
		// Mutate result and verify input is unchanged
		result[0] = 0xFF
		if !bytes.Equal(input, original) {
			t.Error("padToSize exact size: mutating result affected input (shared memory)")
		}
	})

	t.Run("truncated returns copy", func(t *testing.T) {
		original := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
		input := append([]byte(nil), original...)
		result := padToSize(input, 4)
		expected := []byte{0x01, 0x02, 0x03, 0x04}
		if !bytes.Equal(result, expected) {
			t.Fatalf("padToSize long: got %x, want %x", result, expected)
		}
		// Mutate result and verify input is unchanged
		result[0] = 0xFF
		if !bytes.Equal(input, original) {
			t.Error("padToSize truncated: mutating result affected input (shared memory)")
		}
	})

	t.Run("padded returns new slice", func(t *testing.T) {
		original := []byte{0x01, 0x02}
		input := append([]byte(nil), original...)
		result := padToSize(input, 4)
		expected := []byte{0x00, 0x00, 0x01, 0x02}
		if !bytes.Equal(result, expected) {
			t.Fatalf("padToSize short: got %x, want %x", result, expected)
		}
		// Mutate result and verify input is unchanged
		result[2] = 0xFF
		if !bytes.Equal(input, original) {
			t.Error("padToSize padded: mutating result affected input (shared memory)")
		}
	})
}
