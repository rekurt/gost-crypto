package gost3410

import (
	"testing"
)

// FuzzFromCompressed fuzz-tests compressed public key deserialization.
// Verifies that FromCompressed never panics on arbitrary input and that
// successfully parsed keys can round-trip through ToCompressed/FromCompressed.
func FuzzFromCompressed(f *testing.F) {
	// Seed corpus: valid-length inputs for 256-bit (33 bytes with prefix, 32 without)
	f.Add(append([]byte{0x02}, make([]byte, 32)...), true)
	f.Add(append([]byte{0x03}, make([]byte, 32)...), true)
	f.Add(make([]byte, 32), false)
	// Invalid lengths and prefixes
	f.Add([]byte{0x04, 0x01}, true)
	f.Add([]byte{}, false)
	f.Add(make([]byte, 64), false)

	f.Fuzz(func(t *testing.T, data []byte, prefix bool) {
		// Try both 256-bit and 512-bit curves
		for _, curve := range []Curve{TC26_256_A, TC26_512_A} {
			pub, err := FromCompressed(curve, data, prefix)
			if err != nil {
				continue
			}

			// If parsing succeeded, verify round-trip
			reEncoded, err := pub.ToCompressed(prefix)
			if err != nil {
				// ToCompressed(false) can fail if X[0] >= 0x80; that's expected
				continue
			}

			pub2, err := FromCompressed(curve, reEncoded, prefix)
			if err != nil {
				t.Fatalf("round-trip FromCompressed failed: %v", err)
			}

			if len(pub.X) != len(pub2.X) || len(pub.Y) != len(pub2.Y) {
				t.Fatal("round-trip produced different coordinate sizes")
			}
		}
	})
}

// FuzzFromUncompressed fuzz-tests uncompressed public key deserialization.
// Verifies that FromUncompressed never panics on arbitrary input.
func FuzzFromUncompressed(f *testing.F) {
	// Seed corpus: valid-length inputs for 256-bit (65 bytes with prefix, 64 without)
	f.Add(append([]byte{0x04}, make([]byte, 64)...), true)
	f.Add(make([]byte, 64), false)
	// Invalid
	f.Add([]byte{0x03, 0x01}, true)
	f.Add([]byte{}, false)
	f.Add(make([]byte, 128), false)

	f.Fuzz(func(t *testing.T, data []byte, prefix bool) {
		for _, curve := range []Curve{TC26_256_A, TC26_512_A} {
			pub, err := FromUncompressed(curve, data, prefix)
			if err != nil {
				continue
			}

			// If parsing succeeded, verify round-trip
			reEncoded := pub.ToUncompressed(prefix)
			pub2, err := FromUncompressed(curve, reEncoded, prefix)
			if err != nil {
				t.Fatalf("round-trip FromUncompressed failed: %v", err)
			}

			if len(pub.X) != len(pub2.X) || len(pub.Y) != len(pub2.Y) {
				t.Fatal("round-trip produced different coordinate sizes")
			}
		}
	})
}
