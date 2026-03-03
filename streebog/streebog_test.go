package streebog

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestStreebog256KnownVectors tests Streebog-256 with test vectors from gogost backend
// Note: Using actual gogost output as reference vectors since that's our implementation backend
func TestStreebog256KnownVectors(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			// Test vector from gogost backend implementation
			name:     "abc",
			input:    "abc",
			expected: "4e2919cf137ed41ec4fb6270c61826cc4fffb660341e0af3688cd0626d23b481",
		},
		{
			// Test vector from gogost backend implementation
			name:     "empty string",
			input:    "",
			expected: "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := []byte(tt.input)
			digest := Sum256(input)
			got := hex.EncodeToString(digest[:])

			if got != tt.expected {
				t.Errorf("Sum256(%q) = %s, want %s", tt.input, got, tt.expected)
			}
		})
	}
}

// TestStreebog512KnownVectors tests Streebog-512 with test vectors from gogost backend
// Note: Using actual gogost output as reference vectors since that's our implementation backend
func TestStreebog512KnownVectors(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			// Test vector from gogost backend implementation
			name:  "abc",
			input: "abc",
			expected: "28156e28317da7c98f4fe2bed6b542d0dab85bb224445fcedaf75d46e26d7eb8d" +
				"5997f3e0915dd6b7f0aab08d9c8beb0d8c64bae2ab8b3c8c6bc53b3bf0db728",
		},
		{
			// Test vector from gogost backend implementation
			name:  "empty string",
			input: "",
			expected: "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7" +
				"362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := []byte(tt.input)
			digest := Sum512(input)
			got := hex.EncodeToString(digest[:])

			if got != tt.expected {
				t.Errorf("Sum512(%q) = %s, want %s", tt.input, got, tt.expected)
			}
		})
	}
}

// TestStreebog256New tests creating a new Streebog-256 hash
func TestStreebog256New(t *testing.T) {
	h := New256()
	if h == nil {
		t.Fatal("New256 returned nil")
	}

	h.Write([]byte("test"))
	digest := h.Sum(nil)
	if len(digest) != 32 {
		t.Errorf("Streebog256 digest size: got %d, want 32", len(digest))
	}
}

// TestStreebog512New tests creating a new Streebog-512 hash
func TestStreebog512New(t *testing.T) {
	h := New512()
	if h == nil {
		t.Fatal("New512 returned nil")
	}

	h.Write([]byte("test"))
	digest := h.Sum(nil)
	if len(digest) != 64 {
		t.Errorf("Streebog512 digest size: got %d, want 64", len(digest))
	}
}

// TestStreebog256Incremental tests incremental hashing for Streebog-256
func TestStreebog256Incremental(t *testing.T) {
	data := []byte("The quick brown fox jumps over the lazy dog")

	// Hash all at once
	expected := Sum256(data)

	// Hash incrementally
	h := New256()
	h.Write(data[:10])
	h.Write(data[10:20])
	h.Write(data[20:])
	got := h.Sum(nil)

	if string(got) != string(expected[:]) {
		t.Error("incremental hashing does not match single hash")
	}
}

// TestStreebog512Incremental tests incremental hashing for Streebog-512
func TestStreebog512Incremental(t *testing.T) {
	data := []byte("The quick brown fox jumps over the lazy dog")

	// Hash all at once
	expected := Sum512(data)

	// Hash incrementally
	h := New512()
	h.Write(data[:10])
	h.Write(data[10:20])
	h.Write(data[20:])
	got := h.Sum(nil)

	if string(got) != string(expected[:]) {
		t.Error("incremental hashing does not match single hash")
	}
}

// TestStreebog256Reset tests hash reset functionality for Streebog-256
func TestStreebog256Reset(t *testing.T) {
	h := New256()
	h.Write([]byte("first"))
	digest1 := h.Sum(nil)

	h.Reset()
	h.Write([]byte("second"))
	digest2 := h.Sum(nil)

	if string(digest1) == string(digest2) {
		t.Error("reset failed - hashes should be different")
	}

	// Hash should match direct computation
	expected := Sum256([]byte("second"))
	if string(digest2) != string(expected[:]) {
		t.Error("reset hash does not match direct hash")
	}
}

// TestStreebog512Reset tests hash reset functionality for Streebog-512
func TestStreebog512Reset(t *testing.T) {
	h := New512()
	h.Write([]byte("first"))
	digest1 := h.Sum(nil)

	h.Reset()
	h.Write([]byte("second"))
	digest2 := h.Sum(nil)

	if string(digest1) == string(digest2) {
		t.Error("reset failed - hashes should be different")
	}

	// Hash should match direct computation
	expected := Sum512([]byte("second"))
	if string(digest2) != string(expected[:]) {
		t.Error("reset hash does not match direct hash")
	}
}

// TestStreebog256Size tests the size method for Streebog-256
func TestStreebog256Size(t *testing.T) {
	h := New256()
	if h.Size() != 32 {
		t.Errorf("Size(): got %d, want 32", h.Size())
	}
	if h.BlockSize() != 64 {
		t.Errorf("BlockSize(): got %d, want 64", h.BlockSize())
	}
}

// TestStreebog512Size tests the size method for Streebog-512
func TestStreebog512Size(t *testing.T) {
	h := New512()
	if h.Size() != 64 {
		t.Errorf("Size(): got %d, want 64", h.Size())
	}
	if h.BlockSize() != 64 {
		t.Errorf("BlockSize(): got %d, want 64", h.BlockSize())
	}
}

// mustDecodeHex decodes a hex string, panicking on error (test helper only).
func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("bad hex in test vector: " + err.Error())
	}
	return b
}

// RFC 6986 / GOST R 34.11-2012 official test vectors.
// M1: 63-byte ASCII string "012345678901234567890123456789012345678901234567890123456789012"
// M2: 72-byte binary message (Russian text in KOI8-R encoding)
// Hash values verified against RFC 6986 Appendix A (converted from LE to BE byte order).

func TestStreebog256_RFC6986(t *testing.T) {
	m2 := mustDecodeHex(
		"d1e520e2e5f2f0e82c20d1f2f0e8e1ee" +
			"e6e820e2edf3f6e82c20e2e5fef2fa20" +
			"f120eceef0ff20f1f2f0e5ebe0ece820" +
			"ede020f5f0e0e1f0fbff20efebfaeafb" +
			"20c8e3eef0e5e2fb")

	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "M1 (63-byte ASCII)",
			input:    []byte("012345678901234567890123456789012345678901234567890123456789012"),
			expected: "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500",
		},
		{
			name:     "M2 (72-byte binary)",
			input:    m2,
			expected: "9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest := Sum256(tt.input)
			got := hex.EncodeToString(digest[:])
			if got != tt.expected {
				t.Errorf("Streebog-256 = %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestStreebog512_RFC6986(t *testing.T) {
	m2 := mustDecodeHex(
		"d1e520e2e5f2f0e82c20d1f2f0e8e1ee" +
			"e6e820e2edf3f6e82c20e2e5fef2fa20" +
			"f120eceef0ff20f1f2f0e5ebe0ece820" +
			"ede020f5f0e0e1f0fbff20efebfaeafb" +
			"20c8e3eef0e5e2fb")

	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:  "M1 (63-byte ASCII)",
			input: []byte("012345678901234567890123456789012345678901234567890123456789012"),
			expected: "1b54d01a4af5b9d5cc3d86d68d285462" +
				"b19abc2475222f35c085122be4ba1ffa" +
				"00ad30f8767b3a82384c6574f024c311" +
				"e2a481332b08ef7f41797891c1646f48",
		},
		{
			name:  "M2 (72-byte binary)",
			input: m2,
			expected: "1e88e62226bfca6f9994f1f2d51569e0" +
				"daf8475a3b0fe61a5300eee46d961376" +
				"035fe83549ada2b8620fcd7c496ce5b3" +
				"3f0cb9dddc2b6460143b03dabac9fb28",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest := Sum512(tt.input)
			got := hex.EncodeToString(digest[:])
			if got != tt.expected {
				t.Errorf("Streebog-512 = %s, want %s", got, tt.expected)
			}
		})
	}
}

// TestStreebogLongMessage tests hashing of a large message (pattern repeated 1024 times).
// Verifies consistency between one-shot Sum and incremental Write across various chunk sizes.
func TestStreebogLongMessage(t *testing.T) {
	pattern := []byte("GOST R 34.11-2012 Streebog long message test pattern. ")
	const repeats = 1024
	data := bytes.Repeat(pattern, repeats)

	t.Run("256", func(t *testing.T) {
		expected := Sum256(data)

		// Incremental with 64-byte chunks (matches block size)
		h := New256()
		for off := 0; off < len(data); off += 64 {
			end := off + 64
			if end > len(data) {
				end = len(data)
			}
			h.Write(data[off:end])
		}
		got := h.Sum(nil)
		if !bytes.Equal(got, expected[:]) {
			t.Errorf("incremental (64B chunks) differs from one-shot Sum256")
		}

		// Incremental with 13-byte chunks (prime size, misaligned with blocks)
		h.Reset()
		for off := 0; off < len(data); off += 13 {
			end := off + 13
			if end > len(data) {
				end = len(data)
			}
			h.Write(data[off:end])
		}
		got = h.Sum(nil)
		if !bytes.Equal(got, expected[:]) {
			t.Errorf("incremental (13B chunks) differs from one-shot Sum256")
		}
	})

	t.Run("512", func(t *testing.T) {
		expected := Sum512(data)

		h := New512()
		for off := 0; off < len(data); off += 64 {
			end := off + 64
			if end > len(data) {
				end = len(data)
			}
			h.Write(data[off:end])
		}
		got := h.Sum(nil)
		if !bytes.Equal(got, expected[:]) {
			t.Errorf("incremental (64B chunks) differs from one-shot Sum512")
		}

		h.Reset()
		for off := 0; off < len(data); off += 13 {
			end := off + 13
			if end > len(data) {
				end = len(data)
			}
			h.Write(data[off:end])
		}
		got = h.Sum(nil)
		if !bytes.Equal(got, expected[:]) {
			t.Errorf("incremental (13B chunks) differs from one-shot Sum512")
		}
	})
}

// TestStreebogIncrementalMatchesSum_RFC6986 verifies that incremental hashing
// of RFC 6986 test vectors produces the same result as one-shot Sum functions.
func TestStreebogIncrementalMatchesSum_RFC6986(t *testing.T) {
	m1 := []byte("012345678901234567890123456789012345678901234567890123456789012")
	m2 := mustDecodeHex(
		"d1e520e2e5f2f0e82c20d1f2f0e8e1ee" +
			"e6e820e2edf3f6e82c20e2e5fef2fa20" +
			"f120eceef0ff20f1f2f0e5ebe0ece820" +
			"ede020f5f0e0e1f0fbff20efebfaeafb" +
			"20c8e3eef0e5e2fb")

	messages := []struct {
		name string
		data []byte
	}{
		{"M1", m1},
		{"M2", m2},
	}

	for _, msg := range messages {
		t.Run(msg.name+"/256", func(t *testing.T) {
			expected := Sum256(msg.data)

			// Split at various points to test boundary handling
			splits := []int{1, 7, 16, 32, len(msg.data) / 2}
			for _, split := range splits {
				if split >= len(msg.data) {
					continue
				}
				h := New256()
				h.Write(msg.data[:split])
				h.Write(msg.data[split:])
				got := h.Sum(nil)
				if !bytes.Equal(got, expected[:]) {
					t.Errorf("split at %d: incremental differs from Sum256", split)
				}
			}
		})

		t.Run(msg.name+"/512", func(t *testing.T) {
			expected := Sum512(msg.data)

			splits := []int{1, 7, 16, 32, len(msg.data) / 2}
			for _, split := range splits {
				if split >= len(msg.data) {
					continue
				}
				h := New512()
				h.Write(msg.data[:split])
				h.Write(msg.data[split:])
				got := h.Sum(nil)
				if !bytes.Equal(got, expected[:]) {
					t.Errorf("split at %d: incremental differs from Sum512", split)
				}
			}
		})
	}
}
