package streebog

import (
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
