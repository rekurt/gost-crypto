package hd

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/rekurt/gost-crypto/gost3410"
)

// TestMaster256 tests master key generation with Streebog-256
func TestMaster256(t *testing.T) {
	seed := []byte("test seed for master key generation")

	privKey, chainCode, err := Master(seed, gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Master failed: %v", err)
	}

	// Check private key
	if privKey == nil {
		t.Fatal("Master returned nil private key")
	}
	if privKey.Curve != gost3410.TC26_256_A {
		t.Error("Master returned wrong curve for Streebog256")
	}
	if len(privKey.D) != 32 {
		t.Errorf("Master private key size: got %d, want 32", len(privKey.D))
	}

	// Check chain code
	if len(chainCode) != 32 {
		t.Errorf("Master chain code size: got %d, want 32", len(chainCode))
	}

	// Check that private key is not all zeros
	allZero := true
	for _, b := range privKey.D {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Master private key is all zeros")
	}
}

// TestMaster512 tests master key generation with Streebog-512
func TestMaster512(t *testing.T) {
	seed := []byte("test seed for master key generation")

	privKey, chainCode, err := Master(seed, gost3410.Streebog512)
	if err != nil {
		t.Fatalf("Master failed: %v", err)
	}

	// Check private key
	if privKey == nil {
		t.Fatal("Master returned nil private key")
	}
	if privKey.Curve != gost3410.TC26_512_A {
		t.Error("Master returned wrong curve for Streebog512")
	}
	if len(privKey.D) != 64 {
		t.Errorf("Master private key size: got %d, want 64", len(privKey.D))
	}

	// Check chain code
	if len(chainCode) != 64 {
		t.Errorf("Master chain code size: got %d, want 64", len(chainCode))
	}

	// Check that private key is not all zeros
	allZero := true
	for _, b := range privKey.D {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Master private key is all zeros")
	}
}

// TestMasterEmptySeed tests error handling for empty seed
func TestMasterEmptySeed(t *testing.T) {
	_, _, err := Master([]byte{}, gost3410.Streebog256)
	if err == nil {
		t.Error("Master with empty seed should fail")
	}
}

// TestDeriveSimplePath tests derivation with simple path
func TestDeriveSimplePath256(t *testing.T) {
	seed := []byte("test seed")
	master, chainCode, err := Master(seed, gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Master failed: %v", err)
	}

	// Check initial chain code size
	if len(chainCode) != 32 {
		t.Fatalf("master chain code size: got %d, want 32", len(chainCode))
	}

	// Derive child at path m/0
	child, newChainCode, err := Derive(master, chainCode, "m/0", gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Derive failed: %v", err)
	}

	// Check derived key
	if child == nil {
		t.Fatal("Derive returned nil key")
	}
	if len(child.D) != 32 {
		t.Errorf("derived key size: got %d, want 32", len(child.D))
	}

	// Check chain code - should match the key size for consistency
	if len(newChainCode) != 32 {
		t.Errorf("derived chain code size: got %d, want 32", len(newChainCode))
	}

	// Derived key should be different from master
	if bytes.Equal(child.D, master.D) {
		t.Error("derived key equals master key - derivation failed")
	}

	// Chain code should be different
	if bytes.Equal(newChainCode, chainCode) {
		t.Error("derived chain code equals master chain code")
	}
}

// TestDeriveHardenedPath tests derivation with hardened path
func TestDeriveHardenedPath256(t *testing.T) {
	seed := []byte("test seed")
	master, chainCode, err := Master(seed, gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Master failed: %v", err)
	}

	// Derive hardened child at path m/0'
	child, _, err := Derive(master, chainCode, "m/0'", gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Derive hardened failed: %v", err)
	}

	if child == nil {
		t.Fatal("Derive hardened returned nil key")
	}

	// Derive non-hardened child at path m/0
	childNonHardened, _, err := Derive(master, chainCode, "m/0", gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Derive non-hardened failed: %v", err)
	}

	// Hardened and non-hardened derivations should produce different keys
	if bytes.Equal(child.D, childNonHardened.D) {
		t.Error("hardened and non-hardened derivations produced same key")
	}
}

// TestDeriveMixedPath tests derivation with mixed hardened/non-hardened path
func TestDeriveMixedPath256(t *testing.T) {
	seed := []byte("test seed")
	master, chainCode, err := Master(seed, gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Master failed: %v", err)
	}

	// Derive at path m/0'/1/2'
	child, _, err := Derive(master, chainCode, "m/0'/1/2'", gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Derive mixed path failed: %v", err)
	}

	if child == nil {
		t.Fatal("Derive returned nil key")
	}
	if len(child.D) != 32 {
		t.Errorf("derived key size: got %d, want 32", len(child.D))
	}
}

// TestDeriveConsistent tests that same seed produces consistent derivations
func TestDeriveConsistent256(t *testing.T) {
	seed := []byte("test seed")

	// First derivation
	master1, chainCode1, err := Master(seed, gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Master failed: %v", err)
	}

	child1, _, err := Derive(master1, chainCode1, "m/44'/0'/0'/0/0", gost3410.Streebog256)
	if err != nil {
		t.Fatalf("First Derive failed: %v", err)
	}

	// Second derivation with same seed
	master2, chainCode2, err := Master(seed, gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Master failed: %v", err)
	}

	child2, _, err := Derive(master2, chainCode2, "m/44'/0'/0'/0/0", gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Second Derive failed: %v", err)
	}

	// Keys should be identical
	if !bytes.Equal(child1.D, child2.D) {
		t.Error("same seed produced different derived keys - not deterministic")
	}
}

// TestDeriveDifferentPaths tests that different paths produce different keys
func TestDeriveDifferentPaths256(t *testing.T) {
	seed := []byte("test seed")
	master, chainCode, err := Master(seed, gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Master failed: %v", err)
	}

	child1, _, err := Derive(master, chainCode, "m/0", gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Derive path 1 failed: %v", err)
	}

	child2, _, err := Derive(master, chainCode, "m/1", gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Derive path 2 failed: %v", err)
	}

	// Different paths should produce different keys
	if bytes.Equal(child1.D, child2.D) {
		t.Error("different paths produced same derived key")
	}
}

// TestDeriveInvalidPath tests error handling for invalid paths
func TestDeriveInvalidPath(t *testing.T) {
	seed := []byte("test seed")
	master, chainCode, err := Master(seed, gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Master failed: %v", err)
	}

	tests := []struct {
		name       string
		path       string
		shouldFail bool
	}{
		{"missing m prefix", "0/1/2", true},
		{"invalid index", "m/abc", true},
		{"negative index", "m/-1", true},
		{"empty path", "m/", false}, // m/ is valid (root), produces same key on first derivation
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Derive(master, chainCode, tt.path, gost3410.Streebog256)
			if tt.shouldFail && err == nil {
				t.Errorf("Derive with invalid path %q should fail", tt.path)
			}
			if !tt.shouldFail && err != nil {
				t.Errorf("Derive with valid path %q should succeed, got %v", tt.path, err)
			}
		})
	}
}

// TestDeriveLongPath tests derivation through long path
func TestDeriveLongPath256(t *testing.T) {
	seed := []byte("test seed")
	master, chainCode, err := Master(seed, gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Master failed: %v", err)
	}

	// Long BIP32-like path
	path := "m/44'/0'/0'/0/0"
	child, _, err := Derive(master, chainCode, path, gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Derive long path failed: %v", err)
	}

	if child == nil {
		t.Fatal("Derive returned nil key")
	}

	// Key should be different from master
	if bytes.Equal(child.D, master.D) {
		t.Error("long path derivation produced master key")
	}
}

// TestMaster512Consistency tests consistency of Streebog512 derivations
func TestMaster512Consistency(t *testing.T) {
	seed := []byte("test seed")

	master1, chainCode1, err := Master(seed, gost3410.Streebog512)
	if err != nil {
		t.Fatalf("Master failed: %v", err)
	}

	master2, chainCode2, err := Master(seed, gost3410.Streebog512)
	if err != nil {
		t.Fatalf("Master failed: %v", err)
	}

	if !bytes.Equal(master1.D, master2.D) {
		t.Error("same seed produced different master keys with Streebog512")
	}

	if !bytes.Equal(chainCode1, chainCode2) {
		t.Error("same seed produced different chain codes with Streebog512")
	}
}

// TestDerive512 tests derivation with Streebog-512
func TestDerive512(t *testing.T) {
	seed := []byte("test seed")
	master, chainCode, err := Master(seed, gost3410.Streebog512)
	if err != nil {
		t.Fatalf("Master failed: %v", err)
	}

	child, _, err := Derive(master, chainCode, "m/0'/1/2'", gost3410.Streebog512)
	if err != nil {
		t.Fatalf("Derive failed: %v", err)
	}

	if child == nil {
		t.Fatal("Derive returned nil key")
	}

	if child.Curve != gost3410.TC26_512_A {
		t.Error("Derive returned wrong curve for Streebog512")
	}

	if len(child.D) != 64 {
		t.Errorf("derived key size: got %d, want 64", len(child.D))
	}
}

// TestMasterDifferentSeeds tests that different seeds produce different keys
func TestMasterDifferentSeeds(t *testing.T) {
	seed1 := []byte("seed1")
	seed2 := []byte("seed2")

	master1, _, err := Master(seed1, gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Master failed: %v", err)
	}

	master2, _, err := Master(seed2, gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Master failed: %v", err)
	}

	if bytes.Equal(master1.D, master2.D) {
		t.Error("different seeds produced same master key")
	}
}

// TestDeriveChainCodePropagation tests that chain code propagates correctly
func TestDeriveChainCodePropagation(t *testing.T) {
	seed := []byte("test seed")
	master, chainCode, err := Master(seed, gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Master failed: %v", err)
	}

	// Derive first level
	child1, chainCode1, err := Derive(master, chainCode, "m/0", gost3410.Streebog256)
	if err != nil {
		t.Fatalf("First Derive failed: %v", err)
	}

	// Derive second level using first level's chain code
	child2, _, err := Derive(child1, chainCode1, "m/0", gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Second Derive failed: %v", err)
	}

	// Direct path should match step-by-step derivation
	childDirect, _, err := Derive(master, chainCode, "m/0/0", gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Direct Derive failed: %v", err)
	}

	if !bytes.Equal(child2.D, childDirect.D) {
		t.Error("step-by-step derivation does not match direct path")
	}
}

// BenchmarkMaster256 benchmarks master key generation with Streebog-256
func BenchmarkMaster256(b *testing.B) {
	seed := []byte("test seed for benchmarking")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = Master(seed, gost3410.Streebog256)
	}
}

// BenchmarkDerive256 benchmarks key derivation with Streebog-256
func BenchmarkDerive256(b *testing.B) {
	seed := []byte("test seed")
	master, chainCode, _ := Master(seed, gost3410.Streebog256)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = Derive(master, chainCode, "m/0'/1/2'", gost3410.Streebog256)
	}
}

// BenchmarkDeriveLongPath benchmarks derivation through long path
func BenchmarkDeriveLongPath(b *testing.B) {
	seed := []byte("test seed")
	master, chainCode, _ := Master(seed, gost3410.Streebog256)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = Derive(master, chainCode, "m/44'/0'/0'/0/0", gost3410.Streebog256)
	}
}

// TestDeriveEmptyPathReturnsParent tests that Derive with "m/" (empty segments after m/)
// returns the parent key unchanged, since there are no derivation steps to apply.
func TestDeriveEmptyPathReturnsParent(t *testing.T) {
	seed := []byte("test seed for empty path")
	master, chainCode, err := Master(seed, gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Master failed: %v", err)
	}

	// "m/" means no child indices - should return the same key
	child, childChain, err := Derive(master, chainCode, "m/", gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Derive with m/ failed: %v", err)
	}

	// With no derivation steps, the result should be the parent key itself
	if !bytes.Equal(child.D, master.D) {
		t.Error("Derive with empty path should return parent key")
	}

	if !bytes.Equal(childChain, chainCode) {
		t.Error("Derive with empty path should return parent chain code")
	}
}

// TestMasterDifferentSeedsDifferentKeys verifies that two different seeds
// produce different master keys for both Streebog256 and Streebog512.
func TestMasterDifferentSeedsDifferentKeys(t *testing.T) {
	seeds := [][]byte{
		[]byte("first unique seed"),
		[]byte("second unique seed"),
		[]byte("third unique seed"),
	}

	for _, h := range []gost3410.HashID{gost3410.Streebog256, gost3410.Streebog512} {
		keys := make([][]byte, len(seeds))
		for i, seed := range seeds {
			master, _, err := Master(seed, h)
			if err != nil {
				t.Fatalf("Master(%d) failed: %v", i, err)
			}
			keys[i] = master.D
		}

		// All keys must be different from each other
		for i := 0; i < len(keys); i++ {
			for j := i + 1; j < len(keys); j++ {
				if bytes.Equal(keys[i], keys[j]) {
					t.Errorf("seeds %d and %d produced identical master keys (hash=%d)", i, j, h)
				}
			}
		}
	}
}

// FuzzParsePath fuzz-tests the parsePath function with arbitrary inputs.
func FuzzParsePath(f *testing.F) {
	// Seed corpus with valid and edge-case paths
	f.Add("")
	f.Add("0")
	f.Add("0'")
	f.Add("0/1/2")
	f.Add("0'/1/2'")
	f.Add("44'/0'/0'/0/0")
	f.Add("abc")
	f.Add("0/abc/1")
	f.Add("-1")
	f.Add("999999999")
	f.Add("/")
	f.Add("//")
	f.Add("'")

	f.Fuzz(func(t *testing.T, path string) {
		// parsePath should never panic - it should either return valid indices or an error
		indices, err := parsePath(path)
		if err != nil {
			return
		}

		// If no error, indices should be valid
		for _, idx := range indices {
			// Each index value should be a valid uint32 (already guaranteed by type)
			_ = idx.value
			_ = idx.hardened
		}
	})
}

func ExampleMaster() {
	seed := []byte("my secure seed phrase")

	privKey, chainCode, err := Master(seed, gost3410.Streebog256)
	if err != nil {
		panic(err)
	}

	fmt.Println("key size:", len(privKey.D))
	fmt.Println("chain code size:", len(chainCode))
	// Output:
	// key size: 32
	// chain code size: 32
}

// TestDeriveHashCurveMismatch verifies that Derive returns a clear error
// when the hash variant does not match the parent key's curve size.
func TestDeriveHashCurveMismatch(t *testing.T) {
	// Generate a 256-bit master key
	seed := []byte("test seed for mismatch")
	master256, chainCode256, err := Master(seed, gost3410.Streebog256)
	if err != nil {
		t.Fatalf("Master256 failed: %v", err)
	}

	// Generate a 512-bit master key
	master512, chainCode512, err := Master(seed, gost3410.Streebog512)
	if err != nil {
		t.Fatalf("Master512 failed: %v", err)
	}

	// Streebog512 hash with 256-bit key should fail
	_, _, err = Derive(master256, chainCode256, "m/0", gost3410.Streebog512)
	if err == nil {
		t.Error("Derive with Streebog512 + 256-bit key should fail")
	}
	if err != nil && !strings.Contains(err.Error(), "does not match key size") {
		t.Errorf("expected 'does not match key size' error, got: %v", err)
	}

	// Streebog256 hash with 512-bit key should fail
	_, _, err = Derive(master512, chainCode512, "m/0", gost3410.Streebog256)
	if err == nil {
		t.Error("Derive with Streebog256 + 512-bit key should fail")
	}
	if err != nil && !strings.Contains(err.Error(), "does not match key size") {
		t.Errorf("expected 'does not match key size' error, got: %v", err)
	}
}

// TestParsePathEmptySegment verifies that parsePath rejects paths with
// empty segments (e.g., "0//1") and returns a descriptive error.
func TestParsePathEmptySegment(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"double slash", "0//1"},
		{"leading slash", "/0/1"},
		{"trailing slash", "0/1/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePath(tt.path)
			if err == nil {
				t.Errorf("parsePath(%q) should fail with empty segment error", tt.path)
			}
			if err != nil && !strings.Contains(err.Error(), "empty path segment") {
				t.Errorf("parsePath(%q): expected 'empty path segment' error, got: %v", tt.path, err)
			}
		})
	}
}
