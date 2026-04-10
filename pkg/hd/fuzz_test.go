package hd

import (
	"testing"

	"github.com/rekurt/gost-crypto/internal/openssl"
	"github.com/rekurt/gost-crypto/pkg/gost3410"
)

// FuzzParsePath exercises ParsePath with arbitrary input strings
// to verify it never panics on malformed paths.
func FuzzParsePath(f *testing.F) {
	// Seed corpus with valid and edge-case paths.
	f.Add("m/44'/0'/0")
	f.Add("m")
	f.Add("")
	f.Add("m/")
	f.Add("/0/1/2")
	f.Add("m/0h/1h/2")
	f.Add("m/2147483647'/0")
	f.Add("m/abc")
	f.Add("m//1")
	f.Add("0'/1'/2'/3'/4'/5'")
	f.Add("m/0/0/0/0/0/0/0/0/0/0")

	f.Fuzz(func(t *testing.T, path string) {
		// ParsePath must not panic on any input.
		_, _ = ParsePath(path)
	})
}

// FuzzDerive exercises Derive with arbitrary seeds and paths to verify
// it never panics. Only valid parsable paths reach Derive; invalid ones
// are rejected early by ParsePath, which we still exercise here.
func FuzzDerive(f *testing.F) {
	if err := openssl.Init(); err != nil {
		f.Skip("gost-engine not available:", err)
	}

	// Seed corpus with representative (seed, path) pairs. The seed must
	// be at least 16 bytes for Master() to accept it; the fuzzer may
	// produce shorter seeds, in which case Master returns an error and
	// we skip the derivation step.
	f.Add(make([]byte, 32), "m/0")
	f.Add(make([]byte, 32), "m/0'/1/2")
	f.Add(make([]byte, 32), "m")
	f.Add(append(make([]byte, 16), 'x'), "m/0/1/2/3/4")

	f.Fuzz(func(t *testing.T, seed []byte, path string) {
		// Bound seed length so the fuzzer doesn't allocate huge buffers.
		if len(seed) > 1024 {
			return
		}
		master, err := Master(seed, gost3410.CurveTC26_256_A)
		if err != nil {
			return // invalid seed; nothing to derive
		}
		defer master.Zeroize()

		child, err := Derive(master, path, gost3410.CurveTC26_256_A)
		if err != nil {
			return // invalid path or deterministic derivation failure
		}
		defer child.Zeroize()

		if child.Key == nil {
			t.Fatalf("Derive returned nil key for path %q", path)
		}
	})
}
