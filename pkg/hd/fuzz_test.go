package hd

import (
	"testing"
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
