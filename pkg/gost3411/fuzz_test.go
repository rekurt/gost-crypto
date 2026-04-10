package gost3411

import (
	"bytes"
	"testing"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

// FuzzSum256 verifies that Streebog-256 never panics on arbitrary input
// and is deterministic (same input always yields the same digest).
func FuzzSum256(f *testing.F) {
	if err := openssl.Init(); err != nil {
		f.Skip("gost-engine not available:", err)
	}
	f.Add([]byte{})
	f.Add([]byte("abc"))
	f.Add(bytes.Repeat([]byte{0xff}, 64))
	f.Add(bytes.Repeat([]byte{0x00}, 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		d1 := Sum256(data)
		d2 := Sum256(data)
		if d1 != d2 {
			t.Fatalf("Sum256 not deterministic for %d bytes", len(data))
		}
		if len(d1) != 32 {
			t.Fatalf("Sum256 wrong length: got %d", len(d1))
		}

		// Streaming hash must match one-shot.
		h := New256()
		_, _ = h.Write(data)
		stream := h.Sum(nil)
		if !bytes.Equal(stream, d1[:]) {
			t.Fatalf("streaming mismatch:\n  stream=%x\n  oneshot=%x", stream, d1)
		}
	})
}

// FuzzSum512 verifies that Streebog-512 never panics on arbitrary input
// and is deterministic.
func FuzzSum512(f *testing.F) {
	if err := openssl.Init(); err != nil {
		f.Skip("gost-engine not available:", err)
	}
	f.Add([]byte{})
	f.Add([]byte("abc"))
	f.Add(bytes.Repeat([]byte{0xaa}, 128))
	f.Add(bytes.Repeat([]byte{0x55}, 2048))

	f.Fuzz(func(t *testing.T, data []byte) {
		d1 := Sum512(data)
		d2 := Sum512(data)
		if d1 != d2 {
			t.Fatalf("Sum512 not deterministic for %d bytes", len(data))
		}
		if len(d1) != 64 {
			t.Fatalf("Sum512 wrong length: got %d", len(d1))
		}

		h := New512()
		_, _ = h.Write(data)
		stream := h.Sum(nil)
		if !bytes.Equal(stream, d1[:]) {
			t.Fatalf("streaming mismatch:\n  stream=%x\n  oneshot=%x", stream, d1)
		}
	})
}
