package gost3411

import (
	"encoding/hex"
	"hash"
	"os"
	"testing"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

func skipIfNoEngine(t *testing.T) {
	t.Helper()
	if err := openssl.Init(); err != nil {
		t.Skip("gost-engine not available:", err)
	}
}

func TestSum256_RFC6986_M1(t *testing.T) {
	skipIfNoEngine(t)
	msg := []byte("012345678901234567890123456789012345678901234567890123456789012")
	got := Sum256(msg)
	want := mustDecodeHex(t, "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500")
	if got != [32]byte(want) {
		t.Errorf("Sum256(M1) mismatch:\ngot  %x\nwant %x", got, want)
	}
}

func TestSum512_RFC6986_M1(t *testing.T) {
	skipIfNoEngine(t)
	msg := []byte("012345678901234567890123456789012345678901234567890123456789012")
	got := Sum512(msg)
	want := mustDecodeHex(t, "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48")
	if got != [64]byte(want) {
		t.Errorf("Sum512(M1) mismatch:\ngot  %x\nwant %x", got, want)
	}
}

func TestNew256_Incremental(t *testing.T) {
	skipIfNoEngine(t)
	h := New256()
	h.Write([]byte("01234567890123456789012345678901"))
	h.Write([]byte("2345678901234567890123456789012"))
	got := h.Sum(nil)
	want := Sum256([]byte("012345678901234567890123456789012345678901234567890123456789012"))
	if [32]byte(got) != want {
		t.Error("Incremental hash != one-shot hash")
	}
}

func TestNew256_SumDoesNotAlterState(t *testing.T) {
	skipIfNoEngine(t)
	h := New256()
	h.Write([]byte("0123456789012345"))

	// Call Sum mid-stream; it must not alter the hash state.
	_ = h.Sum(nil)

	h.Write([]byte("67890123456789012345678901234567890123456789012"))
	got := h.Sum(nil)
	want := Sum256([]byte("012345678901234567890123456789012345678901234567890123456789012"))
	if [32]byte(got) != want {
		t.Error("Sum() altered internal state: incremental hash != one-shot hash")
	}
}

func TestNew256_ImplementsHashInterface(t *testing.T) {
	skipIfNoEngine(t)
	var _ hash.Hash = New256()
}

func TestNew512_ImplementsHashInterface(t *testing.T) {
	skipIfNoEngine(t)
	var _ hash.Hash = New512()
}

func TestWrite_AcceptsLargeInputWithoutError(t *testing.T) {
	h := &streebogHash{}
	defer h.closeResources()

	in := make([]byte, memoryBufferLimit+1)
	n, err := h.Write(in)
	if err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	if n != len(in) {
		t.Fatalf("Write() n = %d, want %d", n, len(in))
	}
	if h.spill == nil {
		t.Fatal("expected spill file for large write")
	}
}

func TestReset_RemovesSpillFile(t *testing.T) {
	h := &streebogHash{}
	in := make([]byte, memoryBufferLimit+1)
	if _, err := h.Write(in); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	name := h.spill.Name()
	h.Reset()

	if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Fatalf("spill file still exists after Reset(), stat err = %v", err)
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}
