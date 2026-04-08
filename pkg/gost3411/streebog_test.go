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

// RFC 6986 M2 test vector: the 576-bit message
// (0x0126...C0) as specified in GOST R 34.11-2012, Appendix A.
func TestSum256_RFC6986_M2(t *testing.T) {
	skipIfNoEngine(t)
	msg := mustDecodeHex(t, "d1e520e2e5f2f0e82c20d1f2f0e8e1ee"+
		"e6e820e2edf3f6e82c20e2e5fef2fa20"+
		"f120eceef0ff20f1f2f0e5ebe0ece820"+
		"ede020f5f0e0e1f0fbff20efebfaeafb"+
		"20c8e3eef0e5e2fb")
	got := Sum256(msg)
	want := mustDecodeHex(t, "9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50")
	if got != [32]byte(want) {
		t.Errorf("Sum256(M2) mismatch:\ngot  %x\nwant %x", got, want)
	}
}

func TestSum512_RFC6986_M2(t *testing.T) {
	skipIfNoEngine(t)
	msg := mustDecodeHex(t, "d1e520e2e5f2f0e82c20d1f2f0e8e1ee"+
		"e6e820e2edf3f6e82c20e2e5fef2fa20"+
		"f120eceef0ff20f1f2f0e5ebe0ece820"+
		"ede020f5f0e0e1f0fbff20efebfaeafb"+
		"20c8e3eef0e5e2fb")
	got := Sum512(msg)
	want := mustDecodeHex(t, "1e88e62226bfca6f9994f1f2d51569e0daf8475a3b0fe61a5300eee46d961376035fe83549ada2b8620fcd7c496ce5b33f0cb9dddc2b6460143b03dabac9fb28")
	if got != [64]byte(want) {
		t.Errorf("Sum512(M2) mismatch:\ngot  %x\nwant %x", got, want)
	}
}

// Test vector: empty message hash.
func TestSum256_Empty(t *testing.T) {
	skipIfNoEngine(t)
	got := Sum256(nil)
	want := mustDecodeHex(t, "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb")
	if got != [32]byte(want) {
		t.Errorf("Sum256(empty) mismatch:\ngot  %x\nwant %x", got, want)
	}
}

func TestSum512_Empty(t *testing.T) {
	skipIfNoEngine(t)
	got := Sum512(nil)
	want := mustDecodeHex(t, "8e945da209aa869f0455928b630484801e4896ce8d5ee4c5b98ccd5f0ca2b2dc722043707d0862e7b1d31aeb5c77a608cf2f3c69e1e56eca0929e8f7e1e5d11b")
	if got != [64]byte(want) {
		t.Errorf("Sum512(empty) mismatch:\ngot  %x\nwant %x", got, want)
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
	_ = hash.Hash(New256())
}

func TestNew512_ImplementsHashInterface(t *testing.T) {
	skipIfNoEngine(t)
	_ = hash.Hash(New512())
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
