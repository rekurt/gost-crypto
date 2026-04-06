package gostcrypto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

func skipIfNoEngine(t *testing.T) {
	t.Helper()
	if err := openssl.Init(); err != nil {
		t.Skip("gost-engine not available:", err)
	}
}

// TestSign_Verify_Roundtrip_256A verifies that Sign then Verify round-trips
// on CurveTC26_256_A.
func TestSign_Verify_Roundtrip_256A(t *testing.T) {
	skipIfNoEngine(t)

	priv, err := GenerateKey(CurveTC26_256_A)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	defer priv.Zeroize()

	msg := []byte("Hello, GOST!")

	sig, err := Sign(priv, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature is empty")
	}

	pub := priv.PublicKey()
	ok, err := Verify(pub, msg, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("valid signature rejected")
	}

	// Corrupted signature must fail.
	corrupt := make([]byte, len(sig))
	copy(corrupt, sig)
	corrupt[0] ^= 0xff

	ok, err = Verify(pub, msg, corrupt)
	if err != nil {
		t.Fatalf("Verify(corrupt): %v", err)
	}
	if ok {
		t.Error("corrupted signature accepted")
	}

	// Different message must fail.
	ok, err = Verify(pub, []byte("different message"), sig)
	if err != nil {
		t.Fatalf("Verify(wrong msg): %v", err)
	}
	if ok {
		t.Error("signature valid for wrong message")
	}
}

// TestSign_Verify_AllCurves tests Sign+Verify on all eight TC26 curves.
func TestSign_Verify_AllCurves(t *testing.T) {
	skipIfNoEngine(t)

	msg := []byte("test message for all curves")

	for _, c := range AllCurves() {
		c := c
		t.Run(c.String(), func(t *testing.T) {
			priv, err := GenerateKey(c)
			if err != nil {
				t.Fatalf("GenerateKey(%s): %v", c, err)
			}
			defer priv.Zeroize()

			sig, err := Sign(priv, msg)
			if err != nil {
				t.Fatalf("Sign(%s): %v", c, err)
			}

			pub := priv.PublicKey()
			ok, err := Verify(pub, msg, sig)
			if err != nil {
				t.Fatalf("Verify(%s): %v", c, err)
			}
			if !ok {
				t.Errorf("valid signature rejected on %s", c)
			}
		})
	}
}

// TestHashSum256_Deterministic verifies that HashSum256 is deterministic.
func TestHashSum256_Deterministic(t *testing.T) {
	skipIfNoEngine(t)

	data := []byte("deterministic hash test")

	h1 := HashSum256(data)
	h2 := HashSum256(data)

	if h1 != h2 {
		t.Errorf("HashSum256 not deterministic:\n  h1 = %x\n  h2 = %x", h1, h2)
	}

	// Different data must produce a different hash.
	h3 := HashSum256([]byte("different data"))
	if h1 == h3 {
		t.Error("different data produced the same hash")
	}

	// Empty data must be valid.
	h4 := HashSum256(nil)
	h5 := HashSum256([]byte{})
	if h4 != h5 {
		t.Errorf("nil and empty data produced different hashes:\n  nil = %x\n  empty = %x", h4, h5)
	}
}

// TestHashSum512_Deterministic verifies that HashSum512 is deterministic.
func TestHashSum512_Deterministic(t *testing.T) {
	skipIfNoEngine(t)

	data := []byte("deterministic hash test 512")

	h1 := HashSum512(data)
	h2 := HashSum512(data)

	if h1 != h2 {
		t.Errorf("HashSum512 not deterministic:\n  h1 = %x\n  h2 = %x", h1, h2)
	}

	// Different data must produce a different hash.
	h3 := HashSum512([]byte("different data"))
	if h1 == h3 {
		t.Error("different data produced the same hash")
	}
}

// TestAgree_Symmetric verifies that Agree(privA, pubB, ukm) == Agree(privB, pubA, ukm).
func TestAgree_Symmetric(t *testing.T) {
	skipIfNoEngine(t)

	privA, err := GenerateKey(CurveTC26_256_A)
	if err != nil {
		t.Fatalf("GenerateKey(A): %v", err)
	}
	defer privA.Zeroize()

	privB, err := GenerateKey(CurveTC26_256_A)
	if err != nil {
		t.Fatalf("GenerateKey(B): %v", err)
	}
	defer privB.Zeroize()

	ukm := make([]byte, 8)
	if _, err := rand.Read(ukm); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	secretAB, err := Agree(privA, privB.PublicKey(), ukm)
	if err != nil {
		t.Fatalf("Agree(A, pubB): %v", err)
	}

	secretBA, err := Agree(privB, privA.PublicKey(), ukm)
	if err != nil {
		t.Fatalf("Agree(B, pubA): %v", err)
	}

	if !bytes.Equal(secretAB, secretBA) {
		t.Errorf("Agree is not symmetric:\n  AB = %x\n  BA = %x", secretAB, secretBA)
	}

	if len(secretAB) == 0 {
		t.Error("shared secret is empty")
	}
}

// TestAgree_DifferentUKM verifies that different UKM values produce
// different shared secrets.
func TestAgree_DifferentUKM(t *testing.T) {
	skipIfNoEngine(t)

	privA, err := GenerateKey(CurveTC26_256_A)
	if err != nil {
		t.Fatalf("GenerateKey(A): %v", err)
	}
	defer privA.Zeroize()

	privB, err := GenerateKey(CurveTC26_256_A)
	if err != nil {
		t.Fatalf("GenerateKey(B): %v", err)
	}
	defer privB.Zeroize()

	ukm1 := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	ukm2 := []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}

	s1, err := Agree(privA, privB.PublicKey(), ukm1)
	if err != nil {
		t.Fatalf("Agree(ukm1): %v", err)
	}

	s2, err := Agree(privA, privB.PublicKey(), ukm2)
	if err != nil {
		t.Fatalf("Agree(ukm2): %v", err)
	}

	if bytes.Equal(s1, s2) {
		t.Error("different UKMs produced the same shared secret")
	}
}

// TestSign_NilKey verifies that Sign handles nil keys correctly.
func TestSign_NilKey(t *testing.T) {
	_, err := Sign(nil, []byte("msg"))
	if err != ErrNilKey {
		t.Errorf("Sign(nil): got %v, want ErrNilKey", err)
	}
}

// TestVerify_NilKey verifies that Verify handles nil keys correctly.
func TestVerify_NilKey(t *testing.T) {
	_, err := Verify(nil, []byte("msg"), []byte("sig"))
	if err != ErrNilKey {
		t.Errorf("Verify(nil): got %v, want ErrNilKey", err)
	}
}

// TestAllCurves_Count verifies that AllCurves returns all 8 curves.
func TestAllCurves_Count(t *testing.T) {
	curves := AllCurves()
	if len(curves) != 8 {
		t.Errorf("AllCurves() returned %d curves, want 8", len(curves))
	}
}

// TestSign_Verify_512BitCurve verifies Sign+Verify on a 512-bit curve.
func TestSign_Verify_512BitCurve(t *testing.T) {
	skipIfNoEngine(t)

	priv, err := GenerateKey(CurveTC26_512_A)
	if err != nil {
		t.Fatalf("GenerateKey(512-A): %v", err)
	}
	defer priv.Zeroize()

	msg := []byte("512-bit curve test message")

	sig, err := Sign(priv, msg)
	if err != nil {
		t.Fatalf("Sign(512-A): %v", err)
	}

	pub := priv.PublicKey()
	ok, err := Verify(pub, msg, sig)
	if err != nil {
		t.Fatalf("Verify(512-A): %v", err)
	}
	if !ok {
		t.Error("valid 512-bit signature rejected")
	}
}
