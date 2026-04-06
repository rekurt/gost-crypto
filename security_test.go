package gostcrypto

import (
	"testing"
)

// TestZeroize_MarksKeyUnusable verifies that after Zeroize, Bytes returns
// an error — the key material has been securely wiped.
func TestZeroize_MarksKeyUnusable(t *testing.T) {
	skipIfNoEngine(t)

	priv, err := GenerateKey(CurveTC26_256_A)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Sanity: Bytes works before Zeroize.
	b, err := priv.Bytes()
	if err != nil {
		t.Fatalf("Bytes before Zeroize: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("Bytes returned empty slice before Zeroize")
	}

	priv.Zeroize()

	// After Zeroize, Bytes() must return an error.
	_, err = priv.Bytes()
	if err == nil {
		t.Error("expected error from Bytes() after Zeroize")
	}
}

// TestCrossCurveRejection_Facade verifies that verifying a signature
// created with one curve using a key from a different curve is rejected.
func TestCrossCurveRejection_Facade(t *testing.T) {
	skipIfNoEngine(t)

	priv256, err := GenerateKey(CurveTC26_256_A)
	if err != nil {
		t.Fatalf("GenerateKey(256A): %v", err)
	}
	defer priv256.Zeroize()

	msg := []byte("cross-curve test")
	sig, err := Sign(priv256, msg)
	if err != nil {
		t.Fatalf("Sign(256A): %v", err)
	}

	priv512, err := GenerateKey(CurveTC26_512_A)
	if err != nil {
		t.Fatalf("GenerateKey(512A): %v", err)
	}
	defer priv512.Zeroize()

	// Verify with a 512-bit key against a 256-bit signature — must fail.
	ok, err := Verify(priv512.PublicKey(), msg, sig)
	if err == nil && ok {
		t.Error("cross-curve verification should not succeed")
	}
}

// TestSign_NilKey_Security verifies that Sign rejects a nil private key
// with ErrNilKey.
func TestSign_NilKey_Security(t *testing.T) {
	_, err := Sign(nil, []byte("test"))
	if err == nil {
		t.Error("expected error for nil key")
	}
	if err != ErrNilKey {
		t.Errorf("expected ErrNilKey, got %v", err)
	}
}

// TestVerify_NilKey_Security verifies that Verify rejects a nil public
// key with ErrNilKey.
func TestVerify_NilKey_Security(t *testing.T) {
	_, err := Verify(nil, []byte("test"), []byte("sig"))
	if err == nil {
		t.Error("expected error for nil key")
	}
	if err != ErrNilKey {
		t.Errorf("expected ErrNilKey, got %v", err)
	}
}

// TestAgree_EmptyUKM verifies that Agree rejects nil UKM with ErrEmptyUKM.
func TestAgree_EmptyUKM(t *testing.T) {
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

	_, err = Agree(privA, privB.PublicKey(), nil)
	if err == nil {
		t.Error("expected error for nil UKM")
	}
	if err != ErrEmptyUKM {
		t.Errorf("expected ErrEmptyUKM, got %v", err)
	}

	// Also test empty (non-nil) UKM.
	_, err = Agree(privA, privB.PublicKey(), []byte{})
	if err == nil {
		t.Error("expected error for empty UKM")
	}
	if err != ErrEmptyUKM {
		t.Errorf("expected ErrEmptyUKM for empty slice, got %v", err)
	}
}
