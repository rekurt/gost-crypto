package gost3410

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestVKO_Symmetry_256A verifies that VKO is symmetric on 256-A:
// VKO(privA, pubB, ukm) == VKO(privB, pubA, ukm).
func TestVKO_Symmetry_256A(t *testing.T) {
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

	secretAB, err := VKO(privA, privB.PublicKey(), ukm)
	if err != nil {
		t.Fatalf("VKO(A, pubB): %v", err)
	}

	secretBA, err := VKO(privB, privA.PublicKey(), ukm)
	if err != nil {
		t.Fatalf("VKO(B, pubA): %v", err)
	}

	if !bytes.Equal(secretAB, secretBA) {
		t.Errorf("VKO is not symmetric:\n  AB = %x\n  BA = %x", secretAB, secretBA)
	}

	if len(secretAB) == 0 {
		t.Error("shared secret is empty")
	}

	// Shared secret must not be all zeros.
	allZero := true
	for _, b := range secretAB {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("shared secret is all zeros")
	}
}

// TestVKO_AllCurves tests VKO symmetry on all eight TC26 curves.
func TestVKO_AllCurves(t *testing.T) {
	skipIfNoEngine(t)

	for _, c := range AllCurves() {
		c := c
		t.Run(c.String(), func(t *testing.T) {
			privA, err := GenerateKey(c)
			if err != nil {
				t.Fatalf("GenerateKey(A, %s): %v", c, err)
			}
			defer privA.Zeroize()

			privB, err := GenerateKey(c)
			if err != nil {
				t.Fatalf("GenerateKey(B, %s): %v", c, err)
			}
			defer privB.Zeroize()

			ukm := make([]byte, 8)
			if _, err := rand.Read(ukm); err != nil {
				t.Fatalf("rand.Read: %v", err)
			}

			secretAB, err := VKO(privA, privB.PublicKey(), ukm)
			if err != nil {
				t.Fatalf("VKO(A, pubB, %s): %v", c, err)
			}

			secretBA, err := VKO(privB, privA.PublicKey(), ukm)
			if err != nil {
				t.Fatalf("VKO(B, pubA, %s): %v", c, err)
			}

			if !bytes.Equal(secretAB, secretBA) {
				t.Errorf("VKO not symmetric on %s:\n  AB = %x\n  BA = %x", c, secretAB, secretBA)
			}

			if len(secretAB) == 0 {
				t.Errorf("shared secret is empty on %s", c)
			}
		})
	}
}

// TestVKO_DifferentUKM verifies that different UKM values produce
// different shared secrets from the same key pair.
func TestVKO_DifferentUKM(t *testing.T) {
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

	secret1, err := VKO(privA, privB.PublicKey(), ukm1)
	if err != nil {
		t.Fatalf("VKO(ukm1): %v", err)
	}

	secret2, err := VKO(privA, privB.PublicKey(), ukm2)
	if err != nil {
		t.Fatalf("VKO(ukm2): %v", err)
	}

	if bytes.Equal(secret1, secret2) {
		t.Errorf("different UKMs produced the same shared secret: %x", secret1)
	}
}

// TestVKO_NilKeys verifies that nil and zeroized keys return ErrNilKey.
func TestVKO_NilKeys(t *testing.T) {
	skipIfNoEngine(t)

	priv, err := GenerateKey(CurveTC26_256_A)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := priv.PublicKey()

	// nil PrivKey.
	_, err = VKO(nil, pub, nil)
	if err != ErrNilKey {
		t.Errorf("VKO(nil priv): got %v, want ErrNilKey", err)
	}

	// nil PubKey.
	_, err = VKO(priv, nil, nil)
	if err != ErrNilKey {
		t.Errorf("VKO(nil pub): got %v, want ErrNilKey", err)
	}

	// Zeroized PrivKey.
	priv2, err := GenerateKey(CurveTC26_256_A)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub2 := priv2.PublicKey()
	priv2.Zeroize()

	_, err = VKO(priv2, pub, nil)
	if err != ErrNilKey {
		t.Errorf("VKO(zeroized priv): got %v, want ErrNilKey", err)
	}

	_, err = VKO(priv, pub2, nil)
	if err != ErrNilKey {
		t.Errorf("VKO(zeroized pub): got %v, want ErrNilKey", err)
	}

	priv.Zeroize()
}

// TestVKO_CrossCurve verifies that keys on different curves produce
// ErrCurveMismatch.
func TestVKO_CrossCurve(t *testing.T) {
	skipIfNoEngine(t)

	priv256, err := GenerateKey(CurveTC26_256_A)
	if err != nil {
		t.Fatalf("GenerateKey(256-A): %v", err)
	}
	defer priv256.Zeroize()

	priv512, err := GenerateKey(CurveTC26_512_A)
	if err != nil {
		t.Fatalf("GenerateKey(512-A): %v", err)
	}
	defer priv512.Zeroize()

	_, err = VKO(priv256, priv512.PublicKey(), nil)
	if err != ErrCurveMismatch {
		t.Errorf("VKO(256, pub512): got %v, want ErrCurveMismatch", err)
	}

	_, err = VKO(priv512, priv256.PublicKey(), nil)
	if err != ErrCurveMismatch {
		t.Errorf("VKO(512, pub256): got %v, want ErrCurveMismatch", err)
	}
}

// TestVKO_NilUKM_RequiresUKM verifies that gost-engine requires UKM
// and returns an error when UKM is nil or empty.
func TestVKO_NilUKM_RequiresUKM(t *testing.T) {
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

	// gost-engine mandates UKM for VKO; nil/empty must fail.
	_, err = VKO(privA, privB.PublicKey(), nil)
	if err == nil {
		t.Error("VKO(nil ukm): expected error, got nil")
	}

	_, err = VKO(privA, privB.PublicKey(), []byte{})
	if err == nil {
		t.Error("VKO(empty ukm): expected error, got nil")
	}
}

// TestVKO_Deterministic verifies that repeated VKO calls with the same
// keys and UKM produce identical shared secrets.
func TestVKO_Deterministic(t *testing.T) {
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

	ukm := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}

	secret1, err := VKO(privA, privB.PublicKey(), ukm)
	if err != nil {
		t.Fatalf("VKO(1): %v", err)
	}

	secret2, err := VKO(privA, privB.PublicKey(), ukm)
	if err != nil {
		t.Fatalf("VKO(2): %v", err)
	}

	if !bytes.Equal(secret1, secret2) {
		t.Errorf("VKO is not deterministic:\n  run1 = %x\n  run2 = %x", secret1, secret2)
	}
}
