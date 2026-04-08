package gost3413

import (
	"testing"
)

func TestKuznechikCMAC_Consistency(t *testing.T) {
	skipIfNoEngine(t)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	cmac, err := NewKuznechikCMAC(key)
	if err != nil {
		t.Fatal(err)
	}
	defer cmac.Zeroize()

	msg := []byte("CMAC test message for Kuznechik")

	// Compute MAC twice — results must be identical.
	mac1, err := cmac.MAC(msg)
	if err != nil {
		t.Fatalf("MAC(1): %v", err)
	}
	mac2, err := cmac.MAC(msg)
	if err != nil {
		t.Fatalf("MAC(2): %v", err)
	}

	if len(mac1) == 0 {
		t.Fatal("MAC returned empty result")
	}
	if len(mac1) != 16 {
		t.Errorf("MAC length = %d, want 16 (Kuznechik block size)", len(mac1))
	}

	for i := range mac1 {
		if mac1[i] != mac2[i] {
			t.Fatalf("MAC not deterministic: byte %d differs", i)
		}
	}
}

func TestKuznechikCMAC_DifferentMessages(t *testing.T) {
	skipIfNoEngine(t)

	key := make([]byte, 32)
	cmac, err := NewKuznechikCMAC(key)
	if err != nil {
		t.Fatal(err)
	}
	defer cmac.Zeroize()

	mac1, err := cmac.MAC([]byte("message one"))
	if err != nil {
		t.Fatal(err)
	}
	mac2, err := cmac.MAC([]byte("message two"))
	if err != nil {
		t.Fatal(err)
	}

	equal := true
	for i := range mac1 {
		if mac1[i] != mac2[i] {
			equal = false
			break
		}
	}
	if equal {
		t.Error("different messages produced identical MACs")
	}
}

func TestMagmaCMAC_Consistency(t *testing.T) {
	skipIfNoEngine(t)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	cmac, err := NewMagmaCMAC(key)
	if err != nil {
		t.Fatal(err)
	}
	defer cmac.Zeroize()

	msg := []byte("CMAC test message for Magma")

	mac1, err := cmac.MAC(msg)
	if err != nil {
		t.Fatalf("MAC(1): %v", err)
	}
	mac2, err := cmac.MAC(msg)
	if err != nil {
		t.Fatalf("MAC(2): %v", err)
	}

	if len(mac1) == 0 {
		t.Fatal("MAC returned empty result")
	}
	if len(mac1) != 8 {
		t.Errorf("MAC length = %d, want 8 (Magma block size)", len(mac1))
	}

	for i := range mac1 {
		if mac1[i] != mac2[i] {
			t.Fatalf("MAC not deterministic: byte %d differs", i)
		}
	}
}

func TestCMAC_InvalidKeySize(t *testing.T) {
	skipIfNoEngine(t)
	_, err := NewKuznechikCMAC(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for 16-byte key")
	}
	_, err = NewMagmaCMAC(make([]byte, 64))
	if err == nil {
		t.Fatal("expected error for 64-byte key")
	}
}
