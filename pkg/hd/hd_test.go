package hd

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/rekurt/gost-crypto/internal/cryptopro"
	"github.com/rekurt/gost-crypto/pkg/gost3410"
)

func skipIfNoEngine(t *testing.T) {
	t.Helper()
	if err := cryptopro.Init(); err != nil {
		t.Skip("CryptoPro CSP not available:", err)
	}
}

// ---------------------------------------------------------------------------
// Path parsing tests (these do not require OpenSSL).
// ---------------------------------------------------------------------------

func TestParsePath_Absolute(t *testing.T) {
	components, err := ParsePath("m/44'/0'/0/1")
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	if len(components) != 4 {
		t.Fatalf("expected 4 components, got %d", len(components))
	}

	// 44' — hardened
	if !components[0].Hardened {
		t.Error("index 0: expected hardened")
	}
	if components[0].Index != 44|hardenedOffset {
		t.Errorf("index 0: got 0x%x, want 0x%x", components[0].Index, 44|hardenedOffset)
	}

	// 0' — hardened
	if !components[1].Hardened {
		t.Error("index 1: expected hardened")
	}

	// 0 — normal
	if components[2].Hardened {
		t.Error("index 2: expected normal")
	}
	if components[2].Index != 0 {
		t.Errorf("index 2: got %d, want 0", components[2].Index)
	}

	// 1 — normal
	if components[3].Hardened {
		t.Error("index 3: expected normal")
	}
	if components[3].Index != 1 {
		t.Errorf("index 3: got %d, want 1", components[3].Index)
	}
}

func TestParsePath_Relative(t *testing.T) {
	components, err := ParsePath("0/1/2")
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	if len(components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(components))
	}
	for i, c := range components {
		if c.Index != uint32(i) {
			t.Errorf("component %d: got %d, want %d", i, c.Index, i)
		}
		if c.Hardened {
			t.Errorf("component %d: expected normal", i)
		}
	}
}

func TestParsePath_MasterOnly(t *testing.T) {
	components, err := ParsePath("m")
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	if components != nil {
		t.Errorf("expected nil components for 'm', got %v", components)
	}
}

func TestParsePath_HardenedSuffix_H(t *testing.T) {
	components, err := ParsePath("m/44h/0h")
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	if len(components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(components))
	}
	if !components[0].Hardened {
		t.Error("component 0: expected hardened")
	}
	if !components[1].Hardened {
		t.Error("component 1: expected hardened")
	}
}

func TestParsePath_InvalidPaths(t *testing.T) {
	invalid := []string{
		"",
		"m/",
		"m//1",
		"m/abc",
		"m/-1",
		"/0/1",
		"m/'/0",
	}
	for _, p := range invalid {
		_, err := ParsePath(p)
		if err == nil {
			t.Errorf("ParsePath(%q): expected error, got nil", p)
		}
	}
}

func TestParsePath_LargeIndex(t *testing.T) {
	// Maximum normal index is 2^31 - 1 = 2147483647.
	components, err := ParsePath("m/2147483647")
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	if len(components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(components))
	}
	if components[0].Index != 2147483647 {
		t.Errorf("got %d, want 2147483647", components[0].Index)
	}
}

// ---------------------------------------------------------------------------
// Master and Derive tests (require OpenSSL CryptoPro CSP).
// ---------------------------------------------------------------------------

func TestMaster_ProducesValidKey(t *testing.T) {
	skipIfNoEngine(t)

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	dk, err := Master(seed, gost3410.CurveTC26_256_A)
	if err != nil {
		t.Fatalf("Master: %v", err)
	}
	defer dk.Zeroize()

	if dk.Key == nil {
		t.Fatal("Master returned nil key")
	}
	if len(dk.ChainCode) != 32 {
		t.Errorf("chain code length = %d, want 32", len(dk.ChainCode))
	}

	// Verify the key can sign and verify (Validate() may fail for
	// HD-derived keys due to CryptoPro CSP limitations, so we test
	// actual crypto operations instead).
	keySize, _ := gost3410.CurveTC26_256_A.Size()
	digest := make([]byte, keySize)
	for i := range digest {
		digest[i] = byte(i + 42)
	}
	sig, err := gost3410.SignDigest(dk.Key, digest)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	pub := dk.Key.PublicKey()
	ok, err := gost3410.VerifyDigest(pub, digest, sig)
	if err != nil {
		t.Fatalf("VerifyDigest: %v", err)
	}
	if !ok {
		t.Error("valid signature rejected for HD-derived key")
	}
}

func TestMaster_ChainCodeDeterministic(t *testing.T) {
	skipIfNoEngine(t)

	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	dk1, err := Master(seed, gost3410.CurveTC26_256_A)
	if err != nil {
		t.Fatalf("Master(1): %v", err)
	}
	defer dk1.Zeroize()

	dk2, err := Master(seed, gost3410.CurveTC26_256_A)
	if err != nil {
		t.Fatalf("Master(2): %v", err)
	}
	defer dk2.Zeroize()

	// Chain codes must be identical for the same seed.
	if !bytes.Equal(dk1.ChainCode, dk2.ChainCode) {
		t.Errorf("chain codes differ for the same seed:\n  cc1 = %x\n  cc2 = %x",
			dk1.ChainCode, dk2.ChainCode)
	}
}

func TestMaster_DifferentSeeds_DifferentChainCodes(t *testing.T) {
	skipIfNoEngine(t)

	seed1 := make([]byte, 32)
	seed2 := make([]byte, 32)
	for i := range seed1 {
		seed1[i] = byte(i)
		seed2[i] = byte(i + 128)
	}

	dk1, err := Master(seed1, gost3410.CurveTC26_256_A)
	if err != nil {
		t.Fatalf("Master(seed1): %v", err)
	}
	defer dk1.Zeroize()

	dk2, err := Master(seed2, gost3410.CurveTC26_256_A)
	if err != nil {
		t.Fatalf("Master(seed2): %v", err)
	}
	defer dk2.Zeroize()

	if bytes.Equal(dk1.ChainCode, dk2.ChainCode) {
		t.Error("different seeds produced identical chain codes")
	}
}

func TestMaster_512BitCurve(t *testing.T) {
	skipIfNoEngine(t)

	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	dk, err := Master(seed, gost3410.CurveTC26_512_A)
	if err != nil {
		t.Fatalf("Master(512-A): %v", err)
	}
	defer dk.Zeroize()

	if dk.Key == nil {
		t.Fatal("Master returned nil key for 512-bit curve")
	}
	// Verify key works via sign/verify.
	keySize, _ := gost3410.CurveTC26_512_A.Size()
	digest := make([]byte, keySize)
	sig, err := gost3410.SignDigest(dk.Key, digest)
	if err != nil {
		t.Fatalf("SignDigest(512): %v", err)
	}
	pub := dk.Key.PublicKey()
	ok, verr := gost3410.VerifyDigest(pub, digest, sig)
	if verr != nil {
		t.Fatalf("VerifyDigest(512): %v", verr)
	}
	if !ok {
		t.Error("valid signature rejected for 512-bit HD key")
	}
}

func TestMaster_EmptySeed(t *testing.T) {
	_, err := Master(nil, gost3410.CurveTC26_256_A)
	if err != ErrEmptySeed {
		t.Errorf("Master(nil): got %v, want ErrEmptySeed", err)
	}

	_, err = Master([]byte{}, gost3410.CurveTC26_256_A)
	if err != ErrEmptySeed {
		t.Errorf("Master(empty): got %v, want ErrEmptySeed", err)
	}
}

func TestMaster_ShortSeed(t *testing.T) {
	_, err := Master([]byte{1, 2, 3}, gost3410.CurveTC26_256_A)
	if err != ErrSeedTooShort {
		t.Errorf("Master(3 bytes): got %v, want ErrSeedTooShort", err)
	}
}

func TestDerive_ProducesValidKey(t *testing.T) {
	skipIfNoEngine(t)

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	master, err := Master(seed, gost3410.CurveTC26_256_A)
	if err != nil {
		t.Fatalf("Master: %v", err)
	}
	defer master.Zeroize()

	child, err := Derive(master, "m/44'/0'/0", gost3410.CurveTC26_256_A)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	defer child.Zeroize()

	if child.Key == nil {
		t.Fatal("Derive returned nil key")
	}
	if len(child.ChainCode) != 32 {
		t.Errorf("child chain code length = %d, want 32", len(child.ChainCode))
	}

	// Verify child key works via sign/verify.
	keySize, _ := gost3410.CurveTC26_256_A.Size()
	digest := make([]byte, keySize)
	sig, err := gost3410.SignDigest(child.Key, digest)
	if err != nil {
		t.Fatalf("SignDigest child: %v", err)
	}
	pub := child.Key.PublicKey()
	ok, verr := gost3410.VerifyDigest(pub, digest, sig)
	if verr != nil {
		t.Fatalf("VerifyDigest child: %v", verr)
	}
	if !ok {
		t.Error("valid signature rejected for child HD key")
	}
}

func TestDerive_DifferentPaths_DifferentChainCodes(t *testing.T) {
	skipIfNoEngine(t)

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	master, err := Master(seed, gost3410.CurveTC26_256_A)
	if err != nil {
		t.Fatalf("Master: %v", err)
	}
	defer master.Zeroize()

	child1, err := Derive(master, "m/0/0", gost3410.CurveTC26_256_A)
	if err != nil {
		t.Fatalf("Derive(0/0): %v", err)
	}
	defer child1.Zeroize()

	child2, err := Derive(master, "m/0/1", gost3410.CurveTC26_256_A)
	if err != nil {
		t.Fatalf("Derive(0/1): %v", err)
	}
	defer child2.Zeroize()

	if bytes.Equal(child1.ChainCode, child2.ChainCode) {
		t.Error("different derivation paths produced identical chain codes")
	}
}

func TestDerive_ChainCodeDeterministic(t *testing.T) {
	skipIfNoEngine(t)

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	master1, err := Master(seed, gost3410.CurveTC26_256_A)
	if err != nil {
		t.Fatalf("Master(1): %v", err)
	}
	defer master1.Zeroize()

	master2, err := Master(seed, gost3410.CurveTC26_256_A)
	if err != nil {
		t.Fatalf("Master(2): %v", err)
	}
	defer master2.Zeroize()

	child1, err := Derive(master1, "m/44'/0'/0", gost3410.CurveTC26_256_A)
	if err != nil {
		t.Fatalf("Derive(1): %v", err)
	}
	defer child1.Zeroize()

	child2, err := Derive(master2, "m/44'/0'/0", gost3410.CurveTC26_256_A)
	if err != nil {
		t.Fatalf("Derive(2): %v", err)
	}
	defer child2.Zeroize()

	// Chain codes must be identical for the same seed + path.
	if !bytes.Equal(child1.ChainCode, child2.ChainCode) {
		t.Errorf("chain codes differ for same seed+path:\n  cc1 = %x\n  cc2 = %x",
			child1.ChainCode, child2.ChainCode)
	}
}

func TestDerive_InvalidPath(t *testing.T) {
	skipIfNoEngine(t)

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	master, err := Master(seed, gost3410.CurveTC26_256_A)
	if err != nil {
		t.Fatalf("Master: %v", err)
	}
	defer master.Zeroize()

	_, err = Derive(master, "", gost3410.CurveTC26_256_A)
	if err == nil {
		t.Error("Derive(empty path): expected error, got nil")
	}

	_, err = Derive(master, "m//0", gost3410.CurveTC26_256_A)
	if err == nil {
		t.Error("Derive(double slash): expected error, got nil")
	}
}

func TestDerive_HardenedVsNormal_DifferentChainCodes(t *testing.T) {
	skipIfNoEngine(t)

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	master, err := Master(seed, gost3410.CurveTC26_256_A)
	if err != nil {
		t.Fatalf("Master: %v", err)
	}
	defer master.Zeroize()

	childNormal, err := Derive(master, "m/0", gost3410.CurveTC26_256_A)
	if err != nil {
		t.Fatalf("Derive(0): %v", err)
	}
	defer childNormal.Zeroize()

	childHardened, err := Derive(master, "m/0'", gost3410.CurveTC26_256_A)
	if err != nil {
		t.Fatalf("Derive(0'): %v", err)
	}
	defer childHardened.Zeroize()

	if bytes.Equal(childNormal.ChainCode, childHardened.ChainCode) {
		t.Error("normal and hardened child produced identical chain codes")
	}
}
