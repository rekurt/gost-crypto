package gost3410

import (
	"crypto"
	"crypto/rand"
	"testing"

	"github.com/rekurt/gost-crypto/internal/cryptopro"
)

// TestCryptoSignerInterface verifies that PrivKey satisfies crypto.Signer
// and produces valid signatures through the interface.
func TestCryptoSignerInterface(t *testing.T) {
	skipIfNoEngine(t)

	for _, c := range AllCurves() {
		c := c
		t.Run(c.String(), func(t *testing.T) {
			priv, err := GenerateKey(c)
			if err != nil {
				t.Fatalf("GenerateKey(%s): %v", c, err)
			}
			defer priv.Zeroize()

			// Use via crypto.Signer interface.
			var signer crypto.Signer = priv

			pub := signer.Public()
			if pub == nil {
				t.Fatal("Public() returned nil")
			}
			gostPub, ok := pub.(*PubKey)
			if !ok {
				t.Fatalf("Public() returned %T, want *PubKey", pub)
			}

			keySize, _ := c.Size()
			digest := make([]byte, keySize)
			if _, err := rand.Read(digest); err != nil {
				t.Fatalf("rand.Read: %v", err)
			}

			sig, err := signer.Sign(rand.Reader, digest, nil)
			if err != nil {
				t.Fatalf("Sign(%s): %v", c, err)
			}

			ok2, err := VerifyDigest(gostPub, digest, sig)
			if err != nil {
				t.Fatalf("VerifyDigest(%s): %v", c, err)
			}
			if !ok2 {
				t.Errorf("crypto.Signer signature rejected for %s", c)
			}
		})
	}
}

func skipIfNoEngine(t *testing.T) {
	t.Helper()
	if err := cryptopro.Init(); err != nil {
		t.Skip("CryptoPro CSP not available:", err)
	}
}

// TestSignVerify_AllCurves generates a key pair on every TC26 curve,
// signs a digest, verifies it, then corrupts the signature and checks
// that verification rejects it.
func TestSignVerify_AllCurves(t *testing.T) {
	skipIfNoEngine(t)

	for _, c := range AllCurves() {
		c := c
		t.Run(c.String(), func(t *testing.T) {
			priv, err := GenerateKey(c)
			if err != nil {
				t.Fatalf("GenerateKey(%s): %v", c, err)
			}
			defer priv.Zeroize()

			pub := priv.PublicKey()

			keySize, _ := c.Size()
			sigSize, _ := c.SignatureSize()

			// Build a deterministic digest of the correct size.
			digest := make([]byte, keySize)
			for i := range digest {
				digest[i] = byte(i)
			}

			sig, err := SignDigest(priv, digest)
			if err != nil {
				t.Fatalf("SignDigest(%s): %v", c, err)
			}
			if len(sig) != sigSize {
				t.Errorf("sig length = %d, want %d", len(sig), sigSize)
			}

			// Valid signature must pass.
			ok, err := VerifyDigest(pub, digest, sig)
			if err != nil {
				t.Fatalf("VerifyDigest(%s): %v", c, err)
			}
			if !ok {
				t.Errorf("valid signature rejected for %s", c)
			}

			// Corrupted signature must fail.
			corrupt := make([]byte, len(sig))
			copy(corrupt, sig)
			corrupt[0] ^= 0xff

			ok, err = VerifyDigest(pub, digest, corrupt)
			if err != nil {
				t.Fatalf("VerifyDigest(%s, corrupt): %v", c, err)
			}
			if ok {
				t.Errorf("corrupted signature accepted for %s", c)
			}
		})
	}
}

// TestPropertySignThenVerify runs 100 iterations of sign-then-verify
// per curve with random digests to check statistical correctness.
func TestPropertySignThenVerify(t *testing.T) {
	skipIfNoEngine(t)

	const iterations = 100

	for _, c := range AllCurves() {
		c := c
		t.Run(c.String(), func(t *testing.T) {
			priv, err := GenerateKey(c)
			if err != nil {
				t.Fatalf("GenerateKey(%s): %v", c, err)
			}
			defer priv.Zeroize()

			pub := priv.PublicKey()
			keySize, _ := c.Size()

			for i := 0; i < iterations; i++ {
				digest := make([]byte, keySize)
				if _, err := rand.Read(digest); err != nil {
					t.Fatalf("rand.Read: %v", err)
				}

				sig, err := SignDigest(priv, digest)
				if err != nil {
					t.Fatalf("iter %d: SignDigest: %v", i, err)
				}

				ok, err := VerifyDigest(pub, digest, sig)
				if err != nil {
					t.Fatalf("iter %d: VerifyDigest: %v", i, err)
				}
				if !ok {
					t.Fatalf("iter %d: valid signature rejected", i)
				}
			}
		})
	}
}

// TestCrossCurveRejection verifies that a signature produced by a
// 256-bit key is rejected when verified with a 512-bit key, and
// vice versa.
func TestCrossCurveRejection(t *testing.T) {
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

	// Sign with 256-bit key.
	digest256 := make([]byte, 32)
	for i := range digest256 {
		digest256[i] = byte(i)
	}
	sig256, err := SignDigest(priv256, digest256)
	if err != nil {
		t.Fatalf("SignDigest(256): %v", err)
	}

	// Attempt to verify 256-bit signature with 512-bit key.
	// The digest length (32) does not match 512-bit key size (64),
	// so VerifyDigest should reject with ErrInvalidKeySize.
	pub512 := priv512.PublicKey()
	ok, err := VerifyDigest(pub512, digest256, sig256)
	if err == nil {
		t.Errorf("expected error verifying 256-sig with 512-key, got ok=%v", ok)
	}

	// Sign with 512-bit key.
	digest512 := make([]byte, 64)
	for i := range digest512 {
		digest512[i] = byte(i + 1)
	}
	sig512, err := SignDigest(priv512, digest512)
	if err != nil {
		t.Fatalf("SignDigest(512): %v", err)
	}

	// Attempt to verify 512-bit signature with 256-bit key.
	pub256 := priv256.PublicKey()
	ok, err = VerifyDigest(pub256, digest512, sig512)
	if err == nil {
		t.Errorf("expected error verifying 512-sig with 256-key, got ok=%v", ok)
	}
}

// TestNilKeyHandling checks that nil or zeroized keys return ErrNilKey.
func TestNilKeyHandling(t *testing.T) {
	skipIfNoEngine(t)

	digest := make([]byte, 32)

	// nil PrivKey.
	_, err := SignDigest(nil, digest)
	if err != ErrNilKey {
		t.Errorf("SignDigest(nil priv): got %v, want ErrNilKey", err)
	}

	// nil PubKey.
	_, err = VerifyDigest(nil, digest, make([]byte, 64))
	if err != ErrNilKey {
		t.Errorf("VerifyDigest(nil pub): got %v, want ErrNilKey", err)
	}

	// Zeroized PrivKey.
	priv, err := GenerateKey(CurveTC26_256_A)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := priv.PublicKey()
	priv.Zeroize()

	_, err = SignDigest(priv, digest)
	if err != ErrNilKey {
		t.Errorf("SignDigest(zeroized): got %v, want ErrNilKey", err)
	}

	// Derived PubKey from zeroized PrivKey must also fail.
	_, err = VerifyDigest(pub, digest, make([]byte, 64))
	if err != ErrNilKey {
		t.Errorf("VerifyDigest(zeroized pub): got %v, want ErrNilKey", err)
	}

	// PrivKey.Bytes on zeroized key.
	_, err = priv.Bytes()
	if err != ErrNilKey {
		t.Errorf("Bytes(zeroized): got %v, want ErrNilKey", err)
	}
}

// TestValidateOnCurve verifies that Validate passes for every generated key.
func TestValidateOnCurve(t *testing.T) {
	skipIfNoEngine(t)

	for _, c := range AllCurves() {
		c := c
		t.Run(c.String(), func(t *testing.T) {
			priv, err := GenerateKey(c)
			if err != nil {
				t.Fatalf("GenerateKey(%s): %v", c, err)
			}
			defer priv.Zeroize()

			pub := priv.PublicKey()
			if err := pub.Validate(); err != nil {
				t.Errorf("Validate(%s): %v", c, err)
			}
		})
	}
}

// TestPrivKeyBytes verifies that Bytes returns key material of correct length.
func TestPrivKeyBytes(t *testing.T) {
	skipIfNoEngine(t)

	for _, c := range AllCurves() {
		c := c
		t.Run(c.String(), func(t *testing.T) {
			priv, err := GenerateKey(c)
			if err != nil {
				t.Fatalf("GenerateKey(%s): %v", c, err)
			}
			defer priv.Zeroize()

			keySize, _ := c.Size()
			raw, err := priv.Bytes()
			if err != nil {
				t.Fatalf("Bytes(%s): %v", c, err)
			}
			if len(raw) != keySize {
				t.Errorf("key bytes length = %d, want %d", len(raw), keySize)
			}

			// Key material must not be all zeros.
			allZero := true
			for _, b := range raw {
				if b != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				t.Errorf("private key bytes are all zeros for %s", c)
			}

			// Cleanse the raw key bytes.
			cryptopro.CleanseBytes(raw)
		})
	}
}

// TestDigestSizeMismatch verifies that wrong-length digests are rejected.
func TestDigestSizeMismatch(t *testing.T) {
	skipIfNoEngine(t)

	priv, err := GenerateKey(CurveTC26_256_A)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	defer priv.Zeroize()

	// 256-bit curve expects 32-byte digest; pass 16 bytes.
	_, err = SignDigest(priv, make([]byte, 16))
	if err != ErrInvalidKeySize {
		t.Errorf("SignDigest(short digest): got %v, want ErrInvalidKeySize", err)
	}

	// Pass 64-byte digest to 256-bit key.
	_, err = SignDigest(priv, make([]byte, 64))
	if err != ErrInvalidKeySize {
		t.Errorf("SignDigest(long digest): got %v, want ErrInvalidKeySize", err)
	}
}

// TestLoadPrivKey_Roundtrip verifies that LoadPrivKey creates a functional key
// that produces valid signatures.
func TestLoadPrivKey_Roundtrip(t *testing.T) {
	skipIfNoEngine(t)

	for _, c := range AllCurves() {
		c := c
		t.Run(c.String(), func(t *testing.T) {
			// Generate a key and extract raw bytes.
			orig, err := GenerateKey(c)
			if err != nil {
				t.Fatalf("GenerateKey(%s): %v", c, err)
			}
			raw, err := orig.Bytes()
			if err != nil {
				t.Fatalf("Bytes: %v", err)
			}
			orig.Zeroize()

			// Load the same key from raw bytes.
			loaded, err := LoadPrivKey(c, raw)
			if err != nil {
				t.Fatalf("LoadPrivKey(%s): %v", c, err)
			}
			defer loaded.Zeroize()

			// Verify loaded key bytes match original.
			loadedRaw, err := loaded.Bytes()
			if err != nil {
				t.Fatalf("loaded.Bytes: %v", err)
			}
			if len(loadedRaw) != len(raw) {
				t.Fatalf("key bytes length: got %d, want %d", len(loadedRaw), len(raw))
			}
			for i := range raw {
				if raw[i] != loadedRaw[i] {
					t.Fatalf("key byte %d differs: got %02x, want %02x", i, loadedRaw[i], raw[i])
				}
			}

			// Sign with loaded key and verify.
			keySize, _ := c.Size()
			digest := make([]byte, keySize)
			for i := range digest {
				digest[i] = byte(i + 42)
			}

			sig, err := SignDigest(loaded, digest)
			if err != nil {
				t.Fatalf("SignDigest: %v", err)
			}

			pub := loaded.PublicKey()
			ok, err := VerifyDigest(pub, digest, sig)
			if err != nil {
				t.Fatalf("VerifyDigest: %v", err)
			}
			if !ok {
				t.Error("valid signature rejected for loaded key")
			}

			cryptopro.CleanseBytes(raw)
			cryptopro.CleanseBytes(loadedRaw)
		})
	}
}

// TestLoadPrivKey_InvalidSize verifies that LoadPrivKey rejects wrong-size input.
func TestLoadPrivKey_InvalidSize(t *testing.T) {
	skipIfNoEngine(t)

	_, err := LoadPrivKey(CurveTC26_256_A, make([]byte, 16))
	if err != ErrInvalidKeySize {
		t.Errorf("LoadPrivKey(16 bytes): got %v, want ErrInvalidKeySize", err)
	}

	_, err = LoadPrivKey(CurveTC26_256_A, make([]byte, 64))
	if err != ErrInvalidKeySize {
		t.Errorf("LoadPrivKey(64 bytes for 256-bit curve): got %v, want ErrInvalidKeySize", err)
	}
}

// TestSignatureSizeMismatch verifies that wrong-length signatures are rejected.
func TestSignatureSizeMismatch(t *testing.T) {
	skipIfNoEngine(t)

	priv, err := GenerateKey(CurveTC26_256_A)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	defer priv.Zeroize()

	pub := priv.PublicKey()
	digest := make([]byte, 32)

	// 256-bit curve expects 64-byte signature; pass 32 bytes.
	_, err = VerifyDigest(pub, digest, make([]byte, 32))
	if err != ErrInvalidSignature {
		t.Errorf("VerifyDigest(short sig): got %v, want ErrInvalidSignature", err)
	}

	// Pass 128-byte signature.
	_, err = VerifyDigest(pub, digest, make([]byte, 128))
	if err != ErrInvalidSignature {
		t.Errorf("VerifyDigest(long sig): got %v, want ErrInvalidSignature", err)
	}
}
