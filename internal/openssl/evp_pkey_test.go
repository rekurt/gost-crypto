package openssl

import (
	"testing"
)

func TestGenerateKey_256A(t *testing.T) {
	if err := Init(); err != nil {
		t.Skipf("gost-engine not available: %v", err)
	}

	pkey, err := GenerateGOSTKey(NID_GostR3410_2012_256, CurveOIDs[0])
	if err != nil {
		t.Fatalf("GenerateGOSTKey(256-A): %v", err)
	}
	defer FreeKey(pkey)

	raw, err := ExtractRawPrivKey(pkey, 32)
	if err != nil {
		t.Fatalf("ExtractRawPrivKey: %v", err)
	}

	if len(raw) != 32 {
		t.Errorf("private key length = %d, want 32", len(raw))
	}

	allZero := true
	for _, b := range raw {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("private key is all zeros")
	}
}

func TestGenerateKey_512A(t *testing.T) {
	if err := Init(); err != nil {
		t.Skipf("gost-engine not available: %v", err)
	}

	pkey, err := GenerateGOSTKey(NID_GostR3410_2012_512, CurveOIDs[4])
	if err != nil {
		t.Fatalf("GenerateGOSTKey(512-A): %v", err)
	}
	defer FreeKey(pkey)

	raw, err := ExtractRawPrivKey(pkey, 64)
	if err != nil {
		t.Fatalf("ExtractRawPrivKey: %v", err)
	}

	if len(raw) != 64 {
		t.Errorf("private key length = %d, want 64", len(raw))
	}

	allZero := true
	for _, b := range raw {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("private key is all zeros")
	}
}

func TestSignVerify_Roundtrip_256A(t *testing.T) {
	if err := Init(); err != nil {
		t.Skipf("gost-engine not available: %v", err)
	}

	pkey, err := GenerateGOSTKey(NID_GostR3410_2012_256, CurveOIDs[0])
	if err != nil {
		t.Fatalf("GenerateGOSTKey: %v", err)
	}
	defer FreeKey(pkey)

	// Create a 32-byte digest (Streebog-256 output size).
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}

	sig, err := SignDigest(pkey, digest)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}

	if len(sig) != 64 {
		t.Errorf("signature length = %d, want 64", len(sig))
	}

	// Verify valid signature.
	ok, err := VerifyDigest(pkey, digest, sig)
	if err != nil {
		t.Fatalf("VerifyDigest: %v", err)
	}
	if !ok {
		t.Error("valid signature rejected")
	}

	// Corrupt the signature and verify it fails.
	corruptSig := make([]byte, len(sig))
	copy(corruptSig, sig)
	corruptSig[0] ^= 0xff

	ok, err = VerifyDigest(pkey, digest, corruptSig)
	if err != nil {
		t.Fatalf("VerifyDigest(corrupt): %v", err)
	}
	if ok {
		t.Error("corrupted signature accepted")
	}
}

func TestGenerateKey_AllCurves(t *testing.T) {
	if err := Init(); err != nil {
		t.Skipf("gost-engine not available: %v", err)
	}

	type curveSpec struct {
		name    string
		nid     int
		oid     string
		keySize int
	}

	specs := []curveSpec{
		{"TC26-256-A", NID_GostR3410_2012_256, CurveOIDs[0], 32},
		{"TC26-256-B", NID_GostR3410_2012_256, CurveOIDs[1], 32},
		{"TC26-256-C", NID_GostR3410_2012_256, CurveOIDs[2], 32},
		{"TC26-256-D", NID_GostR3410_2012_256, CurveOIDs[3], 32},
		{"TC26-512-A", NID_GostR3410_2012_512, CurveOIDs[4], 64},
		{"TC26-512-B", NID_GostR3410_2012_512, CurveOIDs[5], 64},
		{"TC26-512-C", NID_GostR3410_2012_512, CurveOIDs[6], 64},
		{"TC26-512-D", NID_GostR3410_2012_512, CurveOIDs[7], 64},
	}

	for _, s := range specs {
		t.Run(s.name, func(t *testing.T) {
			pkey, err := GenerateGOSTKey(s.nid, s.oid)
			if err != nil {
				t.Fatalf("GenerateGOSTKey(%s): %v", s.name, err)
			}
			defer FreeKey(pkey)

			pub, err := ExtractRawPubKey(pkey)
			if err != nil {
				t.Fatalf("ExtractRawPubKey(%s): %v", s.name, err)
			}

			// Public key in SPKI format includes the algorithm OID header.
			// It should be at least 2*keySize (the raw X||Y point) plus header.
			if len(pub) < 2*s.keySize {
				t.Errorf("public key SPKI length = %d, expected >= %d", len(pub), 2*s.keySize)
			}
			t.Logf("pub key SPKI length for %s: %d bytes", s.name, len(pub))

			// Quick sign/verify round-trip.
			digest := make([]byte, s.keySize)
			for i := range digest {
				digest[i] = byte(i + 1)
			}

			sig, err := SignDigest(pkey, digest)
			if err != nil {
				t.Fatalf("SignDigest(%s): %v", s.name, err)
			}

			ok, err := VerifyDigest(pkey, digest, sig)
			if err != nil {
				t.Fatalf("VerifyDigest(%s): %v", s.name, err)
			}
			if !ok {
				t.Errorf("signature verification failed for %s", s.name)
			}
		})
	}
}
