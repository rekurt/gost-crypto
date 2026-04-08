package gost3410

import (
	"bytes"
	"testing"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

func TestPrivKey_MarshalUnmarshal_Roundtrip(t *testing.T) {
	skipIfNoEngine(t)

	for _, c := range AllCurves() {
		c := c
		t.Run(c.String(), func(t *testing.T) {
			priv, err := GenerateKey(c)
			if err != nil {
				t.Fatalf("GenerateKey(%s): %v", c, err)
			}
			defer priv.Zeroize()

			// Marshal
			data, err := priv.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}

			// Curve ID should be first byte.
			if Curve(data[0]) != c {
				t.Errorf("curve byte = %d, want %d", data[0], c)
			}

			// Unmarshal into a new key.
			var restored PrivKey
			if err := restored.UnmarshalBinary(data); err != nil {
				t.Fatalf("UnmarshalBinary: %v", err)
			}
			defer restored.Zeroize()

			// Verify the restored key matches.
			origBytes, _ := priv.Bytes()
			restoredBytes, _ := restored.Bytes()

			if !bytes.Equal(origBytes, restoredBytes) {
				t.Error("restored key bytes differ from original")
			}

			openssl.CleanseBytes(origBytes)
			openssl.CleanseBytes(restoredBytes)

			// Sign with restored key and verify with original pubkey.
			keySize, _ := c.Size()
			digest := make([]byte, keySize)
			for i := range digest {
				digest[i] = byte(i)
			}

			sig, err := SignDigest(&restored, digest)
			if err != nil {
				t.Fatalf("SignDigest with restored key: %v", err)
			}

			ok, err := VerifyDigest(priv.PublicKey(), digest, sig)
			if err != nil {
				t.Fatalf("VerifyDigest: %v", err)
			}
			if !ok {
				t.Error("signature from restored key not verified by original pubkey")
			}
		})
	}
}

func TestPrivKey_UnmarshalBinary_InvalidData(t *testing.T) {
	skipIfNoEngine(t)

	var k PrivKey

	// Too short.
	if err := k.UnmarshalBinary([]byte{0}); err == nil {
		t.Error("expected error for 1-byte input")
	}

	// Invalid curve ID.
	if err := k.UnmarshalBinary([]byte{255, 0, 0, 0, 0}); err == nil {
		t.Error("expected error for invalid curve ID")
	}

	// Wrong key length for curve.
	data := make([]byte, 1+16) // 16 bytes is wrong for any curve
	data[0] = byte(CurveTC26_256_A)
	if err := k.UnmarshalBinary(data); err == nil {
		t.Error("expected error for wrong key length")
	}
}

func TestPubKey_MarshalBinary(t *testing.T) {
	skipIfNoEngine(t)

	priv, err := GenerateKey(CurveTC26_256_A)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Zeroize()

	pub := priv.PublicKey()
	data, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	if len(data) < 2 {
		t.Fatal("marshaled pubkey too short")
	}
	if Curve(data[0]) != CurveTC26_256_A {
		t.Errorf("curve byte = %d, want %d", data[0], CurveTC26_256_A)
	}
}
