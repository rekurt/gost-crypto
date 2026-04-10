package gost3410

import (
	"testing"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

// FuzzLoadPrivKey exercises LoadPrivKey with arbitrary byte inputs
// to verify it never panics on invalid key material.
func FuzzLoadPrivKey(f *testing.F) {
	if err := openssl.Init(); err != nil {
		f.Skip("gost-engine not available:", err)
	}

	// Seed corpus.
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 16))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, raw []byte) {
		// LoadPrivKey must not panic on any input. Errors are expected
		// for invalid sizes or out-of-range values.
		key, err := LoadPrivKey(CurveTC26_256_A, raw)
		if err == nil && key != nil {
			key.Zeroize()
		}
	})
}

// FuzzVerifyDigest exercises VerifyDigest with arbitrary signatures
// to verify it never panics.
func FuzzVerifyDigest(f *testing.F) {
	if err := openssl.Init(); err != nil {
		f.Skip("gost-engine not available:", err)
	}

	priv, err := GenerateKey(CurveTC26_256_A)
	if err != nil {
		f.Fatalf("GenerateKey: %v", err)
	}
	pub := priv.PublicKey()

	digest := make([]byte, 32)
	validSig, _ := SignDigest(priv, digest)

	f.Add(validSig)
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 128))

	f.Fuzz(func(t *testing.T, sig []byte) {
		// VerifyDigest must not panic on any signature input.
		_, _ = VerifyDigest(pub, digest, sig)
	})
}

// FuzzLoadPrivKey_512 exercises the 512-bit curve load path with arbitrary
// byte inputs to verify it never panics on invalid key material.
func FuzzLoadPrivKey_512(f *testing.F) {
	if err := openssl.Init(); err != nil {
		f.Skip("gost-engine not available:", err)
	}

	f.Add(make([]byte, 64))
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 128))

	f.Fuzz(func(t *testing.T, raw []byte) {
		key, err := LoadPrivKey(CurveTC26_512_A, raw)
		if err == nil && key != nil {
			key.Zeroize()
		}
	})
}

// FuzzUnmarshalBinary exercises PrivKey.UnmarshalBinary with arbitrary
// byte inputs to verify it never panics and rejects malformed data.
func FuzzUnmarshalBinary(f *testing.F) {
	if err := openssl.Init(); err != nil {
		f.Skip("gost-engine not available:", err)
	}

	// Seed corpus with valid roundtrips plus edge cases.
	if priv, err := GenerateKey(CurveTC26_256_A); err == nil {
		if raw, err := priv.MarshalBinary(); err == nil {
			f.Add(raw)
		}
		priv.Zeroize()
	}
	if priv, err := GenerateKey(CurveTC26_512_A); err == nil {
		if raw, err := priv.MarshalBinary(); err == nil {
			f.Add(raw)
		}
		priv.Zeroize()
	}
	f.Add([]byte{})
	f.Add([]byte{0xff})
	f.Add(make([]byte, 33))
	f.Add(make([]byte, 65))

	f.Fuzz(func(t *testing.T, data []byte) {
		k := &PrivKey{}
		if err := k.UnmarshalBinary(data); err == nil {
			k.Zeroize()
		}
	})
}
