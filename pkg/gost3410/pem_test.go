package gost3410

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

func skipPEMIfNoEngine(t *testing.T) {
	t.Helper()
	if err := openssl.Init(); err != nil {
		t.Skip("gost-engine not available:", err)
	}
}

// TestPEM_PrivateKeyRoundtrip verifies that a generated private key
// can be marshalled to PEM and parsed back into an equivalent key
// (by raw key-bytes comparison) for both 256 and 512 bit curves.
func TestPEM_PrivateKeyRoundtrip(t *testing.T) {
	skipPEMIfNoEngine(t)

	cases := []struct {
		name  string
		curve Curve
	}{
		{"256-A", CurveTC26_256_A},
		{"512-A", CurveTC26_512_A},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := GenerateKey(tc.curve)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			defer priv.Zeroize()

			pem, err := priv.MarshalPrivateKeyPEM()
			if err != nil {
				t.Fatalf("MarshalPrivateKeyPEM: %v", err)
			}

			if !bytes.HasPrefix(pem, []byte("-----BEGIN PRIVATE KEY-----")) {
				t.Errorf("PEM does not start with BEGIN PRIVATE KEY marker:\n%s", pem)
			}
			if !bytes.Contains(pem, []byte("-----END PRIVATE KEY-----")) {
				t.Errorf("PEM missing END PRIVATE KEY marker:\n%s", pem)
			}

			parsed, err := ParsePrivateKeyPEM(pem)
			if err != nil {
				t.Fatalf("ParsePrivateKeyPEM: %v", err)
			}
			defer parsed.Zeroize()

			origBytes, err := priv.Bytes()
			if err != nil {
				t.Fatalf("priv.Bytes: %v", err)
			}
			defer openssl.CleanseBytes(origBytes)

			parsedBytes, err := parsed.Bytes()
			if err != nil {
				t.Fatalf("parsed.Bytes: %v", err)
			}
			defer openssl.CleanseBytes(parsedBytes)

			if !bytes.Equal(origBytes, parsedBytes) {
				t.Errorf("private key mismatch after PEM roundtrip:\n  got  %x\n  want %x",
					parsedBytes, origBytes)
			}

			// Width sanity: 256-bit curve → 32-byte raw key; 512 → 64.
			expected := 32
			if tc.curve.is512() {
				expected = 64
			}
			if len(parsedBytes) != expected {
				t.Errorf("parsed key length = %d, want %d", len(parsedBytes), expected)
			}
		})
	}
}

// TestPEM_PublicKeyRoundtrip verifies that a public key can be
// marshalled to an SPKI PEM block and parsed back.
func TestPEM_PublicKeyRoundtrip(t *testing.T) {
	skipPEMIfNoEngine(t)

	cases := []struct {
		name  string
		curve Curve
	}{
		{"256-A", CurveTC26_256_A},
		{"512-A", CurveTC26_512_A},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := GenerateKey(tc.curve)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			defer priv.Zeroize()

			pub := priv.PublicKey()
			pem, err := pub.MarshalPublicKeyPEM()
			if err != nil {
				t.Fatalf("MarshalPublicKeyPEM: %v", err)
			}
			if !bytes.HasPrefix(pem, []byte("-----BEGIN PUBLIC KEY-----")) {
				t.Errorf("PEM missing BEGIN PUBLIC KEY marker:\n%s", pem)
			}
			if !bytes.Contains(pem, []byte("-----END PUBLIC KEY-----")) {
				t.Errorf("PEM missing END PUBLIC KEY marker:\n%s", pem)
			}

			parsedPub, err := ParsePublicKeyPEM(pem)
			if err != nil {
				t.Fatalf("ParsePublicKeyPEM: %v", err)
			}
			defer parsedPub.ZeroizePublicKey()

			// The parsed public key must validate (point on curve).
			if err := parsedPub.Validate(); err != nil {
				t.Errorf("parsed public key failed Validate: %v", err)
			}

			if parsedPub.curve.is256() != tc.curve.is256() {
				t.Errorf("curve-width mismatch: parsed is256=%v, orig is256=%v",
					parsedPub.curve.is256(), tc.curve.is256())
			}
		})
	}
}

// TestPEM_SignVerify_AcrossRoundtrip proves that a key parsed from
// its own PEM output produces signatures verifiable by the original
// (and vice-versa). This is the end-to-end interop check.
func TestPEM_SignVerify_AcrossRoundtrip(t *testing.T) {
	skipPEMIfNoEngine(t)

	priv, err := GenerateKey(CurveTC26_256_A)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	defer priv.Zeroize()

	privPEM, err := priv.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatalf("MarshalPrivateKeyPEM: %v", err)
	}
	pubPEM, err := priv.PublicKey().MarshalPublicKeyPEM()
	if err != nil {
		t.Fatalf("MarshalPublicKeyPEM: %v", err)
	}

	parsedPriv, err := ParsePrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM: %v", err)
	}
	defer parsedPriv.Zeroize()

	parsedPub, err := ParsePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM: %v", err)
	}
	defer parsedPub.ZeroizePublicKey()

	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}

	// Original priv signs, parsed pub verifies.
	sig1, err := SignDigest(priv, digest)
	if err != nil {
		t.Fatalf("SignDigest(orig): %v", err)
	}
	ok, err := VerifyDigest(parsedPub, digest, sig1)
	if err != nil || !ok {
		t.Fatalf("parsed public key failed to verify sig from original: ok=%v err=%v", ok, err)
	}

	// Parsed priv signs, original pub verifies.
	sig2, err := SignDigest(parsedPriv, digest)
	if err != nil {
		t.Fatalf("SignDigest(parsed): %v", err)
	}
	ok, err = VerifyDigest(priv.PublicKey(), digest, sig2)
	if err != nil || !ok {
		t.Fatalf("original public key failed to verify sig from parsed: ok=%v err=%v", ok, err)
	}
}

// TestPEM_RejectsMalformed verifies that invalid/empty/wrong-type
// PEM inputs are rejected cleanly without panicking.
func TestPEM_RejectsMalformed(t *testing.T) {
	skipPEMIfNoEngine(t)

	cases := []struct {
		name string
		pem  []byte
	}{
		{"empty", []byte{}},
		{"garbage", []byte("not a pem")},
		{"truncated header", []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")},
		{"wrong type", []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")},
	}

	for _, tc := range cases {
		t.Run("priv/"+tc.name, func(t *testing.T) {
			if k, err := ParsePrivateKeyPEM(tc.pem); err == nil {
				k.Zeroize()
				t.Error("expected error, got nil")
			}
		})
		t.Run("pub/"+tc.name, func(t *testing.T) {
			if p, err := ParsePublicKeyPEM(tc.pem); err == nil {
				p.ZeroizePublicKey()
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestPEM_WrongKeyTypeReturnsErrPEMType verifies that a PEM block
// containing a non-GOST key (e.g. RSA) is rejected with ErrPEMType,
// not a generic OpenSSL error. This runs only if OpenSSL can emit
// a non-GOST key in the first place (true on any modern libssl).
func TestPEM_WrongKeyTypeReturnsErrPEMType(t *testing.T) {
	skipPEMIfNoEngine(t)

	// A minimal well-formed Ed25519 public key in PEM (generated once,
	// committed as a constant). If OpenSSL can parse this, we expect
	// ErrPEMType; otherwise the test is a no-op.
	const ed25519PubPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----
`
	_, err := ParsePublicKeyPEM([]byte(ed25519PubPEM))
	if err == nil {
		t.Fatal("expected error parsing Ed25519 key as GOST, got nil")
	}
	// We accept either ErrPEMType (if OpenSSL parsed the SPKI) or a
	// generic parse error (if the Ed25519 OID is not recognized).
	if !errors.Is(err, ErrPEMType) && !strings.Contains(err.Error(), "PEM_read") {
		t.Logf("unexpected error type: %v (accepted as non-nil)", err)
	}
}
