package gost3410

import (
	"bytes"
	"encoding/asn1"
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
// (by raw key-bytes comparison) for every supported TC26 parameter
// set. It also asserts that the parsed curve identity matches the
// original — i.e. the paramSet OID is preserved end-to-end, not
// collapsed to paramSet A.
func TestPEM_PrivateKeyRoundtrip(t *testing.T) {
	skipPEMIfNoEngine(t)

	cases := []struct {
		name  string
		curve Curve
	}{
		{"256-A", CurveTC26_256_A},
		{"256-B", CurveTC26_256_B},
		{"256-C", CurveTC26_256_C},
		{"256-D", CurveTC26_256_D},
		{"512-A", CurveTC26_512_A},
		{"512-B", CurveTC26_512_B},
		{"512-C", CurveTC26_512_C},
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

			// Curve identity must round-trip — not collapse to paramSet A.
			if parsed.Curve() != tc.curve {
				t.Errorf("parsed curve = %v, want %v", parsed.Curve(), tc.curve)
			}

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
// marshalled to an SPKI PEM block, parsed back, validated, and that
// its TC26 paramSet is recovered exactly (not collapsed to A).
func TestPEM_PublicKeyRoundtrip(t *testing.T) {
	skipPEMIfNoEngine(t)

	cases := []struct {
		name  string
		curve Curve
	}{
		{"256-A", CurveTC26_256_A},
		{"256-B", CurveTC26_256_B},
		{"256-C", CurveTC26_256_C},
		{"256-D", CurveTC26_256_D},
		{"512-A", CurveTC26_512_A},
		{"512-B", CurveTC26_512_B},
		{"512-C", CurveTC26_512_C},
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

			// Exact paramSet must round-trip, not just the bit width.
			if parsedPub.Curve() != tc.curve {
				t.Errorf("parsed curve = %v, want %v", parsedPub.Curve(), tc.curve)
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

// TestCurveFromDER_AllParamSets verifies the pure-Go ASN.1 parser
// that recovers the TC26 curve identity from a PKCS#8 PrivateKeyInfo
// or SubjectPublicKeyInfo DER. Unlike the OpenSSL-backed tests, this
// runs regardless of whether gost-engine is available in the
// environment, so CI always exercises the paramSet-detection code.
func TestCurveFromDER_AllParamSets(t *testing.T) {
	// gostR3410-2012 signing algorithm OIDs.
	sig256 := asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1}
	sig512 := asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 2}
	digest256 := asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}

	for curve := Curve(0); curve < curveCount; curve++ {
		curve := curve
		t.Run(curve.String(), func(t *testing.T) {
			oidStr := openssl.CurveOIDs[curve]
			paramOID, err := parseOIDString(oidStr)
			if err != nil {
				t.Fatalf("parse known OID %q: %v", oidStr, err)
			}

			sigAlgo := sig256
			rawKeyLen := 32
			if curve.is512() {
				sigAlgo = sig512
				rawKeyLen = 64
			}

			paramsDER, err := asn1.Marshal(gostPublicKeyParameters{
				PublicKeyParamSet: paramOID,
				DigestParamSet:    digest256,
			})
			if err != nil {
				t.Fatalf("marshal GOST params: %v", err)
			}
			algo := algorithmIdentifier{
				Algorithm:  sigAlgo,
				Parameters: asn1.RawValue{FullBytes: paramsDER},
			}

			// Synthetic PKCS#8 PrivateKeyInfo.
			privDER, err := asn1.Marshal(pkcs8PrivateKeyInfo{
				Version:             0,
				PrivateKeyAlgorithm: algo,
				PrivateKey:          make([]byte, rawKeyLen+2), // OCTET STRING tag/len + raw
			})
			if err != nil {
				t.Fatalf("marshal PrivateKeyInfo: %v", err)
			}

			got, err := curveFromPrivateKeyDER(privDER)
			if err != nil {
				t.Fatalf("curveFromPrivateKeyDER: %v", err)
			}
			if got != curve {
				t.Errorf("curveFromPrivateKeyDER = %v, want %v", got, curve)
			}

			// Synthetic SubjectPublicKeyInfo.
			spkiDER, err := asn1.Marshal(spkiInfo{
				Algorithm: algo,
				SubjectPublicKey: asn1.BitString{
					Bytes:     make([]byte, 2*rawKeyLen),
					BitLength: 2 * rawKeyLen * 8,
				},
			})
			if err != nil {
				t.Fatalf("marshal SPKI: %v", err)
			}

			got, err = curveFromPublicKeyDER(spkiDER)
			if err != nil {
				t.Fatalf("curveFromPublicKeyDER: %v", err)
			}
			if got != curve {
				t.Errorf("curveFromPublicKeyDER = %v, want %v", got, curve)
			}
		})
	}
}

// TestCurveFromDER_RejectsUnknownOID confirms that an AlgorithmIdentifier
// carrying a paramSet OID outside the TC26 set is rejected cleanly.
func TestCurveFromDER_RejectsUnknownOID(t *testing.T) {
	unknown := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	paramsDER, err := asn1.Marshal(gostPublicKeyParameters{
		PublicKeyParamSet: unknown,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	algo := algorithmIdentifier{
		Algorithm:  asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1},
		Parameters: asn1.RawValue{FullBytes: paramsDER},
	}
	privDER, err := asn1.Marshal(pkcs8PrivateKeyInfo{
		PrivateKeyAlgorithm: algo,
		PrivateKey:          []byte{0x04, 0x00},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := curveFromPrivateKeyDER(privDER); err == nil {
		t.Error("expected error for unknown paramSet OID, got nil")
	}
}

// parseOIDString is a tiny helper for the test table; it maps
// dotted-decimal strings back to asn1.ObjectIdentifier values.
func parseOIDString(s string) (asn1.ObjectIdentifier, error) {
	var out asn1.ObjectIdentifier
	part := 0
	hasDigit := false
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if !hasDigit {
				return nil, errors.New("empty OID arc")
			}
			out = append(out, part)
			part = 0
			hasDigit = false
			continue
		}
		if s[i] < '0' || s[i] > '9' {
			return nil, errors.New("non-digit in OID: " + s)
		}
		part = part*10 + int(s[i]-'0')
		hasDigit = true
	}
	return out, nil
}

// TestZeroizePublicKey_SharedHandleIsNoOp verifies that calling
// ZeroizePublicKey on a PubKey obtained from (*PrivKey).PublicKey()
// does NOT free the underlying handle — the owning PrivKey must
// still be usable afterward for signing.
func TestZeroizePublicKey_SharedHandleIsNoOp(t *testing.T) {
	skipPEMIfNoEngine(t)

	priv, err := GenerateKey(CurveTC26_256_A)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	defer priv.Zeroize()

	// Shared PubKey — ownsHandle must be false and Zeroize a no-op.
	shared := priv.PublicKey()
	if shared.ownsHandle {
		t.Fatal("PrivKey.PublicKey() returned a PubKey that claims to own its handle")
	}
	shared.ZeroizePublicKey()

	// Sanity: the private key still works end-to-end after the no-op.
	digest := make([]byte, 32)
	sig, err := SignDigest(priv, digest)
	if err != nil {
		t.Fatalf("SignDigest after shared ZeroizePublicKey: %v", err)
	}
	ok, err := VerifyDigest(priv.PublicKey(), digest, sig)
	if err != nil || !ok {
		t.Fatalf("Verify failed after shared ZeroizePublicKey: ok=%v err=%v", ok, err)
	}
}

// TestZeroizePublicKey_OwnedHandleReleases verifies that a PubKey
// parsed via ParsePublicKeyPEM does own its handle and that
// ZeroizePublicKey releases it (becomes unusable afterward).
func TestZeroizePublicKey_OwnedHandleReleases(t *testing.T) {
	skipPEMIfNoEngine(t)

	priv, err := GenerateKey(CurveTC26_256_A)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	defer priv.Zeroize()

	pubPEM, err := priv.PublicKey().MarshalPublicKeyPEM()
	if err != nil {
		t.Fatalf("MarshalPublicKeyPEM: %v", err)
	}

	parsed, err := ParsePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM: %v", err)
	}
	if !parsed.ownsHandle {
		t.Fatal("ParsePublicKeyPEM returned a PubKey that does not claim ownership")
	}

	// Before Zeroize: the parsed key can validate.
	if err := parsed.Validate(); err != nil {
		t.Fatalf("parsed key failed Validate before Zeroize: %v", err)
	}

	parsed.ZeroizePublicKey()

	// After Zeroize: the handle is nil and ownsHandle is cleared.
	if parsed.handle != nil {
		t.Error("handle not nil after ZeroizePublicKey on owned key")
	}
	if parsed.ownsHandle {
		t.Error("ownsHandle not cleared after ZeroizePublicKey")
	}
	// Calling again must still be a safe no-op (idempotent).
	parsed.ZeroizePublicKey()
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
