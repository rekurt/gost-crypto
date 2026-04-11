package cms

import (
	"math/big"
	"testing"
	"time"

	"github.com/rekurt/gost-crypto/internal/cryptopro"
	"github.com/rekurt/gost-crypto/pkg/gost3410"
	"github.com/rekurt/gost-crypto/pkg/gostx509"
)

func skipIfNoEngine(t *testing.T) {
	t.Helper()
	if err := cryptopro.Init(); err != nil {
		t.Skip("CryptoPro CSP not available:", err)
	}
}

// helper to create a test key + cert.
func testKeyCert(t *testing.T, curve gost3410.Curve) (*gost3410.PrivKey, *gostx509.Certificate) {
	t.Helper()
	priv, err := gost3410.GenerateKey(curve)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cert, err := gostx509.CreateSelfSigned(priv, gostx509.Subject{
		CommonName: "CMS Test Signer",
		Country:    "RU",
	}, gostx509.CertOptions{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		priv.Zeroize()
		t.Fatalf("CreateSelfSigned: %v", err)
	}

	return priv, cert
}

func TestSign_Detached_Verify(t *testing.T) {
	skipIfNoEngine(t)

	priv, cert := testKeyCert(t, gost3410.CurveTC26_256_A)
	defer priv.Zeroize()
	defer cert.Free()

	data := []byte("This is a legally significant document for ЭДО testing.")

	// Create detached signature.
	signed, err := Sign(priv, cert, data, SignOptions{Detached: true})
	if err != nil {
		t.Fatalf("Sign(detached): %v", err)
	}
	defer signed.Free()

	// Verify with original data.
	err = signed.Verify(data, VerifyOptions{NoCertVerify: true})
	if err != nil {
		t.Fatalf("Verify(detached): %v", err)
	}

	// Verify with wrong data should fail.
	err = signed.Verify([]byte("tampered data"), VerifyOptions{NoCertVerify: true})
	if err == nil {
		t.Error("Verify should fail with wrong data")
	}
}

func TestSign_Attached_Verify(t *testing.T) {
	skipIfNoEngine(t)

	priv, cert := testKeyCert(t, gost3410.CurveTC26_256_A)
	defer priv.Zeroize()
	defer cert.Free()

	data := []byte("Attached signature test data for CMS/PKCS#7")

	// Create attached signature.
	signed, err := Sign(priv, cert, data, SignOptions{Detached: false})
	if err != nil {
		t.Fatalf("Sign(attached): %v", err)
	}
	defer signed.Free()

	// Verify without providing data (content is embedded).
	err = signed.Verify(nil, VerifyOptions{NoCertVerify: true})
	if err != nil {
		t.Fatalf("Verify(attached): %v", err)
	}
}

func TestSign_DER_Roundtrip(t *testing.T) {
	skipIfNoEngine(t)

	priv, cert := testKeyCert(t, gost3410.CurveTC26_256_A)
	defer priv.Zeroize()
	defer cert.Free()

	data := []byte("DER roundtrip test")

	signed, err := Sign(priv, cert, data, SignOptions{Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	defer signed.Free()

	// Serialize to DER.
	der, err := signed.DER()
	if err != nil {
		t.Fatalf("DER: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("DER returned empty")
	}

	// Parse back.
	parsed, err := ParseDER(der)
	if err != nil {
		t.Fatalf("ParseDER: %v", err)
	}
	defer parsed.Free()

	// Verify the parsed signature.
	err = parsed.Verify(data, VerifyOptions{NoCertVerify: true})
	if err != nil {
		t.Fatalf("Verify(parsed): %v", err)
	}
}

func TestSign_512bit(t *testing.T) {
	skipIfNoEngine(t)

	priv, cert := testKeyCert(t, gost3410.CurveTC26_512_A)
	defer priv.Zeroize()
	defer cert.Free()

	data := []byte("512-bit curve CMS test")

	signed, err := Sign(priv, cert, data, SignOptions{Detached: true})
	if err != nil {
		t.Fatalf("Sign(512): %v", err)
	}
	defer signed.Free()

	err = signed.Verify(data, VerifyOptions{NoCertVerify: true})
	if err != nil {
		t.Fatalf("Verify(512): %v", err)
	}
}

func TestSign_NilInputs(t *testing.T) {
	_, err := Sign(nil, nil, nil, SignOptions{})
	if err == nil {
		t.Error("expected error for nil inputs")
	}
}
