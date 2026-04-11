package gostx509

import (
	"bytes"
	"math/big"
	"testing"
	"time"

	"github.com/rekurt/gost-crypto/internal/cryptopro"
	"github.com/rekurt/gost-crypto/pkg/gost3410"
)

func skipIfNoEngine(t *testing.T) {
	t.Helper()
	if err := cryptopro.Init(); err != nil {
		t.Skip("CryptoPro CSP not available:", err)
	}
}

func TestCreateSelfSigned_256(t *testing.T) {
	skipIfNoEngine(t)

	priv, err := gost3410.GenerateKey(gost3410.CurveTC26_256_A)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Zeroize()

	cert, err := CreateSelfSigned(priv, Subject{
		CommonName:   "Test GOST CA",
		Organization: "Test Organization",
		Country:      "RU",
	}, CertOptions{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateSelfSigned: %v", err)
	}
	defer cert.Free()

	// Verify subject CN.
	if cn := cert.SubjectCN(); cn != "Test GOST CA" {
		t.Errorf("SubjectCN = %q, want %q", cn, "Test GOST CA")
	}

	// Self-signed: issuer = subject.
	if cn := cert.IssuerCN(); cn != "Test GOST CA" {
		t.Errorf("IssuerCN = %q, want %q", cn, "Test GOST CA")
	}

	// Verify self-signed signature.
	if err := cert.VerifySelfSigned(); err != nil {
		t.Errorf("VerifySelfSigned: %v", err)
	}

	// Verify with explicit public key.
	if err := cert.Verify(priv.PublicKey()); err != nil {
		t.Errorf("Verify(pub): %v", err)
	}
}

func TestCreateSelfSigned_512(t *testing.T) {
	skipIfNoEngine(t)

	priv, err := gost3410.GenerateKey(gost3410.CurveTC26_512_A)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Zeroize()

	cert, err := CreateSelfSigned(priv, Subject{
		CommonName: "512-bit Test",
		Country:    "RU",
	}, CertOptions{
		SerialNumber: big.NewInt(42),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateSelfSigned(512): %v", err)
	}
	defer cert.Free()

	if err := cert.VerifySelfSigned(); err != nil {
		t.Errorf("VerifySelfSigned(512): %v", err)
	}
}

func TestCert_DER_Roundtrip(t *testing.T) {
	skipIfNoEngine(t)

	priv, err := gost3410.GenerateKey(gost3410.CurveTC26_256_A)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Zeroize()

	cert, err := CreateSelfSigned(priv, Subject{
		CommonName: "DER Test",
		Country:    "RU",
	}, CertOptions{
		SerialNumber: big.NewInt(100),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cert.Free()

	// Serialize to DER.
	der, err := cert.DER()
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

	if cn := parsed.SubjectCN(); cn != "DER Test" {
		t.Errorf("parsed SubjectCN = %q, want %q", cn, "DER Test")
	}

	// Re-serialize and compare.
	der2, err := parsed.DER()
	if err != nil {
		t.Fatalf("second DER: %v", err)
	}
	if !bytes.Equal(der, der2) {
		t.Error("DER roundtrip mismatch")
	}
}

func TestCert_PEM_Roundtrip(t *testing.T) {
	skipIfNoEngine(t)

	priv, err := gost3410.GenerateKey(gost3410.CurveTC26_256_A)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Zeroize()

	cert, err := CreateSelfSigned(priv, Subject{
		CommonName: "PEM Test",
		Country:    "RU",
	}, CertOptions{
		SerialNumber: big.NewInt(200),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cert.Free()

	pem, err := cert.PEM()
	if err != nil {
		t.Fatalf("PEM: %v", err)
	}

	if !bytes.HasPrefix(pem, []byte("-----BEGIN CERTIFICATE-----")) {
		t.Error("PEM does not start with expected header")
	}

	parsed, err := ParsePEM(pem)
	if err != nil {
		t.Fatalf("ParsePEM: %v", err)
	}
	defer parsed.Free()

	if cn := parsed.SubjectCN(); cn != "PEM Test" {
		t.Errorf("parsed SubjectCN = %q, want %q", cn, "PEM Test")
	}
}

func TestCreateCSR(t *testing.T) {
	skipIfNoEngine(t)

	priv, err := gost3410.GenerateKey(gost3410.CurveTC26_256_A)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Zeroize()

	csr, err := CreateCSR(priv, Subject{
		CommonName:   "CSR Test",
		Organization: "Test Org",
		Country:      "RU",
	})
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	defer csr.Free()

	// Serialize to PEM.
	pem, err := csr.PEM()
	if err != nil {
		t.Fatalf("CSR PEM: %v", err)
	}

	if !bytes.HasPrefix(pem, []byte("-----BEGIN CERTIFICATE REQUEST-----")) {
		t.Error("CSR PEM does not start with expected header")
	}

	// Serialize to DER.
	der, err := csr.DER()
	if err != nil {
		t.Fatalf("CSR DER: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("CSR DER returned empty")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	skipIfNoEngine(t)

	priv1, _ := gost3410.GenerateKey(gost3410.CurveTC26_256_A)
	defer priv1.Zeroize()
	priv2, _ := gost3410.GenerateKey(gost3410.CurveTC26_256_A)
	defer priv2.Zeroize()

	cert, err := CreateSelfSigned(priv1, Subject{
		CommonName: "Wrong Key Test",
	}, CertOptions{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cert.Free()

	// Verify with wrong key should fail.
	err = cert.Verify(priv2.PublicKey())
	if err == nil {
		t.Error("Verify with wrong key should fail")
	}
}

func TestCreateSelfSigned_NilKey(t *testing.T) {
	_, err := CreateSelfSigned(nil, Subject{CommonName: "test"}, CertOptions{})
	if err == nil {
		t.Error("expected error for nil key")
	}
}
