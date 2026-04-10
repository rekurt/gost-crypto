// Example: issue and verify a self-signed X.509 certificate with
// GOST R 34.10-2012 keys, then write the certificate and its private
// key to PEM files that are fully interoperable with `openssl x509`
// and `openssl pkey`.
//
// Run:  go run ./_examples/x509-cert
package main

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/rekurt/gost-crypto/pkg/gost3410"
	"github.com/rekurt/gost-crypto/pkg/gostx509"
)

func main() {
	fmt.Println("=== GOST R 34.10-2012 self-signed X.509 certificate ===")

	// 1. Generate a GOST R 34.10-2012 (256-bit) private key.
	priv, err := gost3410.GenerateKey(gost3410.CurveTC26_256_A)
	if err != nil {
		die("GenerateKey: %v", err)
	}
	defer priv.Zeroize()
	fmt.Printf("Generated private key: curve=%s\n", priv.Curve())

	// 2. Build the certificate subject and validity window.
	subject := gostx509.Subject{
		CommonName:   "Test GOST Certificate",
		Organization: "gost-crypto example",
		Country:      "RU",
	}
	opts := gostx509.CertOptions{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	// 3. Issue the self-signed certificate. The library picks the
	//    matching Streebog digest (256 or 512) based on the key curve.
	cert, err := gostx509.CreateSelfSigned(priv, subject, opts)
	if err != nil {
		die("CreateSelfSigned: %v", err)
	}
	defer cert.Free()
	fmt.Printf("Issued certificate: subject=%q\n", cert.SubjectCN())

	// 4. Verify the self-signature using the embedded public key.
	if err := cert.VerifySelfSigned(); err != nil {
		die("VerifySelfSigned: %v", err)
	}
	fmt.Println("Self-signature verified.")

	// 5. Marshal the cert to PEM and the private key to PKCS#8 PEM.
	certPEM, err := cert.PEM()
	if err != nil {
		die("cert.PEM: %v", err)
	}
	keyPEM, err := priv.MarshalPrivateKeyPEM()
	if err != nil {
		die("MarshalPrivateKeyPEM: %v", err)
	}

	// 6. Write to a temp dir. We use os.MkdirTemp so the example is
	//    repeatable and leaves no stale files in the source tree.
	dir, err := os.MkdirTemp("", "gost-x509-")
	if err != nil {
		die("MkdirTemp: %v", err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		die("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		die("write key: %v", err)
	}
	fmt.Printf("Wrote PEM files:\n  %s\n  %s\n", certPath, keyPath)

	// 7. Re-parse both PEM files from disk and verify the round-trip
	//    survived intact (cert still self-verifies; reloaded key
	//    signs + the original pub verifies).
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		die("read cert: %v", err)
	}
	parsedCert, err := gostx509.ParsePEM(certBytes)
	if err != nil {
		die("ParsePEM cert: %v", err)
	}
	defer parsedCert.Free()
	if err := parsedCert.VerifySelfSigned(); err != nil {
		die("parsed VerifySelfSigned: %v", err)
	}
	fmt.Printf("Parsed certificate: subject=%q issuer=%q\n",
		parsedCert.SubjectCN(), parsedCert.IssuerCN())

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		die("read key: %v", err)
	}
	parsedKey, err := gost3410.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		die("ParsePrivateKeyPEM: %v", err)
	}
	defer parsedKey.Zeroize()

	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}
	sig, err := gost3410.SignDigest(parsedKey, digest)
	if err != nil {
		die("SignDigest(parsedKey): %v", err)
	}
	ok, err := gost3410.VerifyDigest(priv.PublicKey(), digest, sig)
	if err != nil || !ok {
		die("original pub failed to verify sig from parsed key (ok=%v err=%v)", ok, err)
	}
	fmt.Println("Round-trip signing check passed.")

	fmt.Println("\nInspect the PEM with OpenSSL (requires gost-engine):")
	fmt.Printf("  openssl x509 -in %s -noout -text\n", certPath)
	fmt.Printf("  openssl pkey -in %s -text -noout\n", keyPath)
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
