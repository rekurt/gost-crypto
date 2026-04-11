// Package gostx509 provides X.509 certificate operations with GOST R 34.10-2012
// digital signatures, backed by CryptoPro CSP (CAPILite CertXxx functions).
//
// This package supports creating self-signed certificates, certificate signing
// requests (CSR), parsing certificates from DER/PEM, and verifying certificate
// signatures — all using GOST elliptic curve algorithms and Streebog hashes.
//
// # Certificate Creation
//
// Create a self-signed certificate:
//
//	priv, _ := gost3410.GenerateKey(gost3410.CurveTC26_256_A)
//	defer priv.Zeroize()
//
//	cert, _ := gostx509.CreateSelfSigned(priv, gostx509.Subject{
//	    CommonName:   "Test CA",
//	    Organization: "Test Org",
//	    Country:      "RU",
//	}, gostx509.CertOptions{
//	    SerialNumber: big.NewInt(1),
//	    NotBefore:    time.Now(),
//	    NotAfter:     time.Now().Add(365 * 24 * time.Hour),
//	})
//	defer cert.Free()
//
//	pem, _ := cert.PEM()
//
// # Standards
//
// RFC 4491 (GOST algorithms in X.509), GOST R 34.10-2012, GOST R 34.11-2012.
package gostx509
