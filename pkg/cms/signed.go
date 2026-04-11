package cms

import (
	"errors"

	"github.com/rekurt/gost-crypto/internal/cryptopro"
	"github.com/rekurt/gost-crypto/pkg/gost3410"
	"github.com/rekurt/gost-crypto/pkg/gostx509"
)

// SignOptions controls CMS signing behavior.
type SignOptions struct {
	// Detached creates a detached signature (content not included in CMS).
	// The original data must be provided separately during verification.
	Detached bool
}

// VerifyOptions controls CMS verification behavior.
type VerifyOptions struct {
	// NoCertVerify skips certificate chain validation.
	// Only the cryptographic signature is verified.
	// This is useful when the signer's certificate is trusted by
	// the application directly (not via a CA chain).
	NoCertVerify bool
}

// SignedData wraps a CMS SignedData structure.
type SignedData struct {
	ci *cryptopro.CMSContentInfo
}

// Sign creates a CMS SignedData structure, signing the data with the
// given GOST R 34.10-2012 private key and certificate.
//
// The digest algorithm is automatically selected based on the key's curve:
// Streebog-256 for 256-bit curves, Streebog-512 for 512-bit curves.
func Sign(priv *gost3410.PrivKey, cert *gostx509.Certificate, data []byte, opts SignOptions) (*SignedData, error) {
	if priv == nil {
		return nil, errors.New("cms: nil private key")
	}
	if cert == nil {
		return nil, errors.New("cms: nil certificate")
	}

	mdNID, err := digestNID(priv.Curve())
	if err != nil {
		return nil, err
	}

	privHandle := priv.Handle()
	if privHandle == nil {
		return nil, errors.New("cms: key has no CryptoPro handle")
	}

	certHandle := cert.CryptoProCert()
	if certHandle == nil {
		return nil, errors.New("cms: certificate has no CryptoPro handle")
	}

	ci, err := cryptopro.CMSSign(certHandle, privHandle, data, mdNID, opts.Detached)
	if err != nil {
		return nil, err
	}

	return &SignedData{ci: ci}, nil
}

// Verify verifies the CMS SignedData signature.
//
// For detached signatures, data must contain the original signed content.
// For attached signatures, data should be nil.
func (s *SignedData) Verify(data []byte, opts VerifyOptions) error {
	if s.ci == nil {
		return errors.New("cms: nil signed data")
	}
	return cryptopro.CMSVerify(s.ci, data, opts.NoCertVerify)
}

// DER returns the CMS structure encoded in DER format.
// This is the standard binary format for CMS/PKCS#7 signatures.
func (s *SignedData) DER() ([]byte, error) {
	return s.ci.MarshalDER()
}

// PEM returns the CMS structure encoded in PEM format.
func (s *SignedData) PEM() ([]byte, error) {
	return s.ci.MarshalPEM()
}

// ParseDER parses a CMS SignedData from DER-encoded bytes.
func ParseDER(der []byte) (*SignedData, error) {
	ci, err := cryptopro.ParseCMSDER(der)
	if err != nil {
		return nil, err
	}
	return &SignedData{ci: ci}, nil
}

// Free releases the underlying CMS structure.
func (s *SignedData) Free() {
	if s.ci != nil {
		s.ci.Free()
		s.ci = nil
	}
}

// digestNID selects the appropriate Streebog NID based on the curve.
func digestNID(c gost3410.Curve) (int, error) {
	sz, err := c.Size()
	if err != nil {
		return 0, err
	}
	switch sz {
	case 32:
		return cryptopro.NID_Streebog256, nil
	case 64:
		return cryptopro.NID_Streebog512, nil
	default:
		return 0, errors.New("cms: unsupported curve size")
	}
}
