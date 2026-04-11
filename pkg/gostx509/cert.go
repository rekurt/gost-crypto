package gostx509

import (
	"errors"
	"math/big"
	"time"

	"github.com/rekurt/gost-crypto/internal/cryptopro"
	"github.com/rekurt/gost-crypto/pkg/gost3410"
)

// Subject represents the distinguished name fields for a certificate.
type Subject struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	Province           string
	Locality           string
}

// CertOptions specifies parameters for certificate creation.
type CertOptions struct {
	SerialNumber *big.Int
	NotBefore    time.Time
	NotAfter     time.Time
}

// Certificate wraps an X.509 certificate backed by CryptoPro.
type Certificate struct {
	cert *cryptopro.X509Cert
}

// CertificateRequest wraps an X.509 CSR backed by CryptoPro.
type CertificateRequest struct {
	req *cryptopro.X509Request
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
		return 0, errors.New("gostx509: unsupported curve size")
	}
}

// toOpensslName converts Subject to cryptopro.X509Name.
func toOpensslName(s Subject) cryptopro.X509Name {
	return cryptopro.X509Name{
		CommonName:         s.CommonName,
		Organization:       s.Organization,
		OrganizationalUnit: s.OrganizationalUnit,
		Country:            s.Country,
		Province:           s.Province,
		Locality:           s.Locality,
	}
}

// CreateSelfSigned creates a self-signed X.509 v3 certificate.
//
// The certificate is signed with the given GOST R 34.10-2012 private key
// using the appropriate Streebog hash (256-bit for 256-bit curves,
// 512-bit for 512-bit curves).
func CreateSelfSigned(priv *gost3410.PrivKey, subject Subject, opts CertOptions) (*Certificate, error) {
	if priv == nil {
		return nil, errors.New("gostx509: nil private key")
	}

	mdNID, err := digestNID(priv.Curve())
	if err != nil {
		return nil, err
	}

	serial := opts.SerialNumber
	if serial == nil {
		serial = big.NewInt(1)
	}

	handle := priv.Handle()
	if handle == nil {
		return nil, errors.New("gostx509: key has no CryptoPro handle")
	}

	cert, err := cryptopro.CreateSelfSignedCert(
		handle,
		toOpensslName(subject),
		serial,
		opts.NotBefore,
		opts.NotAfter,
		mdNID,
	)
	if err != nil {
		return nil, err
	}

	return &Certificate{cert: cert}, nil
}

// CreateCSR creates a Certificate Signing Request (CSR/PKCS#10).
func CreateCSR(priv *gost3410.PrivKey, subject Subject) (*CertificateRequest, error) {
	if priv == nil {
		return nil, errors.New("gostx509: nil private key")
	}

	mdNID, err := digestNID(priv.Curve())
	if err != nil {
		return nil, err
	}

	handle := priv.Handle()
	if handle == nil {
		return nil, errors.New("gostx509: key has no CryptoPro handle")
	}

	req, err := cryptopro.CreateCSR(handle, toOpensslName(subject), mdNID)
	if err != nil {
		return nil, err
	}

	return &CertificateRequest{req: req}, nil
}

// ParseDER parses a certificate from DER-encoded bytes.
func ParseDER(der []byte) (*Certificate, error) {
	cert, err := cryptopro.ParseCertDER(der)
	if err != nil {
		return nil, err
	}
	return &Certificate{cert: cert}, nil
}

// ParsePEM parses a certificate from PEM-encoded bytes.
func ParsePEM(pem []byte) (*Certificate, error) {
	cert, err := cryptopro.ParseCertPEM(pem)
	if err != nil {
		return nil, err
	}
	return &Certificate{cert: cert}, nil
}

// --- Certificate methods ---

// DER returns the certificate encoded in DER format.
func (c *Certificate) DER() ([]byte, error) {
	return c.cert.MarshalDER()
}

// PEM returns the certificate encoded in PEM format.
func (c *Certificate) PEM() ([]byte, error) {
	return c.cert.MarshalPEM()
}

// SubjectCN returns the Common Name from the certificate's subject.
func (c *Certificate) SubjectCN() string {
	return c.cert.SubjectCN()
}

// IssuerCN returns the Common Name from the certificate's issuer.
func (c *Certificate) IssuerCN() string {
	return c.cert.IssuerCN()
}

// Verify verifies the certificate's signature against the given public key.
// For self-signed certificates, pass the certificate's own public key.
func (c *Certificate) Verify(pub *gost3410.PubKey) error {
	if pub == nil {
		return errors.New("gostx509: nil public key")
	}
	handle := pub.Handle()
	if handle == nil {
		return errors.New("gostx509: public key has no CryptoPro handle")
	}
	return cryptopro.VerifyCert(c.cert, handle)
}

// VerifySelfSigned verifies that the certificate is validly self-signed.
// Under the CryptoPro CSP backend this dispatches to
// CryptVerifyCertificateSignatureEx in self-signed mode — no public-key
// handle extraction is required because the CSP resolves the public key
// directly from the certificate context.
func (c *Certificate) VerifySelfSigned() error {
	return cryptopro.VerifyCert(c.cert, nil)
}

// CryptoProCert returns the underlying CryptoPro X509Cert handle for use by
// other packages (e.g., CMS signing). The returned handle is shared —
// do not free it separately.
func (c *Certificate) CryptoProCert() *cryptopro.X509Cert {
	return c.cert
}

// Free releases the underlying CryptoPro X509 structure.
func (c *Certificate) Free() {
	if c.cert != nil {
		c.cert.Free()
		c.cert = nil
	}
}

// --- CSR methods ---

// DER returns the CSR encoded in DER format.
func (r *CertificateRequest) DER() ([]byte, error) {
	return r.req.MarshalDER()
}

// PEM returns the CSR encoded in PEM format.
func (r *CertificateRequest) PEM() ([]byte, error) {
	return r.req.MarshalPEM()
}

// Free releases the underlying CryptoPro X509_REQ structure.
func (r *CertificateRequest) Free() {
	if r.req != nil {
		r.req.Free()
		r.req = nil
	}
}
