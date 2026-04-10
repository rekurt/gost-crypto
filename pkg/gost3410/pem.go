package gost3410

import (
	"errors"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

// ErrPEMType is returned when a parsed PEM block has an algorithm
// identifier that does not match a GOST R 34.10-2012 key.
var ErrPEMType = errors.New("gost3410: PEM block is not a GOST R 34.10-2012 key")

// MarshalPrivateKeyPEM serializes the private key as an unencrypted
// PKCS#8 "PRIVATE KEY" PEM block, interoperable with OpenSSL
// gost-engine (verify with `openssl pkey -in key.pem -text`).
//
// The returned PEM contains a standard SubjectPrivateKeyInfo structure
// whose AlgorithmIdentifier uses the GOST R 34.10-2012 OID
// (1.2.643.7.1.1.1.1 for 256-bit, 1.2.643.7.1.1.1.2 for 512-bit)
// per RFC 4491 / RFC 7836.
//
// The caller is responsible for securely handling the returned bytes —
// they contain the raw private key material.
func (k *PrivKey) MarshalPrivateKeyPEM() ([]byte, error) {
	if k == nil || k.handle == nil || k.handle.IsNil() {
		return nil, ErrNilKey
	}
	return openssl.MarshalPKCS8PrivateKeyPEM(k.handle)
}

// ParsePrivateKeyPEM parses an unencrypted PEM-encoded GOST R 34.10-2012
// private key (PKCS#8 "PRIVATE KEY" block or algorithm-specific legacy
// block — both auto-detected) and returns a new *PrivKey.
//
// The caller must Zeroize the returned key when done.
func ParsePrivateKeyPEM(pem []byte) (*PrivKey, error) {
	h, nid, err := openssl.ParsePrivateKeyPEM(pem)
	if err != nil {
		if errors.Is(err, openssl.ErrUnsupportedKeyType) {
			return nil, ErrPEMType
		}
		return nil, err
	}

	c, err := curveFromSignNID(nid)
	if err != nil {
		h.Free()
		return nil, err
	}

	return &PrivKey{handle: h, curve: c}, nil
}

// MarshalPublicKeyPEM serializes the public key as a
// SubjectPublicKeyInfo "PUBLIC KEY" PEM block, interoperable with
// OpenSSL gost-engine (verify with `openssl pkey -pubin -in pub.pem -text`).
func (p *PubKey) MarshalPublicKeyPEM() ([]byte, error) {
	if p == nil || p.handle == nil || p.handle.IsNil() {
		return nil, ErrNilKey
	}
	return openssl.MarshalPKIXPublicKeyPEM(p.handle)
}

// ParsePublicKeyPEM parses a PEM-encoded SubjectPublicKeyInfo GOST
// R 34.10-2012 public key and returns a new *PubKey.
//
// Unlike PubKey values obtained from a PrivKey, the returned PubKey
// owns its own EVP_PKEY handle. Call ZeroizePublicKey to release it.
func ParsePublicKeyPEM(pem []byte) (*PubKey, error) {
	h, nid, err := openssl.ParsePublicKeyPEM(pem)
	if err != nil {
		if errors.Is(err, openssl.ErrUnsupportedKeyType) {
			return nil, ErrPEMType
		}
		return nil, err
	}

	c, err := curveFromSignNID(nid)
	if err != nil {
		h.Free()
		return nil, err
	}

	return &PubKey{handle: h, curve: c}, nil
}

// ZeroizePublicKey releases the EVP_PKEY handle held by a PubKey that
// was parsed standalone (e.g. via ParsePublicKeyPEM). It is a no-op
// for a PubKey obtained via PrivKey.PublicKey() — in that case the
// PrivKey owns the handle.
//
// Calling ZeroizePublicKey on a shared handle would break the owning
// PrivKey; callers that mix the two sources should track ownership
// themselves. This method only protects against double-free on
// standalone PubKey values.
func (p *PubKey) ZeroizePublicKey() {
	if p != nil && p.handle != nil {
		p.handle.Free()
		p.handle = nil
	}
}

// curveFromSignNID picks a canonical 256/512 curve for a parsed key.
// PEM blocks identify the signing algorithm (by NID) but not the
// specific parameter set. We default to the most common paramSet (A)
// for each width; applications that need to distinguish paramSets
// should inspect the embedded paramSet OID manually.
func curveFromSignNID(nid int) (Curve, error) {
	switch nid {
	case openssl.NID_GostR3410_2012_256:
		return CurveTC26_256_A, nil
	case openssl.NID_GostR3410_2012_512:
		return CurveTC26_512_A, nil
	default:
		return 0, ErrUnknownCurve
	}
}
