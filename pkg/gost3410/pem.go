package gost3410

import (
	"encoding/asn1"
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
// The returned PEM contains a standard PrivateKeyInfo whose
// AlgorithmIdentifier uses the RFC 4491 / RFC 7836 signing OID
// (1.2.643.7.1.1.1.1 for 256-bit, 1.2.643.7.1.1.1.2 for 512-bit)
// and its TC26 paramSet OID in the algorithm parameters.
//
// The caller is responsible for securely handling the returned
// bytes — they contain the raw private key material.
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
// The exact TC26 paramSet is recovered from the algorithm parameters
// of the encoded key: all eight parameter sets round-trip, and the
// returned PrivKey's Curve() reflects the input accurately.
//
// The caller must Zeroize the returned key when done.
func ParsePrivateKeyPEM(pem []byte) (*PrivKey, error) {
	h, _, err := openssl.ParsePrivateKeyPEM(pem)
	if err != nil {
		if errors.Is(err, openssl.ErrUnsupportedKeyType) {
			return nil, ErrPEMType
		}
		return nil, err
	}

	der, err := openssl.PrivKeyDER(h)
	if err != nil {
		h.Free()
		return nil, err
	}
	// Wipe the DER buffer once we're done reading the paramSet OID —
	// PKCS#8 DER carries the raw private key material.
	defer openssl.CleanseBytes(der)

	c, err := curveFromPrivateKeyDER(der)
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
// The exact TC26 paramSet is recovered from the SPKI
// AlgorithmIdentifier parameters. The returned PubKey owns its
// EVP_PKEY handle; call ZeroizePublicKey to release it.
func ParsePublicKeyPEM(pem []byte) (*PubKey, error) {
	h, _, err := openssl.ParsePublicKeyPEM(pem)
	if err != nil {
		if errors.Is(err, openssl.ErrUnsupportedKeyType) {
			return nil, ErrPEMType
		}
		return nil, err
	}

	der, err := openssl.PubKeyDER(h)
	if err != nil {
		h.Free()
		return nil, err
	}

	c, err := curveFromPublicKeyDER(der)
	if err != nil {
		h.Free()
		return nil, err
	}

	return &PubKey{handle: h, curve: c, ownsHandle: true}, nil
}

// ZeroizePublicKey releases the EVP_PKEY handle held by a PubKey,
// but only when the PubKey owns it. It is a safe no-op for a PubKey
// obtained via (*PrivKey).PublicKey() — in that case the PrivKey is
// the sole owner of the handle and freeing it here would break
// subsequent operations on the PrivKey.
//
// For PubKey values returned by ParsePublicKeyPEM (which own their
// handles), call this method when done.
func (p *PubKey) ZeroizePublicKey() {
	if p == nil || !p.ownsHandle || p.handle == nil {
		return
	}
	p.handle.Free()
	p.handle = nil
	p.ownsHandle = false
}

// --- ASN.1 helpers for recovering the TC26 paramSet ---

// pkcs8PrivateKeyInfo mirrors RFC 5208 PrivateKeyInfo with the
// algorithm parameters captured as a RawValue so we can re-parse them
// as the GOST-specific parameter structure without the outer decoder
// failing on an unknown shape.
type pkcs8PrivateKeyInfo struct {
	Version             int
	PrivateKeyAlgorithm algorithmIdentifier
	PrivateKey          []byte
	// Optional attributes / publicKey tagged fields — ignored.
}

// spkiInfo mirrors RFC 5280 SubjectPublicKeyInfo for GOST keys.
type spkiInfo struct {
	Algorithm        algorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// algorithmIdentifier keeps the parameters as a RawValue so that an
// empty/absent field or a GOST-specific SEQUENCE both decode cleanly.
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// gostPublicKeyParameters is the RFC 4491 / RFC 7836 structure
// embedded in the AlgorithmIdentifier parameters field of a GOST
// R 34.10-2012 key.
//
//	GostR3410-2012-PublicKeyParameters ::= SEQUENCE {
//	    publicKeyParamSet OBJECT IDENTIFIER,
//	    digestParamSet    OBJECT IDENTIFIER OPTIONAL
//	}
type gostPublicKeyParameters struct {
	PublicKeyParamSet asn1.ObjectIdentifier
	DigestParamSet    asn1.ObjectIdentifier `asn1:"optional"`
}

// curveFromPrivateKeyDER parses a PKCS#8 PrivateKeyInfo DER encoding
// and returns the Curve that matches the embedded TC26 paramSet OID.
func curveFromPrivateKeyDER(der []byte) (Curve, error) {
	var info pkcs8PrivateKeyInfo
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return 0, errors.New("gost3410: failed to parse PrivateKeyInfo: " + err.Error())
	}
	return curveFromAlgorithmParameters(info.PrivateKeyAlgorithm.Parameters)
}

// curveFromPublicKeyDER parses a SubjectPublicKeyInfo DER encoding
// and returns the Curve that matches the embedded TC26 paramSet OID.
func curveFromPublicKeyDER(der []byte) (Curve, error) {
	var info spkiInfo
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return 0, errors.New("gost3410: failed to parse SubjectPublicKeyInfo: " + err.Error())
	}
	return curveFromAlgorithmParameters(info.Algorithm.Parameters)
}

// curveFromAlgorithmParameters extracts the publicKeyParamSet OID from
// an AlgorithmIdentifier.parameters RawValue and maps it back to a
// Curve. If the parameters are absent or the OID is not one of the
// eight known TC26 parameter sets, an error is returned.
func curveFromAlgorithmParameters(params asn1.RawValue) (Curve, error) {
	if len(params.FullBytes) == 0 {
		return 0, errors.New("gost3410: missing GOST paramSet in AlgorithmIdentifier")
	}
	var p gostPublicKeyParameters
	if _, err := asn1.Unmarshal(params.FullBytes, &p); err != nil {
		return 0, errors.New("gost3410: failed to parse GOST paramSet: " + err.Error())
	}
	return curveFromOIDString(p.PublicKeyParamSet.String())
}

// curveFromOIDString performs a reverse lookup of openssl.CurveOIDs.
func curveFromOIDString(oid string) (Curve, error) {
	for i, known := range openssl.CurveOIDs {
		if known == oid {
			return Curve(i), nil
		}
	}
	return 0, errors.New("gost3410: unknown TC26 paramSet OID " + oid)
}
