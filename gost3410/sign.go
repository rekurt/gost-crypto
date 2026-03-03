package gost3410

import (
	"errors"
)

// SignDigest computes a GOST R 34.10-2012 signature over the message digest.
// The digest must be computed using the appropriate Streebog variant for the key size.
// Returns signature in GOST OCTET STRING format: r||s, each of size equal to key size.
func (k *PrivKey) SignDigest(digest []byte) ([]byte, error) {
	if k == nil {
		return nil, errors.New("nil private key")
	}

	keySize, err := k.Curve.Size()
	if err != nil {
		return nil, err
	}

	// Validate digest size matches key size
	if len(digest) != keySize {
		return nil, errors.New("digest size does not match key size")
	}

	// Sign using backend
	sig, err := backendSign(k.Curve, k.D, digest)
	if err != nil {
		return nil, err
	}

	// gogost returns sig as s||r (both in big-endian, not little-endian!)
	// We want r||s (big-endian)
	if len(sig) != 2*keySize {
		return nil, errors.New("invalid signature length from backend")
	}

	// Reorder: gogost returns s||r, we need r||s
	result := make([]byte, 2*keySize)
	s := sig[:keySize]
	r := sig[keySize:]

	copy(result[:keySize], r)
	copy(result[keySize:], s)

	return result, nil
}

// Verify checks a GOST R 34.10-2012 signature over the message digest.
// Expects signature as r||s (GOST OCTET STRING).
func (p *PubKey) Verify(digest []byte, sig []byte) (bool, error) {
	if p == nil {
		return false, errors.New("nil public key")
	}

	keySize, err := p.Curve.Size()
	if err != nil {
		return false, err
	}

	// Validate digest size matches key size
	if len(digest) != keySize {
		return false, errors.New("digest size does not match key size")
	}

	// Validate signature size
	if len(sig) != 2*keySize {
		return false, errors.New("invalid signature size")
	}

	// Convert signature from r||s (big-endian) to s||r (big-endian) format (gogost expects s||r big-endian)
	r := sig[:keySize]
	s := sig[keySize:]
	gogostSig := make([]byte, 2*keySize)

	copy(gogostSig[:keySize], s)
	copy(gogostSig[keySize:], r)

	// Verify using backend
	return backendVerify(p.Curve, p.X, p.Y, digest, gogostSig)
}
