package gost3410

import (
	"crypto/rand"
	"errors"

	gg "github.com/ddulesov/gogost/gost3410"
)

// HashID selects which Streebog variant to use with signatures.
type HashID int

const (
	// HashAuto is the zero value and indicates that the hash algorithm
	// should be inferred automatically (e.g., from key size).
	HashAuto    HashID = iota
	Streebog256        // GOST R 34.11-2012 with 256-bit output
	Streebog512        // GOST R 34.11-2012 with 512-bit output
)

// Sign computes a GOST R 34.10-2012 signature over the message digest.
// The digest must be computed using the selected Streebog variant.
// Returns signature in GOST OCTET STRING format: r||s, each of size equal to key size.
func (k *PrivKey) Sign(digest []byte, h HashID) ([]byte, error) {
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

	// Get gogost curve and mode
	ggCurve, err := getCurve(k.Curve)
	if err != nil {
		return nil, err
	}

	mode, err := getMode(k.Curve)
	if err != nil {
		return nil, err
	}

	// Create gogost private key
	ggPrivKey, err := gg.NewPrivateKey(ggCurve, mode, k.D)
	if err != nil {
		return nil, err
	}

	// Sign using gogost library
	sig, err := ggPrivKey.SignDigest(digest, rand.Reader)
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
func (p *PubKey) Verify(digest []byte, sig []byte, h HashID) (bool, error) {
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

	// Get gogost curve and mode
	ggCurve, err := getCurve(p.Curve)
	if err != nil {
		return false, err
	}

	mode, err := getMode(p.Curve)
	if err != nil {
		return false, err
	}

	// Create gogost public key from X, Y coordinates
	// gogost.NewPublicKey expects raw format as: X||Y with both coordinates reversed to little-endian
	// We have X, Y stored as big-endian bytes, so we need to reverse them before passing to gogost

	rawKey := make([]byte, 2*keySize)

	// Reverse X to little-endian and place at first position
	for i := 0; i < keySize; i++ {
		rawKey[i] = p.X[keySize-1-i]
	}
	// Reverse Y to little-endian and place at second position
	for i := 0; i < keySize; i++ {
		rawKey[keySize+i] = p.Y[keySize-1-i]
	}

	ggPubKey, err := gg.NewPublicKey(ggCurve, mode, rawKey)
	if err != nil {
		return false, err
	}

	// Convert signature from r||s (big-endian) to s||r (big-endian) format (gogost expects s||r big-endian)
	r := sig[:keySize]
	s := sig[keySize:]
	gogostSig := make([]byte, 2*keySize)

	copy(gogostSig[:keySize], s)
	copy(gogostSig[keySize:], r)

	// Verify using gogost library
	return ggPubKey.VerifyDigest(digest, gogostSig)
}
