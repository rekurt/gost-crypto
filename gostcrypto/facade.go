// Package gostcrypto provides a high-level facade that combines Streebog
// hashing (GOST R 34.11-2012) with GOST R 34.10-2012 signing and
// verification in a single call.
package gostcrypto

import (
	"errors"

	"github.com/rekurt/gost-crypto/gost3410"
	"github.com/rekurt/gost-crypto/streebog"
)

// Options controls hashing and other parameters for signing/verification.
type Options struct {
	// Hash selects Streebog-256 or Streebog-512. If zero, inferred from key size.
	Hash gost3410.HashID
}

// Sign hashes msg with configured Streebog and signs using GOST R 34.10-2012.
// Returns GOST OCTET STRING signature r||s.
func Sign(priv *gost3410.PrivKey, msg []byte, opt *Options) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("nil private key")
	}
	var h gost3410.HashID
	if opt != nil && (opt.Hash == gost3410.Streebog256 || opt.Hash == gost3410.Streebog512) {
		h = opt.Hash
	} else {
		// infer from key size
		switch len(priv.D) {
		case 32:
			h = gost3410.Streebog256
		case 64:
			h = gost3410.Streebog512
		default:
			return nil, errors.New("unsupported private key size")
		}
	}

	var digest []byte
	switch h {
	case gost3410.Streebog256:
		sum := streebog.Sum256(msg)
		digest = sum[:]
	case gost3410.Streebog512:
		sum := streebog.Sum512(msg)
		digest = sum[:]
	default:
		return nil, errors.New("unknown hash id")
	}
	return priv.SignDigest(digest)
}

// Verify hashes msg with configured Streebog and verifies GOST R 34.10-2012 signature (r||s).
func Verify(pub *gost3410.PubKey, msg, sig []byte, opt *Options) (bool, error) {
	if pub == nil {
		return false, errors.New("nil public key")
	}
	var h gost3410.HashID
	if opt != nil && (opt.Hash == gost3410.Streebog256 || opt.Hash == gost3410.Streebog512) {
		h = opt.Hash
	} else {
		switch len(pub.X) {
		case 32:
			h = gost3410.Streebog256
		case 64:
			h = gost3410.Streebog512
		default:
			return false, errors.New("unsupported public key size")
		}
	}

	var digest []byte
	switch h {
	case gost3410.Streebog256:
		sum := streebog.Sum256(msg)
		digest = sum[:]
	case gost3410.Streebog512:
		sum := streebog.Sum512(msg)
		digest = sum[:]
	default:
		return false, errors.New("unknown hash id")
	}
	return pub.Verify(digest, sig)
}
