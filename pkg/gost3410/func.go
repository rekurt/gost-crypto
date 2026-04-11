package gost3410

import (
	"github.com/rekurt/gost-crypto/internal/cryptopro"
)

// SignDigest signs a pre-computed digest with the given private key.
// The digest length must equal the key size (32 for 256-bit curves,
// 64 for 512-bit curves).
func SignDigest(priv *PrivKey, digest []byte) ([]byte, error) {
	if priv == nil || priv.handle.IsNil() {
		return nil, ErrNilKey
	}

	keySize, err := priv.curve.Size()
	if err != nil {
		return nil, err
	}
	if len(digest) != keySize {
		return nil, ErrInvalidKeySize
	}

	return cryptopro.SignDigestH(priv.handle, digest)
}

// VerifyDigest verifies a signature over a pre-computed digest using the
// given public key.
// The digest length must equal the key size and the signature length must
// equal twice the key size.
// Returns (true, nil) on valid signature, (false, nil) on invalid
// signature, and (false, err) on operational error.
func VerifyDigest(pub *PubKey, digest, sig []byte) (bool, error) {
	if pub == nil || pub.handle.IsNil() {
		return false, ErrNilKey
	}

	keySize, err := pub.curve.Size()
	if err != nil {
		return false, err
	}
	sigSize, err := pub.curve.SignatureSize()
	if err != nil {
		return false, err
	}

	if len(digest) != keySize {
		return false, ErrInvalidKeySize
	}
	if len(sig) != sigSize {
		return false, ErrInvalidSignature
	}

	return cryptopro.VerifyDigestH(pub.handle, digest, sig)
}
