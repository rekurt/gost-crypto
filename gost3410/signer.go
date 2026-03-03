package gost3410

import (
	"crypto"
	"io"
)

// Compile-time assertion: PrivKey implements crypto.Signer.
var _ crypto.Signer = (*PrivKey)(nil)

// Public returns the public key corresponding to this private key,
// satisfying the crypto.Signer interface. Returns nil if the key derivation fails.
func (k *PrivKey) Public() crypto.PublicKey {
	pub, err := k.PublicKey()
	if err != nil {
		return nil
	}
	return pub
}

// Sign signs digest with the private key, satisfying the crypto.Signer interface.
// The rand parameter is ignored because the gogost backend uses crypto/rand internally.
// The opts parameter is ignored; the hash algorithm is determined by key size.
func (k *PrivKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return k.SignDigest(digest)
}
