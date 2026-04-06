package gostcrypto

import "github.com/rekurt/gost-crypto/pkg/gost3410"

// PrivKey is a GOST R 34.10-2012 private key.
type PrivKey = gost3410.PrivKey

// PubKey is a GOST R 34.10-2012 public key.
type PubKey = gost3410.PubKey

// GenerateKey generates a new GOST R 34.10-2012 key pair for the given curve.
func GenerateKey(c Curve) (*PrivKey, error) {
	return gost3410.GenerateKey(c)
}
