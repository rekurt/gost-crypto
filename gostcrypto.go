package gostcrypto

import (
	"github.com/rekurt/gost-crypto/pkg/gost3410"
	"github.com/rekurt/gost-crypto/pkg/gost3411"
)

// Sign hashes msg with Streebog and signs with GOST R 34.10-2012.
//
// The hash size is chosen automatically based on the key's curve:
// Streebog-256 for 256-bit curves, Streebog-512 for 512-bit curves.
func Sign(priv *PrivKey, msg []byte) ([]byte, error) {
	if priv == nil {
		return nil, ErrNilKey
	}
	keySize, err := priv.Curve().Size()
	if err != nil {
		return nil, err
	}
	var digest []byte
	switch keySize {
	case 32:
		sum := gost3411.Sum256(msg)
		digest = sum[:]
	case 64:
		sum := gost3411.Sum512(msg)
		digest = sum[:]
	default:
		return nil, ErrUnknownCurve
	}
	return gost3410.SignDigest(priv, digest)
}

// Verify hashes msg with Streebog and verifies a GOST R 34.10-2012 signature.
//
// The hash size is chosen automatically based on the key's curve:
// Streebog-256 for 256-bit curves, Streebog-512 for 512-bit curves.
func Verify(pub *PubKey, msg, sig []byte) (bool, error) {
	if pub == nil {
		return false, ErrNilKey
	}
	keySize, err := pub.Curve().Size()
	if err != nil {
		return false, err
	}
	var digest []byte
	switch keySize {
	case 32:
		sum := gost3411.Sum256(msg)
		digest = sum[:]
	case 64:
		sum := gost3411.Sum512(msg)
		digest = sum[:]
	default:
		return false, ErrUnknownCurve
	}
	return gost3410.VerifyDigest(pub, digest, sig)
}

// HashSum256 returns the Streebog-256 digest of data.
func HashSum256(data []byte) [32]byte {
	return gost3411.Sum256(data)
}

// HashSum512 returns the Streebog-512 digest of data.
func HashSum512(data []byte) [64]byte {
	return gost3411.Sum512(data)
}

// Agree performs GOST VKO key agreement between a local private key
// and a remote peer's public key. The ukm (User Keying Material) is
// required and must be non-empty.
//
// Agree is symmetric: Agree(privA, pubB, ukm) == Agree(privB, pubA, ukm).
func Agree(priv *PrivKey, pub *PubKey, ukm []byte) ([]byte, error) {
	if priv == nil {
		return nil, ErrNilKey
	}
	if pub == nil {
		return nil, ErrNilKey
	}
	return gost3410.VKO(priv, pub, ukm)
}
