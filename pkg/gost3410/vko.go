package gost3410

import (
	"errors"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

// ErrCurveMismatch is returned when VKO is called with keys on different curves.
var ErrCurveMismatch = errors.New("gost3410: curve mismatch between private and peer public key")

// ErrEmptyUKM is returned when VKO is called without User Keying Material.
var ErrEmptyUKM = errors.New("gost3410: ukm must not be empty (required by GOST VKO)")

// VKO performs GOST VKO key agreement (GOST R 34.10-2012, Appendix B)
// between a local private key and a remote peer's public key.
//
// The ukm (User Keying Material) parameter is required by gost-engine
// and must be non-nil and non-empty. UKM is incorporated into the key
// derivation to produce session-unique shared secrets. Different UKM
// values yield different shared secrets from the same key pair.
// Typical UKM length is 8 bytes.
//
// VKO is symmetric: VKO(privA, pubB, ukm) == VKO(privB, pubA, ukm).
//
// Both keys must be on the same curve; otherwise ErrCurveMismatch is returned.
func VKO(priv *PrivKey, peerPub *PubKey, ukm []byte) ([]byte, error) {
	if priv == nil || priv.handle.IsNil() {
		return nil, ErrNilKey
	}
	if peerPub == nil || peerPub.handle.IsNil() {
		return nil, ErrNilKey
	}
	if priv.curve != peerPub.curve {
		return nil, ErrCurveMismatch
	}
	if len(ukm) == 0 {
		return nil, ErrEmptyUKM
	}

	return openssl.DeriveVKO(priv.handle, peerPub.handle, ukm)
}
