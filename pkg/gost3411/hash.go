package gost3411

import "crypto"

// Streebog hash function identifiers for use with crypto.SignerOpts.
//
// These constants provide unique non-zero identifiers so callers can
// distinguish between Streebog-256 and Streebog-512 when used as
// crypto.SignerOpts.HashFunc(). They are intentionally set to values
// within Go's internal range but NOT registered with crypto.RegisterHash
// (Go's maxHash limit prevents registration of custom hash IDs).
//
// To create a Streebog hasher, use New256() or New512() directly.
// Do NOT call HashStreebog256.New() — the hashes are not registered.
const (
	// HashStreebog256 identifies Streebog-256 for crypto.SignerOpts.
	HashStreebog256 crypto.Hash = 17

	// HashStreebog512 identifies Streebog-512 for crypto.SignerOpts.
	HashStreebog512 crypto.Hash = 18
)
