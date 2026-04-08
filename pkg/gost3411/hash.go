package gost3411

import "crypto"

// Streebog hash function identifiers for use with crypto.SignerOpts.
//
// These constants identify the Streebog hash algorithm when used with
// the crypto.Signer interface. They are NOT registered with
// crypto.RegisterHash because Go's internal maxHash limit prevents
// registration of custom hash IDs.
//
// To create a Streebog hasher, use New256() or New512() directly
// instead of HashStreebog256.New().
const (
	// HashStreebog256 identifies Streebog-256 for crypto.SignerOpts.
	// Use gost3411.New256() to create a hasher.
	HashStreebog256 crypto.Hash = 0

	// HashStreebog512 identifies Streebog-512 for crypto.SignerOpts.
	// Use gost3411.New512() to create a hasher.
	HashStreebog512 crypto.Hash = 0
)

// Note: crypto.RegisterHash is NOT used because Go limits hash IDs
// to its internal maxHash constant (~20). Custom hash algorithms
// cannot be registered via the standard mechanism. Use New256()/New512()
// directly for creating hash instances.
