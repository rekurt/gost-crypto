package gost3411

import "crypto"

// Streebog hash function identifiers for use with crypto.SignerOpts.
//
// These constants are assigned values above Go's internal maxHash limit
// to guarantee they never collide with standard library hash IDs
// (SHA-256, BLAKE2b, etc.). They cannot be used with crypto.RegisterHash,
// crypto.Hash.Available(), or crypto.Hash.New().
//
// To create a Streebog hasher, call New256() or New512() directly.
const (
	// HashStreebog256 identifies Streebog-256 for crypto.SignerOpts.HashFunc().
	HashStreebog256 crypto.Hash = 100

	// HashStreebog512 identifies Streebog-512 for crypto.SignerOpts.HashFunc().
	HashStreebog512 crypto.Hash = 101
)
