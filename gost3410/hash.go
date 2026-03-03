// Package gost3410 implements GOST R 34.10-2012 elliptic curve digital
// signatures with TC26 parameter sets, key generation, serialization, and
// public key recovery.
package gost3410

// HashID selects which Streebog variant to use with signatures.
type HashID int

const (
	// HashAuto is the zero value and indicates that the hash algorithm
	// should be inferred automatically (e.g., from key size).
	HashAuto    HashID = iota
	Streebog256        // GOST R 34.11-2012 with 256-bit output
	Streebog512        // GOST R 34.11-2012 with 512-bit output
)
