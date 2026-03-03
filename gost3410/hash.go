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
