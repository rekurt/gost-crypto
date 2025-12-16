package streebog

import (
	"hash"

	g256 "github.com/ddulesov/gogost/gost34112012256"
	g512 "github.com/ddulesov/gogost/gost34112012512"
)

// New256 returns a Streebog-256 hasher implementing hash.Hash.
func New256() hash.Hash { return g256.New() }

// New512 returns a Streebog-512 hasher implementing hash.Hash.
func New512() hash.Hash { return g512.New() }

// Sum256 computes Streebog-256 over data and returns 32-byte digest.
func Sum256(data []byte) [32]byte {
	h := New256()
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Sum512 computes Streebog-512 over data and returns 64-byte digest.
func Sum512(data []byte) [64]byte {
	h := New512()
	h.Write(data)
	var out [64]byte
	copy(out[:], h.Sum(nil))
	return out
}
