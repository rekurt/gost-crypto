package gost3411

import "crypto"

// GOST hash function identifiers for use with crypto.SignerOpts
// and crypto.RegisterHash. These values are in the private-use range
// (above 20) to avoid conflicts with standard Go crypto.Hash constants.
const (
	HashStreebog256 crypto.Hash = 100 + iota
	HashStreebog512
)

func init() {
	crypto.RegisterHash(HashStreebog256, New256)
	crypto.RegisterHash(HashStreebog512, New512)
}
