// Package hd provides HD (Hierarchical Deterministic) key derivation using HKDF on Streebog hashing.
package hd

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"github.com/rekurt/gost-crypto/gost3410"
	"github.com/rekurt/gost-crypto/streebog"
)

// Master generates a master private key and chain code from a seed using HKDF.
// The hash parameter determines which Streebog variant (256 or 512) to use.
func Master(seed []byte, h gost3410.HashID) (*gost3410.PrivKey, []byte, error) {
	if len(seed) == 0 {
		return nil, nil, errors.New("seed cannot be empty")
	}

	// Determine key size based on HashID
	var keySize int
	switch h {
	case gost3410.Streebog256:
		keySize = 32
	case gost3410.Streebog512:
		keySize = 64
	default:
		return nil, nil, errors.New("invalid hash id")
	}

	// HKDF-Extract: salt = "GOST-HD"
	salt := []byte("GOST-HD")
	prk := hkdfExtract(salt, seed, h)

	// HKDF-Expand: derive master key (keySize bytes) and chain code (keySize bytes)
	info := []byte("master")
	okm := hkdfExpand(prk, info, 2*keySize, h)

	masterKeyBytes := okm[:keySize]
	chainCode := okm[keySize:]

	// Create master private key
	curve := gost3410.TC26_256_A
	if h == gost3410.Streebog512 {
		curve = gost3410.TC26_512_A
	}

	privKey, err := gost3410.FromRawPrivReduce(curve, masterKeyBytes)
	if err != nil {
		return nil, nil, err
	}

	return privKey, chainCode, nil
}

// Derive derives a child key at the specified path.
// Path format: "m/index1/index2'/..." where indices with ' are hardened.
// Example: "m/0'/1/2'" means hardened at indices 0 and 2.
func Derive(parent *gost3410.PrivKey, chainCode []byte, path string, h gost3410.HashID) (*gost3410.PrivKey, []byte, error) {
	if !strings.HasPrefix(path, "m/") {
		return nil, nil, errors.New("path must start with 'm/'")
	}

	// Determine key size based on HashID
	var keySize int
	switch h {
	case gost3410.Streebog256:
		keySize = 32
	case gost3410.Streebog512:
		keySize = 64
	default:
		return nil, nil, errors.New("invalid hash id")
	}

	// Validate that hash size matches parent key's curve size
	curveSize, err := parent.Curve.Size()
	if err != nil {
		return nil, nil, err
	}
	if curveSize != keySize {
		return nil, nil, fmt.Errorf("hash size (%d) does not match key size (%d)", keySize, curveSize)
	}

	// Parse path
	indices, err := parsePath(path[2:]) // Skip "m/"
	if err != nil {
		return nil, nil, err
	}

	// Iteratively derive keys
	currentPriv := parent
	currentChain := chainCode

	for _, index := range indices {
		var newPriv *gost3410.PrivKey
		var newChain []byte

		// Derive at index
		newPriv, newChain, err = deriveAt(currentPriv, currentChain, index.value, index.hardened, h, keySize)
		if err != nil {
			return nil, nil, err
		}

		currentPriv = newPriv
		currentChain = newChain
	}

	return currentPriv, currentChain, nil
}

// Helper types and functions

type pathIndex struct {
	value    uint32
	hardened bool
}

func parsePath(path string) ([]pathIndex, error) {
	if path == "" {
		return []pathIndex{}, nil
	}

	parts := strings.Split(path, "/")
	indices := make([]pathIndex, len(parts))

	for i, part := range parts {
		if part == "" {
			return nil, errors.New("empty path segment")
		}

		hardened := false
		if strings.HasSuffix(part, "'") {
			hardened = true
			part = part[:len(part)-1]
		}

		val, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, errors.New("invalid path index: " + part)
		}

		indices[i] = pathIndex{uint32(val), hardened}
	}

	return indices, nil
}

func deriveAt(privKey *gost3410.PrivKey, chainCode []byte, index uint32, hardened bool, h gost3410.HashID, keySize int) (*gost3410.PrivKey, []byte, error) {
	// Build HMAC data
	var data []byte

	if hardened {
		// Hardened: 0x00 || private key
		data = append([]byte{0x00}, privKey.D...)
	} else {
		// Non-hardened: public key X coordinate
		pubKey, err := privKey.PublicKey()
		if err != nil {
			return nil, nil, err
		}
		data = pubKey.X
	}

	// Append index (big-endian, 4 bytes)
	data = append(data, byte((index>>24)&0xFF), byte((index>>16)&0xFF), byte((index>>8)&0xFF), byte(index&0xFF))

	// HMAC-Extract using chain code as salt
	prk := hmacStreebog(chainCode, data, h)

	// HMAC-Expand to get 2*keySize bytes (for key and new chain code)
	okm := hkdfExpand(prk, []byte(nil), 2*keySize, h)

	// Split into key and chain code
	childKeyBytes := okm[:keySize]
	childChain := okm[keySize : 2*keySize]

	// Create child private key
	childPriv, err := gost3410.FromRawPrivReduce(privKey.Curve, childKeyBytes)
	if err != nil {
		return nil, nil, err
	}

	return childPriv, childChain, nil
}

func hkdfExtract(salt, ikm []byte, h gost3410.HashID) []byte {
	// HMAC-Streebog output size matches the hash variant (32 or 64 bytes),
	// so no truncation is needed.
	return hmacStreebog(salt, ikm, h)
}

func hkdfExpand(prk, info []byte, length int, h gost3410.HashID) []byte {
	// HMAC-based key derivation
	// T = T(1) | T(2) | T(3) | ...
	// T(1) = HMAC(PRK, "" | info | 0x01)
	// T(N) = HMAC(PRK, T(N-1) | info | N)

	keySize := 32
	if h == gost3410.Streebog512 {
		keySize = 64
	}

	result := make([]byte, 0, length)
	var t []byte
	n := (length + keySize - 1) / keySize // Ceiling division

	for i := 1; i <= n; i++ {
		msg := append([]byte{}, t...)
		msg = append(msg, info...)
		msg = append(msg, byte(i))

		t = hmacStreebog(prk, msg, h)[:keySize]
		result = append(result, t...)
	}

	return result[:length]
}

func hmacStreebog(key, data []byte, h gost3410.HashID) []byte {
	// Create HMAC using Streebog
	var hashFunc func() hash.Hash
	if h == gost3410.Streebog512 {
		hashFunc = streebog.New512
	} else {
		hashFunc = streebog.New256
	}

	h256 := hmac.New(hashFunc, key)
	h256.Write(data)
	return h256.Sum(nil)
}
