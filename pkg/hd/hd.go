// Package hd implements hierarchical deterministic (HD) key derivation
// for GOST R 34.10-2012, inspired by BIP-32.
//
// It uses HKDF-Streebog to deterministically derive chain codes and
// private key material from a master seed, with a BIP-32-style path
// notation (e.g. "m/44'/0'/0"). Both chain codes and private keys are
// fully deterministic: the same seed and path always produce the same key.
package hd

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/rekurt/gost-crypto/internal/openssl"
	"github.com/rekurt/gost-crypto/pkg/gost3410"
	"github.com/rekurt/gost-crypto/pkg/kdf"
)

// Sentinel errors.
var (
	// ErrInvalidPath is returned when the derivation path is malformed.
	ErrInvalidPath = errors.New("hd: invalid derivation path")

	// ErrEmptySeed is returned when the seed is nil or empty.
	ErrEmptySeed = errors.New("hd: seed must not be empty")

	// ErrSeedTooShort is returned when the seed is shorter than 16 bytes.
	ErrSeedTooShort = errors.New("hd: seed must be at least 16 bytes")
)

const (
	// hardenedOffset is the BIP-32 hardened-child flag.
	hardenedOffset = 0x80000000

	// masterKeySalt is the HKDF salt for master key generation.
	masterKeySalt = "GOST R 34.10-2012 HD seed"
)

// PathComponent represents a single step in a derivation path.
type PathComponent struct {
	Index    uint32
	Hardened bool
}

// DerivedKey bundles a GOST private key with its chain code.
// The chain code is used as input to subsequent child derivations.
type DerivedKey struct {
	// Key is the GOST R 34.10-2012 private key, deterministically
	// derived from the seed and derivation path via HKDF-Streebog.
	Key *PrivKey

	// ChainCode is 32 bytes of HKDF-derived material used for child
	// derivation, deterministically derived from the seed and path.
	ChainCode []byte
}

// PrivKey is an alias for gost3410.PrivKey.
type PrivKey = gost3410.PrivKey

// Curve is an alias for gost3410.Curve.
type Curve = gost3410.Curve

// ParsePath parses a BIP-32-style derivation path string into its
// components. Accepted formats:
//
//	"m/44'/0'/0/1"  — absolute path with master prefix
//	"44'/0'/0/1"    — relative path (no master prefix)
//
// Hardened indices are indicated by a trailing apostrophe (') or "h".
// Returns ErrInvalidPath if the path is malformed.
func ParsePath(path string) ([]PathComponent, error) {
	if path == "" {
		return nil, ErrInvalidPath
	}

	// Strip master prefix.
	s := path
	if strings.HasPrefix(s, "m/") {
		s = s[2:]
	} else if s == "m" {
		// Just "m" means the master key itself; no derivation steps.
		return nil, nil
	}

	if s == "" {
		return nil, ErrInvalidPath
	}

	parts := strings.Split(s, "/")
	components := make([]PathComponent, 0, len(parts))

	for _, part := range parts {
		if part == "" {
			return nil, ErrInvalidPath
		}

		hardened := false
		clean := part

		if strings.HasSuffix(clean, "'") {
			hardened = true
			clean = clean[:len(clean)-1]
		} else if strings.HasSuffix(clean, "h") {
			hardened = true
			clean = clean[:len(clean)-1]
		}

		if clean == "" {
			return nil, ErrInvalidPath
		}

		idx, err := strconv.ParseUint(clean, 10, 31)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid index %q", ErrInvalidPath, part)
		}

		u := uint32(idx)
		if hardened {
			u |= hardenedOffset
		}

		components = append(components, PathComponent{
			Index:    u,
			Hardened: hardened,
		})
	}

	return components, nil
}

// Master derives a master DerivedKey from a seed for the given curve.
//
// The seed should be high-entropy random bytes (at least 16 bytes;
// 32 or 64 bytes recommended).
//
// Both the chain code and private key are deterministically derived
// via HKDF-Streebog-512 from the seed. If the initial HKDF material
// falls outside the valid range [1, q-1], rejection sampling with
// deterministic re-derivation is applied (see loadKeyWithRetry).
func Master(seed []byte, c Curve) (*DerivedKey, error) {
	if len(seed) == 0 {
		return nil, ErrEmptySeed
	}
	if len(seed) < 16 {
		return nil, ErrSeedTooShort
	}

	// Use HKDF-Streebog-512 to extract key material + chain code.
	keySize, err := c.Size()
	if err != nil {
		return nil, err
	}
	// Derive keySize bytes for private key + 32 bytes for chain code.
	salt := []byte(masterKeySalt)
	material := kdf.HKDF512(salt, seed, []byte("master"), keySize+32)

	// Key material is bytes [0..keySize), chain code is bytes [keySize..keySize+32).
	chainCode := make([]byte, 32)
	copy(chainCode, material[keySize:keySize+32])

	// Load the private key from HKDF-derived material.
	// If the raw bytes happen to be >= q (curve order) or zero, retry
	// with incremented info to get different material (standard rejection
	// sampling approach for deterministic key derivation).
	key, err := loadKeyWithRetry(c, material[:keySize], salt, seed, "master-retry", keySize)
	// Wipe the intermediate HKDF material — it contains raw key bytes.
	openssl.CleanseBytes(material)
	if err != nil {
		return nil, fmt.Errorf("hd: master key loading: %w", err)
	}

	return &DerivedKey{
		Key:       key,
		ChainCode: chainCode,
	}, nil
}

// Derive performs child key derivation from a parent DerivedKey along
// the given path.
//
// Each path component produces a new child chain code via HKDF using
// the parent chain code and the serialized index as inputs.
//
// Both chain codes and private keys are deterministically derived
// from the parent key material using HKDF-Streebog.
func Derive(parent *DerivedKey, path string, c Curve) (*DerivedKey, error) {
	components, err := ParsePath(path)
	if err != nil {
		return nil, err
	}
	if len(components) == 0 {
		// Path "m" — return a copy of parent with same key material.
		parentBytes, err := parent.Key.Bytes()
		if err != nil {
			return nil, fmt.Errorf("hd: derive copy: %w", err)
		}
		keyCopy, err := gost3410.LoadPrivKey(c, parentBytes)
		openssl.CleanseBytes(parentBytes)
		if err != nil {
			return nil, fmt.Errorf("hd: derive copy: %w", err)
		}
		cc := make([]byte, len(parent.ChainCode))
		copy(cc, parent.ChainCode)
		return &DerivedKey{Key: keyCopy, ChainCode: cc}, nil
	}

	keySize, err := c.Size()
	if err != nil {
		return nil, err
	}

	currentCC := parent.ChainCode
	var lastKeyMaterial []byte

	for _, comp := range components {
		// Serialize the index as 4 big-endian bytes for the info parameter.
		info := []byte{
			byte(comp.Index >> 24),
			byte(comp.Index >> 16),
			byte(comp.Index >> 8),
			byte(comp.Index),
		}

		// Derive keySize bytes for key material + 32 bytes for child chain code.
		childMaterial := kdf.HKDF256(currentCC, info, []byte("child"), keySize+32)

		lastKeyMaterial = childMaterial[:keySize]
		childCC := make([]byte, 32)
		copy(childCC, childMaterial[keySize:keySize+32])
		currentCC = childCC
	}

	// Load the deterministic key from derived material.
	key, err := loadKeyWithRetry(c, lastKeyMaterial, currentCC, lastKeyMaterial, "child-retry", keySize)
	// Wipe intermediate key material.
	if len(lastKeyMaterial) > 0 {
		openssl.CleanseBytes(lastKeyMaterial)
	}
	if err != nil {
		return nil, fmt.Errorf("hd: child key loading: %w", err)
	}

	return &DerivedKey{
		Key:       key,
		ChainCode: currentCC,
	}, nil
}

// loadKeyWithRetry attempts to load a private key from raw material.
// If the raw bytes are outside the valid range [1, q-1] for the curve
// (causing LoadPrivKey to fail), it re-derives material using HKDF with
// an incremented counter until a valid key is obtained.
// This is standard rejection sampling for deterministic key derivation.
func loadKeyWithRetry(c gost3410.Curve, raw, salt, ikm []byte, infoPrefix string, keySize int) (*gost3410.PrivKey, error) {
	// First attempt with the original material.
	key, err := gost3410.LoadPrivKey(c, raw)
	if err == nil {
		return key, nil
	}

	// Rejection sampling: re-derive with incremented counter.
	const maxRetries = 255
	for i := 1; i <= maxRetries; i++ {
		info := []byte(fmt.Sprintf("%s-%d", infoPrefix, i))
		newMaterial := kdf.HKDF256(salt, ikm, info, keySize)
		key, err = gost3410.LoadPrivKey(c, newMaterial)
		if err == nil {
			return key, nil
		}
	}

	return nil, fmt.Errorf("failed to derive valid key after %d attempts", maxRetries)
}

// Zeroize securely wipes the key and chain code using OPENSSL_cleanse
// (which the compiler cannot optimize away, unlike a Go for-loop).
func (dk *DerivedKey) Zeroize() {
	if dk.Key != nil {
		dk.Key.Zeroize()
	}
	if len(dk.ChainCode) > 0 {
		openssl.CleanseBytes(dk.ChainCode)
	}
}
