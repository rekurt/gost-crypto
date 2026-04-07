// Package hd implements hierarchical deterministic (HD) key derivation
// for GOST R 34.10-2012, inspired by BIP-32.
//
// It uses HKDF-Streebog to derive chain codes and key material from a
// master seed, with a BIP-32-style path notation (e.g. "m/44'/0'/0").
//
// LIMITATION: deterministic private key construction from raw bytes is
// not yet supported because pkg/gost3410 does not expose a ParsePrivKey
// function. As a result, Master and Derive currently generate random
// keys via GenerateKey. The HKDF-derived chain code is authentic, but
// the private key is NOT deterministically derived from the seed. This
// will be resolved when ParsePrivKey is implemented (future task).
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
	// Key is the GOST R 34.10-2012 private key.
	// NOTE: currently generated randomly, not deterministically from seed.
	// TODO: use deterministic key loading when ParsePrivKey is available.
	Key *PrivKey

	// ChainCode is 32 bytes of HKDF-derived material used for child
	// derivation. The chain code IS deterministically derived from the
	// seed and path.
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
// The chain code is deterministically derived via HKDF-Streebog-512
// from the seed. However, the private key is currently generated
// randomly (see package-level documentation for the limitation).
func Master(seed []byte, c Curve) (*DerivedKey, error) {
	if len(seed) == 0 {
		return nil, ErrEmptySeed
	}
	if len(seed) < 16 {
		return nil, ErrSeedTooShort
	}

	// Use HKDF-Streebog-512 to extract key material + chain code.
	// We derive 96 bytes: first 32 for key material (unused until
	// ParsePrivKey exists), next 32 for chain code, last 32 reserved.
	salt := []byte(masterKeySalt)
	material := kdf.HKDF512(salt, seed, []byte("master"), 96)

	// Chain code is bytes [32..64).
	chainCode := make([]byte, 32)
	copy(chainCode, material[32:64])

	// TODO: when ParsePrivKey is available, use material[0:32] (or
	// material[0:64] for 512-bit curves) to construct the key
	// deterministically. For now, generate a random key.
	key, err := gost3410.GenerateKey(c)
	if err != nil {
		return nil, fmt.Errorf("hd: master key generation: %w", err)
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
// NOTE: the returned private key is currently random at each level
// (see package-level documentation). The chain code derivation is
// fully deterministic.
func Derive(parent *DerivedKey, path string, c Curve) (*DerivedKey, error) {
	components, err := ParsePath(path)
	if err != nil {
		return nil, err
	}
	if len(components) == 0 {
		// Path "m" — return a copy of parent.
		keyCopy, err := gost3410.GenerateKey(c)
		if err != nil {
			return nil, fmt.Errorf("hd: derive copy: %w", err)
		}
		cc := make([]byte, len(parent.ChainCode))
		copy(cc, parent.ChainCode)
		return &DerivedKey{Key: keyCopy, ChainCode: cc}, nil
	}

	currentCC := parent.ChainCode

	for _, comp := range components {
		// Serialize the index as 4 big-endian bytes for the info parameter.
		info := []byte{
			byte(comp.Index >> 24),
			byte(comp.Index >> 16),
			byte(comp.Index >> 8),
			byte(comp.Index),
		}

		// Derive 64 bytes: first 32 for key material (unused), next 32 for child chain code.
		//
		// HKDF256 signature: HKDF256(salt, ikm, info, length).
		// Here the chain code is salt (public, non-secret context) and the
		// serialized index is ikm. This parameter order will be revisited
		// when ParsePrivKey is implemented and the full derivation becomes
		// deterministic. See review finding I5.
		childMaterial := kdf.HKDF256(currentCC, info, []byte("child"), 64)

		childCC := make([]byte, 32)
		copy(childCC, childMaterial[32:64])
		currentCC = childCC
	}

	// TODO: use the accumulated key material to construct a deterministic
	// key when ParsePrivKey is available.
	key, err := gost3410.GenerateKey(c)
	if err != nil {
		return nil, fmt.Errorf("hd: child key generation: %w", err)
	}

	return &DerivedKey{
		Key:       key,
		ChainCode: currentCC,
	}, nil
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
