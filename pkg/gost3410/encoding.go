package gost3410

import (
	"encoding"
	"fmt"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

// Compile-time assertions: keys implement encoding interfaces.
var (
	_ encoding.BinaryMarshaler   = (*PrivKey)(nil)
	_ encoding.BinaryUnmarshaler = (*PrivKey)(nil)
	_ encoding.BinaryMarshaler   = (*PubKey)(nil)
)

// MarshalBinary implements encoding.BinaryMarshaler.
// Returns the raw private key bytes prefixed with a 1-byte curve identifier.
// Format: [curve_id (1 byte)] [raw_key (32 or 64 bytes)]
//
// WARNING: The returned bytes contain sensitive private key material.
// The caller should securely erase them when no longer needed.
func (k *PrivKey) MarshalBinary() ([]byte, error) {
	if k.handle.IsNil() {
		return nil, ErrNilKey
	}
	raw, err := k.Bytes()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+len(raw))
	out[0] = byte(k.curve)
	copy(out[1:], raw)
	// Wipe the intermediate raw key copy.
	openssl.CleanseBytes(raw)
	return out, nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
// Expects format: [curve_id (1 byte)] [raw_key (32 or 64 bytes)]
//
// This replaces the current key material. The previous key is zeroized.
func (k *PrivKey) UnmarshalBinary(data []byte) error {
	if len(data) < 2 {
		return ErrInvalidKeySize
	}
	c := Curve(data[0])
	if !c.valid() {
		return fmt.Errorf("%w: curve id %d", ErrUnknownCurve, data[0])
	}
	raw := data[1:]
	sz, err := c.Size()
	if err != nil {
		return err
	}
	if len(raw) != sz {
		return ErrInvalidKeySize
	}

	// Load the key via the standard path.
	loaded, err := LoadPrivKey(c, raw)
	if err != nil {
		return err
	}

	// Zeroize the old key if any, then adopt the new one.
	k.Zeroize()
	k.handle = loaded.handle
	k.curve = loaded.curve
	return nil
}

// MarshalBinary implements encoding.BinaryMarshaler for the public key.
// Returns the raw public key bytes prefixed with a 1-byte curve identifier.
// Format: [curve_id (1 byte)] [raw_pubkey (variable length)]
func (p *PubKey) MarshalBinary() ([]byte, error) {
	if p.handle.IsNil() {
		return nil, ErrNilKey
	}
	raw, err := p.Bytes()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+len(raw))
	out[0] = byte(p.curve)
	copy(out[1:], raw)
	return out, nil
}
