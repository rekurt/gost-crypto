package gost3410

import (
	"crypto"
	"errors"
	"io"

	"github.com/rekurt/gost-crypto/internal/cryptopro"
)

// Compile-time assertion: PrivKey implements crypto.Signer.
var _ crypto.Signer = (*PrivKey)(nil)

// Sentinel errors for key operations.
var (
	ErrPointNotOnCurve  = errors.New("gost3410: point not on curve")
	ErrInvalidKeySize   = errors.New("gost3410: invalid key size")
	ErrInvalidSignature = errors.New("gost3410: invalid signature size")
	ErrNilKey           = errors.New("gost3410: nil key")
)

// PrivKey holds a GOST R 34.10-2012 private key backed by CryptoPro CSP.
//
// Callers MUST call Zeroize when done to securely wipe key material
// and release the underlying HCRYPTKEY / HCRYPTPROV pair. A GC finalizer
// is set as a safety net, but explicit cleanup is strongly recommended.
type PrivKey struct {
	handle *cryptopro.KeyHandle
	curve  Curve
}

// PubKey holds a GOST R 34.10-2012 public key backed by CryptoPro CSP.
//
// PubKey shares the HCRYPTKEY owned by the originating PrivKey.
// Do NOT free or zeroize the PubKey separately — the PrivKey owns the
// handle lifetime.
type PubKey struct {
	handle *cryptopro.KeyHandle // shared, read-only; owned by PrivKey
	curve  Curve
}

// LoadPrivKey creates a GOST R 34.10-2012 private key from raw bytes.
// The raw bytes must be big-endian and exactly the key size for the curve
// (32 bytes for 256-bit curves, 64 bytes for 512-bit curves).
// The raw value must be in range [1, q-1] where q is the curve order.
func LoadPrivKey(c Curve, raw []byte) (*PrivKey, error) {
	sz, err := c.Size()
	if err != nil {
		return nil, err
	}
	if len(raw) != sz {
		return nil, ErrInvalidKeySize
	}

	nid, err := c.signNID()
	if err != nil {
		return nil, err
	}
	oid, err := c.oid()
	if err != nil {
		return nil, err
	}

	h, err := cryptopro.LoadGOSTPrivKeyHandle(nid, oid, raw)
	if err != nil {
		return nil, err
	}

	return &PrivKey{handle: h, curve: c}, nil
}

// GenerateKey generates a new GOST R 34.10-2012 key pair for the given curve.
func GenerateKey(c Curve) (*PrivKey, error) {
	nid, err := c.signNID()
	if err != nil {
		return nil, err
	}
	oid, err := c.oid()
	if err != nil {
		return nil, err
	}

	h, err := cryptopro.GenerateGOSTKeyHandle(nid, oid)
	if err != nil {
		return nil, err
	}

	return &PrivKey{handle: h, curve: c}, nil
}

// PublicKey returns the public key derived from this private key.
// The returned PubKey shares the same underlying handle — do not free it.
func (k *PrivKey) PublicKey() *PubKey {
	return &PubKey{handle: k.handle, curve: k.curve}
}

// Curve returns the curve parameter set associated with this private key.
func (k *PrivKey) Curve() Curve { return k.curve }

// Handle returns the underlying CryptoPro CSP KeyHandle for use by internal
// packages that need direct access (e.g., X.509 certificate operations).
// The returned handle is shared — do not free it separately.
func (k *PrivKey) Handle() *cryptopro.KeyHandle { return k.handle }

// Public returns the public key corresponding to this private key,
// implementing the crypto.Signer interface.
func (k *PrivKey) Public() crypto.PublicKey {
	return k.PublicKey()
}

// Sign signs digest with the private key, implementing the crypto.Signer
// interface. The rand parameter is ignored because OpenSSL uses its own
// CSPRNG internally. The opts parameter is currently unused but accepted
// for interface compliance.
//
// The digest must be a pre-computed Streebog hash of the correct size
// for the curve (32 bytes for 256-bit curves, 64 bytes for 512-bit curves).
func (k *PrivKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return SignDigest(k, digest)
}

// Bytes returns the raw private key bytes.
// The returned slice should be treated as sensitive material and cleansed
// by the caller when no longer needed (cryptopro.CleanseBytes).
func (k *PrivKey) Bytes() ([]byte, error) {
	if k.handle.IsNil() {
		return nil, ErrNilKey
	}
	sz, err := k.curve.Size()
	if err != nil {
		return nil, err
	}
	return cryptopro.ExtractRawPrivKeyH(k.handle, sz)
}

// Zeroize securely wipes any extractable key material and frees the
// underlying HCRYPTKEY / HCRYPTPROV. After Zeroize, the key (and any
// derived PubKey) must not be used.
func (k *PrivKey) Zeroize() {
	if k.handle != nil {
		k.handle.Free()
		k.handle = nil
	}
}

// Curve returns the curve parameter set associated with this public key.
func (p *PubKey) Curve() Curve { return p.curve }

// Handle returns the underlying CryptoPro CSP KeyHandle for use by internal
// packages that need direct access (e.g., X.509 certificate operations).
// The returned handle is shared — do not free it separately.
func (p *PubKey) Handle() *cryptopro.KeyHandle { return p.handle }

// Bytes returns the raw public key bytes as produced by CryptoPro CSP
// (a PUBLICKEYBLOB — BLOBHEADER + CRYPT_PUBKEY_INFO + raw X||Y point).
func (p *PubKey) Bytes() ([]byte, error) {
	if p.handle.IsNil() {
		return nil, ErrNilKey
	}
	return cryptopro.ExtractRawPubKeyH(p.handle)
}

// Validate checks that the public key point lies on the curve. CryptoPro
// CSP validates key material at import time, so this is a no-op for keys
// already held as live handles.
func (p *PubKey) Validate() error {
	if p.handle.IsNil() {
		return ErrNilKey
	}
	if err := cryptopro.ValidatePublicKeyH(p.handle); err != nil {
		return ErrPointNotOnCurve
	}
	return nil
}
