package gost3413

import (
	"crypto/cipher"
	"errors"

	"github.com/rekurt/gost-crypto/internal/cryptopro"
	"github.com/rekurt/gost-crypto/pkg/gost3412"
)

const (
	mgmNonceSize = 16 // Kuznechik-MGM uses 128-bit nonce
	mgmTagSize   = 16 // 128-bit authentication tag
)

// mgmAEAD implements cipher.AEAD using Kuznechik-MGM in pure Go on top
// of the raw Kuznechik block cipher supplied by pkg/gost3412 (which is
// itself backed by CryptoPro CSP's raw ECB primitive).
type mgmAEAD struct {
	key  [32]byte
	core *mgmCore
}

// NewKuznechikMGMFromKey creates a cipher.AEAD using Kuznechik-MGM.
// key must be exactly 32 bytes.
func NewKuznechikMGMFromKey(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("gost3413: invalid key size (must be 32 bytes)")
	}
	if err := cryptopro.Init(); err != nil {
		return nil, err
	}
	block, err := gost3412.NewKuznechik(key)
	if err != nil {
		return nil, err
	}
	core, err := newMGMCore(block)
	if err != nil {
		return nil, err
	}
	m := &mgmAEAD{core: core}
	copy(m.key[:], key)
	cryptopro.MlockBytes(m.key[:])
	return m, nil
}

func (m *mgmAEAD) NonceSize() int { return mgmNonceSize }
func (m *mgmAEAD) Overhead() int  { return mgmTagSize }

// Seal encrypts and authenticates plaintext, authenticates additionalData,
// and appends the result to dst.
func (m *mgmAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	out, err := m.core.Seal(dst, nonce, plaintext, additionalData)
	if err != nil {
		panic("gost3413: " + err.Error())
	}
	return out
}

// Open decrypts and authenticates ciphertext, authenticates additionalData,
// and appends the resulting plaintext to dst.
func (m *mgmAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return m.core.Open(dst, nonce, ciphertext, additionalData)
}

// Zeroize securely wipes the key material.
func (m *mgmAEAD) Zeroize() {
	if z, ok := m.core.block.(interface{ Zeroize() }); ok {
		z.Zeroize()
	}
	cryptopro.CleanseBytes(m.key[:])
	cryptopro.MunlockBytes(m.key[:])
}

// NewMGMFromKey is a backward-compatible alias for NewKuznechikMGMFromKey.
//
// Deprecated: Use NewKuznechikMGMFromKey for consistency with other mode
// constructors.
func NewMGMFromKey(key []byte) (cipher.AEAD, error) {
	return NewKuznechikMGMFromKey(key)
}

// sliceForAppend takes a destination slice and a requested number of bytes.
// It returns a slice with the data appended and a sub-slice pointing to the
// newly appended portion. Kept for backward compatibility with earlier
// callers that used this helper through the package surface.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
