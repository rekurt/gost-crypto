package gost3413

import (
	"crypto/cipher"
	"errors"

	"github.com/rekurt/gost-crypto/internal/cryptopro"
	"github.com/rekurt/gost-crypto/pkg/gost3412"
)

const (
	magmaMGMNonceSize = 8 // Magma-MGM uses 64-bit nonce
	magmaMGMTagSize   = 8 // 64-bit authentication tag
)

// magmaMGMAEAD implements cipher.AEAD using Magma-MGM in pure Go on top
// of the raw Magma block cipher supplied by pkg/gost3412.
type magmaMGMAEAD struct {
	key  [32]byte
	core *mgmCore
}

// NewMagmaMGMFromKey creates a cipher.AEAD using Magma-MGM.
func NewMagmaMGMFromKey(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("gost3413: invalid key size (must be 32 bytes)")
	}
	if err := cryptopro.Init(); err != nil {
		return nil, err
	}
	block, err := gost3412.NewMagma(key)
	if err != nil {
		return nil, err
	}
	core, err := newMGMCore(block)
	if err != nil {
		return nil, err
	}
	m := &magmaMGMAEAD{core: core}
	copy(m.key[:], key)
	cryptopro.MlockBytes(m.key[:])
	return m, nil
}

func (m *magmaMGMAEAD) NonceSize() int { return magmaMGMNonceSize }
func (m *magmaMGMAEAD) Overhead() int  { return magmaMGMTagSize }

func (m *magmaMGMAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	out, err := m.core.Seal(dst, nonce, plaintext, additionalData)
	if err != nil {
		panic("gost3413: " + err.Error())
	}
	return out
}

func (m *magmaMGMAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return m.core.Open(dst, nonce, ciphertext, additionalData)
}

// Zeroize securely wipes the key material.
func (m *magmaMGMAEAD) Zeroize() {
	if z, ok := m.core.block.(interface{ Zeroize() }); ok {
		z.Zeroize()
	}
	cryptopro.CleanseBytes(m.key[:])
	cryptopro.MunlockBytes(m.key[:])
}
