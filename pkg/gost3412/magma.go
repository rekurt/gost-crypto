package gost3412

import (
	"crypto/cipher"
	"errors"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

const (
	// MagmaKeySize is the key size in bytes for Magma (256 bits).
	MagmaKeySize = 32
	// MagmaBlockSize is the block size in bytes for Magma (64 bits).
	MagmaBlockSize = 8
)

// magmaCipher implements cipher.Block using magma-ecb via gost-engine.
type magmaCipher struct {
	key    [MagmaKeySize]byte
	encCtx *openssl.CipherCtx
	decCtx *openssl.CipherCtx
}

// NewMagma returns a new cipher.Block implementing the Magma block cipher
// (GOST R 34.12-2015, 64-bit block). key must be exactly 32 bytes.
func NewMagma(key []byte) (cipher.Block, error) {
	if len(key) != MagmaKeySize {
		return nil, errors.New("gost3412: invalid Magma key size (must be 32 bytes)")
	}
	if err := openssl.Init(); err != nil {
		return nil, err
	}

	m := new(magmaCipher)
	copy(m.key[:], key)
	openssl.MlockBytes(m.key[:])

	var err error
	m.encCtx, err = openssl.NewCipherCtx()
	if err != nil {
		return nil, err
	}
	if err := m.encCtx.InitEncrypt(openssl.NID_Magma_ECB, m.key[:], nil); err != nil {
		m.encCtx.Close()
		return nil, err
	}
	if err := m.encCtx.SetPadding(0); err != nil {
		m.encCtx.Close()
		return nil, err
	}

	m.decCtx, err = openssl.NewCipherCtx()
	if err != nil {
		m.encCtx.Close()
		return nil, err
	}
	if err := m.decCtx.InitDecrypt(openssl.NID_Magma_ECB, m.key[:], nil); err != nil {
		m.encCtx.Close()
		m.decCtx.Close()
		return nil, err
	}
	if err := m.decCtx.SetPadding(0); err != nil {
		m.encCtx.Close()
		m.decCtx.Close()
		return nil, err
	}

	return m, nil
}

func (m *magmaCipher) BlockSize() int { return MagmaBlockSize }

func (m *magmaCipher) Encrypt(dst, src []byte) {
	if len(src) < MagmaBlockSize {
		panic("gost3412: input not full block")
	}
	if len(dst) < MagmaBlockSize {
		panic("gost3412: output not full block")
	}

	if err := m.encCtx.InitEncrypt(openssl.NID_Magma_ECB, m.key[:], nil); err != nil {
		panic("gost3412: " + err.Error())
	}
	if err := m.encCtx.SetPadding(0); err != nil {
		panic("gost3412: " + err.Error())
	}

	out, err := m.encCtx.Update(src[:MagmaBlockSize])
	if err != nil {
		panic("gost3412: " + err.Error())
	}
	copy(dst, out)

	tail, err := m.encCtx.Final()
	if err != nil {
		panic("gost3412: " + err.Error())
	}
	if len(tail) > 0 {
		copy(dst[len(out):], tail)
	}
}

func (m *magmaCipher) Decrypt(dst, src []byte) {
	if len(src) < MagmaBlockSize {
		panic("gost3412: input not full block")
	}
	if len(dst) < MagmaBlockSize {
		panic("gost3412: output not full block")
	}

	if err := m.decCtx.InitDecrypt(openssl.NID_Magma_ECB, m.key[:], nil); err != nil {
		panic("gost3412: " + err.Error())
	}
	if err := m.decCtx.SetPadding(0); err != nil {
		panic("gost3412: " + err.Error())
	}

	out, err := m.decCtx.Update(src[:MagmaBlockSize])
	if err != nil {
		panic("gost3412: " + err.Error())
	}
	copy(dst, out)

	tail, err := m.decCtx.Final()
	if err != nil {
		panic("gost3412: " + err.Error())
	}
	if len(tail) > 0 {
		copy(dst[len(out):], tail)
	}
}

// Zeroize securely wipes the key material and frees cached cipher contexts.
func (m *magmaCipher) Zeroize() {
	openssl.CleanseBytes(m.key[:])
	openssl.MunlockBytes(m.key[:])
	if m.encCtx != nil {
		m.encCtx.Close()
		m.encCtx = nil
	}
	if m.decCtx != nil {
		m.decCtx.Close()
		m.decCtx = nil
	}
}
