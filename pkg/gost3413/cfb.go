package gost3413

import (
	"crypto/cipher"
	"errors"

	"github.com/rekurt/gost-crypto/internal/cryptopro"
	"github.com/rekurt/gost-crypto/pkg/gost3412"
)

// CFB implements GOST R 34.13-2015 CFB (cipher feedback) mode.
// CFB turns a block cipher into a self-synchronising stream cipher.
//
// Implementation: pure Go on top of pkg/gost3412's cipher.Block wrapper
// using crypto/cipher.NewCFBEncrypter / NewCFBDecrypter.
type CFB struct {
	key       [32]byte
	block     cipher.Block
	blockSize int
}

// NewKuznechikCFB creates a CFB mode cipher using Kuznechik.
func NewKuznechikCFB(key []byte) (*CFB, error) {
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
	c := &CFB{block: block, blockSize: block.BlockSize()}
	copy(c.key[:], key)
	cryptopro.MlockBytes(c.key[:])
	return c, nil
}

// NewMagmaCFB creates a CFB mode cipher using Magma.
func NewMagmaCFB(key []byte) (*CFB, error) {
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
	c := &CFB{block: block, blockSize: block.BlockSize()}
	copy(c.key[:], key)
	cryptopro.MlockBytes(c.key[:])
	return c, nil
}

// Encrypt encrypts plaintext using CFB mode with the given IV.
func (c *CFB) Encrypt(iv, plaintext []byte) ([]byte, error) {
	if len(iv) != c.blockSize {
		return nil, errors.New("gost3413: invalid IV length for CFB")
	}
	out := make([]byte, len(plaintext))
	cipher.NewCFBEncrypter(c.block, iv).XORKeyStream(out, plaintext)
	return out, nil
}

// Decrypt decrypts ciphertext using CFB mode.
func (c *CFB) Decrypt(iv, ciphertext []byte) ([]byte, error) {
	if len(iv) != c.blockSize {
		return nil, errors.New("gost3413: invalid IV length for CFB")
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCFBDecrypter(c.block, iv).XORKeyStream(out, ciphertext)
	return out, nil
}

// StreamEncrypter returns a cipher.Stream for streaming encryption.
func (c *CFB) StreamEncrypter(iv []byte) cipher.Stream {
	return cipher.NewCFBEncrypter(c.block, iv)
}

// StreamDecrypter returns a cipher.Stream for streaming decryption.
func (c *CFB) StreamDecrypter(iv []byte) cipher.Stream {
	return cipher.NewCFBDecrypter(c.block, iv)
}

// Zeroize securely wipes the key material.
func (c *CFB) Zeroize() {
	if z, ok := c.block.(interface{ Zeroize() }); ok {
		z.Zeroize()
	}
	cryptopro.CleanseBytes(c.key[:])
	cryptopro.MunlockBytes(c.key[:])
}
