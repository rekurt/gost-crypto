package gost3413

import (
	"crypto/cipher"
	"errors"

	"github.com/rekurt/gost-crypto/internal/cryptopro"
	"github.com/rekurt/gost-crypto/pkg/gost3412"
)

// CBC implements GOST R 34.13-2015 CBC (cipher block chaining) mode.
// Plaintext length must be a multiple of the block size.
// Padding is the caller's responsibility.
//
// CBC is built in pure Go on top of the raw ECB block cipher provided
// by pkg/gost3412 (which is itself backed by CryptoPro CSP). This
// matches Go's crypto/cipher convention and does not rely on any
// CBC-specific features of the underlying CSP.
type CBC struct {
	key       [32]byte
	block     cipher.Block
	blockSize int
}

// NewKuznechikCBC creates a CBC mode cipher using the Kuznechik block cipher.
// key must be exactly 32 bytes.
func NewKuznechikCBC(key []byte) (*CBC, error) {
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
	c := &CBC{block: block, blockSize: block.BlockSize()}
	copy(c.key[:], key)
	cryptopro.MlockBytes(c.key[:])
	return c, nil
}

// NewMagmaCBC creates a CBC mode cipher using the Magma block cipher.
func NewMagmaCBC(key []byte) (*CBC, error) {
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
	c := &CBC{block: block, blockSize: block.BlockSize()}
	copy(c.key[:], key)
	cryptopro.MlockBytes(c.key[:])
	return c, nil
}

// BlockSize returns the block size of the underlying cipher.
func (c *CBC) BlockSize() int { return c.blockSize }

// Encrypt encrypts plaintext using CBC mode with the given IV.
// Plaintext length must be a multiple of BlockSize(). Padding is the
// caller's responsibility.
func (c *CBC) Encrypt(iv, plaintext []byte) ([]byte, error) {
	if len(iv) != c.blockSize {
		return nil, errors.New("gost3413: invalid IV length for CBC")
	}
	if len(plaintext)%c.blockSize != 0 {
		return nil, errors.New("gost3413: plaintext is not a multiple of block size")
	}
	out := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(c.block, iv)
	mode.CryptBlocks(out, plaintext)
	return out, nil
}

// Decrypt decrypts ciphertext using CBC mode with the given IV.
func (c *CBC) Decrypt(iv, ciphertext []byte) ([]byte, error) {
	if len(iv) != c.blockSize {
		return nil, errors.New("gost3413: invalid IV length for CBC")
	}
	if len(ciphertext)%c.blockSize != 0 {
		return nil, errors.New("gost3413: ciphertext is not a multiple of block size")
	}
	out := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(c.block, iv)
	mode.CryptBlocks(out, ciphertext)
	return out, nil
}

// Zeroize securely wipes the key material.
func (c *CBC) Zeroize() {
	if z, ok := c.block.(interface{ Zeroize() }); ok {
		z.Zeroize()
	}
	cryptopro.CleanseBytes(c.key[:])
	cryptopro.MunlockBytes(c.key[:])
}
