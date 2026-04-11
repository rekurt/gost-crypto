package gost3413

import (
	"crypto/cipher"
	"errors"

	"github.com/rekurt/gost-crypto/internal/cryptopro"
	"github.com/rekurt/gost-crypto/pkg/gost3412"
)

// CTR implements GOST R 34.13-2015 CTR (counter) mode.
// CTR turns a block cipher into a stream cipher; the same function is
// used for both encryption and decryption.
//
// Implementation: pure Go on top of pkg/gost3412's cipher.Block wrapper,
// using the standard crypto/cipher.NewCTR mode.
type CTR struct {
	key       [32]byte
	block     cipher.Block
	blockSize int
}

// NewKuznechikCTR creates a CTR mode cipher using Kuznechik.
func NewKuznechikCTR(key []byte) (*CTR, error) {
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
	c := &CTR{block: block, blockSize: block.BlockSize()}
	copy(c.key[:], key)
	cryptopro.MlockBytes(c.key[:])
	return c, nil
}

// NewMagmaCTR creates a CTR mode cipher using Magma.
func NewMagmaCTR(key []byte) (*CTR, error) {
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
	c := &CTR{block: block, blockSize: block.BlockSize()}
	copy(c.key[:], key)
	cryptopro.MlockBytes(c.key[:])
	return c, nil
}

// padIV grows an IV to the cipher's full block size by zero-extending on
// the right, matching the historical gost-engine behaviour where CTR
// accepted short IVs.
func (c *CTR) padIV(iv []byte) []byte {
	if len(iv) == c.blockSize {
		return iv
	}
	out := make([]byte, c.blockSize)
	copy(out, iv)
	return out
}

// Encrypt encrypts plaintext using CTR mode with the given IV.
func (c *CTR) Encrypt(iv, plaintext []byte) ([]byte, error) {
	iv = c.padIV(iv)
	out := make([]byte, len(plaintext))
	cipher.NewCTR(c.block, iv).XORKeyStream(out, plaintext)
	return out, nil
}

// Decrypt is identical to Encrypt in CTR mode.
func (c *CTR) Decrypt(iv, ciphertext []byte) ([]byte, error) {
	return c.Encrypt(iv, ciphertext)
}

// Stream returns a cipher.Stream for use with the io.Reader helpers.
func (c *CTR) Stream(iv []byte) cipher.Stream {
	iv = c.padIV(iv)
	return cipher.NewCTR(c.block, iv)
}

// Zeroize securely wipes the key material.
func (c *CTR) Zeroize() {
	if z, ok := c.block.(interface{ Zeroize() }); ok {
		z.Zeroize()
	}
	cryptopro.CleanseBytes(c.key[:])
	cryptopro.MunlockBytes(c.key[:])
}
