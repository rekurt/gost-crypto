package gost3413

import (
	"errors"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

// CBC implements GOST R 34.13-2015 CBC (cipher block chaining) mode.
// Plaintext length must be a multiple of the block size.
// Padding is the caller's responsibility.
type CBC struct {
	key       [32]byte
	nid       int
	blockSize int
}

// NewKuznechikCBC creates a CBC mode cipher using the Kuznechik block cipher.
// key must be exactly 32 bytes.
func NewKuznechikCBC(key []byte) (*CBC, error) {
	if len(key) != 32 {
		return nil, errors.New("gost3413: invalid key size (must be 32 bytes)")
	}
	if err := openssl.Init(); err != nil {
		return nil, err
	}
	c := &CBC{nid: openssl.NID_Kuznechik_CBC, blockSize: 16}
	copy(c.key[:], key)
	return c, nil
}

// NewMagmaCBC creates a CBC mode cipher using the Magma block cipher.
// key must be exactly 32 bytes.
func NewMagmaCBC(key []byte) (*CBC, error) {
	if len(key) != 32 {
		return nil, errors.New("gost3413: invalid key size (must be 32 bytes)")
	}
	if err := openssl.Init(); err != nil {
		return nil, err
	}
	c := &CBC{nid: openssl.NID_Magma_CBC, blockSize: 8}
	copy(c.key[:], key)
	return c, nil
}

// BlockSize returns the block size of the underlying cipher.
func (c *CBC) BlockSize() int { return c.blockSize }

// Encrypt encrypts plaintext using CBC mode with the given IV.
// Plaintext length must be a multiple of BlockSize().
// Padding is disabled; the caller must handle padding.
func (c *CBC) Encrypt(iv, plaintext []byte) ([]byte, error) {
	if len(plaintext)%c.blockSize != 0 {
		return nil, errors.New("gost3413: plaintext is not a multiple of block size")
	}

	ctx, err := openssl.NewCipherCtx()
	if err != nil {
		return nil, err
	}
	defer ctx.Close()

	if err := ctx.InitEncrypt(c.nid, c.key[:], iv); err != nil {
		return nil, err
	}
	if err := ctx.SetPadding(0); err != nil {
		return nil, err
	}

	out, err := ctx.Update(plaintext)
	if err != nil {
		return nil, err
	}

	tail, err := ctx.Final()
	if err != nil {
		return nil, err
	}
	if len(tail) > 0 {
		out = append(out, tail...)
	}

	return out, nil
}

// Decrypt decrypts ciphertext using CBC mode with the given IV.
// Ciphertext length must be a multiple of BlockSize().
func (c *CBC) Decrypt(iv, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%c.blockSize != 0 {
		return nil, errors.New("gost3413: ciphertext is not a multiple of block size")
	}

	ctx, err := openssl.NewCipherCtx()
	if err != nil {
		return nil, err
	}
	defer ctx.Close()

	if err := ctx.InitDecrypt(c.nid, c.key[:], iv); err != nil {
		return nil, err
	}
	if err := ctx.SetPadding(0); err != nil {
		return nil, err
	}

	out, err := ctx.Update(ciphertext)
	if err != nil {
		return nil, err
	}

	tail, err := ctx.Final()
	if err != nil {
		return nil, err
	}
	if len(tail) > 0 {
		out = append(out, tail...)
	}

	return out, nil
}

// Zeroize securely wipes the key material from memory.
func (c *CBC) Zeroize() {
	openssl.CleanseBytes(c.key[:])
}
