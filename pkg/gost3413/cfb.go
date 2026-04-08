package gost3413

import (
	"errors"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

// CFB implements GOST R 34.13-2015 CFB (cipher feedback) mode.
// CFB mode turns a block cipher into a self-synchronizing stream cipher.
type CFB struct {
	key [32]byte
	nid int
}

// NewKuznechikCFB creates a CFB mode cipher using the Kuznechik block cipher.
// key must be exactly 32 bytes.
func NewKuznechikCFB(key []byte) (*CFB, error) {
	if len(key) != 32 {
		return nil, errors.New("gost3413: invalid key size (must be 32 bytes)")
	}
	if err := openssl.Init(); err != nil {
		return nil, err
	}
	c := &CFB{nid: openssl.NID_Kuznechik_CFB}
	copy(c.key[:], key)
	openssl.MlockBytes(c.key[:])
	return c, nil
}

// NewMagmaCFB creates a CFB mode cipher using the Magma block cipher.
// key must be exactly 32 bytes.
func NewMagmaCFB(key []byte) (*CFB, error) {
	if len(key) != 32 {
		return nil, errors.New("gost3413: invalid key size (must be 32 bytes)")
	}
	if err := openssl.Init(); err != nil {
		return nil, err
	}
	c := &CFB{nid: openssl.NID_Magma_CFB}
	copy(c.key[:], key)
	openssl.MlockBytes(c.key[:])
	return c, nil
}

// Encrypt encrypts plaintext using CFB mode with the given IV.
func (c *CFB) Encrypt(iv, plaintext []byte) ([]byte, error) {
	ctx, err := openssl.NewCipherCtx()
	if err != nil {
		return nil, err
	}
	defer ctx.Close()

	if err := ctx.InitEncrypt(c.nid, c.key[:], iv); err != nil {
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

// Decrypt decrypts ciphertext using CFB mode with the given IV.
func (c *CFB) Decrypt(iv, ciphertext []byte) ([]byte, error) {
	ctx, err := openssl.NewCipherCtx()
	if err != nil {
		return nil, err
	}
	defer ctx.Close()

	if err := ctx.InitDecrypt(c.nid, c.key[:], iv); err != nil {
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
func (c *CFB) Zeroize() {
	openssl.CleanseBytes(c.key[:])
	openssl.MunlockBytes(c.key[:])
}
