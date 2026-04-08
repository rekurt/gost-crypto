package gost3413

import (
	"errors"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

// CTR implements GOST R 34.13-2015 CTR (counter) mode encryption.
// CTR mode turns a block cipher into a stream cipher. The same function
// is used for both encryption and decryption.
type CTR struct {
	key [32]byte
	nid int
}

// NewKuznechikCTR creates a CTR mode cipher using the Kuznechik block cipher.
// key must be exactly 32 bytes. iv must be the correct IV size for the cipher
// (typically 8 bytes for Kuznechik-CTR in gost-engine).
func NewKuznechikCTR(key []byte) (*CTR, error) {
	if len(key) != 32 {
		return nil, errors.New("gost3413: invalid key size (must be 32 bytes)")
	}
	if err := openssl.Init(); err != nil {
		return nil, err
	}
	c := &CTR{nid: openssl.NID_Kuznechik_CTR}
	copy(c.key[:], key)
	openssl.MlockBytes(c.key[:])
	return c, nil
}

// NewMagmaCTR creates a CTR mode cipher using the Magma block cipher.
// key must be exactly 32 bytes.
func NewMagmaCTR(key []byte) (*CTR, error) {
	if len(key) != 32 {
		return nil, errors.New("gost3413: invalid key size (must be 32 bytes)")
	}
	if err := openssl.Init(); err != nil {
		return nil, err
	}
	c := &CTR{nid: openssl.NID_Magma_CTR}
	copy(c.key[:], key)
	openssl.MlockBytes(c.key[:])
	return c, nil
}

// NID returns the OpenSSL cipher NID, for use with [EncryptReader]/[DecryptReader].
func (c *CTR) NID() int { return c.nid }

// Key returns a copy of the key for use with [EncryptReader]/[DecryptReader].
// The caller must securely erase the returned slice when done.
func (c *CTR) Key() []byte {
	k := make([]byte, len(c.key))
	copy(k, c.key[:])
	return k
}

// Encrypt encrypts plaintext using CTR mode with the given IV.
// The IV size depends on the underlying cipher and gost-engine implementation.
func (c *CTR) Encrypt(iv, plaintext []byte) ([]byte, error) {
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

// Decrypt decrypts ciphertext using CTR mode with the given IV.
// In CTR mode, decryption is identical to encryption.
func (c *CTR) Decrypt(iv, ciphertext []byte) ([]byte, error) {
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
func (c *CTR) Zeroize() {
	openssl.CleanseBytes(c.key[:])
	openssl.MunlockBytes(c.key[:])
}
