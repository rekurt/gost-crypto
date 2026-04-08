package gost3413

import (
	"errors"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

// OFB implements GOST R 34.13-2015 OFB (output feedback) mode.
// OFB turns a block cipher into a synchronous stream cipher.
// The same function is used for both encryption and decryption.
type OFB struct {
	key [32]byte
	nid int
}

// NewKuznechikOFB creates an OFB mode cipher using the Kuznechik block cipher.
// key must be exactly 32 bytes.
func NewKuznechikOFB(key []byte) (*OFB, error) {
	if len(key) != 32 {
		return nil, errors.New("gost3413: invalid key size (must be 32 bytes)")
	}
	if err := openssl.Init(); err != nil {
		return nil, err
	}
	o := &OFB{nid: openssl.NID_Kuznechik_OFB}
	copy(o.key[:], key)
	return o, nil
}

// NewMagmaOFB creates an OFB mode cipher using the Magma block cipher.
// key must be exactly 32 bytes.
func NewMagmaOFB(key []byte) (*OFB, error) {
	if len(key) != 32 {
		return nil, errors.New("gost3413: invalid key size (must be 32 bytes)")
	}
	if err := openssl.Init(); err != nil {
		return nil, err
	}
	o := &OFB{nid: openssl.NID_Magma_OFB}
	copy(o.key[:], key)
	return o, nil
}

// Encrypt encrypts plaintext using OFB mode with the given IV.
func (o *OFB) Encrypt(iv, plaintext []byte) ([]byte, error) {
	return o.xor(iv, plaintext, true)
}

// Decrypt decrypts ciphertext using OFB mode with the given IV.
// In OFB mode, decryption is identical to encryption.
func (o *OFB) Decrypt(iv, ciphertext []byte) ([]byte, error) {
	return o.xor(iv, ciphertext, false)
}

func (o *OFB) xor(iv, data []byte, encrypt bool) ([]byte, error) {
	ctx, err := openssl.NewCipherCtx()
	if err != nil {
		return nil, err
	}
	defer ctx.Close()

	if encrypt {
		err = ctx.InitEncrypt(o.nid, o.key[:], iv)
	} else {
		err = ctx.InitDecrypt(o.nid, o.key[:], iv)
	}
	if err != nil {
		return nil, err
	}

	out, err := ctx.Update(data)
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
func (o *OFB) Zeroize() {
	openssl.CleanseBytes(o.key[:])
}
