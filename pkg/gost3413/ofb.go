package gost3413

import (
	"crypto/cipher"
	"errors"

	"github.com/rekurt/gost-crypto/internal/cryptopro"
	"github.com/rekurt/gost-crypto/pkg/gost3412"
)

// OFB implements GOST R 34.13-2015 OFB (output feedback) mode.
// OFB turns a block cipher into a synchronous stream cipher.
// The same function is used for both encryption and decryption.
type OFB struct {
	key       [32]byte
	block     cipher.Block
	blockSize int
}

// NewKuznechikOFB creates an OFB mode cipher using Kuznechik.
func NewKuznechikOFB(key []byte) (*OFB, error) {
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
	o := &OFB{block: block, blockSize: block.BlockSize()}
	copy(o.key[:], key)
	cryptopro.MlockBytes(o.key[:])
	return o, nil
}

// NewMagmaOFB creates an OFB mode cipher using Magma.
func NewMagmaOFB(key []byte) (*OFB, error) {
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
	o := &OFB{block: block, blockSize: block.BlockSize()}
	copy(o.key[:], key)
	cryptopro.MlockBytes(o.key[:])
	return o, nil
}

// Encrypt encrypts plaintext using OFB mode with the given IV.
func (o *OFB) Encrypt(iv, plaintext []byte) ([]byte, error) {
	if len(iv) != o.blockSize {
		return nil, errors.New("gost3413: invalid IV length for OFB")
	}
	out := make([]byte, len(plaintext))
	cipher.NewOFB(o.block, iv).XORKeyStream(out, plaintext)
	return out, nil
}

// Decrypt is identical to Encrypt in OFB mode.
func (o *OFB) Decrypt(iv, ciphertext []byte) ([]byte, error) {
	return o.Encrypt(iv, ciphertext)
}

// Stream returns a cipher.Stream for streaming OFB.
func (o *OFB) Stream(iv []byte) cipher.Stream {
	return cipher.NewOFB(o.block, iv)
}

// Zeroize securely wipes the key material.
func (o *OFB) Zeroize() {
	if z, ok := o.block.(interface{ Zeroize() }); ok {
		z.Zeroize()
	}
	cryptopro.CleanseBytes(o.key[:])
	cryptopro.MunlockBytes(o.key[:])
}
