package gost3413

import (
	"crypto/cipher"
	"errors"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

const (
	magmaMGMNonceSize = 8 // Magma-MGM uses 64-bit nonce
	magmaMGMTagSize   = 8 // 64-bit authentication tag
)

// magmaMGMAEAD implements cipher.AEAD using magma-mgm via gost-engine.
type magmaMGMAEAD struct {
	key [32]byte
}

// NewMagmaMGMFromKey creates a cipher.AEAD using Magma-MGM.
// key must be exactly 32 bytes.
func NewMagmaMGMFromKey(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("gost3413: invalid key size (must be 32 bytes)")
	}
	if err := openssl.Init(); err != nil {
		return nil, err
	}
	m := new(magmaMGMAEAD)
	copy(m.key[:], key)
	openssl.MlockBytes(m.key[:])
	return m, nil
}

func (m *magmaMGMAEAD) NonceSize() int { return magmaMGMNonceSize }
func (m *magmaMGMAEAD) Overhead() int  { return magmaMGMTagSize }

// Seal encrypts and authenticates plaintext, authenticates additionalData,
// and appends the result to dst, returning the updated slice.
func (m *magmaMGMAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != magmaMGMNonceSize {
		panic("gost3413: incorrect nonce length for Magma-MGM")
	}

	ctx, err := openssl.NewCipherCtx()
	if err != nil {
		panic("gost3413: " + err.Error())
	}
	defer ctx.Close()

	if err := ctx.InitEncrypt(openssl.NID_Magma_MGM, m.key[:], nonce); err != nil {
		panic("gost3413: " + err.Error())
	}

	if err := ctx.SetAAD(additionalData); err != nil {
		panic("gost3413: " + err.Error())
	}

	var ciphertext []byte
	if len(plaintext) > 0 {
		ciphertext, err = ctx.Update(plaintext)
		if err != nil {
			panic("gost3413: " + err.Error())
		}
	}

	tail, err := ctx.Final()
	if err != nil {
		panic("gost3413: " + err.Error())
	}
	if len(tail) > 0 {
		ciphertext = append(ciphertext, tail...)
	}

	tag, err := ctx.GetTag(magmaMGMTagSize)
	if err != nil {
		panic("gost3413: " + err.Error())
	}

	ret, out := sliceForAppend(dst, len(ciphertext)+magmaMGMTagSize)
	copy(out, ciphertext)
	copy(out[len(ciphertext):], tag)
	return ret
}

// Open decrypts and authenticates ciphertext, authenticates additionalData,
// and appends the resulting plaintext to dst, returning the updated slice.
func (m *magmaMGMAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != magmaMGMNonceSize {
		return nil, errors.New("gost3413: incorrect nonce length for Magma-MGM")
	}
	if len(ciphertext) < magmaMGMTagSize {
		return nil, errors.New("gost3413: ciphertext too short")
	}

	tag := ciphertext[len(ciphertext)-magmaMGMTagSize:]
	ct := ciphertext[:len(ciphertext)-magmaMGMTagSize]

	ctx, err := openssl.NewCipherCtx()
	if err != nil {
		return nil, err
	}
	defer ctx.Close()

	if err := ctx.InitDecrypt(openssl.NID_Magma_MGM, m.key[:], nonce); err != nil {
		return nil, err
	}

	if err := ctx.SetAAD(additionalData); err != nil {
		return nil, err
	}

	if err := ctx.SetTag(tag); err != nil {
		return nil, err
	}

	var plaintext []byte
	if len(ct) > 0 {
		plaintext, err = ctx.Update(ct)
		if err != nil {
			return nil, err
		}
	}

	tail, err := ctx.Final()
	if err != nil {
		return nil, errors.New("gost3413: authentication failed")
	}
	if len(tail) > 0 {
		plaintext = append(plaintext, tail...)
	}

	ret, out := sliceForAppend(dst, len(plaintext))
	copy(out, plaintext)
	return ret, nil
}

// Zeroize securely wipes the key material from memory.
func (m *magmaMGMAEAD) Zeroize() {
	openssl.CleanseBytes(m.key[:])
	openssl.MunlockBytes(m.key[:])
}
