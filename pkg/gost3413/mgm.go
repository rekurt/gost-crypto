// Package gost3413 implements GOST R 34.13-2015 cipher modes (MGM AEAD)
// backed by OpenSSL gost-engine.
package gost3413

import (
	"crypto/cipher"
	"errors"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

const (
	mgmNonceSize = 16 // Kuznechik-MGM uses 128-bit nonce
	mgmTagSize   = 16 // 128-bit authentication tag
)

// mgmAEAD implements cipher.AEAD using kuznyechik-mgm via gost-engine.
type mgmAEAD struct {
	key [32]byte
}

// NewMGMFromKey creates a cipher.AEAD using Kuznechik-MGM.
// key must be exactly 32 bytes.
func NewMGMFromKey(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("gost3413: invalid key size (must be 32 bytes)")
	}
	if err := openssl.Init(); err != nil {
		return nil, err
	}
	m := new(mgmAEAD)
	copy(m.key[:], key)
	return m, nil
}

func (m *mgmAEAD) NonceSize() int { return mgmNonceSize }
func (m *mgmAEAD) Overhead() int  { return mgmTagSize }

// Seal encrypts and authenticates plaintext, authenticates additionalData,
// and appends the result to dst, returning the updated slice.
// nonce must be NonceSize() bytes long and unique for each call.
func (m *mgmAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != mgmNonceSize {
		panic("gost3413: incorrect nonce length")
	}

	ctx, err := openssl.NewCipherCtx()
	if err != nil {
		panic("gost3413: " + err.Error())
	}
	defer ctx.Close()

	if err := ctx.InitEncrypt(openssl.NID_Kuznechik_MGM, m.key[:], nonce); err != nil {
		panic("gost3413: " + err.Error())
	}

	// Set AAD
	if err := ctx.SetAAD(additionalData); err != nil {
		panic("gost3413: " + err.Error())
	}

	// Encrypt plaintext
	var ciphertext []byte
	if len(plaintext) > 0 {
		ciphertext, err = ctx.Update(plaintext)
		if err != nil {
			panic("gost3413: " + err.Error())
		}
	}

	// Finalize
	tail, err := ctx.Final()
	if err != nil {
		panic("gost3413: " + err.Error())
	}
	if len(tail) > 0 {
		ciphertext = append(ciphertext, tail...)
	}

	// Get authentication tag
	tag, err := ctx.GetTag(mgmTagSize)
	if err != nil {
		panic("gost3413: " + err.Error())
	}

	// Append ciphertext + tag to dst
	ret, out := sliceForAppend(dst, len(ciphertext)+mgmTagSize)
	copy(out, ciphertext)
	copy(out[len(ciphertext):], tag)
	return ret
}

// Open decrypts and authenticates ciphertext, authenticates additionalData,
// and appends the resulting plaintext to dst, returning the updated slice.
// ciphertext must include the authentication tag (last Overhead() bytes).
func (m *mgmAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != mgmNonceSize {
		return nil, errors.New("gost3413: incorrect nonce length")
	}
	if len(ciphertext) < mgmTagSize {
		return nil, errors.New("gost3413: ciphertext too short")
	}

	// Split ciphertext and tag
	tag := ciphertext[len(ciphertext)-mgmTagSize:]
	ct := ciphertext[:len(ciphertext)-mgmTagSize]

	ctx, err := openssl.NewCipherCtx()
	if err != nil {
		return nil, err
	}
	defer ctx.Close()

	if err := ctx.InitDecrypt(openssl.NID_Kuznechik_MGM, m.key[:], nonce); err != nil {
		return nil, err
	}

	// Set AAD
	if err := ctx.SetAAD(additionalData); err != nil {
		return nil, err
	}

	// Set expected tag before decryption
	if err := ctx.SetTag(tag); err != nil {
		return nil, err
	}

	// Decrypt
	var plaintext []byte
	if len(ct) > 0 {
		plaintext, err = ctx.Update(ct)
		if err != nil {
			return nil, err
		}
	}

	// Finalize (verifies tag)
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
func (m *mgmAEAD) Zeroize() {
	openssl.CleanseBytes(m.key[:])
}

// sliceForAppend takes a destination slice and a requested number of bytes.
// It returns a slice with the data appended and a sub-slice pointing to the
// newly appended portion. This matches the pattern used in crypto/cipher.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
