package gost3412

import (
	"crypto/cipher"
	"errors"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

const (
	// KuznechikKeySize is the key size in bytes for Kuznechik (256 bits).
	KuznechikKeySize = 32
	// KuznechikBlockSize is the block size in bytes for Kuznechik (128 bits).
	KuznechikBlockSize = 16
)

// Zeroizable is implemented by cipher types that hold key material.
type Zeroizable interface {
	Zeroize()
}

// kuznechikCipher implements cipher.Block using kuznyechik-ecb via gost-engine.
// Cipher contexts are cached to avoid per-call EVP_CIPHER_CTX allocation overhead.
type kuznechikCipher struct {
	key    [KuznechikKeySize]byte
	encCtx *openssl.CipherCtx // cached encrypt context
	decCtx *openssl.CipherCtx // cached decrypt context
}

// NewKuznechik returns a new cipher.Block implementing the Kuznechik block cipher.
// key must be exactly 32 bytes.
func NewKuznechik(key []byte) (cipher.Block, error) {
	if len(key) != KuznechikKeySize {
		return nil, errors.New("gost3412: invalid key size (must be 32 bytes)")
	}
	if err := openssl.Init(); err != nil {
		return nil, err
	}

	k := new(kuznechikCipher)
	copy(k.key[:], key)
	openssl.MlockBytes(k.key[:])

	// Pre-initialise encrypt context.
	var err error
	k.encCtx, err = openssl.NewCipherCtx()
	if err != nil {
		return nil, err
	}
	if err := k.encCtx.InitEncrypt(openssl.NID_Kuznechik_ECB, k.key[:], nil); err != nil {
		k.encCtx.Close()
		return nil, err
	}
	if err := k.encCtx.SetPadding(0); err != nil {
		k.encCtx.Close()
		return nil, err
	}

	// Pre-initialise decrypt context.
	k.decCtx, err = openssl.NewCipherCtx()
	if err != nil {
		k.encCtx.Close()
		return nil, err
	}
	if err := k.decCtx.InitDecrypt(openssl.NID_Kuznechik_ECB, k.key[:], nil); err != nil {
		k.encCtx.Close()
		k.decCtx.Close()
		return nil, err
	}
	if err := k.decCtx.SetPadding(0); err != nil {
		k.encCtx.Close()
		k.decCtx.Close()
		return nil, err
	}

	return k, nil
}

func (k *kuznechikCipher) BlockSize() int { return KuznechikBlockSize }

func (k *kuznechikCipher) Encrypt(dst, src []byte) {
	if len(src) < KuznechikBlockSize {
		panic("gost3412: input not full block")
	}
	if len(dst) < KuznechikBlockSize {
		panic("gost3412: output not full block")
	}

	// Re-init the cached context for a fresh ECB operation (resets internal
	// state while keeping the key schedule).
	if err := k.encCtx.InitEncrypt(openssl.NID_Kuznechik_ECB, k.key[:], nil); err != nil {
		panic("gost3412: " + err.Error())
	}
	if err := k.encCtx.SetPadding(0); err != nil {
		panic("gost3412: " + err.Error())
	}

	out, err := k.encCtx.Update(src[:KuznechikBlockSize])
	if err != nil {
		panic("gost3412: " + err.Error())
	}
	copy(dst, out)

	tail, err := k.encCtx.Final()
	if err != nil {
		panic("gost3412: " + err.Error())
	}
	if len(tail) > 0 {
		copy(dst[len(out):], tail)
	}
}

func (k *kuznechikCipher) Decrypt(dst, src []byte) {
	if len(src) < KuznechikBlockSize {
		panic("gost3412: input not full block")
	}
	if len(dst) < KuznechikBlockSize {
		panic("gost3412: output not full block")
	}

	if err := k.decCtx.InitDecrypt(openssl.NID_Kuznechik_ECB, k.key[:], nil); err != nil {
		panic("gost3412: " + err.Error())
	}
	if err := k.decCtx.SetPadding(0); err != nil {
		panic("gost3412: " + err.Error())
	}

	out, err := k.decCtx.Update(src[:KuznechikBlockSize])
	if err != nil {
		panic("gost3412: " + err.Error())
	}
	copy(dst, out)

	tail, err := k.decCtx.Final()
	if err != nil {
		panic("gost3412: " + err.Error())
	}
	if len(tail) > 0 {
		copy(dst[len(out):], tail)
	}
}

// Zeroize securely wipes the key material and frees cached cipher contexts.
// The cipher must not be used after calling Zeroize.
func (k *kuznechikCipher) Zeroize() {
	openssl.CleanseBytes(k.key[:])
	openssl.MunlockBytes(k.key[:])
	if k.encCtx != nil {
		k.encCtx.Close()
		k.encCtx = nil
	}
	if k.decCtx != nil {
		k.decCtx.Close()
		k.decCtx = nil
	}
}
