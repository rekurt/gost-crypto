package gost3413

import (
	"errors"

	"github.com/rekurt/gost-crypto/internal/cryptopro"
)

// CMAC computes CMAC (OMAC1) message authentication codes using
// GOST block ciphers (Kuznechik or Magma) per GOST R 34.13-2015.
//
// The NID stored here refers to the CBC-mode cipher (e.g., kuznyechik-cbc),
// which is correct: OpenSSL's CMAC_Init accepts a CBC cipher as its
// underlying block cipher, and constructs the CMAC internally.
type CMAC struct {
	key [32]byte
	nid int // NID of the CBC-mode cipher (CMAC is built on top of CBC)
}

// NewKuznechikCMAC creates a CMAC instance using the Kuznechik block cipher.
// key must be exactly 32 bytes.
func NewKuznechikCMAC(key []byte) (*CMAC, error) {
	if len(key) != 32 {
		return nil, errors.New("gost3413: invalid key size (must be 32 bytes)")
	}
	if err := cryptopro.Init(); err != nil {
		return nil, err
	}
	c := &CMAC{nid: cryptopro.NID_Kuznechik_CBC}
	copy(c.key[:], key)
	cryptopro.MlockBytes(c.key[:])
	return c, nil
}

// NewMagmaCMAC creates a CMAC instance using the Magma block cipher.
// key must be exactly 32 bytes.
func NewMagmaCMAC(key []byte) (*CMAC, error) {
	if len(key) != 32 {
		return nil, errors.New("gost3413: invalid key size (must be 32 bytes)")
	}
	if err := cryptopro.Init(); err != nil {
		return nil, err
	}
	c := &CMAC{nid: cryptopro.NID_Magma_CBC}
	copy(c.key[:], key)
	cryptopro.MlockBytes(c.key[:])
	return c, nil
}

// MAC computes the CMAC authentication tag over the given message.
// Returns a tag of block size length (16 bytes for Kuznechik, 8 bytes for Magma).
func (c *CMAC) MAC(message []byte) ([]byte, error) {
	return cryptopro.CMAC(c.nid, c.key[:], message)
}

// Zeroize securely wipes the key material from memory.
func (c *CMAC) Zeroize() {
	cryptopro.CleanseBytes(c.key[:])
	cryptopro.MunlockBytes(c.key[:])
}
