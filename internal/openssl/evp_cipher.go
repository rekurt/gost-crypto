package openssl

/*
#include <openssl/evp.h>
#include <openssl/err.h>

// Wrapper for EVP_get_cipherbynid which may be a macro.
static const EVP_CIPHER *go_EVP_get_cipherbynid(int nid) {
	return EVP_get_cipherbynid(nid);
}
*/
import "C"
import (
	"fmt"
	"runtime"
	"unsafe"
)

// CipherCtx wraps an EVP_CIPHER_CTX for symmetric encryption/decryption.
type CipherCtx struct {
	ctx *C.EVP_CIPHER_CTX
}

// NewCipherCtx allocates a new EVP_CIPHER_CTX.
// The caller must call Close when finished, though a runtime finalizer
// provides a safety net.
func NewCipherCtx() (*CipherCtx, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	ctx := C.EVP_CIPHER_CTX_new()
	if ctx == nil {
		return nil, fmtSSLError("EVP_CIPHER_CTX_new")
	}
	c := &CipherCtx{ctx: ctx}
	runtime.SetFinalizer(c, (*CipherCtx).finalize)
	return c, nil
}

// InitEncrypt initialises the context for encryption with the given NID, key, and IV.
// key and iv lengths must match the cipher requirements.
func (c *CipherCtx) InitEncrypt(nid int, key, iv []byte) error {
	ciph := C.go_EVP_get_cipherbynid(C.int(nid))
	if ciph == nil {
		return fmtSSLError("EVP_get_cipherbynid")
	}
	if err := validateCipherKeyIVLengths(ciph, key, iv); err != nil {
		return err
	}
	var keyPtr, ivPtr *C.uchar
	if len(key) > 0 {
		keyPtr = (*C.uchar)(unsafe.Pointer(&key[0]))
	}
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	if C.EVP_EncryptInit_ex(c.ctx, ciph, gostEngine, keyPtr, ivPtr) != 1 {
		return fmtSSLError("EVP_EncryptInit_ex")
	}
	return nil
}

// InitDecrypt initialises the context for decryption with the given NID, key, and IV.
func (c *CipherCtx) InitDecrypt(nid int, key, iv []byte) error {
	ciph := C.go_EVP_get_cipherbynid(C.int(nid))
	if ciph == nil {
		return fmtSSLError("EVP_get_cipherbynid")
	}
	if err := validateCipherKeyIVLengths(ciph, key, iv); err != nil {
		return err
	}
	var keyPtr, ivPtr *C.uchar
	if len(key) > 0 {
		keyPtr = (*C.uchar)(unsafe.Pointer(&key[0]))
	}
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	if C.EVP_DecryptInit_ex(c.ctx, ciph, gostEngine, keyPtr, ivPtr) != 1 {
		return fmtSSLError("EVP_DecryptInit_ex")
	}
	return nil
}

// Update feeds data through the cipher. Returns output bytes produced.
func (c *CipherCtx) Update(in []byte) ([]byte, error) {
	// Allocate output buffer: input length + one block is always sufficient.
	blockSize := int(C.EVP_CIPHER_CTX_block_size(c.ctx))
	out := make([]byte, len(in)+blockSize)
	var outLen C.int

	var inPtr *C.uchar
	inLen := C.int(len(in))
	if len(in) > 0 {
		inPtr = (*C.uchar)(unsafe.Pointer(&in[0]))
	} else {
		// For empty input, pass a non-nil pointer to avoid undefined behaviour.
		var dummy C.uchar
		inPtr = &dummy
		inLen = 0
	}

	if C.EVP_CipherUpdate(c.ctx, (*C.uchar)(unsafe.Pointer(&out[0])), &outLen, inPtr, inLen) != 1 {
		return nil, fmtSSLError("EVP_CipherUpdate")
	}
	return out[:outLen], nil
}

// Final completes the cipher operation. Returns any remaining output bytes.
func (c *CipherCtx) Final() ([]byte, error) {
	blockSize := int(C.EVP_CIPHER_CTX_block_size(c.ctx))
	out := make([]byte, blockSize)
	var outLen C.int
	if C.EVP_CipherFinal_ex(c.ctx, (*C.uchar)(unsafe.Pointer(&out[0])), &outLen) != 1 {
		return nil, fmtSSLError("EVP_CipherFinal_ex")
	}
	return out[:outLen], nil
}

// SetAAD sets additional authenticated data for AEAD ciphers (e.g., MGM).
// Must be called after Init and before the first Update.
func (c *CipherCtx) SetAAD(aad []byte) error {
	var outLen C.int
	var aadPtr *C.uchar
	if len(aad) > 0 {
		aadPtr = (*C.uchar)(unsafe.Pointer(&aad[0]))
	} else {
		var dummy C.uchar
		aadPtr = &dummy
	}
	if C.EVP_CipherUpdate(c.ctx, nil, &outLen, aadPtr, C.int(len(aad))) != 1 {
		return fmtSSLError("EVP_CipherUpdate(AAD)")
	}
	return nil
}

// GetTag retrieves the authentication tag after encryption (AEAD).
// Must be called after Final.
func (c *CipherCtx) GetTag(tagLen int) ([]byte, error) {
	tag := make([]byte, tagLen)
	if C.EVP_CIPHER_CTX_ctrl(c.ctx, C.EVP_CTRL_AEAD_GET_TAG, C.int(tagLen), unsafe.Pointer(&tag[0])) != 1 {
		return nil, fmtSSLError("EVP_CIPHER_CTX_ctrl(GET_TAG)")
	}
	return tag, nil
}

// SetTag sets the expected authentication tag before decryption (AEAD).
// Must be called after InitDecrypt and before Final.
func (c *CipherCtx) SetTag(tag []byte) error {
	if len(tag) == 0 {
		return nil
	}
	if C.EVP_CIPHER_CTX_ctrl(c.ctx, C.EVP_CTRL_AEAD_SET_TAG, C.int(len(tag)), unsafe.Pointer(&tag[0])) != 1 {
		return fmtSSLError("EVP_CIPHER_CTX_ctrl(SET_TAG)")
	}
	return nil
}

// SetPadding enables (1) or disables (0) PKCS#7 padding.
// For ECB/CBC ciphers operating on exact block-size input, call SetPadding(0)
// after Init to avoid "bad decrypt" errors on Final.
func (c *CipherCtx) SetPadding(pad int) error {
	if C.EVP_CIPHER_CTX_set_padding(c.ctx, C.int(pad)) != 1 {
		return fmtSSLError("EVP_CIPHER_CTX_set_padding")
	}
	return nil
}

// Close frees the underlying EVP_CIPHER_CTX. Safe to call multiple times.
func (c *CipherCtx) Close() {
	if c.ctx != nil {
		runtime.SetFinalizer(c, nil)
		C.EVP_CIPHER_CTX_free(c.ctx)
		c.ctx = nil
	}
}

func (c *CipherCtx) finalize() {
	if c.ctx != nil {
		C.EVP_CIPHER_CTX_free(c.ctx)
	}
}

func validateCipherKeyIVLengths(ciph *C.EVP_CIPHER, key, iv []byte) error {
	keyLen := int(C.EVP_CIPHER_key_length(ciph))
	if keyLen > 0 && len(key) != keyLen {
		return fmt.Errorf("openssl: invalid key length: got %d, want %d", len(key), keyLen)
	}

	ivLen := int(C.EVP_CIPHER_iv_length(ciph))
	if ivLen > 0 && len(iv) != ivLen {
		return fmt.Errorf("openssl: invalid iv length: got %d, want %d", len(iv), ivLen)
	}
	if ivLen == 0 && len(iv) != 0 {
		return fmt.Errorf("openssl: invalid iv length: got %d, want 0", len(iv))
	}
	return nil
}
