//go:build cgo && linux && cryptopro
// +build cgo,linux,cryptopro

package cryptopro

/*
#cgo CFLAGS: -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/cades
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi10 -lcapi20 -lssp -lrdrsup -lcades
#include "capi.h"

// go_import_plaintext_key builds a PLAINTEXTKEYBLOB for a symmetric GOST
// key (32 bytes) and imports it into the given provider, returning a
// fresh HCRYPTKEY for Kuznechik or Magma.
//
// Layout of PLAINTEXTKEYBLOB as expected by CAPILite:
//   BLOBHEADER { bType=PLAINTEXTKEYBLOB, bVersion=CUR_BLOB_VERSION,
//                reserved=0, aiKeyAlg=alg }
//   DWORD key_length
//   BYTE  key_material[key_length]
static BOOL go_import_plaintext_key(HCRYPTPROV prov, ALG_ID alg,
                                    const BYTE *key, DWORD key_len,
                                    HCRYPTKEY *out) {
    DWORD blob_len = sizeof(BLOBHEADER) + sizeof(DWORD) + key_len;
    BYTE *blob = (BYTE*)malloc(blob_len);
    if (blob == NULL) return FALSE;
    BLOBHEADER *hdr = (BLOBHEADER*)blob;
    hdr->bType = PLAINTEXTKEYBLOB;
    hdr->bVersion = CUR_BLOB_VERSION;
    hdr->reserved = 0;
    hdr->aiKeyAlg = alg;
    DWORD *len_field = (DWORD*)(blob + sizeof(BLOBHEADER));
    *len_field = key_len;
    memcpy(blob + sizeof(BLOBHEADER) + sizeof(DWORD), key, key_len);

    BOOL rc = CryptImportKey(prov, blob, blob_len, 0, CRYPT_EXPORTABLE, out);
    explicit_bzero(blob, blob_len);
    free(blob);
    return rc;
}

// go_set_cipher_mode sets CRYPT_MODE_ECB / CRYPT_MODE_CBC via KP_MODE.
static BOOL go_set_cipher_mode(HCRYPTKEY key, DWORD mode) {
    return CryptSetKeyParam(key, KP_MODE, (BYTE*)&mode, 0);
}

// go_set_iv writes the cipher IV via KP_IV.
static BOOL go_set_iv(HCRYPTKEY key, const BYTE *iv, DWORD iv_len) {
    // CAPILite's KP_IV does not take an explicit length (the CSP knows
    // the block size from the algorithm). Nevertheless the buffer must
    // contain at least one block worth of IV bytes.
    (void)iv_len;
    return CryptSetKeyParam(key, KP_IV, (BYTE*)iv, 0);
}

// go_set_padding disables PKCS#7 padding (for ECB / CBC on exact-block
// input). CAPILite expects ZERO_PADDING = 3 for "no padding".
static BOOL go_set_padding(HCRYPTKEY key, int enable) {
    DWORD pad = 3; // ZERO_PADDING = no padding
    if (enable) {
        pad = 1; // PKCS5_PADDING
    }
    return CryptSetKeyParam(key, KP_PADDING, (BYTE*)&pad, 0);
}

// go_encrypt is a single-shot encrypt call. The caller must size `buf`
// to at least data_len + block_size bytes.
static BOOL go_encrypt(HCRYPTKEY key, BOOL final, BYTE *buf, DWORD data_len,
                       DWORD buf_len, DWORD *out_len) {
    DWORD len = data_len;
    BOOL rc = CryptEncrypt(key, 0, final, 0, buf, &len, buf_len);
    *out_len = len;
    return rc;
}

// go_decrypt is the symmetrical decrypt single-shot call.
static BOOL go_decrypt(HCRYPTKEY key, BOOL final, BYTE *buf, DWORD data_len,
                       DWORD *out_len) {
    DWORD len = data_len;
    BOOL rc = CryptDecrypt(key, 0, final, 0, buf, &len);
    *out_len = len;
    return rc;
}
*/
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

// CipherCtx wraps a CryptoPro CSP HCRYPTKEY created from a
// PLAINTEXTKEYBLOB, configured for ECB or CBC mode on a GOST block cipher.
//
// It mirrors the contract of the legacy openssl.CipherCtx but supports
// only the modes that CryptoPro CSP implements natively. Consumers that
// need CTR / CFB / OFB / MGM now build those on top of the raw ECB
// block cipher in pkg/gost3413 (pure Go over cipher.Block).
type CipherCtx struct {
	hKey      C.HCRYPTKEY
	hProv     C.HCRYPTPROV
	alg       C.ALG_ID
	blockSize int
	encrypt   bool
	// Cached key material for Init*() re-initialisation. Zeroised on Close().
	keyBuf []byte
}

// NewCipherCtx allocates an empty CipherCtx. The caller must follow with
// InitEncrypt / InitDecrypt before any Update call.
func NewCipherCtx() (*CipherCtx, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	c := &CipherCtx{}
	runtime.SetFinalizer(c, (*CipherCtx).finalize)
	return c, nil
}

// algForNID maps a cryptopro cipher NID to a CAPILite ALG_ID and block size.
// Only native modes are accepted; software-dispatch sentinels return an error.
func algForNID(nid int) (alg C.ALG_ID, blockSize int, err error) {
	switch nid {
	case NID_Kuznechik_ECB:
		return C.ALG_ID(C.CALG_GR3412_2015_K), 16, nil
	case NID_Magma_ECB:
		return C.ALG_ID(C.CALG_GR3412_2015_M), 8, nil
	}
	if IsSoftwareMode(nid) {
		return 0, 0, errors.New("cryptopro: cipher mode must be built in software on top of raw ECB (see pkg/gost3413)")
	}
	return 0, 0, errors.New("cryptopro: unknown cipher NID")
}

// modeForNID returns the CAPILite CRYPT_MODE_* constant that matches a
// native NID. Currently only ECB is native; CBC would land here too if
// we ever expose it.
func modeForNID(nid int) C.DWORD {
	switch nid {
	case NID_Kuznechik_ECB, NID_Magma_ECB:
		return C.CRYPT_MODE_ECB
	default:
		return C.CRYPT_MODE_ECB
	}
}

func (c *CipherCtx) initCommon(nid int, key []byte, encrypt bool) error {
	alg, blockSize, err := algForNID(nid)
	if err != nil {
		return err
	}
	if len(key) != 32 {
		return errors.New("cryptopro: GOST cipher key must be 32 bytes")
	}

	// Release any previously installed session key.
	if c.hKey != 0 {
		C.CryptDestroyKey(c.hKey)
		c.hKey = 0
	}

	// All symmetric ops use the 256-bit verify-context provider.
	c.hProv = globalProv256

	var hKey C.HCRYPTKEY
	if C.go_import_plaintext_key(c.hProv, alg,
		(*C.BYTE)(unsafe.Pointer(&key[0])), C.DWORD(len(key)), &hKey) == 0 {
		return cspError("CryptImportKey(PLAINTEXTKEYBLOB)")
	}

	// Set mode (ECB) and disable padding by default.
	if C.go_set_cipher_mode(hKey, modeForNID(nid)) == 0 {
		C.CryptDestroyKey(hKey)
		return cspError("CryptSetKeyParam(KP_MODE)")
	}
	if C.go_set_padding(hKey, 0) == 0 {
		C.CryptDestroyKey(hKey)
		return cspError("CryptSetKeyParam(KP_PADDING)")
	}

	c.hKey = hKey
	c.alg = alg
	c.blockSize = blockSize
	c.encrypt = encrypt

	// Cache key for potential re-initialisation.
	if cap(c.keyBuf) < len(key) {
		c.keyBuf = make([]byte, len(key))
	} else {
		c.keyBuf = c.keyBuf[:len(key)]
	}
	copy(c.keyBuf, key)
	return nil
}

// InitEncrypt configures the context for encryption with the given NID,
// key and IV. For ECB mode pass iv=nil.
func (c *CipherCtx) InitEncrypt(nid int, key, iv []byte) error {
	if err := c.initCommon(nid, key, true); err != nil {
		return err
	}
	if len(iv) > 0 {
		if C.go_set_iv(c.hKey,
			(*C.BYTE)(unsafe.Pointer(&iv[0])), C.DWORD(len(iv))) == 0 {
			return cspError("CryptSetKeyParam(KP_IV)")
		}
	}
	return nil
}

// InitDecrypt configures the context for decryption.
func (c *CipherCtx) InitDecrypt(nid int, key, iv []byte) error {
	if err := c.initCommon(nid, key, false); err != nil {
		return err
	}
	if len(iv) > 0 {
		if C.go_set_iv(c.hKey,
			(*C.BYTE)(unsafe.Pointer(&iv[0])), C.DWORD(len(iv))) == 0 {
			return cspError("CryptSetKeyParam(KP_IV)")
		}
	}
	return nil
}

// Update feeds data through the cipher. For Kuznechik / Magma in ECB mode
// the caller must pass exactly block-aligned input (the constructors in
// pkg/gost3412 guarantee this).
func (c *CipherCtx) Update(in []byte) ([]byte, error) {
	if c.hKey == 0 {
		return nil, errors.New("cryptopro: cipher context not initialised")
	}

	// CryptEncrypt / CryptDecrypt operate in-place: we copy input into a
	// buffer sized with one extra block for padding growth, then hand
	// the resulting length back.
	bufLen := len(in) + c.blockSize
	buf := make([]byte, bufLen)
	copy(buf, in)

	var outLen C.DWORD
	if c.encrypt {
		if C.go_encrypt(c.hKey, 0,
			(*C.BYTE)(unsafe.Pointer(&buf[0])), C.DWORD(len(in)),
			C.DWORD(bufLen), &outLen) == 0 {
			return nil, cspError("CryptEncrypt")
		}
	} else {
		if C.go_decrypt(c.hKey, 0,
			(*C.BYTE)(unsafe.Pointer(&buf[0])), C.DWORD(len(in)),
			&outLen) == 0 {
			return nil, cspError("CryptDecrypt")
		}
	}
	return buf[:int(outLen)], nil
}

// Final flushes the cipher. For the Update/Final split we pass an empty
// chunk with Final=TRUE so the CSP can emit any tail bytes / verify padding.
func (c *CipherCtx) Final() ([]byte, error) {
	if c.hKey == 0 {
		return nil, errors.New("cryptopro: cipher context not initialised")
	}
	buf := make([]byte, c.blockSize)
	var outLen C.DWORD
	if c.encrypt {
		if C.go_encrypt(c.hKey, 1,
			(*C.BYTE)(unsafe.Pointer(&buf[0])), 0,
			C.DWORD(len(buf)), &outLen) == 0 {
			return nil, cspError("CryptEncrypt(final)")
		}
	} else {
		if C.go_decrypt(c.hKey, 1,
			(*C.BYTE)(unsafe.Pointer(&buf[0])), 0,
			&outLen) == 0 {
			return nil, cspError("CryptDecrypt(final)")
		}
	}
	return buf[:int(outLen)], nil
}

// SetPadding enables (1) or disables (0) PKCS#7 padding on the context.
// pkg/gost3412 and pkg/gost3413 call this with 0 for exact-block operation.
func (c *CipherCtx) SetPadding(enable int) error {
	if c.hKey == 0 {
		return errors.New("cryptopro: cipher context not initialised")
	}
	if C.go_set_padding(c.hKey, C.int(enable)) == 0 {
		return cspError("CryptSetKeyParam(KP_PADDING)")
	}
	return nil
}

// SetAAD is retained as a no-op on the native backend: AEAD modes (MGM) are
// implemented entirely in software by pkg/gost3413 on top of the raw block
// cipher. Kept for API symmetry with the old openssl.CipherCtx interface.
func (c *CipherCtx) SetAAD(_ []byte) error {
	return errors.New("cryptopro: AEAD AAD not supported on native cipher ctx — use pkg/gost3413 MGM")
}

// GetTag / SetTag share the same rationale as SetAAD.
func (c *CipherCtx) GetTag(_ int) ([]byte, error) {
	return nil, errors.New("cryptopro: AEAD tag not supported on native cipher ctx")
}

func (c *CipherCtx) SetTag(_ []byte) error {
	return errors.New("cryptopro: AEAD tag not supported on native cipher ctx")
}

// Close releases the underlying HCRYPTKEY and wipes any cached key bytes.
// Safe to call multiple times.
func (c *CipherCtx) Close() {
	if c == nil {
		return
	}
	if c.hKey != 0 {
		C.CryptDestroyKey(c.hKey)
		c.hKey = 0
	}
	if len(c.keyBuf) > 0 {
		CleanseBytes(c.keyBuf)
		c.keyBuf = nil
	}
	runtime.SetFinalizer(c, nil)
}

func (c *CipherCtx) finalize() {
	if c.hKey != 0 {
		C.CryptDestroyKey(c.hKey)
		c.hKey = 0
	}
	if len(c.keyBuf) > 0 {
		CleanseBytes(c.keyBuf)
	}
}
