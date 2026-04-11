//go:build cgo && linux && cryptopro
// +build cgo,linux,cryptopro

package cryptopro

/*
#cgo CFLAGS: -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/cades
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi10 -lcapi20 -lssp -lrdrsup -lcades
#include "capi.h"

// go_imit_compute computes a GOST IMIT (MAC) over `msg` using a session key
// held in HCRYPTKEY form. CAPILite dispatches IMIT via a hash object whose
// algorithm is one of CALG_GR3412_2015_K_IMIT / CALG_GR3412_2015_M_IMIT /
// CALG_G28147_IMIT. The hash takes a session key via CryptSetHashParam
// (HP_HMAC_INFO in the HMAC case, or HP_HASHSTARTVECT / the CSP's IMIT
// convention for MAC algorithms).
//
// On CryptoPro CSP 5.0+ the canonical recipe is:
//   1. CryptCreateHash(prov, imit_alg_id, session_key, 0, &hash)
//   2. CryptHashData(hash, msg, msg_len, 0)
//   3. CryptGetHashParam(hash, HP_HASHVAL, out, &out_len, 0)
//
// The session key must already be imported via CryptImportKey /
// go_import_plaintext_key, because CryptCreateHash requires the key handle
// as its third argument for MAC algorithms.
static BOOL go_imit_compute(HCRYPTPROV prov, HCRYPTKEY session_key,
                            ALG_ID imit_alg,
                            const BYTE *msg, DWORD msg_len,
                            BYTE *out, DWORD *out_len) {
    HCRYPTHASH hash = 0;
    if (!CryptCreateHash(prov, imit_alg, session_key, 0, &hash)) {
        return FALSE;
    }
    if (msg_len > 0) {
        if (!CryptHashData(hash, msg, msg_len, 0)) {
            CryptDestroyHash(hash);
            return FALSE;
        }
    }
    if (!CryptGetHashParam(hash, HP_HASHVAL, out, out_len, 0)) {
        CryptDestroyHash(hash);
        return FALSE;
    }
    CryptDestroyHash(hash);
    return TRUE;
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

// CMAC computes a GOST IMIT (OMAC1 / CMAC) over `message` using the given
// 32-byte session key. The `cipherNID` selects which IMIT variant to use.
// Accepted NIDs and their tag sizes:
//
//	NID_Kuznechik_CBC → Kuznechik-IMIT, 16-byte tag
//	NID_Magma_CBC     → Magma-IMIT, 8-byte tag
//
// The CBC NIDs are accepted for backward compatibility with the old
// openssl backend, which passed CBC NIDs to EVP_MAC / CMAC_Init.
func CMAC(cipherNID int, key, message []byte) ([]byte, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("cryptopro: CMAC key must be 32 bytes")
	}

	var (
		baseAlg C.ALG_ID
		imitAlg C.ALG_ID
		tagSize C.DWORD
	)
	switch cipherNID {
	case NID_Kuznechik_CBC, NID_Kuznechik_ECB, NID_Kuznechik_IMIT:
		baseAlg = C.ALG_ID(C.CALG_GR3412_2015_K)
		imitAlg = C.ALG_ID(C.CALG_GR3412_2015_K_IMIT)
		tagSize = 16
	case NID_Magma_CBC, NID_Magma_ECB, NID_Magma_IMIT:
		baseAlg = C.ALG_ID(C.CALG_GR3412_2015_M)
		imitAlg = C.ALG_ID(C.CALG_GR3412_2015_M_IMIT)
		tagSize = 8
	default:
		return nil, errors.New("cryptopro: CMAC: unsupported cipher NID")
	}

	// Import session key as a plaintext blob attached to the global
	// 256-bit verify context.
	var sessionKey C.HCRYPTKEY
	if C.go_import_plaintext_key(globalProv256, baseAlg,
		(*C.BYTE)(unsafe.Pointer(&key[0])), C.DWORD(len(key)),
		&sessionKey) == 0 {
		return nil, cspError("CryptImportKey(CMAC session key)")
	}
	defer C.CryptDestroyKey(sessionKey)

	out := make([]byte, int(tagSize))
	actualLen := tagSize
	var msgPtr *C.BYTE
	if len(message) > 0 {
		msgPtr = (*C.BYTE)(unsafe.Pointer(&message[0]))
	}
	if C.go_imit_compute(globalProv256, sessionKey, imitAlg,
		msgPtr, C.DWORD(len(message)),
		(*C.BYTE)(unsafe.Pointer(&out[0])), &actualLen) == 0 {
		return nil, cspError("CryptGetHashParam(IMIT HP_HASHVAL)")
	}
	return out[:int(actualLen)], nil
}
