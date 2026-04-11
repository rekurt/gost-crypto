//go:build cgo && linux && cryptopro
// +build cgo,linux,cryptopro

package cryptopro

/*
#cgo CFLAGS: -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/cades
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi10 -lcapi20 -lssp -lrdrsup -lcades
#include "capi.h"

// go_hash_oneshot computes a Streebog digest in a single call. The caller
// is responsible for sizing `out` to 32 (256-bit) or 64 (512-bit) bytes.
static BOOL go_hash_oneshot(HCRYPTPROV prov, ALG_ID alg,
                            const BYTE *data, DWORD data_len,
                            BYTE *out, DWORD out_len) {
    HCRYPTHASH hash = 0;
    if (!CryptCreateHash(prov, alg, 0, 0, &hash)) {
        return FALSE;
    }
    if (data_len > 0) {
        if (!CryptHashData(hash, data, data_len, 0)) {
            CryptDestroyHash(hash);
            return FALSE;
        }
    }
    DWORD sz = out_len;
    if (!CryptGetHashParam(hash, HP_HASHVAL, out, &sz, 0)) {
        CryptDestroyHash(hash);
        return FALSE;
    }
    CryptDestroyHash(hash);
    return TRUE;
}
*/
import "C"

import (
	"unsafe"
)

// HashBytes computes a one-shot Streebog hash via CryptCreateHash /
// CryptHashData / CryptGetHashParam(HP_HASHVAL). This is the CryptoPro
// CSP equivalent of the former openssl.HashBytes().
//
// The NID must be NID_Streebog256 or NID_Streebog512.
func HashBytes(nid int, data []byte) ([]byte, error) {
	if err := Init(); err != nil {
		return nil, err
	}

	var outLen int
	switch nid {
	case NID_Streebog256:
		outLen = 32
	case NID_Streebog512:
		outLen = 64
	default:
		return nil, &CSPError{Op: "HashBytes", Text: "unsupported hash NID"}
	}

	out := make([]byte, outLen)
	var dataPtr *C.BYTE
	if len(data) > 0 {
		dataPtr = (*C.BYTE)(unsafe.Pointer(&data[0]))
	}

	// Streebog-512 requires the 512-bit provider; Streebog-256 works with
	// either, but we match to avoid the CSP complaining about algorithm
	// availability.
	prov := globalProv256
	if nid == NID_Streebog512 {
		prov = globalProv512
	}

	if C.go_hash_oneshot(prov, C.ALG_ID(nid),
		dataPtr, C.DWORD(len(data)),
		(*C.BYTE)(unsafe.Pointer(&out[0])), C.DWORD(outLen)) == 0 {
		return nil, cspError("CryptGetHashParam(HP_HASHVAL)")
	}
	return out, nil
}
