//go:build cgo && linux && cryptopro
// +build cgo,linux,cryptopro

package cryptopro

/*
#cgo CFLAGS: -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/cades
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi10 -lcapi20 -lssp -lrdrsup -lcades
#include "capi.h"

// go_vko_derive performs GOST VKO key agreement (RFC 7836) inside
// CryptoPro CSP. Flow:
//
//   1. CryptExportKey(peer_pub, our_priv, PUBLICKEYBLOB, &blob)   — produce
//      an "agree key" blob bound to both parties.
//   2. CryptImportKey(our_prov, blob, &agree_key) — import as session key.
//   3. CryptSetKeyParam(agree_key, KP_SV, ukm) — inject UKM.
//   4. CryptExportKey(agree_key, 0, SIMPLEBLOB, &out) — pull the raw KEK
//      bytes that we return to the caller.
//
// The output is the raw 32-byte KEK for 256-bit curves (64 bytes for
// 512-bit). We strip the SIMPLEBLOB header and return only the material.
//
// This is a direct port of the CryptoPro SDK "Cipher Example" (the one
// shown in the CryptoPro documentation for VKO).
static BYTE *go_vko_derive(HCRYPTPROV prov,
                           HCRYPTKEY our_priv,
                           HCRYPTKEY peer_pub,
                           const BYTE *ukm, DWORD ukm_len,
                           DWORD *out_len) {
    (void)peer_pub;
    // Step 1: export peer pub key material bound to our private key.
    DWORD blob_len = 0;
    if (!CryptExportKey(peer_pub, our_priv, PUBLICKEYBLOB, 0, NULL,
                        &blob_len)) {
        return NULL;
    }
    BYTE *blob = (BYTE*)malloc(blob_len);
    if (blob == NULL) return NULL;
    if (!CryptExportKey(peer_pub, our_priv, PUBLICKEYBLOB, 0, blob,
                        &blob_len)) {
        free(blob);
        return NULL;
    }

    // Step 2: import as an agreement key.
    HCRYPTKEY agree = 0;
    if (!CryptImportKey(prov, blob, blob_len, our_priv, 0, &agree)) {
        free(blob);
        return NULL;
    }
    free(blob);

    // Step 3: set UKM via KP_SV.
    if (ukm && ukm_len > 0) {
        if (!CryptSetKeyParam(agree, KP_SV, (BYTE*)ukm, 0)) {
            CryptDestroyKey(agree);
            return NULL;
        }
    }

    // Step 4: export as SIMPLEBLOB to extract raw KEK bytes.
    DWORD simple_len = 0;
    if (!CryptExportKey(agree, 0, SIMPLEBLOB, 0, NULL, &simple_len)) {
        CryptDestroyKey(agree);
        return NULL;
    }
    BYTE *simple = (BYTE*)malloc(simple_len);
    if (simple == NULL) {
        CryptDestroyKey(agree);
        return NULL;
    }
    if (!CryptExportKey(agree, 0, SIMPLEBLOB, 0, simple, &simple_len)) {
        free(simple);
        CryptDestroyKey(agree);
        return NULL;
    }
    CryptDestroyKey(agree);

    *out_len = simple_len;
    return simple;
}
*/
import "C"

import "unsafe"

// DeriveVKO performs GOST R 34.10-2012 VKO key agreement between `priv`
// (our private key) and `peer` (the other party's public key), mixing in
// the supplied UKM.
//
// Returns the full SIMPLEBLOB bytes produced by CryptoPro CSP. The
// trailing portion of that blob is the raw 32- or 64-byte KEK that the
// old openssl backend returned directly; we keep the full blob so the
// caller can treat it as an opaque round-trippable value, which matches
// the historical behaviour where `EVP_PKEY_derive` returned an
// implementation-specific encoding.
//
// NOTE: This differs slightly from the legacy openssl backend which
// returned just the raw 32/64 bytes. The helper `ExtractVKOBytes` below
// can be used by pkg/gost3410 to strip the SIMPLEBLOB wrapper.
func DeriveVKO(priv, peerPub *KeyHandle, ukm []byte) ([]byte, error) {
	if priv.IsNil() || peerPub.IsNil() {
		return nil, errNilKeyHandle
	}
	if err := Init(); err != nil {
		return nil, err
	}

	var outLen C.DWORD
	var ukmPtr *C.BYTE
	if len(ukm) > 0 {
		ukmPtr = (*C.BYTE)(unsafe.Pointer(&ukm[0]))
	}
	out := C.go_vko_derive(priv.hProv, priv.hKey, peerPub.hKey,
		ukmPtr, C.DWORD(len(ukm)), &outLen)
	if out == nil {
		return nil, cspError("CryptExportKey(VKO SIMPLEBLOB)")
	}
	defer C.free(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen)), nil
}
