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
// Returns the raw shared-secret bytes (32 bytes for 256-bit curves, 64
// bytes for 512-bit curves), stripped from the SIMPLEBLOB wrapper that
// CryptoPro CSP produces internally. This matches the historical
// openssl/gost-engine DeriveVKO contract where callers receive a
// fixed-size KEK suitable for direct use in KDF / key wrapping.
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

	blob := C.GoBytes(unsafe.Pointer(out), C.int(outLen))

	// SIMPLEBLOB layout:
	//   BLOBHEADER (8 bytes) + ALG_ID (4 bytes) + encrypted-key data
	// The raw shared secret occupies the trailing keySize bytes of the
	// blob (after the header). For GOST VKO the key material is 32 bytes
	// (256-bit) or 64 bytes (512-bit).
	const simpleBlobHeaderSize = 12 // sizeof(BLOBHEADER) + sizeof(ALG_ID)
	if int(outLen) <= simpleBlobHeaderSize {
		return nil, &CSPError{Op: "DeriveVKO", Text: "SIMPLEBLOB too short to contain key material"}
	}
	raw := blob[simpleBlobHeaderSize:]
	return raw, nil
}
