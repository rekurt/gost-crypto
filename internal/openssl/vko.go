package openssl

/*
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <stdlib.h>
#include <string.h>

// go_evp_pkey_derive performs GOST VKO key agreement (ECDH with UKM).
//
// Two-phase usage:
//   Phase 1 (size query): pass out==NULL, *out_len receives required buffer size.
//   Phase 2 (compute):    pass out buffer of *out_len bytes.
//
// UKM (User Keying Material) is set via EVP_PKEY_CTX_ctrl when provided.
// Returns 1 on success, negative values indicate which step failed.
static int go_evp_pkey_derive(EVP_PKEY *priv_pkey, EVP_PKEY *peer_pkey,
                               ENGINE *eng,
                               const unsigned char *ukm, int ukm_len,
                               unsigned char *out, size_t *out_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_pkey, eng);
    if (!ctx) return -1;

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -2;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peer_pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -3;
    }

    // Set UKM via EVP_PKEY_CTX_ctrl (EVP_PKEY_CTRL_SET_IV = 8).
    // gost-engine uses this control to set the User Keying Material.
    if (ukm && ukm_len > 0) {
        if (EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_DERIVE,
                              EVP_PKEY_CTRL_SET_IV, ukm_len,
                              (void*)ukm) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return -4;
        }
    }

    int rc = EVP_PKEY_derive(ctx, out, out_len);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// DeriveVKO performs GOST VKO key agreement between a private key and a
// peer's public key, optionally incorporating User Keying Material (UKM).
//
// This corresponds to the VKO function defined in GOST R 34.10-2012
// (Appendix B). The shared secret length depends on the curve:
// 64 bytes for 256-bit curves, 128 bytes for 512-bit curves.
//
// If ukm is nil or empty, the derivation proceeds without UKM.
func DeriveVKO(privHandle, peerPubHandle *KeyHandle, ukm []byte) ([]byte, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	if privHandle.IsNil() {
		return nil, fmt.Errorf("openssl: DeriveVKO: private key handle is nil")
	}
	if peerPubHandle.IsNil() {
		return nil, fmt.Errorf("openssl: DeriveVKO: peer public key handle is nil")
	}

	var ukmPtr *C.uchar
	ukmLen := C.int(0)
	if len(ukm) > 0 {
		ukmPtr = (*C.uchar)(unsafe.Pointer(&ukm[0]))
		ukmLen = C.int(len(ukm))
	}

	// Phase 1: query output size.
	var outLen C.size_t
	rc := C.go_evp_pkey_derive(
		privHandle.pkey, peerPubHandle.pkey, gostEngine,
		ukmPtr, ukmLen,
		nil, &outLen,
	)
	if rc <= 0 {
		return nil, fmtSSLError(fmt.Sprintf("DeriveVKO(size, rc=%d)", int(rc)))
	}

	if outLen == 0 {
		return nil, fmt.Errorf("openssl: DeriveVKO: derived key length is zero")
	}

	// Phase 2: compute the shared secret.
	out := make([]byte, outLen)
	rc = C.go_evp_pkey_derive(
		privHandle.pkey, peerPubHandle.pkey, gostEngine,
		ukmPtr, ukmLen,
		(*C.uchar)(unsafe.Pointer(&out[0])), &outLen,
	)
	if rc <= 0 {
		return nil, fmtSSLError(fmt.Sprintf("DeriveVKO(derive, rc=%d)", int(rc)))
	}

	return out[:outLen], nil
}

