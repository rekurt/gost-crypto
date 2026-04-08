package openssl

/*
#include <openssl/cmac.h>
#include <openssl/evp.h>

// Wrapper for EVP_get_cipherbynid which may be a macro.
static const EVP_CIPHER *go_cmac_get_cipher(int nid) {
	return EVP_get_cipherbynid(nid);
}
*/
import "C"
import (
	"unsafe"
)

// CMAC computes CMAC (OMAC1) using the specified block cipher NID.
// The NID should refer to a CBC-mode cipher (e.g., kuznyechik-cbc, magma-cbc).
func CMAC(cipherNID int, key, message []byte) ([]byte, error) {
	if err := Init(); err != nil {
		return nil, err
	}

	ciph := C.go_cmac_get_cipher(C.int(cipherNID))
	if ciph == nil {
		return nil, fmtSSLError("EVP_get_cipherbynid(CMAC)")
	}

	ctx := C.CMAC_CTX_new()
	if ctx == nil {
		return nil, fmtSSLError("CMAC_CTX_new")
	}
	defer C.CMAC_CTX_free(ctx)

	if C.CMAC_Init(ctx,
		unsafe.Pointer(&key[0]), C.size_t(len(key)),
		ciph, gostEngine) != 1 {
		return nil, fmtSSLError("CMAC_Init")
	}

	if len(message) > 0 {
		if C.CMAC_Update(ctx, unsafe.Pointer(&message[0]), C.size_t(len(message))) != 1 {
			return nil, fmtSSLError("CMAC_Update")
		}
	}

	// Get the MAC output. Block size is the maximum possible output.
	var outLen C.size_t
	// First call to get the length.
	if C.CMAC_Final(ctx, nil, &outLen) != 1 {
		return nil, fmtSSLError("CMAC_Final(size)")
	}

	out := make([]byte, outLen)
	if C.CMAC_Final(ctx, (*C.uchar)(unsafe.Pointer(&out[0])), &outLen) != 1 {
		return nil, fmtSSLError("CMAC_Final")
	}

	return out[:outLen], nil
}
