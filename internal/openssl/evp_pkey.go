package openssl

/*
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <stdlib.h>
#include <string.h>

// go_generate_gost_key generates a GOST key pair using EVP_PKEY_keygen.
// signNID selects gost2012_256 or gost2012_512; curveOID sets the paramset.
static EVP_PKEY *go_generate_gost_key(ENGINE *eng, int sign_nid,
                                       const char *curve_oid) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(sign_nid, eng);
    if (!ctx) return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    // Set the curve parameter set via ctrl_str.
    if (EVP_PKEY_CTX_ctrl_str(ctx, "paramset", curve_oid) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// go_evp_pkey_sign signs a digest using EVP_PKEY_sign (low-level, no hashing).
// Returns signature length in *out_len; caller must provide sig buffer of *out_len bytes.
// On first call with sig==NULL, returns required size in *out_len.
static int go_evp_pkey_sign(EVP_PKEY *pkey, ENGINE *eng,
                             const unsigned char *digest, size_t digest_len,
                             unsigned char *sig, size_t *sig_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, eng);
    if (!ctx) return -1;

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -2;
    }

    int rc = EVP_PKEY_sign(ctx, sig, sig_len, digest, digest_len);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

// go_evp_pkey_verify verifies a signature over a digest.
// Returns 1 on success, 0 on invalid signature, <0 on error.
static int go_evp_pkey_verify(EVP_PKEY *pkey, ENGINE *eng,
                               const unsigned char *digest, size_t digest_len,
                               const unsigned char *sig, size_t sig_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, eng);
    if (!ctx) return -1;

    if (EVP_PKEY_verify_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -2;
    }

    int rc = EVP_PKEY_verify(ctx, sig, sig_len, digest, digest_len);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

// go_extract_raw_pub_key extracts the raw public key bytes.
// Returns 0 on success, -1 on error. Sets *out_len.
// First call with out==NULL to get length, then call again with buffer.
static int go_extract_raw_pub_key(EVP_PKEY *pkey,
                                   unsigned char *out, size_t *out_len) {
    if (EVP_PKEY_get_raw_public_key(pkey, out, out_len) != 1) {
        return -1;
    }
    return 0;
}

// go_extract_raw_priv_key extracts the raw private key bytes.
// Returns 0 on success, -1 on error.
static int go_extract_raw_priv_key(EVP_PKEY *pkey,
                                    unsigned char *out, size_t *out_len) {
    if (EVP_PKEY_get_raw_private_key(pkey, out, out_len) != 1) {
        return -1;
    }
    return 0;
}

// go_i2d_private_key serializes the private key to DER into a C-allocated buffer.
// Caller must free *out with free(). Returns DER length, or <=0 on error.
static int go_i2d_private_key(EVP_PKEY *pkey, unsigned char **out) {
    int len = i2d_PrivateKey(pkey, NULL);
    if (len <= 0) return len;
    *out = (unsigned char *)malloc(len);
    if (!*out) return -1;
    unsigned char *p = *out;
    int len2 = i2d_PrivateKey(pkey, &p);
    if (len2 <= 0) {
        OPENSSL_cleanse(*out, len);
        free(*out);
        *out = NULL;
    }
    return len2;
}

// go_i2d_pubkey serializes the public key to SubjectPublicKeyInfo DER
// into a C-allocated buffer.
// Caller must free *out with free(). Returns DER length, or <=0 on error.
static int go_i2d_pubkey(EVP_PKEY *pkey, unsigned char **out) {
    int len = i2d_PUBKEY(pkey, NULL);
    if (len <= 0) return len;
    *out = (unsigned char *)malloc(len);
    if (!*out) return -1;
    unsigned char *p = *out;
    int len2 = i2d_PUBKEY(pkey, &p);
    if (len2 <= 0) {
        free(*out);
        *out = NULL;
    }
    return len2;
}

// go_load_gost_privkey loads a GOST private key from raw bytes.
// Strategy: generate a throwaway key to obtain a valid DER template,
// then patch the raw private key bytes and deserialize.
// Returns NULL on error.
static EVP_PKEY *go_load_gost_privkey(ENGINE *eng, int sign_nid,
                                       const char *curve_oid,
                                       const unsigned char *raw, int raw_len) {
    // Step 1: generate a throwaway key to get a valid DER structure.
    EVP_PKEY *tmpl = go_generate_gost_key(eng, sign_nid, curve_oid);
    if (!tmpl) return NULL;

    // Step 2: serialize to DER.
    unsigned char *der = NULL;
    int der_len = go_i2d_private_key(tmpl, &der);
    EVP_PKEY_free(tmpl);
    if (der_len <= 0 || !der) return NULL;
    if (der_len < raw_len) {
        OPENSSL_cleanse(der, der_len);
        free(der);
        return NULL;
    }

    // Step 3: patch the raw key bytes at the end of the DER
    // (mirrors the extraction logic in ExtractRawPrivKey).
    memcpy(der + der_len - raw_len, raw, raw_len);

    // Step 4: deserialize back.
    const unsigned char *p = der;
    EVP_PKEY *pkey = d2i_PrivateKey(sign_nid, NULL, &p, der_len);
    OPENSSL_cleanse(der, der_len);
    free(der);
    return pkey;
}

// go_evp_pkey_param_check runs EVP_PKEY_param_check on the key.
static int go_evp_pkey_param_check(EVP_PKEY *pkey, ENGINE *eng) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, eng);
    if (!ctx) return -1;
    int rc = EVP_PKEY_param_check(ctx);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

// go_evp_pkey_public_check runs EVP_PKEY_public_check on the key.
static int go_evp_pkey_public_check(EVP_PKEY *pkey, ENGINE *eng) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, eng);
    if (!ctx) return -1;
    int rc = EVP_PKEY_public_check(ctx);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}
*/
import "C"
import (
	"unsafe"
)

// LoadGOSTPrivKey creates a GOST R 34.10-2012 key from raw private key bytes.
// The raw bytes are big-endian and must be exactly keySize bytes long.
func LoadGOSTPrivKey(signNID int, curveOID string, raw []byte) (*C.EVP_PKEY, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, &OpenSSLError{Op: "LoadGOSTPrivKey", Text: "empty raw key"}
	}

	cOID := C.CString(curveOID)
	defer C.free(unsafe.Pointer(cOID))

	pkey := C.go_load_gost_privkey(gostEngine, C.int(signNID), cOID,
		(*C.uchar)(unsafe.Pointer(&raw[0])), C.int(len(raw)))
	if pkey == nil {
		return nil, fmtSSLError("LoadGOSTPrivKey")
	}
	return pkey, nil
}

// GenerateGOSTKey generates a new GOST R 34.10-2012 key pair.
// signNID must be NID_GostR3410_2012_256 or _512.
// curveOID is one of the CurveOIDs entries (e.g. "1.2.643.7.1.2.1.1.1").
func GenerateGOSTKey(signNID int, curveOID string) (*C.EVP_PKEY, error) {
	if err := Init(); err != nil {
		return nil, err
	}

	cOID := C.CString(curveOID)
	defer C.free(unsafe.Pointer(cOID))

	pkey := C.go_generate_gost_key(gostEngine, C.int(signNID), cOID)
	if pkey == nil {
		return nil, fmtSSLError("GenerateGOSTKey")
	}
	return pkey, nil
}

// ExtractRawPrivKey extracts the raw private key bytes from an EVP_PKEY.
// keySize is the expected key length (32 for 256-bit, 64 for 512-bit).
//
// NOTE: gost-engine may not support EVP_PKEY_get_raw_private_key.
// If that fails, this function falls back to i2d_PrivateKey ASN.1 extraction.
func ExtractRawPrivKey(pkey *C.EVP_PKEY, keySize int) ([]byte, error) {
	// Try the standard raw API first.
	var sz C.size_t
	if C.go_extract_raw_priv_key(pkey, nil, &sz) == 0 && int(sz) > 0 {
		buf := make([]byte, sz)
		if C.go_extract_raw_priv_key(pkey, (*C.uchar)(unsafe.Pointer(&buf[0])), &sz) == 0 {
			return buf[:sz], nil
		}
	}
	drainSSLErrors()

	// Fallback: extract via i2d_PrivateKey (DER) and parse the raw key
	// from the ASN.1 OCTET STRING at the end.
	var cDer *C.uchar
	derLen := C.go_i2d_private_key(pkey, &cDer)
	if derLen <= 0 || cDer == nil {
		return nil, fmtSSLError("i2d_PrivateKey")
	}
	defer C.free(unsafe.Pointer(cDer))

	// Copy the DER into Go memory for parsing.
	der := C.GoBytes(unsafe.Pointer(cDer), derLen)

	// KNOWN LIMITATION: This heuristic assumes the raw key is the last keySize
	// bytes of the DER encoding. This is empirically correct for gost-engine v3.x
	// but may break with different ASN.1 structures. Round-trip tests (generate →
	// extract → sign → verify) in evp_pkey_test.go validate this assumption.
	if int(derLen) < keySize {
		CleanseBytes(der)
		return nil, &OpenSSLError{
			Op:   "ExtractRawPrivKey",
			Text: "DER too short for expected key size",
		}
	}
	raw := make([]byte, keySize)
	copy(raw, der[int(derLen)-keySize:])
	CleanseBytes(der)

	allZero := true
	for _, b := range raw {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, &OpenSSLError{Op: "ExtractRawPrivKey", Text: "extracted key is all zeros — DER parsing may have failed"}
	}

	return raw, nil
}

// ExtractRawPubKey extracts the raw public key bytes from an EVP_PKEY.
// Returns the SubjectPublicKeyInfo DER encoding. The raw X||Y point can be
// extracted from the BIT STRING at the end of the SPKI structure.
func ExtractRawPubKey(pkey *C.EVP_PKEY) ([]byte, error) {
	// Try EVP_PKEY_get_raw_public_key first.
	var sz C.size_t
	if C.go_extract_raw_pub_key(pkey, nil, &sz) == 0 && int(sz) > 0 {
		buf := make([]byte, sz)
		if C.go_extract_raw_pub_key(pkey, (*C.uchar)(unsafe.Pointer(&buf[0])), &sz) == 0 {
			return buf[:sz], nil
		}
	}
	drainSSLErrors()

	// Fallback: extract via i2d_PUBKEY (SubjectPublicKeyInfo).
	var cDer *C.uchar
	derLen := C.go_i2d_pubkey(pkey, &cDer)
	if derLen <= 0 || cDer == nil {
		return nil, fmtSSLError("i2d_PUBKEY")
	}
	defer C.free(unsafe.Pointer(cDer))

	return C.GoBytes(unsafe.Pointer(cDer), derLen), nil
}

// SignDigest signs a pre-computed digest using EVP_PKEY_sign.
// The digest must already be the correct size for the key type.
func SignDigest(pkey *C.EVP_PKEY, digest []byte) ([]byte, error) {
	if len(digest) == 0 {
		return nil, &OpenSSLError{Op: "SignDigest", Text: "empty digest"}
	}
	if err := Init(); err != nil {
		return nil, err
	}

	// First call: get required signature size.
	var sigLen C.size_t
	rc := C.go_evp_pkey_sign(pkey, gostEngine,
		(*C.uchar)(unsafe.Pointer(&digest[0])), C.size_t(len(digest)),
		nil, &sigLen)
	if rc <= 0 {
		return nil, fmtSSLError("EVP_PKEY_sign(size)")
	}

	sig := make([]byte, sigLen)
	rc = C.go_evp_pkey_sign(pkey, gostEngine,
		(*C.uchar)(unsafe.Pointer(&digest[0])), C.size_t(len(digest)),
		(*C.uchar)(unsafe.Pointer(&sig[0])), &sigLen)
	if rc <= 0 {
		return nil, fmtSSLError("EVP_PKEY_sign")
	}
	return sig[:sigLen], nil
}

// VerifyDigest verifies a signature over a pre-computed digest.
// Returns (true, nil) if valid, (false, nil) if invalid, (false, err) on error.
func VerifyDigest(pkey *C.EVP_PKEY, digest, sig []byte) (bool, error) {
	if len(digest) == 0 {
		return false, &OpenSSLError{Op: "VerifyDigest", Text: "empty digest"}
	}
	if len(sig) == 0 {
		return false, &OpenSSLError{Op: "VerifyDigest", Text: "empty signature"}
	}
	if err := Init(); err != nil {
		return false, err
	}

	rc := C.go_evp_pkey_verify(pkey, gostEngine,
		(*C.uchar)(unsafe.Pointer(&digest[0])), C.size_t(len(digest)),
		(*C.uchar)(unsafe.Pointer(&sig[0])), C.size_t(len(sig)))

	switch rc {
	case 1:
		return true, nil
	case 0:
		// Invalid signature — not an error condition.
		drainSSLErrors()
		return false, nil
	default:
		return false, fmtSSLError("EVP_PKEY_verify")
	}
}

// FreeKey releases an EVP_PKEY.
func FreeKey(pkey *C.EVP_PKEY) {
	if pkey != nil {
		C.EVP_PKEY_free(pkey)
	}
}

// ValidatePublicKey runs both EVP_PKEY_param_check and EVP_PKEY_public_check.
func ValidatePublicKey(pkey *C.EVP_PKEY) error {
	if err := Init(); err != nil {
		return err
	}

	if rc := C.go_evp_pkey_param_check(pkey, gostEngine); rc != 1 {
		return fmtSSLError("EVP_PKEY_param_check")
	}
	if rc := C.go_evp_pkey_public_check(pkey, gostEngine); rc != 1 {
		return fmtSSLError("EVP_PKEY_public_check")
	}
	return nil
}
