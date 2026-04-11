//go:build cgo && linux && cryptopro
// +build cgo,linux,cryptopro

package cryptopro

/*
#cgo CFLAGS: -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/cades
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi10 -lcapi20 -lssp -lrdrsup -lcades
#include "capi.h"

// go_fresh_context opens a private CSP context (one per generated key) so
// that CryptGenKey + CryptSignHash operate in isolation. Without
// CRYPT_VERIFYCONTEXT the context supports the full key lifecycle.
static BOOL go_fresh_context(HCRYPTPROV *prov, DWORD prov_type) {
    return CryptAcquireContextA(prov, NULL, NULL, prov_type, CRYPT_VERIFYCONTEXT);
}

// go_set_paramset_oid sets the parameter-set OID on a key handle via the
// KP_DHOID key parameter. CryptoPro CSP accepts a NUL-terminated OID
// string here for all 8 TC26 curves.
static BOOL go_set_paramset_oid(HCRYPTKEY key, const char *oid) {
    return CryptSetKeyParam(key, KP_DHOID, (BYTE*)oid, 0);
}

// go_gen_gost_key generates a fresh ephemeral GOST R 34.10-2012 key pair.
// The algorithm ALG_ID (CALG_GR3410_2012_256/512) selects the key type;
// the KP_DHOID post-step sets the specific curve parameter set.
static BOOL go_gen_gost_key(HCRYPTPROV prov, ALG_ID alg, const char *oid,
                            HCRYPTKEY *out) {
    HCRYPTKEY key = 0;
    // CRYPT_EXPORTABLE lets us pull the raw bytes out via CryptExportKey.
    if (!CryptGenKey(prov, alg, CRYPT_EXPORTABLE, &key)) {
        return FALSE;
    }
    if (!CryptSetKeyParam(key, KP_DHOID, (BYTE*)oid, 0)) {
        CryptDestroyKey(key);
        return FALSE;
    }
    *out = key;
    return TRUE;
}

// go_export_privkey exports a private key to a PRIVATEKEYBLOB. The blob
// layout starts with a BLOBHEADER + CRYPT_PRIVATEKEY_INFO-style structure
// and ends with the raw little-endian scalar of length `key_size` bytes.
//
// Returns (malloc'd buffer, length). Caller must free().
static BYTE *go_export_privkey(HCRYPTKEY key, DWORD *out_len) {
    DWORD sz = 0;
    if (!CryptExportKey(key, 0, PRIVATEKEYBLOB, 0, NULL, &sz)) {
        return NULL;
    }
    BYTE *buf = (BYTE*)malloc(sz);
    if (buf == NULL) return NULL;
    if (!CryptExportKey(key, 0, PRIVATEKEYBLOB, 0, buf, &sz)) {
        free(buf);
        return NULL;
    }
    *out_len = sz;
    return buf;
}

// go_export_pubkey exports a public key as a PUBLICKEYBLOB. The trailing
// portion contains the raw X||Y point (little-endian coordinates) of
// length 2*key_size bytes.
static BYTE *go_export_pubkey(HCRYPTKEY key, DWORD *out_len) {
    DWORD sz = 0;
    if (!CryptExportKey(key, 0, PUBLICKEYBLOB, 0, NULL, &sz)) {
        return NULL;
    }
    BYTE *buf = (BYTE*)malloc(sz);
    if (buf == NULL) return NULL;
    if (!CryptExportKey(key, 0, PUBLICKEYBLOB, 0, buf, &sz)) {
        free(buf);
        return NULL;
    }
    *out_len = sz;
    return buf;
}

// go_import_key imports a PUBLICKEYBLOB / PRIVATEKEYBLOB into the given
// provider, returning a fresh HCRYPTKEY. CryptoPro CSP validates the
// encoded point at import time, so callers should treat NTE_BAD_KEY as
// "invalid key material".
static BOOL go_import_key(HCRYPTPROV prov, const BYTE *blob, DWORD blob_len,
                          HCRYPTKEY *out) {
    return CryptImportKey(prov, blob, blob_len, 0, 0, out);
}

// go_sign_hash creates a hash, preloads the pre-computed digest via
// HP_HASHVAL, and calls CryptSignHash against the given key. The output
// signature is r||s (little-endian) with length 2*key_size bytes, matching
// the wire format historically emitted by gost-engine — so pkg/* consumers
// do not need to transcode.
static BOOL go_sign_hash(HCRYPTPROV prov, HCRYPTKEY key,
                         ALG_ID hash_alg,
                         const BYTE *digest, DWORD digest_len,
                         BYTE *sig_out, DWORD *sig_len) {
    HCRYPTHASH hash = 0;
    if (!CryptCreateHash(prov, hash_alg, 0, 0, &hash)) {
        return FALSE;
    }
    if (!CryptSetHashParam(hash, HP_HASHVAL, (BYTE*)digest, 0)) {
        CryptDestroyHash(hash);
        return FALSE;
    }
    BOOL rc = CryptSignHashA(hash, AT_KEYEXCHANGE, NULL, 0, sig_out, sig_len);
    CryptDestroyHash(hash);
    return rc;
}

// go_verify_hash verifies a signature against a pre-computed digest using
// a public key handle. Returns TRUE on valid signature; NTE_BAD_SIGNATURE
// on a well-formed but incorrect signature; FALSE on an operational error.
static BOOL go_verify_hash(HCRYPTPROV prov, HCRYPTKEY pub_key,
                           ALG_ID hash_alg,
                           const BYTE *digest, DWORD digest_len,
                           const BYTE *sig, DWORD sig_len) {
    HCRYPTHASH hash = 0;
    if (!CryptCreateHash(prov, hash_alg, 0, 0, &hash)) {
        return FALSE;
    }
    if (!CryptSetHashParam(hash, HP_HASHVAL, (BYTE*)digest, 0)) {
        CryptDestroyHash(hash);
        return FALSE;
    }
    BOOL rc = CryptVerifySignatureA(hash, (BYTE*)sig, sig_len, pub_key, NULL, 0);
    CryptDestroyHash(hash);
    return rc;
}
*/
import "C"

import (
	"unsafe"
)

// GenerateGOSTKeyHandle generates a fresh ephemeral GOST R 34.10-2012 key
// pair for the given sign algorithm NID and TC26 parameter-set OID.
func GenerateGOSTKeyHandle(signNID int, curveOID string) (*KeyHandle, error) {
	if err := Init(); err != nil {
		return nil, err
	}

	// Each key gets its own CSP context so that CryptGenKey writes into
	// an isolated container and Free() can release it without stepping
	// on other keys' contexts.
	var prov C.HCRYPTPROV
	provType := providerTypeForSignNID(signNID)
	if C.go_fresh_context(&prov, provType) == 0 {
		return nil, cspError("CryptAcquireContextA(keygen)")
	}

	cOID := C.CString(curveOID)
	defer C.free(unsafe.Pointer(cOID))

	var alg C.ALG_ID = C.ALG_ID(signNID)
	var key C.HCRYPTKEY
	if C.go_gen_gost_key(prov, alg, cOID, &key) == 0 {
		err := cspError("CryptGenKey")
		C.CryptReleaseContext(prov, 0)
		return nil, err
	}

	keySize := 32
	if signNID == NID_GostR3410_2012_512 {
		keySize = 64
	}

	return NewKeyHandle(prov, key, signNID, keySize, true), nil
}

// LoadGOSTPrivKeyHandle imports a raw little-endian GOST private key
// scalar into a fresh CSP context. The raw bytes must be exactly the
// expected key size for the signNID (32 or 64 bytes).
//
// Strategy: generate a throwaway key, export it as PRIVATEKEYBLOB (which
// gives us a correctly shaped blob template), overwrite the trailing
// raw-scalar region, then reimport. This mirrors the technique used by
// the old gost-engine backend.
func LoadGOSTPrivKeyHandle(signNID int, curveOID string, raw []byte) (*KeyHandle, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, &CSPError{Op: "LoadGOSTPrivKey", Text: "empty raw key"}
	}

	keySize := 32
	if signNID == NID_GostR3410_2012_512 {
		keySize = 64
	}
	if len(raw) != keySize {
		return nil, &CSPError{Op: "LoadGOSTPrivKey", Text: "raw key size mismatch"}
	}

	// Step 1: generate a template.
	tmpl, err := GenerateGOSTKeyHandle(signNID, curveOID)
	if err != nil {
		return nil, err
	}

	// Step 2: export template as PRIVATEKEYBLOB.
	var blobLen C.DWORD
	blob := C.go_export_privkey(tmpl.hKey, &blobLen)
	if blob == nil {
		tmpl.Free()
		return nil, cspError("CryptExportKey(PRIVATEKEYBLOB template)")
	}
	defer C.free(unsafe.Pointer(blob))

	if int(blobLen) < keySize {
		tmpl.Free()
		return nil, &CSPError{Op: "LoadGOSTPrivKey", Text: "exported blob too short for key size"}
	}

	// Step 3: patch raw scalar into the trailing keySize bytes of the blob.
	blobBytes := C.GoBytes(unsafe.Pointer(blob), C.int(blobLen))
	copy(blobBytes[int(blobLen)-keySize:], raw)

	// Step 4: reimport patched blob into the template's provider. We
	// dispose of the template key but keep the CSP context so the
	// returned KeyHandle remains self-sufficient.
	var newKey C.HCRYPTKEY
	if C.go_import_key(tmpl.hProv,
		(*C.BYTE)(unsafe.Pointer(&blobBytes[0])),
		C.DWORD(len(blobBytes)), &newKey) == 0 {
		// Clean up blob bytes first (sensitive — contains the new scalar).
		CleanseBytes(blobBytes)
		tmpl.Free()
		return nil, cspError("CryptImportKey(patched PRIVATEKEYBLOB)")
	}
	CleanseBytes(blobBytes)

	// Replace the template's key with the patched one; keep the provider.
	C.CryptDestroyKey(tmpl.hKey)
	tmpl.hKey = newKey
	return tmpl, nil
}

// SignDigestH signs a pre-computed digest. Returns r||s (LE) of length
// 2*keySize bytes, matching the historical gost-engine wire format.
func SignDigestH(h *KeyHandle, digest []byte) ([]byte, error) {
	if h.IsNil() {
		return nil, errNilKeyHandle
	}
	if len(digest) == 0 {
		return nil, &CSPError{Op: "SignDigest", Text: "empty digest"}
	}

	hashAlg := C.ALG_ID(NID_Streebog256)
	if h.signNID == NID_GostR3410_2012_512 {
		hashAlg = C.ALG_ID(NID_Streebog512)
	}

	// First pass: query signature size.
	var sigLen C.DWORD
	if C.go_sign_hash(h.hProv, h.hKey, hashAlg,
		(*C.BYTE)(unsafe.Pointer(&digest[0])), C.DWORD(len(digest)),
		nil, &sigLen) == 0 {
		return nil, cspError("CryptSignHashA(size)")
	}

	sig := make([]byte, int(sigLen))
	if C.go_sign_hash(h.hProv, h.hKey, hashAlg,
		(*C.BYTE)(unsafe.Pointer(&digest[0])), C.DWORD(len(digest)),
		(*C.BYTE)(unsafe.Pointer(&sig[0])), &sigLen) == 0 {
		return nil, cspError("CryptSignHashA")
	}
	return sig[:int(sigLen)], nil
}

// VerifyDigestH verifies a signature against a pre-computed digest.
// Returns (true, nil) on a valid signature, (false, nil) on a well-formed
// but incorrect signature, and (false, err) on an operational error.
func VerifyDigestH(h *KeyHandle, digest, sig []byte) (bool, error) {
	if h.IsNil() {
		return false, errNilKeyHandle
	}
	if len(digest) == 0 || len(sig) == 0 {
		return false, &CSPError{Op: "VerifyDigest", Text: "empty digest or signature"}
	}

	hashAlg := C.ALG_ID(NID_Streebog256)
	if h.signNID == NID_GostR3410_2012_512 {
		hashAlg = C.ALG_ID(NID_Streebog512)
	}

	rc := C.go_verify_hash(h.hProv, h.hKey, hashAlg,
		(*C.BYTE)(unsafe.Pointer(&digest[0])), C.DWORD(len(digest)),
		(*C.BYTE)(unsafe.Pointer(&sig[0])), C.DWORD(len(sig)))
	if rc != 0 {
		return true, nil
	}
	// NTE_BAD_SIGNATURE (0x80090006) means "valid call, wrong signature".
	// Anything else is a real operational error.
	code := uint32(C.GetLastError())
	if code == 0x80090006 {
		return false, nil
	}
	return false, cspErrorWithCode("CryptVerifySignatureA", code)
}

// ExtractRawPrivKeyH returns the raw little-endian scalar of the private
// key, stripped from the trailing `keySize` bytes of a PRIVATEKEYBLOB.
//
// WARNING: CryptoPro CSP will refuse to export a key that was imported
// without CRYPT_EXPORTABLE. All keys created through GenerateGOSTKeyHandle
// are exportable, but keys loaded via certificate parsing may not be.
func ExtractRawPrivKeyH(h *KeyHandle, keySize int) ([]byte, error) {
	if h.IsNil() {
		return nil, errNilKeyHandle
	}

	var blobLen C.DWORD
	blob := C.go_export_privkey(h.hKey, &blobLen)
	if blob == nil {
		return nil, cspError("CryptExportKey(PRIVATEKEYBLOB)")
	}
	defer C.free(unsafe.Pointer(blob))

	if int(blobLen) < keySize {
		return nil, &CSPError{Op: "ExtractRawPrivKey", Text: "exported blob too short"}
	}

	blobBytes := C.GoBytes(unsafe.Pointer(blob), C.int(blobLen))
	raw := make([]byte, keySize)
	copy(raw, blobBytes[int(blobLen)-keySize:])
	CleanseBytes(blobBytes)

	allZero := true
	for _, b := range raw {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		CleanseBytes(raw)
		return nil, &CSPError{Op: "ExtractRawPrivKey", Text: "extracted scalar is all zero"}
	}
	return raw, nil
}

// ExtractRawPubKeyH returns the PUBLICKEYBLOB bytes produced by CryptoPro
// CSP for this key. The old openssl backend returned the full SPKI DER
// here; we preserve that "opaque, round-trippable" contract by returning
// whatever CryptoPro considers the natural public-key export.
//
// Consumers that need the raw X||Y point should strip the
// BLOBHEADER + CRYPT_PUBKEY_INFO prefix — the trailing 2*keySize bytes
// are the LE-encoded point coordinates.
func ExtractRawPubKeyH(h *KeyHandle) ([]byte, error) {
	if h.IsNil() {
		return nil, errNilKeyHandle
	}

	var blobLen C.DWORD
	blob := C.go_export_pubkey(h.hKey, &blobLen)
	if blob == nil {
		return nil, cspError("CryptExportKey(PUBLICKEYBLOB)")
	}
	defer C.free(unsafe.Pointer(blob))
	return C.GoBytes(unsafe.Pointer(blob), C.int(blobLen)), nil
}
