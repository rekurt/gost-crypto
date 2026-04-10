package openssl

/*
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>

// go_pkey_to_pkcs8_pem writes pkey as an unencrypted PKCS#8 PEM
// "PRIVATE KEY" block into a memory BIO, copies the result into a
// caller-owned buffer, and returns its length (or <=0 on error).
// On success, *out points to a malloc()'d buffer; the caller must free it.
static int go_pkey_to_pkcs8_pem(EVP_PKEY *pkey, char **out) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return -1;
    // cipher=NULL, kstr=NULL, klen=0 -> unencrypted PKCS#8.
    if (PEM_write_bio_PKCS8PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        BIO_free(bio);
        return -2;
    }
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    if (len <= 0 || !data) {
        BIO_free(bio);
        return -3;
    }
    *out = (char *)malloc((size_t)len);
    if (!*out) {
        BIO_free(bio);
        return -4;
    }
    memcpy(*out, data, (size_t)len);
    BIO_free(bio);
    return (int)len;
}

// go_pkey_from_pem parses an unencrypted private key from PEM data.
// Accepts both PKCS#8 ("PRIVATE KEY") and algorithm-specific blocks
// because PEM_read_bio_PrivateKey auto-detects.
static EVP_PKEY *go_pkey_from_pem(const char *pem_data, int pem_len, ENGINE *eng) {
    (void)eng; // engine is active as default — reserved for future use
    BIO *bio = BIO_new_mem_buf(pem_data, pem_len);
    if (!bio) return NULL;
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return pkey;
}

// go_pubkey_to_pem writes pkey as a SubjectPublicKeyInfo PEM
// "PUBLIC KEY" block into a caller-owned buffer.
static int go_pubkey_to_pem(EVP_PKEY *pkey, char **out) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return -1;
    if (PEM_write_bio_PUBKEY(bio, pkey) != 1) {
        BIO_free(bio);
        return -2;
    }
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    if (len <= 0 || !data) {
        BIO_free(bio);
        return -3;
    }
    *out = (char *)malloc((size_t)len);
    if (!*out) {
        BIO_free(bio);
        return -4;
    }
    memcpy(*out, data, (size_t)len);
    BIO_free(bio);
    return (int)len;
}

// go_pubkey_from_pem parses a SubjectPublicKeyInfo ("PUBLIC KEY") PEM block.
static EVP_PKEY *go_pubkey_from_pem(const char *pem_data, int pem_len) {
    BIO *bio = BIO_new_mem_buf(pem_data, pem_len);
    if (!bio) return NULL;
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return pkey;
}

// go_pkey_id returns EVP_PKEY_id(pkey) so Go can detect which GOST
// algorithm an imported key belongs to without probing.
static int go_pkey_id(EVP_PKEY *pkey) {
    return EVP_PKEY_id(pkey);
}

// go_pem_i2d_private_key serializes pkey to DER via i2d_PrivateKey.
// Renamed to avoid clashing with go_i2d_private_key declared in
// evp_pkey.go's preamble — CGO preambles are per-file.
// On success *out is a caller-owned malloc'd buffer; return value is
// the DER length (<=0 on error).
static int go_pem_i2d_private_key(EVP_PKEY *pkey, unsigned char **out) {
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

// go_pem_i2d_pubkey serializes pkey's public part to SubjectPublicKeyInfo
// DER via i2d_PUBKEY. Renamed for the same reason as above.
static int go_pem_i2d_pubkey(EVP_PKEY *pkey, unsigned char **out) {
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
*/
import "C"
import (
	"errors"
	"unsafe"
)

// ErrUnsupportedKeyType is returned when a parsed key's algorithm NID
// does not match a known GOST R 34.10-2012 signing NID.
var ErrUnsupportedKeyType = errors.New("openssl: unsupported key type (not GOST R 34.10-2012)")

// MarshalPKCS8PrivateKeyPEM serializes a GOST private key as an
// unencrypted PKCS#8 "PRIVATE KEY" PEM block via OpenSSL. The output
// is byte-compatible with `openssl pkey -in key.pem -text`.
func MarshalPKCS8PrivateKeyPEM(h *KeyHandle) ([]byte, error) {
	if h == nil || h.IsNil() {
		return nil, errors.New("openssl: nil key handle")
	}
	if err := Init(); err != nil {
		return nil, err
	}

	var cOut *C.char
	n := C.go_pkey_to_pkcs8_pem(h.pkey, &cOut)
	if n <= 0 || cOut == nil {
		return nil, fmtSSLError("PEM_write_bio_PKCS8PrivateKey")
	}
	defer C.free(unsafe.Pointer(cOut))

	return C.GoBytes(unsafe.Pointer(cOut), n), nil
}

// ParsePrivateKeyPEM parses a PEM-encoded unencrypted private key
// (PKCS#8 or algorithm-specific) via OpenSSL and returns a KeyHandle
// plus the resolved signing NID.
//
// The returned KeyHandle owns an EVP_PKEY; the caller must Free it
// when done.
func ParsePrivateKeyPEM(pem []byte) (*KeyHandle, int, error) {
	if len(pem) == 0 {
		return nil, 0, errors.New("openssl: empty PEM")
	}
	if err := Init(); err != nil {
		return nil, 0, err
	}

	cPEM := C.CString(string(pem))
	defer C.free(unsafe.Pointer(cPEM))

	pkey := C.go_pkey_from_pem(cPEM, C.int(len(pem)), gostEngine)
	if pkey == nil {
		return nil, 0, fmtSSLError("PEM_read_bio_PrivateKey")
	}

	nid := int(C.go_pkey_id(pkey))
	if nid != NID_GostR3410_2012_256 && nid != NID_GostR3410_2012_512 {
		C.EVP_PKEY_free(pkey)
		return nil, 0, ErrUnsupportedKeyType
	}

	return NewKeyHandle(pkey), nid, nil
}

// MarshalPKIXPublicKeyPEM serializes a GOST public key as a
// SubjectPublicKeyInfo "PUBLIC KEY" PEM block via OpenSSL.
func MarshalPKIXPublicKeyPEM(h *KeyHandle) ([]byte, error) {
	if h == nil || h.IsNil() {
		return nil, errors.New("openssl: nil key handle")
	}
	if err := Init(); err != nil {
		return nil, err
	}

	var cOut *C.char
	n := C.go_pubkey_to_pem(h.pkey, &cOut)
	if n <= 0 || cOut == nil {
		return nil, fmtSSLError("PEM_write_bio_PUBKEY")
	}
	defer C.free(unsafe.Pointer(cOut))

	return C.GoBytes(unsafe.Pointer(cOut), n), nil
}

// ParsePublicKeyPEM parses a PEM-encoded SubjectPublicKeyInfo block
// via OpenSSL and returns a KeyHandle plus the resolved signing NID.
func ParsePublicKeyPEM(pem []byte) (*KeyHandle, int, error) {
	if len(pem) == 0 {
		return nil, 0, errors.New("openssl: empty PEM")
	}
	if err := Init(); err != nil {
		return nil, 0, err
	}

	cPEM := C.CString(string(pem))
	defer C.free(unsafe.Pointer(cPEM))

	pkey := C.go_pubkey_from_pem(cPEM, C.int(len(pem)))
	if pkey == nil {
		return nil, 0, fmtSSLError("PEM_read_bio_PUBKEY")
	}

	nid := int(C.go_pkey_id(pkey))
	if nid != NID_GostR3410_2012_256 && nid != NID_GostR3410_2012_512 {
		C.EVP_PKEY_free(pkey)
		return nil, 0, ErrUnsupportedKeyType
	}

	return NewKeyHandle(pkey), nid, nil
}

// PrivKeyDER returns the DER encoding of the private key behind h,
// using OpenSSL's i2d_PrivateKey. For GOST keys the result is a
// PKCS#8-style PrivateKeyInfo whose AlgorithmIdentifier.parameters
// field carries the TC26 paramSet OID — callers can parse that to
// recover the exact curve that the key was built with.
//
// The returned bytes are a fresh Go copy; the underlying C buffer is
// cleansed and freed before return.
func PrivKeyDER(h *KeyHandle) ([]byte, error) {
	if h == nil || h.IsNil() {
		return nil, errors.New("openssl: nil key handle")
	}
	var cDer *C.uchar
	n := C.go_pem_i2d_private_key(h.pkey, &cDer)
	if n <= 0 || cDer == nil {
		return nil, fmtSSLError("i2d_PrivateKey")
	}
	out := C.GoBytes(unsafe.Pointer(cDer), n)
	// i2d_PrivateKey malloc's the buffer; cleanse via OPENSSL_cleanse
	// before free so the wipe is not optimised away as a dead store.
	// A plain memset right before free is a classic compiler footgun;
	// OPENSSL_cleanse uses a memory barrier to guarantee the write is
	// retained.
	Cleanse(unsafe.Pointer(cDer), int(n))
	C.free(unsafe.Pointer(cDer))
	return out, nil
}

// PubKeyDER returns the SubjectPublicKeyInfo DER encoding of the
// public key behind h, using OpenSSL's i2d_PUBKEY. For GOST keys
// this contains the same TC26 paramSet OID in its
// AlgorithmIdentifier as PrivKeyDER would.
func PubKeyDER(h *KeyHandle) ([]byte, error) {
	if h == nil || h.IsNil() {
		return nil, errors.New("openssl: nil key handle")
	}
	var cDer *C.uchar
	n := C.go_pem_i2d_pubkey(h.pkey, &cDer)
	if n <= 0 || cDer == nil {
		return nil, fmtSSLError("i2d_PUBKEY")
	}
	out := C.GoBytes(unsafe.Pointer(cDer), n)
	C.free(unsafe.Pointer(cDer))
	return out, nil
}
