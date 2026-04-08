package openssl

/*
#include <openssl/cms.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>

// go_cms_sign creates a CMS SignedData from data, signing with the given
// cert+key pair using the specified digest. flags control detached/attached.
static CMS_ContentInfo *go_cms_sign(X509 *cert, EVP_PKEY *pkey,
                                     const unsigned char *data, int data_len,
                                     int md_nid, unsigned int flags, ENGINE *eng) {
    BIO *bio_data = BIO_new_mem_buf(data, data_len);
    if (!bio_data) return NULL;

    const EVP_MD *md = EVP_get_digestbynid(md_nid);
    if (!md) {
        BIO_free(bio_data);
        return NULL;
    }

    // CMS_sign with signer added manually for engine support.
    CMS_ContentInfo *cms = CMS_sign(NULL, NULL, NULL, bio_data,
                                     flags | CMS_PARTIAL | CMS_STREAM);
    if (!cms) {
        BIO_free(bio_data);
        return NULL;
    }

    CMS_SignerInfo *si = CMS_add1_signer(cms, cert, pkey, md, flags);
    if (!si) {
        CMS_ContentInfo_free(cms);
        BIO_free(bio_data);
        return NULL;
    }

    // Reset BIO for final.
    BIO_reset(bio_data);
    if (CMS_final(cms, bio_data, NULL, flags) != 1) {
        CMS_ContentInfo_free(cms);
        BIO_free(bio_data);
        return NULL;
    }

    BIO_free(bio_data);
    return cms;
}

// go_cms_verify verifies a CMS SignedData against the given data.
static int go_cms_verify(CMS_ContentInfo *cms,
                          const unsigned char *data, int data_len,
                          X509_STORE *store, unsigned int flags) {
    BIO *bio_data = NULL;
    if (data && data_len > 0) {
        bio_data = BIO_new_mem_buf(data, data_len);
        if (!bio_data) return -1;
    }

    int rc = CMS_verify(cms, NULL, store, bio_data, NULL, flags);

    if (bio_data) BIO_free(bio_data);
    return rc;
}

// go_cms_to_der serializes CMS to DER.
static int go_cms_to_der(CMS_ContentInfo *cms, unsigned char **out) {
    int len = i2d_CMS_ContentInfo(cms, NULL);
    if (len <= 0) return len;
    *out = (unsigned char *)malloc(len);
    if (!*out) return -1;
    unsigned char *p = *out;
    int len2 = i2d_CMS_ContentInfo(cms, &p);
    if (len2 <= 0) {
        free(*out);
        *out = NULL;
    }
    return len2;
}

// go_cms_from_der parses CMS from DER bytes.
static CMS_ContentInfo *go_cms_from_der(const unsigned char *data, int len) {
    const unsigned char *p = data;
    return d2i_CMS_ContentInfo(NULL, &p, len);
}
*/
import "C"
import (
	"encoding/pem"
	"errors"
	"unsafe"
)

// CMSContentInfo wraps an OpenSSL CMS_ContentInfo structure.
type CMSContentInfo struct {
	cms *C.CMS_ContentInfo
}

// CMSSign creates a CMS SignedData structure.
// If detached is true, the data is not included in the CMS structure
// (the signature is detached from the content).
func CMSSign(cert *X509Cert, privKey *KeyHandle, data []byte, mdNID int, detached bool) (*CMSContentInfo, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	if cert == nil || cert.x == nil {
		return nil, errors.New("openssl: nil certificate for CMS sign")
	}
	if privKey.IsNil() {
		return nil, errors.New("openssl: nil private key for CMS sign")
	}

	var flags C.uint = C.CMS_BINARY | C.CMS_NOSMIMECAP
	if detached {
		flags |= C.CMS_DETACHED
	}

	var dataPtr *C.uchar
	if len(data) > 0 {
		dataPtr = (*C.uchar)(unsafe.Pointer(&data[0]))
	}

	cms := C.go_cms_sign(cert.x, privKey.pkey,
		dataPtr, C.int(len(data)),
		C.int(mdNID), flags, gostEngine)
	if cms == nil {
		return nil, fmtSSLError("CMS_sign")
	}

	return &CMSContentInfo{cms: cms}, nil
}

// CMSVerify verifies a CMS SignedData structure.
// For detached signatures, data must contain the original content.
// For attached signatures, data should be nil.
// If noCertVerify is true, certificate chain validation is skipped
// (only the signature itself is verified).
func CMSVerify(ci *CMSContentInfo, data []byte, noCertVerify bool) error {
	if ci == nil || ci.cms == nil {
		return errors.New("openssl: nil CMS content")
	}

	var flags C.uint = C.CMS_BINARY
	if noCertVerify {
		flags |= C.CMS_NO_SIGNER_CERT_VERIFY | C.CMS_NOVERIFY
	}

	var dataPtr *C.uchar
	dataLen := C.int(0)
	if len(data) > 0 {
		dataPtr = (*C.uchar)(unsafe.Pointer(&data[0]))
		dataLen = C.int(len(data))
	}

	rc := C.go_cms_verify(ci.cms, dataPtr, dataLen, nil, flags)
	if rc != 1 {
		return fmtSSLError("CMS_verify")
	}
	return nil
}

// MarshalDER serializes the CMS structure to DER format.
func (ci *CMSContentInfo) MarshalDER() ([]byte, error) {
	var cDer *C.uchar
	derLen := C.go_cms_to_der(ci.cms, &cDer)
	if derLen <= 0 || cDer == nil {
		return nil, fmtSSLError("i2d_CMS_ContentInfo")
	}
	defer C.free(unsafe.Pointer(cDer))
	return C.GoBytes(unsafe.Pointer(cDer), derLen), nil
}

// MarshalPEM serializes the CMS structure to PEM format.
// Uses Go's encoding/pem over DER to avoid OpenSSL macro compatibility issues.
func (ci *CMSContentInfo) MarshalPEM() ([]byte, error) {
	der, err := ci.MarshalDER()
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "CMS",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

// ParseCMSDER parses a CMS structure from DER bytes.
func ParseCMSDER(der []byte) (*CMSContentInfo, error) {
	if len(der) == 0 {
		return nil, errors.New("openssl: empty CMS DER data")
	}
	cms := C.go_cms_from_der((*C.uchar)(unsafe.Pointer(&der[0])), C.int(len(der)))
	if cms == nil {
		return nil, fmtSSLError("d2i_CMS_ContentInfo")
	}
	return &CMSContentInfo{cms: cms}, nil
}

// Free releases the underlying CMS_ContentInfo.
func (ci *CMSContentInfo) Free() {
	if ci.cms != nil {
		C.CMS_ContentInfo_free(ci.cms)
		ci.cms = nil
	}
}
