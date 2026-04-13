//go:build cgo && linux && cryptopro
// +build cgo,linux,cryptopro

package cryptopro

/*
#cgo CFLAGS: -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/cades
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi10 -lcapi20 -lssp -lrdrsup -lcades
#include "capi.h"

// go_cades_bind_key associates a CSP key container with a certificate
// context so that CadesSignMessage can locate the private key.
// Duplicated from x509.go because CGO static functions are per-file.
static BOOL go_cades_bind_key(PCCERT_CONTEXT cert, HCRYPTPROV prov,
                              DWORD key_spec) {
    CRYPT_KEY_PROV_INFO info;
    memset(&info, 0, sizeof(info));
    info.dwKeySpec = key_spec;
    (void)prov;
    return CertSetCertificateContextProperty(
        cert, CERT_KEY_PROV_INFO_PROP_ID, 0, &info);
}

// go_cades_sign creates a CAdES-BES signature over `data` using the given
// certificate and its bound private key handle. Detached / attached is
// selected via `detached`. On success, returns a malloc'd buffer with the
// encoded CAdES / CMS DER bytes; caller must free.
//
// The CAdES-C API expects:
//   - CRYPT_SIGN_MESSAGE_PARA with the signer cert + hash algorithm
//   - CADES_SIGN_PARA with the CAdES signature type (CADES_BES)
//   - CADES_SIGN_MESSAGE_PARA combining both
//
// Then CadesSignMessage produces a CRYPT_DATA_BLOB containing the DER
// bytes. We copy those into a caller-owned buffer.
static BYTE *go_cades_sign(PCCERT_CONTEXT cert, HCRYPTPROV prov,
                           ALG_ID hash_alg,
                           const BYTE *data, DWORD data_len,
                           BOOL detached, DWORD *out_len) {
    CRYPT_SIGN_MESSAGE_PARA sign_para;
    memset(&sign_para, 0, sizeof(sign_para));
    sign_para.cbSize = sizeof(sign_para);
    sign_para.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    sign_para.pSigningCert = cert;
    // Hash algorithm OID picked from the provider-specific ALG_ID.
    const char *hash_oid;
    switch (hash_alg) {
    case CALG_GR3411_2012_256:
        hash_oid = szOID_CP_GOST_R3411_12_256;
        break;
    case CALG_GR3411_2012_512:
        hash_oid = szOID_CP_GOST_R3411_12_512;
        break;
    default:
        return NULL;
    }
    sign_para.HashAlgorithm.pszObjId = (LPSTR)hash_oid;
    sign_para.cMsgCert = 1;
    sign_para.rgpMsgCert = &cert;

    CADES_SIGN_PARA cades_para;
    memset(&cades_para, 0, sizeof(cades_para));
    cades_para.dwSize = sizeof(cades_para);
    cades_para.dwCadesType = CADES_BES;

    CADES_SIGN_MESSAGE_PARA msg_para;
    memset(&msg_para, 0, sizeof(msg_para));
    msg_para.dwSize = sizeof(msg_para);
    msg_para.pSignMessagePara = &sign_para;
    msg_para.pCadesSignPara = &cades_para;

    const BYTE *body[1] = { data };
    DWORD      body_len[1] = { data_len };

    PCRYPT_DATA_BLOB signed_blob = NULL;
    if (!CadesSignMessage(&msg_para, detached, 1, body, body_len,
                          &signed_blob)) {
        return NULL;
    }
    if (signed_blob == NULL || signed_blob->cbData == 0 ||
        signed_blob->pbData == NULL) {
        if (signed_blob) CadesFreeBlob(signed_blob);
        return NULL;
    }

    BYTE *out = (BYTE*)malloc(signed_blob->cbData);
    if (out == NULL) {
        CadesFreeBlob(signed_blob);
        return NULL;
    }
    memcpy(out, signed_blob->pbData, signed_blob->cbData);
    *out_len = signed_blob->cbData;
    CadesFreeBlob(signed_blob);
    return out;
}

// go_cades_verify verifies a CAdES / CMS DER blob against an optional
// detached content. Returns TRUE on success.
static BOOL go_cades_verify(const BYTE *sig, DWORD sig_len,
                            const BYTE *data, DWORD data_len,
                            BOOL detached, BOOL no_cert_verify) {
    CADES_VERIFICATION_PARA cades_para;
    memset(&cades_para, 0, sizeof(cades_para));
    cades_para.dwSize = sizeof(cades_para);
    cades_para.dwCadesType = CADES_BES;

    CRYPT_VERIFY_MESSAGE_PARA verify_para;
    memset(&verify_para, 0, sizeof(verify_para));
    verify_para.cbSize = sizeof(verify_para);
    verify_para.dwMsgAndCertEncodingType =
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    CADES_VERIFY_MESSAGE_PARA msg_para;
    memset(&msg_para, 0, sizeof(msg_para));
    msg_para.dwSize = sizeof(msg_para);
    msg_para.pVerifyMessagePara = &verify_para;
    msg_para.pCadesVerifyPara = &cades_para;

    // When noCertVerify is TRUE, skip certificate chain validation by
    // setting CADES_SKIP_CERT_VALIDITY_CHECK on the CAdES verification
    // parameters. This matches the contract of VerifyOptions.NoCertVerify.
    if (no_cert_verify) {
        cades_para.dwFlags |= CADES_SKIP_CERT_VALIDITY_CHECK;
    }

    PCADES_VERIFICATION_INFO info = NULL;
    BOOL rc;
    if (detached) {
        const BYTE *body[1] = { data };
        DWORD      body_len[1] = { data_len };
        rc = CadesVerifyDetachedMessage(&msg_para, 0,
                                        sig, sig_len,
                                        1, body, body_len,
                                        &info);
    } else {
        rc = CadesVerifyMessage(&msg_para, 0,
                                sig, sig_len,
                                NULL, NULL, &info);
    }
    BOOL ok = FALSE;
    if (rc && info != NULL && info->dwStatus == CADES_VERIFY_SUCCESS) {
        ok = TRUE;
    }
    if (info != NULL) {
        CadesFreeVerificationInfo(info);
    }
    return ok;
}
*/
import "C"

import (
	"encoding/pem"
	"errors"
	"unsafe"
)

// CMSContentInfo wraps the DER bytes of a CAdES / CMS SignedData structure
// produced by libcades. Because libcades works in terms of encoded blobs
// rather than live PKCS#7 structures, there is no per-instance handle to
// track — the struct is just a typed byte container. The Marshal / Parse
// methods preserve the same contract the pkg/cms package relied on under
// the old openssl backend.
type CMSContentInfo struct {
	der []byte
}

// CMSSign produces a CAdES-BES / PKCS#7 SignedData over `data`, signing
// with the given certificate context and private key.
//
// CadesSignMessage locates the signing key through the certificate's
// CERT_KEY_PROV_INFO_PROP_ID property. If the certificate was created
// via CreateSelfSignedCert the property is already set. For externally
// parsed certificates we bind the caller-provided private key's provider
// to the certificate context here, so that CadesSignMessage can find it.
func CMSSign(cert *X509Cert, priv *KeyHandle, data []byte, mdNID int, detached bool) (*CMSContentInfo, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	if cert == nil || cert.ctx == nil {
		return nil, errors.New("cryptopro: nil certificate for CMS sign")
	}
	if priv.IsNil() {
		return nil, errors.New("cryptopro: nil private key for CMS sign")
	}

	// Ensure the certificate has a KEY_PROV_INFO linkage so
	// CadesSignMessage can locate the private key. This is idempotent
	// for certs that already have the property (CreateSelfSignedCert)
	// and fixes externally-parsed certs (ParseCertDER / ParseCertPEM).
	if C.go_cades_bind_key(cert.ctx, priv.hProv, C.AT_KEYEXCHANGE) == 0 {
		return nil, cspError("CertSetCertificateContextProperty(KEY_PROV_INFO for CMS sign)")
	}

	var dataPtr *C.BYTE
	if len(data) > 0 {
		dataPtr = (*C.BYTE)(unsafe.Pointer(&data[0]))
	}

	detachedFlag := C.BOOL(0)
	if detached {
		detachedFlag = C.BOOL(1)
	}

	var outLen C.DWORD
	out := C.go_cades_sign(cert.ctx, priv.hProv, C.ALG_ID(mdNID),
		dataPtr, C.DWORD(len(data)), detachedFlag, &outLen)
	if out == nil {
		return nil, cspError("CadesSignMessage")
	}
	defer C.free(unsafe.Pointer(out))

	der := C.GoBytes(unsafe.Pointer(out), C.int(outLen))
	return &CMSContentInfo{der: der}, nil
}

// CMSVerify validates a CAdES / CMS SignedData blob against optional
// detached content.
func CMSVerify(ci *CMSContentInfo, data []byte, noCertVerify bool) error {
	if ci == nil || len(ci.der) == 0 {
		return errors.New("cryptopro: nil CMS content")
	}
	if err := Init(); err != nil {
		return err
	}

	var dataPtr *C.BYTE
	if len(data) > 0 {
		dataPtr = (*C.BYTE)(unsafe.Pointer(&data[0]))
	}
	detached := C.BOOL(0)
	if len(data) > 0 {
		detached = C.BOOL(1)
	}
	noVerify := C.BOOL(0)
	if noCertVerify {
		noVerify = C.BOOL(1)
	}

	rc := C.go_cades_verify(
		(*C.BYTE)(unsafe.Pointer(&ci.der[0])), C.DWORD(len(ci.der)),
		dataPtr, C.DWORD(len(data)),
		detached, noVerify)
	if rc == 0 {
		return cspError("CadesVerifyMessage")
	}
	return nil
}

// MarshalDER returns the raw CAdES / CMS DER bytes.
func (ci *CMSContentInfo) MarshalDER() ([]byte, error) {
	if ci == nil {
		return nil, errors.New("cryptopro: nil CMS content")
	}
	out := make([]byte, len(ci.der))
	copy(out, ci.der)
	return out, nil
}

// MarshalPEM wraps the DER bytes in a "CMS" / "PKCS7" PEM block.
func (ci *CMSContentInfo) MarshalPEM() ([]byte, error) {
	der, err := ci.MarshalDER()
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CMS", Bytes: der}), nil
}

// ParseCMSDER parses a DER blob into a CMSContentInfo. No structural
// validation happens here — we just wrap the bytes; Verify will reject
// malformed blobs.
func ParseCMSDER(der []byte) (*CMSContentInfo, error) {
	if len(der) == 0 {
		return nil, errors.New("cryptopro: empty CMS DER data")
	}
	out := make([]byte, len(der))
	copy(out, der)
	return &CMSContentInfo{der: out}, nil
}

// Free is a no-op because CMSContentInfo holds only Go-owned bytes.
// Kept for API compatibility with the old openssl backend.
func (ci *CMSContentInfo) Free() {
	if ci == nil {
		return
	}
	CleanseBytes(ci.der)
	ci.der = nil
}
