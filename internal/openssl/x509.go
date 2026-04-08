package openssl

/*
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

// go_openssl_free wraps OPENSSL_free (which may be a macro).
static void go_openssl_free(void *ptr) {
    OPENSSL_free(ptr);
}

// go_x509_sign signs a certificate with the given key and digest NID.
static int go_x509_sign(X509 *cert, EVP_PKEY *pkey, int md_nid, ENGINE *eng) {
    const EVP_MD *md = EVP_get_digestbynid(md_nid);
    if (!md) return -1;

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) return -2;

    EVP_PKEY_CTX *pkctx = NULL;
    if (EVP_DigestSignInit(mctx, &pkctx, md, eng, pkey) != 1) {
        EVP_MD_CTX_free(mctx);
        return -3;
    }

    int rc = X509_sign_ctx(cert, mctx);
    EVP_MD_CTX_free(mctx);
    return rc;
}

// go_x509_req_sign signs a CSR with the given key and digest NID.
static int go_x509_req_sign(X509_REQ *req, EVP_PKEY *pkey, int md_nid, ENGINE *eng) {
    const EVP_MD *md = EVP_get_digestbynid(md_nid);
    if (!md) return -1;

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) return -2;

    EVP_PKEY_CTX *pkctx = NULL;
    if (EVP_DigestSignInit(mctx, &pkctx, md, eng, pkey) != 1) {
        EVP_MD_CTX_free(mctx);
        return -3;
    }

    int rc = X509_REQ_sign_ctx(req, mctx);
    EVP_MD_CTX_free(mctx);
    return rc;
}

// go_x509_verify verifies a certificate's signature using the issuer's key.
static int go_x509_verify(X509 *cert, EVP_PKEY *pkey) {
    return X509_verify(cert, pkey);
}

// go_x509_to_der serializes an X509 to DER format.
// Caller must free *out with free(). Returns length, or <=0 on error.
static int go_x509_to_der(X509 *cert, unsigned char **out) {
    int len = i2d_X509(cert, NULL);
    if (len <= 0) return len;
    *out = (unsigned char *)malloc(len);
    if (!*out) return -1;
    unsigned char *p = *out;
    int len2 = i2d_X509(cert, &p);
    if (len2 <= 0) {
        free(*out);
        *out = NULL;
    }
    return len2;
}

// go_x509_from_der parses an X509 from DER bytes.
static X509 *go_x509_from_der(const unsigned char *data, int len) {
    const unsigned char *p = data;
    return d2i_X509(NULL, &p, len);
}

// go_x509_to_pem serializes an X509 to PEM format in a BIO, returns the string.
static int go_x509_to_pem(X509 *cert, char **out, int *out_len) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return -1;
    if (PEM_write_bio_X509(bio, cert) != 1) {
        BIO_free(bio);
        return -2;
    }
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    *out = (char *)malloc(len + 1);
    if (!*out) {
        BIO_free(bio);
        return -3;
    }
    memcpy(*out, data, len);
    (*out)[len] = '\0';
    *out_len = (int)len;
    BIO_free(bio);
    return 0;
}

// go_x509_from_pem parses an X509 from PEM string.
static X509 *go_x509_from_pem(const char *pem_data, int pem_len) {
    BIO *bio = BIO_new_mem_buf(pem_data, pem_len);
    if (!bio) return NULL;
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return cert;
}

// go_x509_req_to_der serializes a CSR to DER.
static int go_x509_req_to_der(X509_REQ *req, unsigned char **out) {
    int len = i2d_X509_REQ(req, NULL);
    if (len <= 0) return len;
    *out = (unsigned char *)malloc(len);
    if (!*out) return -1;
    unsigned char *p = *out;
    int len2 = i2d_X509_REQ(req, &p);
    if (len2 <= 0) {
        free(*out);
        *out = NULL;
    }
    return len2;
}

// go_x509_req_to_pem serializes a CSR to PEM.
static int go_x509_req_to_pem(X509_REQ *req, char **out, int *out_len) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return -1;
    if (PEM_write_bio_X509_REQ(bio, req) != 1) {
        BIO_free(bio);
        return -2;
    }
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    *out = (char *)malloc(len + 1);
    if (!*out) {
        BIO_free(bio);
        return -3;
    }
    memcpy(*out, data, len);
    (*out)[len] = '\0';
    *out_len = (int)len;
    BIO_free(bio);
    return 0;
}
*/
import "C"
import (
	"errors"
	"math/big"
	"time"
	"unicode/utf8"
	"unsafe"
)

// X509Cert wraps an OpenSSL X509 structure.
type X509Cert struct {
	x *C.X509
}

// X509Request wraps an OpenSSL X509_REQ structure.
type X509Request struct {
	req *C.X509_REQ
}

// X509Name represents distinguished name fields for a certificate subject/issuer.
type X509Name struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	Province           string
	Locality           string
}

// CreateSelfSignedCert creates a self-signed X.509 certificate using GOST keys.
// The certificate is signed with the provided private key using the specified
// digest NID (typically NID_Streebog256 or NID_Streebog512).
func CreateSelfSignedCert(privKey *KeyHandle, subject X509Name, serial *big.Int, notBefore, notAfter time.Time, mdNID int) (*X509Cert, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	if privKey.IsNil() {
		return nil, errors.New("openssl: nil private key")
	}

	cert := C.X509_new()
	if cert == nil {
		return nil, fmtSSLError("X509_new")
	}

	// Set version to v3.
	C.X509_set_version(cert, 2) // 0-indexed: v3 = 2

	// Set serial number.
	serialBytes := serial.Bytes()
	asn1Int := C.ASN1_INTEGER_new()
	if asn1Int == nil {
		C.X509_free(cert)
		return nil, fmtSSLError("ASN1_INTEGER_new")
	}
	if len(serialBytes) > 0 {
		bn := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&serialBytes[0])), C.int(len(serialBytes)), nil)
		if bn == nil {
			C.ASN1_INTEGER_free(asn1Int)
			C.X509_free(cert)
			return nil, fmtSSLError("BN_bin2bn")
		}
		C.BN_to_ASN1_INTEGER(bn, asn1Int)
		C.BN_free(bn)
	}
	C.X509_set_serialNumber(cert, asn1Int)
	C.ASN1_INTEGER_free(asn1Int)

	// Set validity period.
	if err := setASN1Time(C.X509_getm_notBefore(cert), notBefore); err != nil {
		C.X509_free(cert)
		return nil, err
	}
	if err := setASN1Time(C.X509_getm_notAfter(cert), notAfter); err != nil {
		C.X509_free(cert)
		return nil, err
	}

	// Set subject name.
	name := C.X509_get_subject_name(cert)
	setNameEntry(name, "CN", subject.CommonName)
	setNameEntry(name, "O", subject.Organization)
	setNameEntry(name, "OU", subject.OrganizationalUnit)
	setNameEntry(name, "C", subject.Country)
	setNameEntry(name, "ST", subject.Province)
	setNameEntry(name, "L", subject.Locality)

	// Self-signed: issuer = subject.
	C.X509_set_issuer_name(cert, name)

	// Set public key.
	C.X509_set_pubkey(cert, privKey.pkey)

	// Sign.
	rc := C.go_x509_sign(cert, privKey.pkey, C.int(mdNID), gostEngine)
	if rc <= 0 {
		C.X509_free(cert)
		return nil, fmtSSLError("X509_sign")
	}

	return &X509Cert{x: cert}, nil
}

// CreateCSR creates a Certificate Signing Request.
func CreateCSR(privKey *KeyHandle, subject X509Name, mdNID int) (*X509Request, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	if privKey.IsNil() {
		return nil, errors.New("openssl: nil private key")
	}

	req := C.X509_REQ_new()
	if req == nil {
		return nil, fmtSSLError("X509_REQ_new")
	}

	C.X509_REQ_set_version(req, 0)

	name := C.X509_REQ_get_subject_name(req)
	setNameEntry(name, "CN", subject.CommonName)
	setNameEntry(name, "O", subject.Organization)
	setNameEntry(name, "OU", subject.OrganizationalUnit)
	setNameEntry(name, "C", subject.Country)
	setNameEntry(name, "ST", subject.Province)
	setNameEntry(name, "L", subject.Locality)

	C.X509_REQ_set_pubkey(req, privKey.pkey)

	rc := C.go_x509_req_sign(req, privKey.pkey, C.int(mdNID), gostEngine)
	if rc <= 0 {
		C.X509_REQ_free(req)
		return nil, fmtSSLError("X509_REQ_sign")
	}

	return &X509Request{req: req}, nil
}

// VerifyCert verifies the certificate's signature against the given public key.
func VerifyCert(cert *X509Cert, pubKey *KeyHandle) error {
	if cert == nil || cert.x == nil {
		return errors.New("openssl: nil certificate")
	}
	if pubKey.IsNil() {
		return errors.New("openssl: nil public key")
	}

	rc := C.go_x509_verify(cert.x, pubKey.pkey)
	if rc != 1 {
		return fmtSSLError("X509_verify")
	}
	return nil
}

// --- Serialization ---

// MarshalDER serializes the certificate to DER format.
func (c *X509Cert) MarshalDER() ([]byte, error) {
	var cDer *C.uchar
	derLen := C.go_x509_to_der(c.x, &cDer)
	if derLen <= 0 || cDer == nil {
		return nil, fmtSSLError("i2d_X509")
	}
	defer C.free(unsafe.Pointer(cDer))
	return C.GoBytes(unsafe.Pointer(cDer), derLen), nil
}

// MarshalPEM serializes the certificate to PEM format.
func (c *X509Cert) MarshalPEM() ([]byte, error) {
	var cPem *C.char
	var pemLen C.int
	rc := C.go_x509_to_pem(c.x, &cPem, &pemLen)
	if rc != 0 || cPem == nil {
		return nil, fmtSSLError("PEM_write_bio_X509")
	}
	defer C.free(unsafe.Pointer(cPem))
	return C.GoBytes(unsafe.Pointer(cPem), pemLen), nil
}

// ParseCertDER parses a certificate from DER bytes.
func ParseCertDER(der []byte) (*X509Cert, error) {
	if len(der) == 0 {
		return nil, errors.New("openssl: empty DER data")
	}
	cert := C.go_x509_from_der((*C.uchar)(unsafe.Pointer(&der[0])), C.int(len(der)))
	if cert == nil {
		return nil, fmtSSLError("d2i_X509")
	}
	return &X509Cert{x: cert}, nil
}

// ParseCertPEM parses a certificate from PEM data.
func ParseCertPEM(pem []byte) (*X509Cert, error) {
	if len(pem) == 0 {
		return nil, errors.New("openssl: empty PEM data")
	}
	cert := C.go_x509_from_pem((*C.char)(unsafe.Pointer(&pem[0])), C.int(len(pem)))
	if cert == nil {
		return nil, fmtSSLError("PEM_read_bio_X509")
	}
	return &X509Cert{x: cert}, nil
}

// SubjectCN returns the Common Name from the certificate's subject.
func (c *X509Cert) SubjectCN() string {
	name := C.X509_get_subject_name(c.x)
	return getNameEntry(name, C.NID_commonName)
}

// IssuerCN returns the Common Name from the certificate's issuer.
func (c *X509Cert) IssuerCN() string {
	name := C.X509_get_issuer_name(c.x)
	return getNameEntry(name, C.NID_commonName)
}

// PublicKey extracts the public key from the certificate as a KeyHandle.
func (c *X509Cert) PublicKey() (*KeyHandle, error) {
	pkey := C.X509_get0_pubkey(c.x)
	if pkey == nil {
		return nil, fmtSSLError("X509_get0_pubkey")
	}
	// X509_get0_pubkey returns a reference — we need to up-ref it.
	C.EVP_PKEY_up_ref(pkey)
	return NewKeyHandle(pkey), nil
}

// Free releases the underlying X509 structure.
func (c *X509Cert) Free() {
	if c.x != nil {
		C.X509_free(c.x)
		c.x = nil
	}
}

// --- CSR serialization ---

// MarshalDER serializes the CSR to DER format.
func (r *X509Request) MarshalDER() ([]byte, error) {
	var cDer *C.uchar
	derLen := C.go_x509_req_to_der(r.req, &cDer)
	if derLen <= 0 || cDer == nil {
		return nil, fmtSSLError("i2d_X509_REQ")
	}
	defer C.free(unsafe.Pointer(cDer))
	return C.GoBytes(unsafe.Pointer(cDer), derLen), nil
}

// MarshalPEM serializes the CSR to PEM format.
func (r *X509Request) MarshalPEM() ([]byte, error) {
	var cPem *C.char
	var pemLen C.int
	rc := C.go_x509_req_to_pem(r.req, &cPem, &pemLen)
	if rc != 0 || cPem == nil {
		return nil, fmtSSLError("PEM_write_bio_X509_REQ")
	}
	defer C.free(unsafe.Pointer(cPem))
	return C.GoBytes(unsafe.Pointer(cPem), pemLen), nil
}

// Free releases the underlying X509_REQ structure.
func (r *X509Request) Free() {
	if r.req != nil {
		C.X509_REQ_free(r.req)
		r.req = nil
	}
}

// --- helpers ---

func setNameEntry(name *C.X509_NAME, field, value string) {
	if value == "" {
		return
	}
	if !utf8.ValidString(value) {
		return // silently skip invalid UTF-8 to avoid malformed certificates
	}
	cField := C.CString(field)
	defer C.free(unsafe.Pointer(cField))
	cValue := C.CString(value)
	defer C.free(unsafe.Pointer(cValue))
	C.X509_NAME_add_entry_by_txt(name, cField, C.MBSTRING_UTF8,
		(*C.uchar)(unsafe.Pointer(cValue)), C.int(len(value)), -1, 0)
}

func getNameEntry(name *C.X509_NAME, nid C.int) string {
	idx := C.X509_NAME_get_index_by_NID(name, nid, -1)
	if idx < 0 {
		return ""
	}
	entry := C.X509_NAME_get_entry(name, idx)
	if entry == nil {
		return ""
	}
	data := C.X509_NAME_ENTRY_get_data(entry)
	if data == nil {
		return ""
	}
	var utf8 *C.uchar
	length := C.ASN1_STRING_to_UTF8(&utf8, data)
	if length < 0 {
		return ""
	}
	defer C.go_openssl_free(unsafe.Pointer(utf8))
	return C.GoStringN((*C.char)(unsafe.Pointer(utf8)), C.int(length))
}

func setASN1Time(t *C.ASN1_TIME, goTime time.Time) error {
	s := goTime.UTC().Format("20060102150405Z")
	cStr := C.CString(s)
	defer C.free(unsafe.Pointer(cStr))
	if C.ASN1_TIME_set_string(t, cStr) != 1 {
		return fmtSSLError("ASN1_TIME_set_string")
	}
	return nil
}
