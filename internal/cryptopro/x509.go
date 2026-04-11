//go:build cgo && linux && cryptopro
// +build cgo,linux,cryptopro

package cryptopro

/*
#cgo CFLAGS: -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/cades
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi10 -lcapi20 -lssp -lrdrsup -lcades
#include "capi.h"

// go_sign_self_cert builds a self-signed X.509 v3 certificate over the
// supplied TBS (to-be-signed) bytes using CryptSignAndEncodeCertificate.
// On success returns a malloc'd DER buffer; caller must free.
//
// `key_spec` is AT_KEYEXCHANGE (the only spec CryptoPro CSP exposes for
// GOST key generation via go_gen_gost_key).
//
// The TBS bytes are expected to contain a pre-built CERT_INFO structure
// encoded by CryptEncodeObjectEx(X509_CERT_TO_BE_SIGNED, ...). Higher
// level wrappers (CreateSelfSignedCert below) assemble the CERT_INFO from
// raw Go-side fields and pass the pointer.
static BYTE *go_sign_self_cert(HCRYPTPROV prov, DWORD key_spec,
                               PCERT_INFO cert_info,
                               const char *hash_oid,
                               DWORD *out_len) {
    CRYPT_ALGORITHM_IDENTIFIER sig_alg;
    memset(&sig_alg, 0, sizeof(sig_alg));
    sig_alg.pszObjId = (LPSTR)hash_oid;

    DWORD sz = 0;
    if (!CryptSignAndEncodeCertificate(prov, key_spec,
                                       X509_ASN_ENCODING,
                                       X509_CERT_TO_BE_SIGNED,
                                       cert_info, &sig_alg, NULL,
                                       NULL, &sz)) {
        return NULL;
    }
    BYTE *buf = (BYTE*)malloc(sz);
    if (buf == NULL) return NULL;
    if (!CryptSignAndEncodeCertificate(prov, key_spec,
                                       X509_ASN_ENCODING,
                                       X509_CERT_TO_BE_SIGNED,
                                       cert_info, &sig_alg, NULL,
                                       buf, &sz)) {
        free(buf);
        return NULL;
    }
    *out_len = sz;
    return buf;
}

// go_cert_context_from_der wraps CertCreateCertificateContext.
static PCCERT_CONTEXT go_cert_context_from_der(const BYTE *der, DWORD der_len) {
    return CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, der, der_len);
}

static void go_cert_free(PCCERT_CONTEXT ctx) {
    if (ctx != NULL) CertFreeCertificateContext(ctx);
}

// go_cert_verify_selfsigned checks that cert is a well-formed self-signed
// X.509 certificate using its own embedded public key.
static BOOL go_cert_verify_selfsigned(PCCERT_CONTEXT cert) {
    return CryptVerifyCertificateSignatureEx(
        0, X509_ASN_ENCODING,
        CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT, (void*)cert,
        CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void*)cert,
        0, NULL);
}

// go_cert_bind_key associates a CSP key container with a certificate via
// CERT_KEY_PROV_INFO_PROP_ID so that later CMS/CAdES signing paths can
// locate the private key starting only from the PCCERT_CONTEXT.
static BOOL go_cert_bind_key(PCCERT_CONTEXT cert, HCRYPTPROV prov,
                             DWORD key_spec) {
    CRYPT_KEY_PROV_INFO info;
    memset(&info, 0, sizeof(info));
    info.pwszContainerName = NULL; // ephemeral container
    info.pwszProvName      = NULL;
    info.dwProvType        = 0;
    info.dwFlags           = 0;
    info.cProvParam        = 0;
    info.rgProvParam       = NULL;
    info.dwKeySpec         = key_spec;
    (void)prov; // kept for signature symmetry; CSP uses default binding
    return CertSetCertificateContextProperty(
        cert, CERT_KEY_PROV_INFO_PROP_ID, 0, &info);
}

// go_name_encode encodes a simple distinguished name with the given
// common-name / org / country fields into an X509_ASN buffer via
// CertStrToNameA. Returns malloc'd buffer.
static BYTE *go_name_encode(const char *name_str, DWORD *out_len) {
    DWORD sz = 0;
    if (!CertStrToNameA(X509_ASN_ENCODING, name_str,
                        CERT_X500_NAME_STR, NULL, NULL, &sz, NULL)) {
        return NULL;
    }
    BYTE *buf = (BYTE*)malloc(sz);
    if (buf == NULL) return NULL;
    if (!CertStrToNameA(X509_ASN_ENCODING, name_str,
                        CERT_X500_NAME_STR, NULL, buf, &sz, NULL)) {
        free(buf);
        return NULL;
    }
    *out_len = sz;
    return buf;
}
*/
import "C"

import (
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
	"unsafe"
)

// X509Cert wraps a CryptoPro CSP PCCERT_CONTEXT. Mirrors the role of the
// legacy openssl.X509Cert wrapper; public API shape is preserved so that
// pkg/gostx509 and pkg/cms need only swap the import path.
type X509Cert struct {
	ctx C.PCCERT_CONTEXT
	// der keeps a Go-owned copy of the certificate DER for Marshal calls
	// and for use by the CAdES signer (which needs the cert bytes, not a
	// live handle).
	der []byte
}

// X509Request is intentionally declared but unimplemented under the
// CryptoPro CSP backend: CAPILite does not ship a PKCS#10 helper with
// GOST support in the public SDK. Callers that previously used CSR
// creation must produce the request out-of-band (e.g. via cryptcp).
type X509Request struct {
	der []byte
}

// X509Name is the distinguished-name struct pkg/gostx509 passes down.
type X509Name struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	Province           string
	Locality           string
}

// toCertStrName renders an X509Name as the "CN=foo, O=bar, ..." format
// accepted by CertStrToNameA.
func (n X509Name) toCertStrName() string {
	parts := make([]string, 0, 6)
	add := func(tag, value string) {
		if value == "" {
			return
		}
		// Escape embedded commas per RFC 4514.
		value = strings.ReplaceAll(value, `\`, `\\`)
		value = strings.ReplaceAll(value, `,`, `\,`)
		parts = append(parts, tag+"="+value)
	}
	add("CN", n.CommonName)
	add("O", n.Organization)
	add("OU", n.OrganizationalUnit)
	add("C", n.Country)
	add("ST", n.Province)
	add("L", n.Locality)
	return strings.Join(parts, ", ")
}

// CreateSelfSignedCert builds a self-signed X.509 v3 certificate bound
// to `privKey`. The returned X509Cert has both a live PCCERT_CONTEXT
// and the encoded DER bytes.
//
// Caveats under CryptoPro CSP:
//   - The TBS is assembled here with serial number, subject / issuer,
//     validity and public key. Extensions (basicConstraints, keyUsage)
//     are not emitted — the certificate is minimal, matching the legacy
//     openssl backend which emitted a bare v3 cert.
//   - The private key is bound to the cert via
//     CertSetCertificateContextProperty(CERT_KEY_PROV_INFO_PROP_ID) so
//     that CadesSignMessage can find it later.
func CreateSelfSignedCert(privKey *KeyHandle, subject X509Name,
	serial *big.Int, notBefore, notAfter time.Time, mdNID int) (*X509Cert, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	if privKey.IsNil() {
		return nil, errors.New("cryptopro: nil private key")
	}

	// 1. Encode distinguished name into an X509_ASN blob.
	nameStr := subject.toCertStrName()
	cName := C.CString(nameStr)
	defer C.free(unsafe.Pointer(cName))

	var nameLen C.DWORD
	nameBlob := C.go_name_encode(cName, &nameLen)
	if nameBlob == nil {
		return nil, cspError("CertStrToNameA")
	}
	defer C.free(unsafe.Pointer(nameBlob))

	// 2. Export public key info (CERT_PUBLIC_KEY_INFO) — CryptoPro CSP
	//    provides CryptExportPublicKeyInfoEx for this.
	var pkInfoLen C.DWORD
	if C.CryptExportPublicKeyInfoEx(privKey.hProv, C.AT_KEYEXCHANGE,
		C.X509_ASN_ENCODING, nil, 0, nil, nil, &pkInfoLen) == 0 {
		return nil, cspError("CryptExportPublicKeyInfoEx(size)")
	}
	pkInfoBuf := C.malloc(C.size_t(pkInfoLen))
	if pkInfoBuf == nil {
		return nil, errors.New("cryptopro: out of memory")
	}
	defer C.free(pkInfoBuf)
	pkInfo := (*C.CERT_PUBLIC_KEY_INFO)(pkInfoBuf)
	if C.CryptExportPublicKeyInfoEx(privKey.hProv, C.AT_KEYEXCHANGE,
		C.X509_ASN_ENCODING, nil, 0, nil, pkInfo, &pkInfoLen) == 0 {
		return nil, cspError("CryptExportPublicKeyInfoEx")
	}

	// 3. Build CERT_INFO.
	var certInfo C.CERT_INFO
	certInfo.dwVersion = C.CERT_V3

	// Serial number: copy bytes little-endian (CAPILite expects LE).
	serialBytes := serial.Bytes()
	if len(serialBytes) == 0 {
		serialBytes = []byte{1}
	}
	leSerial := make([]byte, len(serialBytes))
	for i, b := range serialBytes {
		leSerial[len(serialBytes)-1-i] = b
	}
	certInfo.SerialNumber.cbData = C.DWORD(len(leSerial))
	certInfo.SerialNumber.pbData = (*C.BYTE)(unsafe.Pointer(&leSerial[0]))

	// Signature algorithm — filled in by CryptSignAndEncodeCertificate.
	// Issuer == Subject for a self-signed cert.
	certInfo.Issuer.cbData = nameLen
	certInfo.Issuer.pbData = nameBlob
	certInfo.Subject.cbData = nameLen
	certInfo.Subject.pbData = nameBlob

	certInfo.NotBefore = goTimeToFiletime(notBefore)
	certInfo.NotAfter = goTimeToFiletime(notAfter)

	certInfo.SubjectPublicKeyInfo = *pkInfo

	// 4. Pick hash OID.
	var hashOID *C.char
	switch mdNID {
	case NID_Streebog256:
		hashOID = C.CString("1.2.643.7.1.1.3.2") // szOID_CP_GOST_R3411_12_256
	case NID_Streebog512:
		hashOID = C.CString("1.2.643.7.1.1.3.3") // szOID_CP_GOST_R3411_12_512
	default:
		return nil, errors.New("cryptopro: unsupported hash NID for X.509")
	}
	defer C.free(unsafe.Pointer(hashOID))

	// 5. Sign & encode.
	var derLen C.DWORD
	derPtr := C.go_sign_self_cert(privKey.hProv, C.AT_KEYEXCHANGE,
		&certInfo, hashOID, &derLen)
	if derPtr == nil {
		return nil, cspError("CryptSignAndEncodeCertificate")
	}
	defer C.free(unsafe.Pointer(derPtr))
	der := C.GoBytes(unsafe.Pointer(derPtr), C.int(derLen))

	// 6. Wrap into a CERT_CONTEXT and bind the private key.
	ctx := C.go_cert_context_from_der(
		(*C.BYTE)(unsafe.Pointer(&der[0])), C.DWORD(len(der)))
	if ctx == nil {
		return nil, cspError("CertCreateCertificateContext")
	}
	if C.go_cert_bind_key(ctx, privKey.hProv, C.AT_KEYEXCHANGE) == 0 {
		C.go_cert_free(ctx)
		return nil, cspError("CertSetCertificateContextProperty(KEY_PROV_INFO)")
	}

	return &X509Cert{ctx: ctx, der: der}, nil
}

// CreateCSR is not implemented under the CryptoPro CSP backend.
func CreateCSR(privKey *KeyHandle, subject X509Name, mdNID int) (*X509Request, error) {
	return nil, errors.New("cryptopro: CSR creation not implemented on CryptoPro CSP backend — use cryptcp or pkg/gostx509 with externally built CSR bytes")
}

// VerifyCert validates a certificate's signature using the supplied
// public-key handle.
func VerifyCert(cert *X509Cert, pubKey *KeyHandle) error {
	if cert == nil || cert.ctx == nil {
		return errors.New("cryptopro: nil certificate")
	}
	if pubKey.IsNil() {
		// No explicit issuer given → self-signed verification path.
		if C.go_cert_verify_selfsigned(cert.ctx) == 0 {
			return cspError("CryptVerifyCertificateSignatureEx(self)")
		}
		return nil
	}
	// For the explicit-issuer path we encode the pubKey as a
	// CERT_PUBLIC_KEY_INFO (via CryptExportPublicKeyInfoEx) and pass it
	// as the issuer key to CryptVerifyCertificateSignatureEx.
	var pkInfoLen C.DWORD
	if C.CryptExportPublicKeyInfoEx(pubKey.hProv, C.AT_KEYEXCHANGE,
		C.X509_ASN_ENCODING, nil, 0, nil, nil, &pkInfoLen) == 0 {
		return cspError("CryptExportPublicKeyInfoEx(size)")
	}
	pkInfoBuf := C.malloc(C.size_t(pkInfoLen))
	if pkInfoBuf == nil {
		return errors.New("cryptopro: out of memory")
	}
	defer C.free(pkInfoBuf)
	pkInfo := (*C.CERT_PUBLIC_KEY_INFO)(pkInfoBuf)
	if C.CryptExportPublicKeyInfoEx(pubKey.hProv, C.AT_KEYEXCHANGE,
		C.X509_ASN_ENCODING, nil, 0, nil, pkInfo, &pkInfoLen) == 0 {
		return cspError("CryptExportPublicKeyInfoEx")
	}
	rc := C.CryptVerifyCertificateSignatureEx(
		0, C.X509_ASN_ENCODING,
		C.CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT, unsafe.Pointer(cert.ctx),
		C.CRYPT_VERIFY_CERT_SIGN_ISSUER_PUBKEY, unsafe.Pointer(pkInfo),
		0, nil)
	if rc == 0 {
		return cspError("CryptVerifyCertificateSignatureEx")
	}
	return nil
}

// MarshalDER returns a Go-owned copy of the certificate DER.
func (c *X509Cert) MarshalDER() ([]byte, error) {
	if c == nil || len(c.der) == 0 {
		return nil, errors.New("cryptopro: nil certificate")
	}
	out := make([]byte, len(c.der))
	copy(out, c.der)
	return out, nil
}

// MarshalPEM wraps the DER in a "CERTIFICATE" PEM block.
func (c *X509Cert) MarshalPEM() ([]byte, error) {
	der, err := c.MarshalDER()
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// ParseCertDER parses a DER-encoded certificate into a CRYPT context.
func ParseCertDER(der []byte) (*X509Cert, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	if len(der) == 0 {
		return nil, errors.New("cryptopro: empty DER data")
	}
	ctx := C.go_cert_context_from_der(
		(*C.BYTE)(unsafe.Pointer(&der[0])), C.DWORD(len(der)))
	if ctx == nil {
		return nil, cspError("CertCreateCertificateContext")
	}
	copied := make([]byte, len(der))
	copy(copied, der)
	return &X509Cert{ctx: ctx, der: copied}, nil
}

// ParseCertPEM decodes a PEM-encoded certificate and forwards to ParseCertDER.
func ParseCertPEM(data []byte) (*X509Cert, error) {
	if len(data) == 0 {
		return nil, errors.New("cryptopro: empty PEM data")
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("cryptopro: no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("cryptopro: unexpected PEM block type %q", block.Type)
	}
	return ParseCertDER(block.Bytes)
}

// SubjectCN extracts the Common Name from the certificate. Implemented via
// CertGetNameStringA (which CryptoPro CSP exposes from libcapi20).
func (c *X509Cert) SubjectCN() string {
	if c == nil || c.ctx == nil {
		return ""
	}
	buf := make([]byte, 256)
	n := C.CertGetNameStringA(c.ctx,
		C.CERT_NAME_ATTR_TYPE,
		0,
		unsafe.Pointer(C.CString("2.5.4.3")), // OID commonName
		(*C.CHAR)(unsafe.Pointer(&buf[0])),
		C.DWORD(len(buf)))
	if n == 0 {
		return ""
	}
	return C.GoStringN((*C.char)(unsafe.Pointer(&buf[0])), C.int(n-1))
}

// IssuerCN extracts the Common Name from the certificate's issuer.
func (c *X509Cert) IssuerCN() string {
	if c == nil || c.ctx == nil {
		return ""
	}
	buf := make([]byte, 256)
	n := C.CertGetNameStringA(c.ctx,
		C.CERT_NAME_ATTR_TYPE,
		C.CERT_NAME_ISSUER_FLAG,
		unsafe.Pointer(C.CString("2.5.4.3")),
		(*C.CHAR)(unsafe.Pointer(&buf[0])),
		C.DWORD(len(buf)))
	if n == 0 {
		return ""
	}
	return C.GoStringN((*C.char)(unsafe.Pointer(&buf[0])), C.int(n-1))
}

// PublicKey is unsupported on the CryptoPro CSP backend for externally
// parsed certificates — CryptImportPublicKeyInfo would need a live
// provider that matches the GOST algorithm. The self-signed verify path
// handles its own needs via go_cert_verify_selfsigned.
func (c *X509Cert) PublicKey() (*KeyHandle, error) {
	return nil, errors.New("cryptopro: X509Cert.PublicKey() not implemented — use VerifyCert(cert, nil) for self-signed verification")
}

// Free releases the underlying CERT_CONTEXT and wipes the cached DER.
func (c *X509Cert) Free() {
	if c == nil {
		return
	}
	if c.ctx != nil {
		C.go_cert_free(c.ctx)
		c.ctx = nil
	}
	CleanseBytes(c.der)
	c.der = nil
}

// --- X509Request ---

// MarshalDER returns the raw CSR bytes (only populated if the request was
// built out-of-band and imported with ParseCSR).
func (r *X509Request) MarshalDER() ([]byte, error) {
	if r == nil || len(r.der) == 0 {
		return nil, errors.New("cryptopro: empty CSR")
	}
	out := make([]byte, len(r.der))
	copy(out, r.der)
	return out, nil
}

// MarshalPEM wraps the request in a PEM block.
func (r *X509Request) MarshalPEM() ([]byte, error) {
	der, err := r.MarshalDER()
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// Free clears the cached DER bytes.
func (r *X509Request) Free() {
	if r == nil {
		return
	}
	CleanseBytes(r.der)
	r.der = nil
}

// --- helpers ---

// goTimeToFiletime converts a Go time.Time into a Windows FILETIME
// (number of 100-ns intervals since 1601-01-01 UTC). CAPILite CERT_INFO
// uses FILETIME for NotBefore / NotAfter.
func goTimeToFiletime(t time.Time) C.FILETIME {
	const (
		ticksPerSecond = int64(10000000)
		epochDiff      = int64(116444736000000000) // 1601→1970 in 100-ns ticks
	)
	ticks := t.UTC().UnixNano()/100 + epochDiff
	return C.FILETIME{
		dwLowDateTime:  C.DWORD(ticks & 0xFFFFFFFF),
		dwHighDateTime: C.DWORD((ticks >> 32) & 0xFFFFFFFF),
	}
}
