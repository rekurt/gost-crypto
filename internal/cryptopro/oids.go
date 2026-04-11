//go:build cgo && linux && cryptopro
// +build cgo,linux,cryptopro

package cryptopro

/*
#cgo CFLAGS: -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/cades
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi10 -lcapi20 -lssp -lrdrsup -lcades
#include "capi.h"
*/
import "C"

// Algorithm identifiers surfaced to the rest of the project.
//
// Historically the internal/openssl backend exposed these as `NID_*`
// package variables resolved at runtime via OBJ_txt2nid(). The CryptoPro
// CSP backend uses ALG_ID constants (32-bit integers) known at compile time,
// so we promote them to typed `int` package-level constants and keep the
// `NID_*` names to minimise churn in pkg/* call sites.
//
// For cipher modes that CryptoPro CSP does not implement natively
// (CTR / CFB / OFB / MGM / ACPKM), we assign private sentinel values
// > 0x10000000 and dispatch them to Go-level software implementations
// in `pkg/gost3413`.
const (
	// Streebog digests.
	NID_Streebog256 = int(C.CALG_GR3411_2012_256)
	NID_Streebog512 = int(C.CALG_GR3411_2012_512)

	// GOST R 34.10-2012 signature algorithms.
	NID_GostR3410_2012_256 = int(C.CALG_GR3410_2012_256)
	NID_GostR3410_2012_512 = int(C.CALG_GR3410_2012_512)

	// Kuznechik (GOST R 34.12-2015, 128-bit block).
	// Only ECB is native in CAPILite; higher modes are implemented in Go
	// on top of the raw ECB block cipher (see pkg/gost3413).
	NID_Kuznechik_ECB       = int(C.CALG_GR3412_2015_K)
	NID_Kuznechik_CBC       = 0x10000001 // software-CBC dispatch
	NID_Kuznechik_CTR       = 0x10000002
	NID_Kuznechik_CFB       = 0x10000003
	NID_Kuznechik_OFB       = 0x10000004
	NID_Kuznechik_MGM       = 0x10000005
	NID_Kuznechik_CTR_ACPKM = 0x10000006

	// Magma (GOST R 34.12-2015, 64-bit block).
	NID_Magma_ECB       = int(C.CALG_GR3412_2015_M)
	NID_Magma_CBC       = 0x10000011
	NID_Magma_CTR       = 0x10000012
	NID_Magma_CFB       = 0x10000013
	NID_Magma_OFB       = 0x10000014
	NID_Magma_MGM       = 0x10000015
	NID_Magma_CTR_ACPKM = 0x10000016

	// MAC / IMIT algorithms.
	NID_Kuznechik_IMIT = int(C.CALG_GR3412_2015_K_IMIT)
	NID_Magma_IMIT     = int(C.CALG_GR3412_2015_M_IMIT)
	NID_G28147_IMIT    = int(C.CALG_G28147_IMIT)

	// HMAC-Streebog identifiers.
	NID_HMAC_Streebog256 = int(C.CALG_PRO_HMAC_2012_256)
	NID_HMAC_Streebog512 = int(C.CALG_PRO_HMAC_2012_512)
)

// IsSoftwareMode reports whether the given cipher NID is a placeholder that
// must be dispatched to a Go-level software implementation rather than a
// native CryptoPro CSP mode. Used by pkg/gost3413 to decide the code path.
func IsSoftwareMode(nid int) bool {
	return nid >= 0x10000000
}

// CurveOIDs maps the 8 TC26 parameter-set indices (matching
// pkg/gost3410.Curve) to CryptoPro CSP OID strings. These OIDs are the
// same TC26 / CryptoPro OIDs used by OpenSSL gost-engine and are accepted
// by CryptAcquireContextA / CryptSetKeyParam(KP_DHOID).
var CurveOIDs = [8]string{
	"1.2.643.7.1.2.1.1.1", // TC26-256-A
	"1.2.643.2.2.35.1",    // TC26-256-B (CryptoPro-A)
	"1.2.643.2.2.35.2",    // TC26-256-C (CryptoPro-B)
	"1.2.643.2.2.35.3",    // TC26-256-D (CryptoPro-C)
	"1.2.643.7.1.2.1.2.1", // TC26-512-A
	"1.2.643.7.1.2.1.2.2", // TC26-512-B
	"1.2.643.7.1.2.1.2.3", // TC26-512-C
	"1.2.643.7.1.2.1.2.0", // TC26-512-D (test curve)
}

// providerTypeForSignNID picks the CryptoPro CSP provider type that matches
// a given GOST R 34.10-2012 sign NID. Used by the key-generation path.
func providerTypeForSignNID(signNID int) C.DWORD {
	if signNID == NID_GostR3410_2012_512 {
		return C.DWORD(C.PROV_GOST_2012_512)
	}
	return C.DWORD(C.PROV_GOST_2012_256)
}
