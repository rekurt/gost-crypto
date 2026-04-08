package openssl

/*
#include <openssl/objects.h>
#include <stdlib.h>
*/
import "C"
import (
	"sync"
	"unsafe"
)

var (
	nidOnce sync.Once

	NID_Streebog256 int
	NID_Streebog512 int

	NID_GostR3410_2012_256 int
	NID_GostR3410_2012_512 int

	NID_Kuznechik_ECB       int
	NID_Kuznechik_CTR       int
	NID_Kuznechik_CBC       int
	NID_Kuznechik_CFB       int
	NID_Kuznechik_OFB       int
	NID_Kuznechik_MGM       int
	NID_Kuznechik_CTR_ACPKM int

	NID_Magma_ECB       int
	NID_Magma_CTR       int
	NID_Magma_CBC       int
	NID_Magma_CFB       int
	NID_Magma_MGM       int
	NID_Magma_CTR_ACPKM int

	// CurveOIDs maps Curve index to OID string for all 8 TC26 parameter sets.
	CurveOIDs = [8]string{
		"1.2.643.7.1.2.1.1.1", // TC26-256-A
		"1.2.643.2.2.35.1",    // TC26-256-B (CryptoPro-A)
		"1.2.643.2.2.35.2",    // TC26-256-C (CryptoPro-B)
		"1.2.643.2.2.35.3",    // TC26-256-D (CryptoPro-C)
		"1.2.643.7.1.2.1.2.1", // TC26-512-A
		"1.2.643.7.1.2.1.2.2", // TC26-512-B
		"1.2.643.7.1.2.1.2.3", // TC26-512-C
		"1.2.643.7.1.2.1.2.0", // TC26-512-D (test)
	}
)

func resolveNIDs() {
	nidOnce.Do(func() {
		NID_Streebog256 = txt2nid("md_gost12_256")
		NID_Streebog512 = txt2nid("md_gost12_512")
		NID_GostR3410_2012_256 = txt2nid("gost2012_256")
		NID_GostR3410_2012_512 = txt2nid("gost2012_512")
		NID_Kuznechik_ECB = txt2nid("kuznyechik-ecb")
		NID_Kuznechik_CTR = txt2nid("kuznyechik-ctr")
		NID_Kuznechik_CBC = txt2nid("kuznyechik-cbc")
		NID_Kuznechik_CFB = txt2nid("kuznyechik-cfb")
		NID_Kuznechik_OFB = txt2nid("kuznyechik-ofb")
		NID_Kuznechik_MGM = txt2nid("kuznyechik-mgm")
		NID_Kuznechik_CTR_ACPKM = txt2nid("kuznyechik-ctr-acpkm")

		NID_Magma_ECB = txt2nid("magma-ecb")
		NID_Magma_CTR = txt2nid("magma-ctr")
		NID_Magma_CBC = txt2nid("magma-cbc")
		NID_Magma_CFB = txt2nid("magma-cfb")
		NID_Magma_MGM = txt2nid("magma-mgm")
		NID_Magma_CTR_ACPKM = txt2nid("magma-ctr-acpkm")
	})
}

func txt2nid(name string) int {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	return int(C.OBJ_txt2nid(cName))
}
