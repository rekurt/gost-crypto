//go:build cgo && linux && cryptopro
// +build cgo,linux,cryptopro

package cryptopro

/*
#cgo CFLAGS: -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/cades
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi10 -lcapi20 -lssp -lrdrsup -lcades
#include "capi.h"

// go_acquire_verify_context opens a CSP context with CRYPT_VERIFYCONTEXT.
// This flag tells CryptoPro CSP that we do not need access to any
// persistent key container — only ephemeral session / verify operations.
// That is what gost-crypto needs: all key material is passed through the
// BLOB API, nothing is ever persisted.
static BOOL go_acquire_verify_context(HCRYPTPROV *prov, DWORD prov_type) {
    return CryptAcquireContextA(prov, NULL, NULL, prov_type, CRYPT_VERIFYCONTEXT);
}
*/
import "C"

import (
	"errors"
	"sync"
)

// ErrCSPNotAvailable is returned when CryptoPro CSP cannot be initialised.
// This typically means the CSP is not installed, the licence is missing,
// or libcapi10.so / libcapi20.so are not on the dynamic-linker path.
var ErrCSPNotAvailable = errors.New(
	"cryptopro: CryptoPro CSP not available — " +
		"install CryptoPro CSP 5.0+ for Linux and ensure libcapi10/libcapi20/libcades are on LD_LIBRARY_PATH",
)

var (
	initOnce sync.Once
	initErr  error

	// globalProv256 is a shared HCRYPTPROV for 256-bit GOST R 34.10-2012.
	// Acquired with CRYPT_VERIFYCONTEXT so no key container is touched.
	globalProv256 C.HCRYPTPROV

	// globalProv512 is the same for 512-bit GOST R 34.10-2012.
	globalProv512 C.HCRYPTPROV
)

// Init initialises CryptoPro CSP lazily. Safe for concurrent callers.
// Subsequent calls return the cached error. Returns nil on success.
func Init() error {
	initOnce.Do(func() {
		if C.go_acquire_verify_context(&globalProv256,
			C.DWORD(C.PROV_GOST_2012_256)) == 0 {
			initErr = ErrCSPNotAvailable
			return
		}
		if C.go_acquire_verify_context(&globalProv512,
			C.DWORD(C.PROV_GOST_2012_512)) == 0 {
			// Release the 256-bit context we already have.
			C.CryptReleaseContext(globalProv256, 0)
			globalProv256 = 0
			initErr = ErrCSPNotAvailable
			return
		}
	})
	return initErr
}

// providerForSignNID returns the shared verify-context HCRYPTPROV that
// matches the given GOST R 34.10-2012 NID (256 vs 512 bit).
//
// The caller must have already called Init() successfully.
func providerForSignNID(signNID int) C.HCRYPTPROV {
	if signNID == NID_GostR3410_2012_512 {
		return globalProv512
	}
	return globalProv256
}

// providerForCurveSize returns the shared provider matching the raw curve
// size (32 bytes → 256-bit, 64 bytes → 512-bit). Convenience for callers
// that do not track the NID separately.
func providerForCurveSize(keySize int) C.HCRYPTPROV {
	if keySize >= 64 {
		return globalProv512
	}
	return globalProv256
}
