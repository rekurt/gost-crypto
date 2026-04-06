package openssl

/*
#cgo pkg-config: libcrypto
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"sync"
	"unsafe"
)

var (
	initOnce   sync.Once
	initErr    error
	gostEngine *C.ENGINE
)

// ErrEngineNotLoaded indicates gost-engine is not available.
var ErrEngineNotLoaded = errors.New("openssl: gost-engine not available — install gost-engine and configure openssl.cnf")

// Init initializes OpenSSL and loads gost-engine. Thread-safe, idempotent.
func Init() error {
	initOnce.Do(func() {
		C.OPENSSL_init_crypto(
			C.OPENSSL_INIT_ADD_ALL_CIPHERS|
				C.OPENSSL_INIT_ADD_ALL_DIGESTS|
				C.OPENSSL_INIT_LOAD_CONFIG,
			nil,
		)

		name := C.CString("gost")
		defer C.free(unsafe.Pointer(name))

		gostEngine = C.ENGINE_by_id(name)
		if gostEngine == nil {
			drainSSLErrors()
			initErr = ErrEngineNotLoaded
			return
		}

		if C.ENGINE_init(gostEngine) != 1 {
			initErr = fmtSSLError("ENGINE_init")
			C.ENGINE_free(gostEngine)
			gostEngine = nil
			return
		}

		C.ENGINE_set_default(gostEngine, C.ENGINE_METHOD_ALL)
		resolveNIDs()
	})
	return initErr
}

// GostEngine returns the loaded engine handle for pkg/* packages.
func GostEngine() *C.ENGINE {
	return gostEngine
}

// Cleanse zeroes memory using OPENSSL_cleanse (not optimized away by compiler).
func Cleanse(ptr unsafe.Pointer, length int) {
	if ptr != nil && length > 0 {
		C.OPENSSL_cleanse(ptr, C.size_t(length))
	}
}

// CleanseBytes zeroes a byte slice using OPENSSL_cleanse.
func CleanseBytes(b []byte) {
	if len(b) > 0 {
		Cleanse(unsafe.Pointer(&b[0]), len(b))
	}
}
