//go:build cgo && linux && cryptopro
// +build cgo,linux,cryptopro

package cryptopro

/*
#cgo CFLAGS: -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/cades
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi10 -lcapi20 -lssp -lrdrsup -lcades
#include "capi.h"
#include <string.h>

// explicit_bzero is the glibc primitive for guaranteed memory wiping; it
// is not optimised away by the compiler. Available on Linux >= glibc 2.25.
static void go_explicit_bzero(void *p, size_t n) {
    if (p != NULL && n > 0) {
        explicit_bzero(p, n);
    }
}
*/
import "C"

import "unsafe"

// Cleanse zeroes a memory region through glibc's explicit_bzero, which the
// C compiler is forbidden from optimising away. This matches the contract
// of the legacy openssl.Cleanse() used throughout pkg/*.
func Cleanse(ptr unsafe.Pointer, length int) {
	if ptr == nil || length <= 0 {
		return
	}
	C.go_explicit_bzero(ptr, C.size_t(length))
}

// CleanseBytes zeroes a Go byte slice in place. Safe to call on nil / empty
// slices.
func CleanseBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	C.go_explicit_bzero(unsafe.Pointer(&b[0]), C.size_t(len(b)))
}
