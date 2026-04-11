//go:build cgo && linux && cryptopro
// +build cgo,linux,cryptopro

package cryptopro

import (
	"sync"
	"syscall"
)

// mlockEnabled tracks whether mlock operations should be attempted.
// If the first mlock call fails (e.g. RLIMIT_MEMLOCK=0) further attempts
// are skipped to avoid log spam. This mirrors the legacy openssl package
// behaviour so that pkg/* consumers can continue to call MlockBytes
// unconditionally.
var (
	mlockOnce    sync.Once
	mlockEnabled bool
)

func initMlock() {
	mlockOnce.Do(func() {
		var test [64]byte
		if err := syscall.Mlock(test[:]); err == nil {
			_ = syscall.Munlock(test[:])
			mlockEnabled = true
		}
	})
}

// MlockBytes pins a byte slice in physical memory so its contents cannot
// be paged out to swap. Best effort — if mlock is unavailable (RLIMIT
// restrictions or non-root) the call silently degrades.
func MlockBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	initMlock()
	if !mlockEnabled {
		return
	}
	_ = syscall.Mlock(b)
}

// MunlockBytes releases a prior MlockBytes pin.
func MunlockBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	initMlock()
	if !mlockEnabled {
		return
	}
	_ = syscall.Munlock(b)
}

// MlockAvailable reports whether mlock is operational on this system.
func MlockAvailable() bool {
	initMlock()
	return mlockEnabled
}
