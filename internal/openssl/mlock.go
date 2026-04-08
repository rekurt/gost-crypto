package openssl

import (
	"sync"
	"syscall"
	"unsafe"
)

// mlockEnabled tracks whether mlock operations should be attempted.
// If the first mlock call fails (e.g., due to RLIMIT_MEMLOCK), further
// attempts are skipped to avoid log spam.
var (
	mlockOnce    sync.Once
	mlockEnabled bool
)

func initMlock() {
	mlockOnce.Do(func() {
		// Test if mlock is available by locking and unlocking a small buffer.
		var test [64]byte
		ptr := unsafe.Pointer(&test[0])
		err := syscall.Mlock(unsafe.Slice((*byte)(ptr), len(test)))
		if err == nil {
			_ = syscall.Munlock(unsafe.Slice((*byte)(ptr), len(test)))
			mlockEnabled = true
		}
		// If mlock is not available (non-root, RLIMIT_MEMLOCK=0), degrade
		// gracefully — keys will still be zeroized but may appear in swap.
	})
}

// MlockBytes locks a byte slice in physical memory, preventing it from
// being swapped to disk. This protects key material from appearing in
// swap partitions or core dumps.
//
// NOTE: This relies on Go's non-moving garbage collector for heap objects.
// As of Go 1.22, the GC does not relocate heap-allocated objects, so the
// memory address passed to mlock remains stable. If a future Go version
// introduces a moving GC, this approach would need to be revised (e.g.,
// allocating key buffers via C.malloc instead of Go arrays).
//
// If mlock is not available (insufficient privileges or resource limits),
// the call silently succeeds — the security degradation is acceptable
// as a fallback. Use MlockAvailable() to check.
func MlockBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	initMlock()
	if !mlockEnabled {
		return
	}
	// Best-effort: ignore errors (may fail for large allocations).
	_ = syscall.Mlock(b)
}

// MunlockBytes unlocks a previously locked byte slice, allowing it to
// be swapped again. Should be called after CleanseBytes to release
// the physical memory reservation.
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

// MlockAvailable returns true if mlock is operational on this system.
// Returns false if insufficient privileges or resource limits prevent
// memory locking.
func MlockAvailable() bool {
	initMlock()
	return mlockEnabled
}
