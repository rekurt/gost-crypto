//go:build cgo && linux && cryptopro
// +build cgo,linux,cryptopro

package cryptopro

/*
#cgo CFLAGS: -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/cades
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi10 -lcapi20 -lssp -lrdrsup -lcades
#include "capi.h"
*/
import "C"

import (
	"errors"
	"runtime"
)

// KeyHandle is an opaque wrapper around a CryptoPro CSP HCRYPTKEY plus the
// HCRYPTPROV used to create it. The pair is needed because most CAPILite
// APIs that take an HCRYPTKEY also implicitly use the originating provider.
//
// KeyHandle is what the rest of the project passes around as "a GOST key"
// — this mirrors the role of the EVP_PKEY wrapper in the old openssl
// backend. The public pkg/gost3410.PrivKey stores a *KeyHandle.
type KeyHandle struct {
	hKey  C.HCRYPTKEY
	hProv C.HCRYPTPROV
	// ownsProv indicates whether Free() should release hProv. For keys
	// generated via GenerateGOSTKeyHandle the provider is a dedicated
	// per-key context (so we own it); for keys imported into a shared
	// verify-context the provider is global and must not be released.
	ownsProv bool
	// signNID / keySize cached for fast access by consumer packages.
	signNID int
	keySize int
}

// NewKeyHandle wraps a raw HCRYPTKEY / HCRYPTPROV pair in a KeyHandle with
// a finalizer safety net. Callers should still invoke Free() explicitly.
func NewKeyHandle(hProv C.HCRYPTPROV, hKey C.HCRYPTKEY, signNID, keySize int, ownsProv bool) *KeyHandle {
	h := &KeyHandle{
		hProv:    hProv,
		hKey:     hKey,
		signNID:  signNID,
		keySize:  keySize,
		ownsProv: ownsProv,
	}
	runtime.SetFinalizer(h, (*KeyHandle).finalize)
	return h
}

// Free releases the underlying HCRYPTKEY (and HCRYPTPROV, if we own it).
// Safe to call multiple times.
func (h *KeyHandle) Free() {
	if h == nil {
		return
	}
	if h.hKey != 0 {
		C.CryptDestroyKey(h.hKey)
		h.hKey = 0
	}
	if h.ownsProv && h.hProv != 0 {
		C.CryptReleaseContext(h.hProv, 0)
		h.hProv = 0
	}
	runtime.SetFinalizer(h, nil)
}

// IsNil reports whether the handle is absent or has already been freed.
func (h *KeyHandle) IsNil() bool {
	return h == nil || h.hKey == 0
}

func (h *KeyHandle) finalize() {
	if h == nil {
		return
	}
	if h.hKey != 0 {
		C.CryptDestroyKey(h.hKey)
		h.hKey = 0
	}
	if h.ownsProv && h.hProv != 0 {
		C.CryptReleaseContext(h.hProv, 0)
		h.hProv = 0
	}
}

// errNilKeyHandle is the sentinel used when pkg/* passes a freed / zero
// handle to an internal function. The public packages translate this to
// their own ErrNilKey.
var errNilKeyHandle = errors.New("cryptopro: nil key handle")

// --- Thin wrappers that pkg/gost3410 calls via the `*H` suffix ---
//
// These forward to the underlying gost3410.go / vko.go entry points and
// mirror the shape of the old openssl package (SignDigestH, VerifyDigestH,
// ExtractRawPrivKeyH, ExtractRawPubKeyH, ValidatePublicKeyH). They are kept
// separate from key.go for readability; the actual implementations live
// alongside the algorithms they exercise.

// ValidatePublicKeyH is a no-op under CryptoPro CSP: the CSP validates
// parameters at import time (CryptImportKey fails with NTE_BAD_KEY for
// invalid points). We keep the function so pkg/gost3410 compiles without
// branching on the backend.
func ValidatePublicKeyH(h *KeyHandle) error {
	if h.IsNil() {
		return errNilKeyHandle
	}
	return nil
}
