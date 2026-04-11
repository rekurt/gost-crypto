//go:build cgo && linux && cryptopro
// +build cgo,linux,cryptopro

package cryptopro

/*
#cgo CFLAGS: -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/cades
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi10 -lcapi20 -lssp -lrdrsup -lcades
#include "capi.h"
*/
import "C"

import "fmt"

// CSPError wraps a CryptoPro CSP / CAPILite / CAdES error surfaced from a
// Cxxx function via GetLastError(). Code is the HRESULT / NTSTATUS value.
type CSPError struct {
	Op    string // CSP function name (e.g. "CryptAcquireContextA")
	Code  uint32 // CryptoPro / Windows-style error code
	Text  string // Best-effort human-readable message
	Cause error  // Optional wrapped error
}

func (e *CSPError) Error() string {
	if e.Text != "" {
		return fmt.Sprintf("cryptopro: %s failed: %s (0x%08x)", e.Op, e.Text, e.Code)
	}
	return fmt.Sprintf("cryptopro: %s failed (0x%08x)", e.Op, e.Code)
}

func (e *CSPError) Unwrap() error { return e.Cause }

// knownCSPErrors maps the most common CryptoPro / CAPILite HRESULTs to a
// short human-readable description. This is intentionally not exhaustive —
// it covers the errors we expect to see from routine operations. Unknown
// codes are still surfaced with their hex value.
//
// Sources: CryptoPro CSP 5.0 developer guide, WinCryptEx.h, cades errors.
var knownCSPErrors = map[uint32]string{
	0x80090001: "NTE_BAD_UID — bad UID",
	0x80090002: "NTE_BAD_HASH — hash parameter invalid",
	0x80090003: "NTE_BAD_KEY — key parameter invalid",
	0x80090004: "NTE_BAD_LEN — bad length",
	0x80090005: "NTE_BAD_DATA — bad data",
	0x80090006: "NTE_BAD_SIGNATURE — invalid signature",
	0x80090007: "NTE_BAD_VER — bad version",
	0x80090008: "NTE_BAD_ALGID — unknown algorithm identifier",
	0x80090009: "NTE_BAD_FLAGS — bad flags",
	0x8009000A: "NTE_BAD_TYPE — bad type",
	0x8009000B: "NTE_BAD_KEY_STATE — key not in correct state",
	0x8009000C: "NTE_BAD_HASH_STATE — hash not in correct state",
	0x8009000D: "NTE_NO_KEY — no key",
	0x8009000E: "NTE_NO_MEMORY — out of memory",
	0x8009000F: "NTE_EXISTS — already exists",
	0x80090010: "NTE_PERM — access denied",
	0x80090011: "NTE_NOT_FOUND — object not found",
	0x80090016: "NTE_KEYSET_NOT_DEF — keyset not defined",
	0x80090019: "NTE_KEYSET_ENTRY_BAD — keyset entry bad",
	0x80090020: "NTE_FAIL — generic failure",
	0x8009001D: "NTE_PROV_DLL_NOT_FOUND — CSP provider DLL not found",
	0x8009001F: "NTE_PROVIDER_DLL_FAIL — CSP provider DLL failed",
	0x80090021: "NTE_SYS_ERR — system error",
	0x80091004: "CRYPT_E_INVALID_MSG_TYPE — invalid CMS message type",
	0x80091008: "CRYPT_E_BAD_ENCODE — bad encoding",
	0x8009100B: "CRYPT_E_NOT_FOUND — object not found",
	0x8009100E: "CRYPT_E_UNEXPECTED_MSG_TYPE",
	0x80091010: "CRYPT_E_UNKNOWN_ALGO",
	0x80091012: "CRYPT_E_SIGNER_NOT_FOUND",
	0x80091014: "CRYPT_E_NO_SIGNER",
	0x80092002: "CRYPT_E_BAD_MSG — invalid CMS message",
	0x80092004: "CRYPT_E_NO_MATCH — no matching cert / key",
	0x80092026: "CRYPT_E_SECURITY_SETTINGS — security settings prevent operation",
}

// cspError builds a CSPError from the most recent CryptoPro error via
// GetLastError(). It should be called immediately after a failing C API.
// Never returns nil.
func cspError(op string) error {
	code := uint32(C.GetLastError())
	text, ok := knownCSPErrors[code]
	if !ok {
		text = "unknown CryptoPro error code"
	}
	return &CSPError{Op: op, Code: code, Text: text}
}

// cspErrorWithCode builds a CSPError from an explicit code (useful when the
// error came from a function return rather than GetLastError).
func cspErrorWithCode(op string, code uint32) error {
	text, ok := knownCSPErrors[code]
	if !ok {
		text = "unknown CryptoPro error code"
	}
	return &CSPError{Op: op, Code: code, Text: text}
}

// FmtCSPError is the exported variant for consumers that need to fabricate
// a CSPError without direct access to the unexported helper.
func FmtCSPError(op string) error { return cspError(op) }
