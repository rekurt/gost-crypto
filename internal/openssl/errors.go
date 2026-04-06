package openssl

/*
#include <openssl/err.h>
*/
import "C"
import "fmt"

// OpenSSLError wraps an error from the OpenSSL error queue.
type OpenSSLError struct {
	Op    string // OpenSSL function name
	Code  uint32 // OpenSSL error code
	Text  string // Human-readable from ERR_error_string_n
	Cause error  // Optional wrapped error
}

func (e *OpenSSLError) Error() string {
	if e.Text != "" {
		return fmt.Sprintf("openssl: %s failed: %s (code=0x%x)", e.Op, e.Text, e.Code)
	}
	return fmt.Sprintf("openssl: %s failed (code=0x%x)", e.Op, e.Code)
}

func (e *OpenSSLError) Unwrap() error {
	return e.Cause
}

// fmtSSLError drains the OpenSSL error queue and returns an *OpenSSLError.
func fmtSSLError(op string) error {
	code := C.ERR_get_error()
	if code == 0 {
		return &OpenSSLError{Op: op, Code: 0, Text: "unknown error (empty queue)"}
	}
	var buf [256]C.char
	C.ERR_error_string_n(C.ulong(code), &buf[0], C.size_t(len(buf)))
	text := C.GoString(&buf[0])
	for C.ERR_get_error() != 0 {
	}
	return &OpenSSLError{Op: op, Code: uint32(code), Text: text}
}

// FmtSSLError is the exported version for use by pkg/* packages.
func FmtSSLError(op string) error {
	return fmtSSLError(op)
}

// drainSSLErrors clears all pending errors from the OpenSSL error queue.
func drainSSLErrors() {
	for C.ERR_get_error() != 0 {
	}
}
