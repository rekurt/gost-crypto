package openssl

import (
	"errors"
	"testing"
)

func TestOpenSSLError_Error(t *testing.T) {
	e := &OpenSSLError{Op: "EVP_DigestInit", Code: 0x1234, Text: "unsupported digest"}
	got := e.Error()
	want := "openssl: EVP_DigestInit failed: unsupported digest (code=0x1234)"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestOpenSSLError_Unwrap(t *testing.T) {
	sentinel := errors.New("base error")
	e := &OpenSSLError{Op: "test", Cause: sentinel}
	if !errors.Is(e, sentinel) {
		t.Error("expected Unwrap to return Cause")
	}
}

func TestInit_LoadsEngine(t *testing.T) {
	if err := Init(); err != nil {
		t.Skipf("gost-engine not available: %v (expected in CI, not locally)", err)
	}
	if NID_Streebog256 == 0 {
		t.Error("NID_Streebog256 not resolved after Init()")
	}
	if NID_Streebog512 == 0 {
		t.Error("NID_Streebog512 not resolved after Init()")
	}
	if NID_GostR3410_2012_256 == 0 {
		t.Error("NID_GostR3410_2012_256 not resolved")
	}
}

func TestInit_IsIdempotent(t *testing.T) {
	err1 := Init()
	err2 := Init()
	if err1 != err2 {
		t.Errorf("Init not idempotent: %v vs %v", err1, err2)
	}
}
