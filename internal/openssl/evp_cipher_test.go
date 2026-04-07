package openssl

import "testing"

func TestCipherCtxInitEncryptRejectsShortKeyAndIV(t *testing.T) {
	if err := Init(); err != nil {
		t.Skipf("gost-engine not available: %v", err)
	}

	ctx, err := NewCipherCtx()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Close()

	if err := ctx.InitEncrypt(NID_Kuznechik_MGM, make([]byte, 31), make([]byte, 15)); err == nil {
		t.Fatal("InitEncrypt accepted short key/iv")
	}
}

func TestCipherCtxInitDecryptRejectsShortKeyAndIV(t *testing.T) {
	if err := Init(); err != nil {
		t.Skipf("gost-engine not available: %v", err)
	}

	ctx, err := NewCipherCtx()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Close()

	if err := ctx.InitDecrypt(NID_Kuznechik_MGM, make([]byte, 31), make([]byte, 15)); err == nil {
		t.Fatal("InitDecrypt accepted short key/iv")
	}
}

