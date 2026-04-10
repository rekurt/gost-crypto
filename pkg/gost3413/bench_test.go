package gost3413

import (
	"crypto/rand"
	"testing"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

func skipBenchIfNoEngine(b *testing.B) {
	b.Helper()
	if err := openssl.Init(); err != nil {
		b.Skip("gost-engine not available:", err)
	}
}

const benchPayload = 1024

func randomBytes(b *testing.B, n int) []byte {
	b.Helper()
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		b.Fatal(err)
	}
	return out
}

// --- CBC ---

func BenchmarkKuznechikCBC_Encrypt_1KB(b *testing.B) {
	skipBenchIfNoEngine(b)
	key := randomBytes(b, 32)
	cbc, err := NewKuznechikCBC(key)
	if err != nil {
		b.Fatal(err)
	}
	iv := randomBytes(b, 16)
	pt := make([]byte, benchPayload)
	b.SetBytes(benchPayload)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cbc.Encrypt(iv, pt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKuznechikCBC_Decrypt_1KB(b *testing.B) {
	skipBenchIfNoEngine(b)
	key := randomBytes(b, 32)
	cbc, err := NewKuznechikCBC(key)
	if err != nil {
		b.Fatal(err)
	}
	iv := randomBytes(b, 16)
	ct, err := cbc.Encrypt(iv, make([]byte, benchPayload))
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(benchPayload)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cbc.Decrypt(iv, ct); err != nil {
			b.Fatal(err)
		}
	}
}

// --- CTR ---

func BenchmarkKuznechikCTR_Encrypt_1KB(b *testing.B) {
	skipBenchIfNoEngine(b)
	key := randomBytes(b, 32)
	ctr, err := NewKuznechikCTR(key)
	if err != nil {
		b.Fatal(err)
	}
	iv := randomBytes(b, 8)
	pt := make([]byte, benchPayload)
	b.SetBytes(benchPayload)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ctr.Encrypt(iv, pt); err != nil {
			b.Fatal(err)
		}
	}
}

// --- CMAC ---

func BenchmarkKuznechikCMAC_1KB(b *testing.B) {
	skipBenchIfNoEngine(b)
	key := randomBytes(b, 32)
	cmac, err := NewKuznechikCMAC(key)
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, benchPayload)
	b.SetBytes(benchPayload)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cmac.MAC(msg); err != nil {
			b.Fatal(err)
		}
	}
}

// --- MGM AEAD (Kuznechik) ---

func BenchmarkKuznechikMGM_Seal_1KB(b *testing.B) {
	skipBenchIfNoEngine(b)
	key := randomBytes(b, 32)
	aead, err := NewKuznechikMGMFromKey(key)
	if err != nil {
		b.Fatal(err)
	}
	nonce := randomBytes(b, aead.NonceSize())
	pt := make([]byte, benchPayload)
	var dst []byte
	b.SetBytes(benchPayload)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = aead.Seal(dst[:0], nonce, pt, nil)
	}
}

func BenchmarkKuznechikMGM_Open_1KB(b *testing.B) {
	skipBenchIfNoEngine(b)
	key := randomBytes(b, 32)
	aead, err := NewKuznechikMGMFromKey(key)
	if err != nil {
		b.Fatal(err)
	}
	nonce := randomBytes(b, aead.NonceSize())
	ct := aead.Seal(nil, nonce, make([]byte, benchPayload), nil)
	var dst []byte
	b.SetBytes(benchPayload)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		dst, err = aead.Open(dst[:0], nonce, ct, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
