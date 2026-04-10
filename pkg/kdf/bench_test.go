package kdf

import (
	"testing"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

func skipBenchIfNoEngine(b *testing.B) {
	b.Helper()
	if err := openssl.Init(); err != nil {
		b.Skip("gost-engine not available:", err)
	}
}

func BenchmarkKDF_GOSTR3411_256(b *testing.B) {
	skipBenchIfNoEngine(b)
	key := make([]byte, 32)
	label := []byte("bench-label")
	seed := make([]byte, 16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = KDF_GOSTR3411_256(key, label, seed)
	}
}

func BenchmarkKDF_GOSTR3411_512(b *testing.B) {
	skipBenchIfNoEngine(b)
	key := make([]byte, 64)
	label := []byte("bench-label")
	seed := make([]byte, 16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = KDF_GOSTR3411_512(key, label, seed)
	}
}

func BenchmarkHKDF256_32B(b *testing.B) {
	skipBenchIfNoEngine(b)
	salt := make([]byte, 32)
	ikm := make([]byte, 32)
	info := []byte("bench-info")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = HKDF256(salt, ikm, info, 32)
	}
}

func BenchmarkHKDF512_64B(b *testing.B) {
	skipBenchIfNoEngine(b)
	salt := make([]byte, 64)
	ikm := make([]byte, 32)
	info := []byte("bench-info")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = HKDF512(salt, ikm, info, 64)
	}
}

func BenchmarkPBKDF2_256_1kIter(b *testing.B) {
	skipBenchIfNoEngine(b)
	password := []byte("correct horse battery staple")
	salt := make([]byte, 16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = PBKDF2_256(password, salt, 1000, 32)
	}
}

func BenchmarkPBKDF2_512_1kIter(b *testing.B) {
	skipBenchIfNoEngine(b)
	password := []byte("correct horse battery staple")
	salt := make([]byte, 16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = PBKDF2_512(password, salt, 1000, 64)
	}
}
