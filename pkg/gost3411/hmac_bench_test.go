package gost3411

import (
	"hash"
	"testing"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

func benchmarkHMAC(b *testing.B, keyLen, msgLen int, newFn func(key []byte) hash.Hash) {
	b.Helper()
	if err := openssl.Init(); err != nil {
		b.Skip("gost-engine not available:", err)
	}
	key := make([]byte, keyLen)
	msg := make([]byte, msgLen)
	b.SetBytes(int64(msgLen))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := newFn(key)
		_, _ = h.Write(msg)
		_ = h.Sum(nil)
	}
}

func BenchmarkHMAC256_64B(b *testing.B) {
	benchmarkHMAC(b, 32, 64, NewHMAC256)
}

func BenchmarkHMAC256_1KB(b *testing.B) {
	benchmarkHMAC(b, 32, 1024, NewHMAC256)
}

func BenchmarkHMAC512_64B(b *testing.B) {
	benchmarkHMAC(b, 64, 64, NewHMAC512)
}

func BenchmarkHMAC512_1KB(b *testing.B) {
	benchmarkHMAC(b, 64, 1024, NewHMAC512)
}
