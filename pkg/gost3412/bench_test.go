package gost3412

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

// --- Kuznechik ---

func BenchmarkKuznechik_NewCipher(b *testing.B) {
	skipBenchIfNoEngine(b)
	key := make([]byte, KuznechikKeySize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := NewKuznechik(key)
		if err != nil {
			b.Fatal(err)
		}
		c.(Zeroizable).Zeroize()
	}
}

func BenchmarkKuznechik_Encrypt(b *testing.B) {
	skipBenchIfNoEngine(b)
	key := make([]byte, KuznechikKeySize)
	c, err := NewKuznechik(key)
	if err != nil {
		b.Fatal(err)
	}
	defer c.(Zeroizable).Zeroize()

	src := make([]byte, KuznechikBlockSize)
	dst := make([]byte, KuznechikBlockSize)
	b.SetBytes(int64(KuznechikBlockSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(dst, src)
	}
}

func BenchmarkKuznechik_Decrypt(b *testing.B) {
	skipBenchIfNoEngine(b)
	key := make([]byte, KuznechikKeySize)
	c, err := NewKuznechik(key)
	if err != nil {
		b.Fatal(err)
	}
	defer c.(Zeroizable).Zeroize()

	src := make([]byte, KuznechikBlockSize)
	dst := make([]byte, KuznechikBlockSize)
	b.SetBytes(int64(KuznechikBlockSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decrypt(dst, src)
	}
}

// --- Magma ---

func BenchmarkMagma_NewCipher(b *testing.B) {
	skipBenchIfNoEngine(b)
	key := make([]byte, MagmaKeySize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := NewMagma(key)
		if err != nil {
			b.Fatal(err)
		}
		c.(Zeroizable).Zeroize()
	}
}

func BenchmarkMagma_Encrypt(b *testing.B) {
	skipBenchIfNoEngine(b)
	key := make([]byte, MagmaKeySize)
	c, err := NewMagma(key)
	if err != nil {
		b.Fatal(err)
	}
	defer c.(Zeroizable).Zeroize()

	src := make([]byte, MagmaBlockSize)
	dst := make([]byte, MagmaBlockSize)
	b.SetBytes(int64(MagmaBlockSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(dst, src)
	}
}

func BenchmarkMagma_Decrypt(b *testing.B) {
	skipBenchIfNoEngine(b)
	key := make([]byte, MagmaKeySize)
	c, err := NewMagma(key)
	if err != nil {
		b.Fatal(err)
	}
	defer c.(Zeroizable).Zeroize()

	src := make([]byte, MagmaBlockSize)
	dst := make([]byte, MagmaBlockSize)
	b.SetBytes(int64(MagmaBlockSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decrypt(dst, src)
	}
}
