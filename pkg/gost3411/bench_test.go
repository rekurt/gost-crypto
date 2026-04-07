package gost3411

import (
	"testing"
)

func BenchmarkStreebog256_64B(b *testing.B) {
	data := make([]byte, 64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum256(data)
	}
}

func BenchmarkStreebog256_1KB(b *testing.B) {
	data := make([]byte, 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum256(data)
	}
}

func BenchmarkStreebog512_64B(b *testing.B) {
	data := make([]byte, 64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum512(data)
	}
}

func BenchmarkStreebog512_1KB(b *testing.B) {
	data := make([]byte, 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum512(data)
	}
}
