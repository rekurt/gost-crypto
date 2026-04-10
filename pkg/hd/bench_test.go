package hd

import (
	"testing"

	"github.com/rekurt/gost-crypto/internal/openssl"
	"github.com/rekurt/gost-crypto/pkg/gost3410"
)

func skipBenchIfNoEngine(b *testing.B) {
	b.Helper()
	if err := openssl.Init(); err != nil {
		b.Skip("gost-engine not available:", err)
	}
}

func benchSeed() []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = byte(i)
	}
	return s
}

func BenchmarkMaster_256A(b *testing.B) {
	skipBenchIfNoEngine(b)
	seed := benchSeed()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dk, err := Master(seed, gost3410.CurveTC26_256_A)
		if err != nil {
			b.Fatal(err)
		}
		dk.Zeroize()
	}
}

func BenchmarkMaster_512A(b *testing.B) {
	skipBenchIfNoEngine(b)
	seed := benchSeed()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dk, err := Master(seed, gost3410.CurveTC26_512_A)
		if err != nil {
			b.Fatal(err)
		}
		dk.Zeroize()
	}
}

func BenchmarkDerive_Depth1(b *testing.B) {
	skipBenchIfNoEngine(b)
	master, err := Master(benchSeed(), gost3410.CurveTC26_256_A)
	if err != nil {
		b.Fatal(err)
	}
	defer master.Zeroize()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		child, err := Derive(master, "m/0", gost3410.CurveTC26_256_A)
		if err != nil {
			b.Fatal(err)
		}
		child.Zeroize()
	}
}

func BenchmarkDerive_Depth5(b *testing.B) {
	skipBenchIfNoEngine(b)
	master, err := Master(benchSeed(), gost3410.CurveTC26_256_A)
	if err != nil {
		b.Fatal(err)
	}
	defer master.Zeroize()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		child, err := Derive(master, "m/0/1/2/3/4", gost3410.CurveTC26_256_A)
		if err != nil {
			b.Fatal(err)
		}
		child.Zeroize()
	}
}

func BenchmarkParsePath(b *testing.B) {
	path := "m/0'/1/2'/3/4'/5"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParsePath(path)
		if err != nil {
			b.Fatal(err)
		}
	}
}
