package gost3410

import (
	"testing"

	"github.com/rekurt/gost-crypto/pkg/gost3411"
)

func BenchmarkGenerateKey_256A(b *testing.B) {
	for i := 0; i < b.N; i++ {
		k, err := GenerateKey(CurveTC26_256_A)
		if err != nil {
			b.Fatal(err)
		}
		k.Zeroize()
	}
}

func BenchmarkGenerateKey_512A(b *testing.B) {
	for i := 0; i < b.N; i++ {
		k, err := GenerateKey(CurveTC26_512_A)
		if err != nil {
			b.Fatal(err)
		}
		k.Zeroize()
	}
}

func BenchmarkSign_256A(b *testing.B) {
	priv, err := GenerateKey(CurveTC26_256_A)
	if err != nil {
		b.Fatal(err)
	}
	defer priv.Zeroize()

	digest := gost3411.Sum256([]byte("benchmark message"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := SignDigest(priv, digest[:])
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign_512A(b *testing.B) {
	priv, err := GenerateKey(CurveTC26_512_A)
	if err != nil {
		b.Fatal(err)
	}
	defer priv.Zeroize()

	digest := gost3411.Sum512([]byte("benchmark message"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := SignDigest(priv, digest[:])
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify_256A(b *testing.B) {
	priv, err := GenerateKey(CurveTC26_256_A)
	if err != nil {
		b.Fatal(err)
	}
	defer priv.Zeroize()

	digest := gost3411.Sum256([]byte("benchmark message"))
	sig, err := SignDigest(priv, digest[:])
	if err != nil {
		b.Fatal(err)
	}
	pub := priv.PublicKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := VerifyDigest(pub, digest[:], sig)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify_512A(b *testing.B) {
	priv, err := GenerateKey(CurveTC26_512_A)
	if err != nil {
		b.Fatal(err)
	}
	defer priv.Zeroize()

	digest := gost3411.Sum512([]byte("benchmark message"))
	sig, err := SignDigest(priv, digest[:])
	if err != nil {
		b.Fatal(err)
	}
	pub := priv.PublicKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := VerifyDigest(pub, digest[:], sig)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLoadPrivKey_256A(b *testing.B) {
	priv, err := GenerateKey(CurveTC26_256_A)
	if err != nil {
		b.Fatal(err)
	}
	raw, err := priv.Bytes()
	if err != nil {
		b.Fatal(err)
	}
	priv.Zeroize()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k, err := LoadPrivKey(CurveTC26_256_A, raw)
		if err != nil {
			b.Fatal(err)
		}
		k.Zeroize()
	}
}
