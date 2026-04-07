package main

import (
	"fmt"

	gostcrypto "github.com/rekurt/gost-crypto"
)

func main() {
	// 256-bit curve signing
	fmt.Println("=== GOST R 34.10-2012 Sign/Verify ===\n")

	priv256, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
	if err != nil {
		panic(err)
	}
	defer priv256.Zeroize()

	message := []byte("Hello, GOST!")

	sig, err := gostcrypto.Sign(priv256, message)
	if err != nil {
		panic(err)
	}
	fmt.Printf("256-bit signature: %d bytes (%x...)\n", len(sig), sig[:8])

	ok, err := gostcrypto.Verify(priv256.PublicKey(), message, sig)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Valid: %v\n", ok)

	// Wrong message detection
	ok, _ = gostcrypto.Verify(priv256.PublicKey(), []byte("wrong"), sig)
	fmt.Printf("Wrong message rejected: %v\n\n", !ok)

	// 512-bit curve signing
	priv512, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_512_A)
	if err != nil {
		panic(err)
	}
	defer priv512.Zeroize()

	sig512, err := gostcrypto.Sign(priv512, message)
	if err != nil {
		panic(err)
	}
	fmt.Printf("512-bit signature: %d bytes (%x...)\n", len(sig512), sig512[:8])

	ok, err = gostcrypto.Verify(priv512.PublicKey(), message, sig512)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Valid: %v\n\n", ok)

	// All curves
	fmt.Println("--- All TC26 curves ---")
	for _, c := range gostcrypto.AllCurves() {
		p, err := gostcrypto.GenerateKey(c)
		if err != nil {
			fmt.Printf("  %s: %v\n", c, err)
			continue
		}
		s, err := gostcrypto.Sign(p, message)
		if err != nil {
			p.Zeroize()
			fmt.Printf("  %s: sign error %v\n", c, err)
			continue
		}
		v, _ := gostcrypto.Verify(p.PublicKey(), message, s)
		p.Zeroize()
		fmt.Printf("  %s: valid=%v\n", c, v)
	}
}
