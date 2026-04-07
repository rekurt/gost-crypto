package main

import (
	"fmt"

	gostcrypto "github.com/rekurt/gost-crypto"
)

func main() {
	fmt.Println("Generating GOST R 34.10-2012 512-bit key pair...")
	privKey, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_512_A)
	if err != nil {
		panic(err)
	}
	defer privKey.Zeroize()

	pubKey := privKey.PublicKey()
	fmt.Println("Private key generated for curve: TC26_512_A")

	message := []byte("512-bit GOST signature example")
	fmt.Printf("\nMessage: %s\n", message)

	digest := gostcrypto.HashSum512(message)
	fmt.Printf("Streebog-512 digest: %x\n", digest[:16])

	fmt.Println("\nSigning message...")
	sig, err := gostcrypto.Sign(privKey, message)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Signature created: %d bytes\n", len(sig))
	fmt.Printf("Signature (first 16 bytes): %x\n", sig[:16])

	fmt.Println("\nVerifying signature...")
	valid, err := gostcrypto.Verify(pubKey, message, sig)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signature valid: %v\n", valid)

	fmt.Println("\nTesting with wrong message...")
	wrongMessage := []byte("Different message")
	valid, err = gostcrypto.Verify(pubKey, wrongMessage, sig)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signature valid for wrong message: %v (expected: false)\n", valid)

	fmt.Println("\nTesting other 512-bit curves...")

	for _, tc := range []struct {
		curve gostcrypto.Curve
		name  string
	}{
		{gostcrypto.CurveTC26_512_B, "TC26_512_B"},
		{gostcrypto.CurveTC26_512_C, "TC26_512_C"},
	} {
		fmt.Printf("\n%s:\n", tc.name)

		priv, err := gostcrypto.GenerateKey(tc.curve)
		if err != nil {
			fmt.Printf("  Error creating key: %v\n", err)
			continue
		}
		defer priv.Zeroize()

		pub := priv.PublicKey()

		s, err := gostcrypto.Sign(priv, message)
		if err != nil {
			fmt.Printf("  Error signing: %v\n", err)
			continue
		}

		ok, err := gostcrypto.Verify(pub, message, s)
		if err != nil {
			fmt.Printf("  Error verifying: %v\n", err)
			continue
		}

		fmt.Printf("  Key generation: OK, Signature verification: %v\n", ok)
	}

	fmt.Println("\nAll examples completed successfully!")
}
