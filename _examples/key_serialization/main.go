package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	gostcrypto "github.com/rekurt/gost-crypto"
)

func main() {
	fmt.Println("GOST R 34.10-2012 Key Operations Example")
	fmt.Println("=========================================\n")

	// Step 1: Generate 256-bit key pair
	fmt.Println("Step 1: Generating 256-bit key pair...")
	privKey, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
	if err != nil {
		panic(err)
	}
	defer privKey.Zeroize()

	privBytes, err := privKey.Bytes()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Private key: %s...\n", hex.EncodeToString(privBytes)[:32])

	// Step 2: Sign and verify
	fmt.Println("\nStep 2: Sign and verify...")
	message := []byte("GOST R 34.10-2012 key operations test")
	fmt.Printf("Message: %s\n", message)

	sig, err := gostcrypto.Sign(privKey, message)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signature: %s...\n", hex.EncodeToString(sig)[:32])

	pubKey := privKey.PublicKey()
	valid, err := gostcrypto.Verify(pubKey, message, sig)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signature valid: %v\n", valid)

	// Step 3: Test with 512-bit curve
	fmt.Println("\nStep 3: Testing with 512-bit curve (TC26_512_A)...")
	privKey512, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_512_A)
	if err != nil {
		panic(err)
	}
	defer privKey512.Zeroize()

	sig512, err := gostcrypto.Sign(privKey512, message)
	if err != nil {
		panic(err)
	}
	fmt.Printf("512-bit signature: %d bytes\n", len(sig512))

	pub512 := privKey512.PublicKey()
	valid, err = gostcrypto.Verify(pub512, message, sig512)
	if err != nil {
		panic(err)
	}
	fmt.Printf("512-bit signature valid: %v\n", valid)

	// Step 4: Test all curves
	fmt.Println("\nStep 4: Testing all 8 TC26 curves...")
	for _, c := range gostcrypto.AllCurves() {
		priv, err := gostcrypto.GenerateKey(c)
		if err != nil {
			fmt.Printf("  %s: Error - %v\n", c, err)
			continue
		}

		s, err := gostcrypto.Sign(priv, message)
		if err != nil {
			priv.Zeroize()
			fmt.Printf("  %s: Sign error - %v\n", c, err)
			continue
		}

		ok, err := gostcrypto.Verify(priv.PublicKey(), message, s)
		priv.Zeroize()
		if err != nil {
			fmt.Printf("  %s: Verify error - %v\n", c, err)
			continue
		}
		fmt.Printf("  %s: OK (valid=%v)\n", c, ok)
	}

	// Step 5: Zeroize and verify cleanup
	fmt.Println("\nStep 5: Testing secure key zeroization...")
	testKey, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
	if err != nil {
		panic(err)
	}

	_, err = testKey.Bytes()
	if err != nil {
		panic(err)
	}
	fmt.Println("Before Zeroize: Bytes() works")

	testKey.Zeroize()
	_, err = testKey.Bytes()
	if err != nil {
		fmt.Println("After Zeroize: Bytes() returns error (key material wiped)")
	}

	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("Key operations example completed!")
	fmt.Println(strings.Repeat("=", 50))
}
