package main

import (
	"fmt"

	gostcrypto "github.com/rekurt/gost-crypto"
)

func main() {
	// Generate a 256-bit key pair
	fmt.Println("Generating GOST R 34.10-2012 256-bit key pair...")
	privKey, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
	if err != nil {
		panic(err)
	}
	defer privKey.Zeroize()

	pubKey := privKey.PublicKey()

	fmt.Println("Private key generated for curve: TC26_256_A")

	// Create a message
	message := []byte("Hello, GOST!")
	fmt.Printf("\nMessage: %s\n", message)

	// Hash with Streebog-256
	digest := gostcrypto.HashSum256(message)
	fmt.Printf("Streebog-256 digest: %x\n", digest[:8])

	// Sign using the facade (auto-selects Streebog-256 for 256-bit curve)
	fmt.Println("\nSigning message...")
	sig, err := gostcrypto.Sign(privKey, message)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Signature created: %d bytes\n", len(sig))
	fmt.Printf("Signature (first 16 bytes): %x\n", sig[:16])

	// Verify signature
	fmt.Println("\nVerifying signature...")
	valid, err := gostcrypto.Verify(pubKey, message, sig)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signature valid: %v\n", valid)

	// Test with wrong message
	fmt.Println("\nTesting with wrong message...")
	wrongMessage := []byte("Wrong message!")
	valid, err = gostcrypto.Verify(pubKey, wrongMessage, sig)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signature valid for wrong message: %v (expected: false)\n", valid)
}
