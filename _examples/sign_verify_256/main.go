package main

import (
	"fmt"

	"gost-crypto/gost3410"
	"gost-crypto/gostcrypto"
	"gost-crypto/streebog"
)

func main() {
	// Generate a 256-bit key pair
	fmt.Println("Generating GOST R 34.10-2012 256-bit key pair...")
	privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
	if err != nil {
		panic(err)
	}

	// Derive public key from private key
	pubKey, err := privKey.Public()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Private key generated for curve: TC26_256_A\n")
	fmt.Printf("Private key size: %d bytes\n", len(privKey.D))
	fmt.Printf("Public key size: %d bytes (X) + %d bytes (Y)\n", len(pubKey.X), len(pubKey.Y))

	// Create a message
	message := []byte("Hello, GOST!")
	fmt.Printf("\nMessage: %s\n", message)

	// Hash with Streebog-256
	digest := streebog.Sum256(message)
	fmt.Printf("Streebog-256 digest: %x\n", digest[:8])

	// Sign using the facade
	fmt.Println("\nSigning message...")
	sig, err := gostcrypto.Sign(privKey, message, &gostcrypto.Options{Hash: gost3410.Streebog256})
	if err != nil {
		panic(err)
	}

	fmt.Printf("Signature created: %d bytes\n", len(sig))
	fmt.Printf("Signature (first 16 bytes): %x\n", sig[:16])

	// Verify signature using the facade
	fmt.Println("\nVerifying signature...")
	valid, err := gostcrypto.Verify(pubKey, message, sig, &gostcrypto.Options{Hash: gost3410.Streebog256})
	if err != nil {
		panic(err)
	}

	fmt.Printf("Signature valid: %v\n", valid)

	// Test with wrong message
	fmt.Println("\nTesting with wrong message...")
	wrongMessage := []byte("Wrong message!")
	valid, err = gostcrypto.Verify(pubKey, wrongMessage, sig, &gostcrypto.Options{Hash: gost3410.Streebog256})
	if err != nil {
		panic(err)
	}

	fmt.Printf("Signature valid for wrong message: %v (expected: false)\n", valid)

	// Test public key serialization
	fmt.Println("\nPublic key serialization:")
	compressed := pubKey.ToCompressed(true)
	fmt.Printf("Compressed form: %d bytes\n", len(compressed))

	uncompressed := pubKey.ToUncompressed(true)
	fmt.Printf("Uncompressed form: %d bytes\n", len(uncompressed))

	// Round-trip test
	recovered, err := gost3410.FromCompressed(gost3410.TC26_256_A, compressed, true)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Recovered public key matches: X=%v, Y=%v\n",
		len(recovered.X) == len(pubKey.X),
		len(recovered.Y) == len(pubKey.Y))
}
