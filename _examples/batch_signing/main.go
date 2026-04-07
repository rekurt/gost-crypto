package main

import (
	"fmt"
	"strings"

	gostcrypto "github.com/rekurt/gost-crypto"
)

func main() {
	fmt.Println("GOST R 34.10-2012 Batch Signing Example")
	fmt.Println("=======================================\n")

	privKey, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
	if err != nil {
		panic(err)
	}
	defer privKey.Zeroize()

	pubKey := privKey.PublicKey()

	fmt.Println("Generated private/public key pair for batch signing")

	// Sign multiple documents
	documents := []struct {
		name string
		data []byte
	}{
		{"Invoice 001", []byte("Invoice #001 Amount: 1000 RUB")},
		{"Invoice 002", []byte("Invoice #002 Amount: 2500 RUB")},
		{"Certificate", []byte("Certificate of authenticity GOST")},
		{"Contract", []byte("Contract dated 2024-12-09")},
		{"Report", []byte("Monthly report for December 2024")},
	}

	fmt.Printf("\nSigning %d documents:\n", len(documents))
	fmt.Println(strings.Repeat("-", 60))

	signatures := make([][]byte, len(documents))

	for i, doc := range documents {
		sig, err := gostcrypto.Sign(privKey, doc.data)
		if err != nil {
			panic(err)
		}
		signatures[i] = sig

		fmt.Printf("%2d. %-20s Signature: %x...\n", i+1, doc.name, sig[:8])
	}

	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("\nVerifying all signatures with public key...\n")
	fmt.Println(strings.Repeat("-", 60))

	allValid := true
	for i, doc := range documents {
		valid, err := gostcrypto.Verify(pubKey, doc.data, signatures[i])
		if err != nil {
			panic(err)
		}

		status := "VALID"
		if !valid {
			status = "INVALID"
			allValid = false
		}

		fmt.Printf("%2d. %-20s %s\n", i+1, doc.name, status)
	}

	fmt.Println(strings.Repeat("-", 60))

	if allValid {
		fmt.Println("\nAll signatures verified successfully!")
	} else {
		fmt.Println("\nSome signatures failed verification!")
	}

	// Test tampering detection
	fmt.Println("\n\nTesting Tampering Detection")
	fmt.Println("============================\n")

	tamperedDoc := make([]byte, len(documents[0].data))
	copy(tamperedDoc, documents[0].data)
	tamperedDoc[0]++

	fmt.Printf("Original: %s\n", documents[0].data)
	fmt.Printf("Tampered: %s\n\n", tamperedDoc)

	valid, err := gostcrypto.Verify(pubKey, tamperedDoc, signatures[0])
	if err != nil {
		panic(err)
	}

	if valid {
		fmt.Println("ERROR: Tampering not detected!")
	} else {
		fmt.Println("Tampering detected: Signature verification failed!")
	}

	// Try to use signature from different document
	fmt.Println("\n\nTesting Signature Confusion Attack")
	fmt.Println("===================================\n")

	valid, err = gostcrypto.Verify(pubKey, documents[0].data, signatures[4])
	if err != nil {
		panic(err)
	}

	if valid {
		fmt.Println("ERROR: Wrong signature accepted!")
	} else {
		fmt.Println("Attack prevented: Wrong signature rejected!")
	}

	fmt.Println("\nBatch signing example completed!")
}
