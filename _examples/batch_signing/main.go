package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/rekurt/gost-crypto/gost3410"
	"github.com/rekurt/gost-crypto/gostcrypto"
)

func main() {
	fmt.Println("GOST R 34.10-2012 Batch Signing Example")
	fmt.Println("=======================================\n")

	privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
	if err != nil {
		panic(err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		panic(err)
	}

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

	opts := &gostcrypto.Options{Hash: gost3410.Streebog256}
	signatures := make([][]byte, len(documents))

	for i, doc := range documents {
		sig, err := gostcrypto.Sign(privKey, doc.data, opts)
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
		valid, err := gostcrypto.Verify(pubKey, doc.data, signatures[i], opts)
		if err != nil {
			panic(err)
		}

		status := "✓ VALID"
		if !valid {
			status = "✗ INVALID"
			allValid = false
		}

		fmt.Printf("%2d. %-20s %s\n", i+1, doc.name, status)
	}

	fmt.Println(strings.Repeat("-", 60))

	if allValid {
		fmt.Println("\n✓ All signatures verified successfully!")
	} else {
		fmt.Println("\n✗ Some signatures failed verification!")
	}

	// Test tampering detection
	fmt.Println("\n\nTesting Tampering Detection")
	fmt.Println("============================\n")

	// Try to tamper with first document
	tamperedDoc := make([]byte, len(documents[0].data))
	copy(tamperedDoc, documents[0].data)
	tamperedDoc[0]++ // Change one byte

	fmt.Printf("Original: %s\n", documents[0].data)
	fmt.Printf("Tampered: %s\n\n", tamperedDoc)

	valid, err := gostcrypto.Verify(pubKey, tamperedDoc, signatures[0], opts)
	if err != nil {
		panic(err)
	}

	if valid {
		fmt.Println("✗ ERROR: Tampering not detected!")
	} else {
		fmt.Println("✓ Tampering detected: Signature verification failed!")
	}

	// Try to use signature from different document
	fmt.Println("\n\nTesting Signature Confusion Attack")
	fmt.Println("===================================\n")

	valid, err = gostcrypto.Verify(pubKey, documents[0].data, signatures[4], opts)
	if err != nil {
		panic(err)
	}

	if valid {
		fmt.Println("✗ ERROR: Wrong signature accepted!")
	} else {
		fmt.Println("✓ Attack prevented: Wrong signature rejected!")
	}

	// Performance benchmark
	fmt.Println("\n\nPerformance Analysis")
	fmt.Println("====================\n")

	numDocs := 100
	fmt.Printf("Signing %d documents...\n", numDocs)

	startSign := time.Now()
	for i := 0; i < numDocs; i++ {
		msg := []byte(fmt.Sprintf("Document %d", i))
		_, err := gostcrypto.Sign(privKey, msg, opts)
		if err != nil {
			panic(err)
		}
	}
	signTime := time.Since(startSign)

	fmt.Printf("Signing: %.2f ms total, %.4f ms per document\n",
		signTime.Seconds()*1000,
		signTime.Seconds()*1000/float64(numDocs))

	// Generate sample signatures for verification timing
	sampleSigs := make([][]byte, 10)
	for i := 0; i < 10; i++ {
		msg := []byte(fmt.Sprintf("Document %d", i))
		sig, _ := gostcrypto.Sign(privKey, msg, opts)
		sampleSigs[i] = sig
	}

	fmt.Printf("\nVerifying %d documents...\n", numDocs)

	startVerify := time.Now()
	for i := 0; i < numDocs; i++ {
		msg := []byte(fmt.Sprintf("Document %d", i%10))
		_, err := gostcrypto.Verify(pubKey, msg, sampleSigs[i%10], opts)
		if err != nil {
			panic(err)
		}
	}
	verifyTime := time.Since(startVerify)

	fmt.Printf("Verification: %.2f ms total, %.4f ms per document\n",
		verifyTime.Seconds()*1000,
		verifyTime.Seconds()*1000/float64(numDocs))

	fmt.Println("\nBatch signing example completed!")
}
