package main

import (
	"encoding/hex"
	"fmt"

	"gost-crypto/gost3410"
	"gost-crypto/gostcrypto"
)

func main() {
	fmt.Println("GOST R 34.10-2012 Key Serialization and Recovery")
	fmt.Println("================================================\n")

	// Step 1: Generate key pair
	fmt.Println("Step 1: Generating key pair...")
	privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
	if err != nil {
		panic(err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		panic(err)
	}

	fmt.Printf("✓ Generated private key (d): %x\n", privKey.D)
	fmt.Printf("✓ Generated public key X: %x\n", pubKey.X[:16])
	fmt.Printf("✓ Generated public key Y: %x\n", pubKey.Y[:16])

	// Step 2: Create test message
	fmt.Println("\nStep 2: Preparing test data...")
	message := []byte("GOST R 34.10-2012 key serialization test")
	fmt.Printf("✓ Message: %s\n", message)

	// Step 3: Sign with original key
	fmt.Println("\nStep 3: Signing message...")
	opts := &gostcrypto.Options{Hash: gost3410.Streebog256}
	originalSignature, err := gostcrypto.Sign(privKey, message, opts)
	if err != nil {
		panic(err)
	}
	fmt.Printf("✓ Signature created: %x...\n", originalSignature[:16])

	// Step 4: Verify with original public key
	fmt.Println("\nStep 4: Verifying with original key...")
	valid, err := gostcrypto.Verify(pubKey, message, originalSignature, opts)
	if err != nil {
		panic(err)
	}
	if !valid {
		panic("Original signature verification failed!")
	}
	fmt.Println("✓ Signature verified successfully with original key")

	// Step 5: Serialize public key in compressed format with prefix
	fmt.Println("\nStep 5: Serializing public key (compressed with prefix)...")
	compressedWithPrefix := pubKey.ToCompressed(true)
	fmt.Printf("✓ Compressed form: %d bytes\n", len(compressedWithPrefix))
	fmt.Printf("✓ Hex: %s\n", hex.EncodeToString(compressedWithPrefix))

	// Step 6: Serialize public key in compressed format without prefix
	fmt.Println("\nStep 6: Serializing public key (compressed without prefix)...")
	compressedWithoutPrefix := pubKey.ToCompressed(false)
	fmt.Printf("✓ Compressed form: %d bytes\n", len(compressedWithoutPrefix))
	fmt.Printf("✓ Hex: %s\n", hex.EncodeToString(compressedWithoutPrefix))

	// Step 7: Serialize public key in uncompressed format with prefix
	fmt.Println("\nStep 7: Serializing public key (uncompressed with prefix)...")
	uncompressedWithPrefix := pubKey.ToUncompressed(true)
	fmt.Printf("✓ Uncompressed form: %d bytes\n", len(uncompressedWithPrefix))
	fmt.Printf("✓ Hex: %s...\n", hex.EncodeToString(uncompressedWithPrefix)[:32])

	// Step 8: Serialize public key in uncompressed format without prefix
	fmt.Println("\nStep 8: Serializing public key (uncompressed without prefix)...")
	uncompressedWithoutPrefix := pubKey.ToUncompressed(false)
	fmt.Printf("✓ Uncompressed form: %d bytes\n", len(uncompressedWithoutPrefix))
	fmt.Printf("✓ Hex: %s...\n", hex.EncodeToString(uncompressedWithoutPrefix)[:32])

	// Step 9: Recover from compressed with prefix
	fmt.Println("\nStep 9: Recovering key from compressed (with prefix)...")
	recoveredFromCompressed1, err := gost3410.FromCompressed(gost3410.TC26_256_A, compressedWithPrefix, true)
	if err != nil {
		panic(err)
	}
	fmt.Println("✓ Key recovered successfully")

	valid, err = gostcrypto.Verify(recoveredFromCompressed1, message, originalSignature, opts)
	if err != nil {
		panic(err)
	}
	if !valid {
		panic("Signature verification failed with recovered key!")
	}
	fmt.Println("✓ Signature verified with recovered key")

	// Step 10: Recover from compressed without prefix
	fmt.Println("\nStep 10: Recovering key from compressed (without prefix)...")
	recoveredFromCompressed2, err := gost3410.FromCompressed(gost3410.TC26_256_A, compressedWithoutPrefix, false)
	if err != nil {
		panic(err)
	}
	fmt.Println("✓ Key recovered successfully")

	valid, err = gostcrypto.Verify(recoveredFromCompressed2, message, originalSignature, opts)
	if err != nil {
		panic(err)
	}
	if !valid {
		panic("Signature verification failed with recovered key!")
	}
	fmt.Println("✓ Signature verified with recovered key")

	// Step 11: Recover from uncompressed with prefix
	fmt.Println("\nStep 11: Recovering key from uncompressed (with prefix)...")
	recoveredFromUncompressed1, err := gost3410.FromUncompressed(gost3410.TC26_256_A, uncompressedWithPrefix, true)
	if err != nil {
		panic(err)
	}
	fmt.Println("✓ Key recovered successfully")

	valid, err = gostcrypto.Verify(recoveredFromUncompressed1, message, originalSignature, opts)
	if err != nil {
		panic(err)
	}
	if !valid {
		panic("Signature verification failed with recovered key!")
	}
	fmt.Println("✓ Signature verified with recovered key")

	// Step 12: Recover from uncompressed without prefix
	fmt.Println("\nStep 12: Recovering key from uncompressed (without prefix)...")
	recoveredFromUncompressed2, err := gost3410.FromUncompressed(gost3410.TC26_256_A, uncompressedWithoutPrefix, false)
	if err != nil {
		panic(err)
	}
	fmt.Println("✓ Key recovered successfully")

	valid, err = gostcrypto.Verify(recoveredFromUncompressed2, message, originalSignature, opts)
	if err != nil {
		panic(err)
	}
	if !valid {
		panic("Signature verification failed with recovered key!")
	}
	fmt.Println("✓ Signature verified with recovered key")

	// Step 13: Verify all recovered keys are identical
	fmt.Println("\nStep 13: Comparing all recovered keys...")
	if pubKey.X != recoveredFromCompressed1.X || pubKey.Y != recoveredFromCompressed1.Y {
		panic("Recovered key 1 does not match original!")
	}
	fmt.Println("✓ Compressed (prefix) matches original")

	if pubKey.X != recoveredFromCompressed2.X || pubKey.Y != recoveredFromCompressed2.Y {
		panic("Recovered key 2 does not match original!")
	}
	fmt.Println("✓ Compressed (no prefix) matches original")

	if pubKey.X != recoveredFromUncompressed1.X || pubKey.Y != recoveredFromUncompressed1.Y {
		panic("Recovered key 3 does not match original!")
	}
	fmt.Println("✓ Uncompressed (prefix) matches original")

	if pubKey.X != recoveredFromUncompressed2.X || pubKey.Y != recoveredFromUncompressed2.Y {
		panic("Recovered key 4 does not match original!")
	}
	fmt.Println("✓ Uncompressed (no prefix) matches original")

	// Step 14: Test with different curve
	fmt.Println("\nStep 14: Testing with 512-bit curve (TC26_512_A)...")
	privKey512, err := gost3410.NewPrivKey(gost3410.TC26_512_A)
	if err != nil {
		panic(err)
	}

	pubKey512, err := privKey512.Public()
	if err != nil {
		panic(err)
	}

	compressedKey512 := pubKey512.ToCompressed(true)
	fmt.Printf("✓ 512-bit compressed key: %d bytes\n", len(compressedKey512))

	recovered512, err := gost3410.FromCompressed(gost3410.TC26_512_A, compressedKey512, true)
	if err != nil {
		panic(err)
	}

	opts512 := &gostcrypto.Options{Hash: gost3410.Streebog512}
	sig512, err := gostcrypto.Sign(privKey512, message, opts512)
	if err != nil {
		panic(err)
	}

	valid, err = gostcrypto.Verify(recovered512, message, sig512, opts512)
	if err != nil {
		panic(err)
	}
	if !valid {
		panic("512-bit signature verification failed!")
	}
	fmt.Println("✓ 512-bit key serialization and recovery works")

	fmt.Println("\n" + "="*50)
	fmt.Println("✓ Key serialization and recovery test completed!")
	fmt.Println("=" * 50)
}
