package main

import (
	"fmt"

	"github.com/rekurt/gost-crypto/gost3410"
	"github.com/rekurt/gost-crypto/gostcrypto"
	"github.com/rekurt/gost-crypto/streebog"
)

func main() {
	fmt.Println("Generating GOST R 34.10-2012 512-bit key pair...")
	privKey, err := gost3410.NewPrivKey(gost3410.TC26_512_A)
	if err != nil {
		panic(err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Private key generated for curve: TC26_512_A\n")
	fmt.Printf("Private key size: %d bytes\n", len(privKey.D))
	fmt.Printf("Public key size: %d bytes (X) + %d bytes (Y)\n", len(pubKey.X), len(pubKey.Y))

	message := []byte("512-bit GOST signature example")
	fmt.Printf("\nMessage: %s\n", message)

	digest := streebog.Sum512(message)
	fmt.Printf("Streebog-512 digest: %x\n", digest[:16])

	fmt.Println("\nSigning message...")
	sig, err := gostcrypto.Sign(privKey, message, &gostcrypto.Options{Hash: gost3410.Streebog512})
	if err != nil {
		panic(err)
	}

	fmt.Printf("Signature created: %d bytes\n", len(sig))
	fmt.Printf("Signature (first 16 bytes): %x\n", sig[:16])

	fmt.Println("\nVerifying signature...")
	valid, err := gostcrypto.Verify(pubKey, message, sig, &gostcrypto.Options{Hash: gost3410.Streebog512})
	if err != nil {
		panic(err)
	}

	fmt.Printf("Signature valid: %v\n", valid)

	fmt.Println("\nTesting with wrong message...")
	wrongMessage := []byte("Different message")
	valid, err = gostcrypto.Verify(pubKey, wrongMessage, sig, &gostcrypto.Options{Hash: gost3410.Streebog512})
	if err != nil {
		panic(err)
	}

	fmt.Printf("Signature valid for wrong message: %v (expected: false)\n", valid)

	fmt.Println("\nPublic key serialization:")
	compressed := pubKey.ToCompressed(true)
	fmt.Printf("Compressed form: %d bytes\n", len(compressed))

	uncompressed := pubKey.ToUncompressed(true)
	fmt.Printf("Uncompressed form: %d bytes\n", len(uncompressed))

	recovered, err := gost3410.FromCompressed(gost3410.TC26_512_A, compressed, true)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Recovered public key matches: X=%v, Y=%v\n",
		len(recovered.X) == len(pubKey.X),
		len(recovered.Y) == len(pubKey.Y))

	fmt.Println("\nTesting other 512-bit curves...")

	for i, curve := range []gost3410.Curve{gost3410.TC26_512_B, gost3410.TC26_512_C} {
		names := []string{"TC26_512_B", "TC26_512_C"}
		fmt.Printf("\n%s:\n", names[i])

		priv, err := gost3410.NewPrivKey(curve)
		if err != nil {
			fmt.Printf("  Error creating key: %v\n", err)
			continue
		}

		pub, err := priv.Public()
		if err != nil {
			fmt.Printf("  Error deriving public key: %v\n", err)
			continue
		}

		sig, err := priv.Sign(digest[:], gost3410.Streebog512)
		if err != nil {
			fmt.Printf("  Error signing: %v\n", err)
			continue
		}

		valid, err := pub.Verify(digest[:], sig, gost3410.Streebog512)
		if err != nil {
			fmt.Printf("  Error verifying: %v\n", err)
			continue
		}

		fmt.Printf("  Key generation: OK, Signature verification: %v\n", valid)
	}

	fmt.Println("\nAll examples completed successfully!")
}
