package main

import (
	"fmt"

	gostcrypto "github.com/rekurt/gost-crypto"
	"github.com/rekurt/gost-crypto/pkg/hd"
)

func main() {
	fmt.Println("GOST R 34.10-2012 Hierarchical Key Derivation Example")
	fmt.Println("=======================================================\n")

	seed := []byte("my random seed for HD wallet - at least 16 bytes")
	fmt.Printf("Master seed: %s\n", seed)
	fmt.Printf("Seed (hex): %x\n\n", seed)

	fmt.Println("Creating master key from seed...")
	masterDK, err := hd.Master(seed, gostcrypto.CurveTC26_256_A)
	if err != nil {
		panic(err)
	}
	defer masterDK.Zeroize()

	masterBytes, err := masterDK.Key.Bytes()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Master private key: %x\n", masterBytes)
	fmt.Printf("Master chain code: %x\n", masterDK.ChainCode)

	fmt.Println("\n--- Deriving keys from path m/0/1/2 ---\n")

	childDK, err := hd.Derive(masterDK, "m/0/1/2", gostcrypto.CurveTC26_256_A)
	if err != nil {
		panic(err)
	}
	defer childDK.Zeroize()

	childBytes, err := childDK.Key.Bytes()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Derived key (m/0/1/2) private key: %x\n", childBytes)
	fmt.Printf("Derived key (m/0/1/2) chain code: %x\n", childDK.ChainCode)

	// Sign with derived key
	msg := []byte("HD wallet transaction")
	sig, err := gostcrypto.Sign(childDK.Key, msg)
	if err != nil {
		panic(err)
	}
	ok, err := gostcrypto.Verify(childDK.Key.PublicKey(), msg, sig)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Sign/Verify with derived key: %v\n", ok)

	fmt.Println("\n--- Deriving hardened keys from path m/0'/1' ---\n")

	hardenedDK, err := hd.Derive(masterDK, "m/0'/1'", gostcrypto.CurveTC26_256_A)
	if err != nil {
		panic(err)
	}
	defer hardenedDK.Zeroize()

	hardenedBytes, err := hardenedDK.Key.Bytes()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Hardened key (m/0'/1') private key: %x\n", hardenedBytes)
	fmt.Printf("Hardened key (m/0'/1') chain code: %x\n", hardenedDK.ChainCode)

	fmt.Println("\n--- Deriving multiple siblings ---\n")

	fmt.Println("Deriving keys at m/0, m/1, m/2:")
	for i := 0; i < 3; i++ {
		path := fmt.Sprintf("m/%d", i)
		siblingDK, err := hd.Derive(masterDK, path, gostcrypto.CurveTC26_256_A)
		if err != nil {
			fmt.Printf("%s: Error - %v\n", path, err)
			continue
		}

		sibBytes, err := siblingDK.Key.Bytes()
		if err != nil {
			siblingDK.Zeroize()
			fmt.Printf("%s: Error getting bytes - %v\n", path, err)
			continue
		}

		fmt.Printf("%s: private=%x...\n", path, sibBytes[:8])
		siblingDK.Zeroize()
	}

	fmt.Println("\n--- Deriving with 512-bit curve ---\n")

	fmt.Println("Creating HD keys with 512-bit TC26_512_A curve...")
	masterDK512, err := hd.Master(seed, gostcrypto.CurveTC26_512_A)
	if err != nil {
		panic(err)
	}
	defer masterDK512.Zeroize()

	masterBytes512, err := masterDK512.Key.Bytes()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Master private key (512-bit): %x\n", masterBytes512)

	child512, err := hd.Derive(masterDK512, "m/0/1", gostcrypto.CurveTC26_512_A)
	if err != nil {
		panic(err)
	}
	defer child512.Zeroize()

	childBytes512, err := child512.Key.Bytes()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Derived key (m/0/1, 512-bit): %x\n", childBytes512)

	fmt.Println("\n--- Error handling ---\n")

	fmt.Println("Testing invalid paths:")
	invalidPaths := []string{
		"m/abc",             // invalid index
		"m/-1",              // negative index
		"m/",                // empty path
		"m/0/1/2/3/4/5/6/7", // very long path (should still work)
	}

	for _, invalidPath := range invalidPaths {
		dk, err := hd.Derive(masterDK, invalidPath, gostcrypto.CurveTC26_256_A)
		if err != nil {
			fmt.Printf("  %s: %v\n", invalidPath, err)
		} else {
			dk.Zeroize()
			if invalidPath == "m/0/1/2/3/4/5/6/7" {
				fmt.Printf("  %s: OK (long paths are allowed)\n", invalidPath)
			} else {
				fmt.Printf("  %s: Error expected but succeeded\n", invalidPath)
			}
		}
	}

	fmt.Println("\nHD key derivation example completed!")
}
