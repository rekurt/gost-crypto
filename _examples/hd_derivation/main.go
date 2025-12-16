package main

import (
	"encoding/hex"
	"fmt"

	"gost-crypto/gost3410"
	"gost-crypto/kdf/hd"
)

func main() {
	fmt.Println("GOST R 34.10-2012 Hierarchical Key Derivation Example")
	fmt.Println("=======================================================\n")

	seed := []byte("my random seed for HD wallet")
	fmt.Printf("Master seed: %s\n", seed)
	fmt.Printf("Seed (hex): %x\n\n", seed)

	fmt.Println("Creating master key from seed...")
	masterKey, masterChain, err := hd.Master(seed, gost3410.Streebog256)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Master private key (d): %x\n", masterKey.D)
	fmt.Printf("Master chain code: %x\n", masterChain)

	fmt.Println("\n--- Deriving keys from path m/0/1/2 ---\n")

	key, chain, err := hd.Derive(masterKey, masterChain, "m/0/1/2", gost3410.Streebog256)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Derived key (m/0/1/2) private key: %x\n", key.D)
	fmt.Printf("Derived key (m/0/1/2) chain code: %x\n", chain)

	pubKey, err := key.Public()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Derived public key X: %x\n", pubKey.X)
	fmt.Printf("Derived public key Y: %x\n", pubKey.Y)

	fmt.Println("\n--- Deriving hardened keys from path m/0'/1' ---\n")

	hardenedKey, hardenedChain, err := hd.Derive(masterKey, masterChain, "m/0'/1'", gost3410.Streebog256)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Hardened key (m/0'/1') private key: %x\n", hardenedKey.D)
	fmt.Printf("Hardened key (m/0'/1') chain code: %x\n", hardenedChain)

	fmt.Println("\n--- Deriving multiple siblings ---\n")

	fmt.Println("Deriving keys at m/0, m/1, m/2:")
	for i := 0; i < 3; i++ {
		path := fmt.Sprintf("m/%d", i)
		childKey, _, err := hd.Derive(masterKey, masterChain, path, gost3410.Streebog256)
		if err != nil {
			fmt.Printf("%s: Error - %v\n", path, err)
			continue
		}

		childPub, err := childKey.Public()
		if err != nil {
			fmt.Printf("%s: Error deriving public key - %v\n", path, err)
			continue
		}

		fmt.Printf("%s: private=%x... public_x=%x...\n",
			path,
			childKey.D[:8],
			childPub.X[:8])
	}

	fmt.Println("\n--- Deriving with 512-bit curve ---\n")

	fmt.Println("Creating HD keys with 512-bit TC26_512_A curve...")
	masterKey512, masterChain512, err := hd.Master(seed, gost3410.Streebog512)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Master private key (512-bit): %x\n", masterKey512.D)

	key512, _, err := hd.Derive(masterKey512, masterChain512, "m/0/1", gost3410.Streebog512)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Derived key (m/0/1, 512-bit): %x\n", key512.D)

	pub512, err := key512.Public()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Derived public key X (512-bit): %x\n", pub512.X)

	fmt.Println("\n--- Testing path consistency ---\n")

	fmt.Println("Verifying that same path produces same keys:")

	key1, _, err := hd.Derive(masterKey, masterChain, "m/44/0/0", gost3410.Streebog256)
	if err != nil {
		panic(err)
	}

	key2, _, err := hd.Derive(masterKey, masterChain, "m/44/0/0", gost3410.Streebog256)
	if err != nil {
		panic(err)
	}

	if hex.EncodeToString(key1.D) == hex.EncodeToString(key2.D) {
		fmt.Println("✓ Path m/44/0/0 produces consistent keys")
	} else {
		fmt.Println("✗ Path m/44/0/0 produces inconsistent keys")
	}

	fmt.Println("\n--- Error handling ---\n")

	fmt.Println("Testing invalid paths:")
	invalidPaths := []string{
		"0/1/2",             // missing m prefix
		"m/abc",             // invalid index
		"m/-1",              // negative index
		"m/",                // empty path
		"m/0/1/2/3/4/5/6/7", // very long path (should still work)
	}

	for _, invalidPath := range invalidPaths {
		_, _, err := hd.Derive(masterKey, masterChain, invalidPath, gost3410.Streebog256)
		if err != nil {
			fmt.Printf("  %s: %v\n", invalidPath, err)
		} else {
			if invalidPath == "m/0/1/2/3/4/5/6/7" {
				fmt.Printf("  %s: OK (long paths are allowed)\n", invalidPath)
			} else {
				fmt.Printf("  %s: Error expected but succeeded\n", invalidPath)
			}
		}
	}

	fmt.Println("\nHD key derivation example completed!")
}
