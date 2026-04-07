package main

import (
	"bytes"
	"encoding/hex"
	"fmt"

	gostcrypto "github.com/rekurt/gost-crypto"
)

func main() {
	fmt.Println("=== GOST VKO Key Agreement ===\n")

	// Generate two key pairs on the same curve
	privA, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
	if err != nil {
		panic(err)
	}
	defer privA.Zeroize()

	privB, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
	if err != nil {
		panic(err)
	}
	defer privB.Zeroize()

	// User Key Material (UKM) — context value, must be non-empty
	ukm := []byte("session-2026-04-08")

	// Derive shared secret from both sides
	secretAB, err := gostcrypto.Agree(privA, privB.PublicKey(), ukm)
	if err != nil {
		panic(err)
	}

	secretBA, err := gostcrypto.Agree(privB, privA.PublicKey(), ukm)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Secret A→B: %s\n", hex.EncodeToString(secretAB))
	fmt.Printf("Secret B→A: %s\n", hex.EncodeToString(secretBA))
	fmt.Printf("Symmetric:  %v\n\n", bytes.Equal(secretAB, secretBA))

	// Different UKM produces different secret
	secretAB2, err := gostcrypto.Agree(privA, privB.PublicKey(), []byte("other-ukm"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("Different UKM → different secret: %v\n", !bytes.Equal(secretAB, secretAB2))
}
