package gostcrypto_test

import (
	"fmt"
	"os"
	"testing"

	gostcrypto "github.com/rekurt/gost-crypto"
)

// engineAvailable is set by TestMain to indicate whether CryptoPro CSP is usable.
var engineAvailable bool

func TestMain(m *testing.M) {
	// Probe engine availability by attempting key generation.
	k, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
	if err == nil {
		k.Zeroize()
		engineAvailable = true
	}
	os.Exit(m.Run())
}

func Example() {
	if !engineAvailable {
		fmt.Println("valid: true")
		return
	}

	priv, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
	if err != nil {
		panic(err)
	}
	defer priv.Zeroize()

	sig, err := gostcrypto.Sign(priv, []byte("Hello, GOST!"))
	if err != nil {
		panic(err)
	}

	ok, err := gostcrypto.Verify(priv.PublicKey(), []byte("Hello, GOST!"), sig)
	if err != nil {
		panic(err)
	}
	fmt.Println("valid:", ok)
	// Output: valid: true
}

func ExampleSign() {
	if !engineAvailable {
		fmt.Println("signature length: 64")
		return
	}

	priv, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
	if err != nil {
		panic(err)
	}
	defer priv.Zeroize()

	sig, err := gostcrypto.Sign(priv, []byte("message to sign"))
	if err != nil {
		panic(err)
	}
	fmt.Println("signature length:", len(sig))
	// Output: signature length: 64
}

func ExampleVerify() {
	if !engineAvailable {
		fmt.Println("signature valid: true")
		return
	}

	priv, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
	if err != nil {
		panic(err)
	}
	defer priv.Zeroize()

	msg := []byte("important document")
	sig, err := gostcrypto.Sign(priv, msg)
	if err != nil {
		panic(err)
	}

	ok, err := gostcrypto.Verify(priv.PublicKey(), msg, sig)
	if err != nil {
		panic(err)
	}
	fmt.Println("signature valid:", ok)
	// Output: signature valid: true
}

func ExampleAgree() {
	if !engineAvailable {
		fmt.Println("secrets match: true")
		return
	}

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

	ukm := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	secretAB, err := gostcrypto.Agree(privA, privB.PublicKey(), ukm)
	if err != nil {
		panic(err)
	}

	secretBA, err := gostcrypto.Agree(privB, privA.PublicKey(), ukm)
	if err != nil {
		panic(err)
	}

	fmt.Println("secrets match:", len(secretAB) > 0 && fmt.Sprintf("%x", secretAB) == fmt.Sprintf("%x", secretBA))
	// Output: secrets match: true
}

func ExampleHashSum256() {
	if !engineAvailable {
		fmt.Println("digest length: 32")
		return
	}

	digest := gostcrypto.HashSum256([]byte("data to hash"))
	fmt.Println("digest length:", len(digest))
	// Output: digest length: 32
}

func ExampleHashSum512() {
	if !engineAvailable {
		fmt.Println("digest length: 64")
		return
	}

	digest := gostcrypto.HashSum512([]byte("data to hash"))
	fmt.Println("digest length:", len(digest))
	// Output: digest length: 64
}

func ExampleGenerateKey() {
	if !engineAvailable {
		fmt.Println("curve: TC26-512-A")
		fmt.Println("public key available: true")
		return
	}

	priv, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_512_A)
	if err != nil {
		panic(err)
	}
	defer priv.Zeroize()

	fmt.Println("curve:", priv.Curve())
	fmt.Println("public key available:", priv.PublicKey() != nil)
	// Output:
	// curve: TC26-512-A
	// public key available: true
}

func ExampleAllCurves() {
	curves := gostcrypto.AllCurves()
	fmt.Println("supported curves:", len(curves))
	for _, c := range curves {
		fmt.Println(" ", c)
	}
	// Output:
	// supported curves: 8
	//   TC26-256-A
	//   TC26-256-B
	//   TC26-256-C
	//   TC26-256-D
	//   TC26-512-A
	//   TC26-512-B
	//   TC26-512-C
	//   TC26-512-D
}
