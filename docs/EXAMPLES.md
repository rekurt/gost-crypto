# Usage Examples

All snippets below are aligned with the current v1 API (`github.com/rekurt/gost-crypto`).

## 1) Sign and verify

```go
package main

import (
    "fmt"

    gostcrypto "github.com/rekurt/gost-crypto"
)

func main() {
    priv, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
    if err != nil {
        panic(err)
    }
    defer priv.Zeroize()

    msg := []byte("hello")

    sig, err := gostcrypto.Sign(priv, msg)
    if err != nil {
        panic(err)
    }

    ok, err := gostcrypto.Verify(priv.PublicKey(), msg, sig)
    if err != nil {
        panic(err)
    }

    fmt.Println("valid:", ok)
}
```

## 2) Hashing (Streebog)

```go
package main

import (
    "fmt"

    gostcrypto "github.com/rekurt/gost-crypto"
)

func main() {
    sum256 := gostcrypto.HashSum256([]byte("data"))
    sum512 := gostcrypto.HashSum512([]byte("data"))

    fmt.Println(len(sum256), len(sum512)) // 32 64
}
```

## 3) VKO key agreement

```go
package main

import (
    "bytes"
    "fmt"

    gostcrypto "github.com/rekurt/gost-crypto"
)

func main() {
    a, _ := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
    b, _ := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
    defer a.Zeroize()
    defer b.Zeroize()

    ukm := []byte("context-ukm")

    s1, err := gostcrypto.Agree(a, b.PublicKey(), ukm)
    if err != nil {
        panic(err)
    }
    s2, err := gostcrypto.Agree(b, a.PublicKey(), ukm)
    if err != nil {
        panic(err)
    }

    fmt.Println("equal:", bytes.Equal(s1, s2))
}
```

## 4) Low-level package usage

```go
package main

import (
    "fmt"

    "github.com/rekurt/gost-crypto/pkg/gost3410"
    "github.com/rekurt/gost-crypto/pkg/gost3411"
)

func main() {
    priv, err := gost3410.GenerateKey(gost3410.CurveTC26_512_A)
    if err != nil {
        panic(err)
    }
    defer priv.Zeroize()

    digest := gost3411.Sum512([]byte("payload"))
    sig, err := gost3410.SignDigest(priv, digest[:])
    if err != nil {
        panic(err)
    }

    ok, err := gost3410.VerifyDigest(priv.PublicKey(), digest[:], sig)
    if err != nil {
        panic(err)
    }

    fmt.Println(ok)
}
```

## 5) Kuznechik + MGM authenticated encryption

```go
package main

import (
    "crypto/rand"
    "fmt"

    "github.com/rekurt/gost-crypto/pkg/gost3413"
)

func main() {
    key := make([]byte, 32) // Kuznechik key = 32 bytes
    rand.Read(key)

    aead, err := gost3413.NewMGMFromKey(key)
    if err != nil {
        panic(err)
    }

    nonce := make([]byte, aead.NonceSize())
    rand.Read(nonce)

    ct := aead.Seal(nil, nonce, []byte("secret"), []byte("aad"))
    pt, err := aead.Open(nil, nonce, ct, []byte("aad"))
    if err != nil {
        panic(err)
    }

    fmt.Println(string(pt)) // secret
}
```

## 6) HD key derivation

```go
package main

import (
    "fmt"

    gostcrypto "github.com/rekurt/gost-crypto"
    "github.com/rekurt/gost-crypto/pkg/hd"
)

func main() {
    seed := []byte("my secret seed phrase - at least 16 bytes")

    master, err := hd.Master(seed, gostcrypto.CurveTC26_256_A)
    if err != nil {
        panic(err)
    }
    defer master.Zeroize()

    child, err := hd.Derive(master, "m/44'/0'/0", gostcrypto.CurveTC26_256_A)
    if err != nil {
        panic(err)
    }
    defer child.Zeroize()

    sig, _ := gostcrypto.Sign(child.Key, []byte("tx"))
    fmt.Printf("sig: %x...\n", sig[:8])
}
```

## Important note for `pkg/hd`

`pkg/hd` derives **both** chain codes and private keys deterministically
from the seed via HKDF-Streebog. The same seed and path always produce
the same GOST R 34.10-2012 key. If the HKDF-derived bytes fall outside
the valid range [1, q-1], rejection sampling with deterministic
re-derivation is applied automatically.
