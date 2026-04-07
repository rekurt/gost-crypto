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

## 5) Important note for `pkg/hd`

`pkg/hd` currently derives chain codes deterministically but does **not** yet construct deterministic private keys from seed material. If you need strict BIP32-like deterministic private keys today, do not rely on `pkg/hd` for that part yet.
