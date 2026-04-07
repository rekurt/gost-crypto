# gost-crypto (Русская документация)

Go-библиотека для российских криптографических стандартов ГОСТ, использующая OpenSSL 3.0+ и [gost-engine](https://github.com/gost-engine/engine).

Реализованы: подписи (ГОСТ Р 34.10-2012), хеширование (Стрибог), шифр Кузнечик, AEAD MGM, согласование ключа VKO, KDF/HKDF и HD-derivation.

- [English README](../README.md)
- [Индекс документации](DOCUMENTATION.ru.md)
- [API](API.ru.md)
- [Примеры](EXAMPLES.ru.md)

## Быстрый старт

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

    msg := []byte("Привет, ГОСТ!")
    sig, err := gostcrypto.Sign(priv, msg)
    if err != nil {
        panic(err)
    }

    ok, err := gostcrypto.Verify(priv.PublicKey(), msg, sig)
    if err != nil {
        panic(err)
    }

    fmt.Println("подпись валидна:", ok)
}
```

## Требования

- Go 1.22+
- OpenSSL 3.0+
- gost-engine v3.0.3+
- `CGO_ENABLED=1`
- C compiler + CMake

Подробно: [DEPLOYMENT.md](DEPLOYMENT.md).

## Замечание по безопасности

Проект не имеет формального аудита и сертификации ФСБ. Для сертифицированных сценариев используйте сертифицированные криптосредства.

Подробно: [SECURITY.md](SECURITY.md).
