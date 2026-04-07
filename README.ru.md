# gost-crypto

[![CI](https://github.com/rekurt/gost-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/rekurt/gost-crypto/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/rekurt/gost-crypto)](https://goreportcard.com/report/github.com/rekurt/gost-crypto)
[![GoDoc](https://pkg.go.dev/badge/github.com/rekurt/gost-crypto)](https://pkg.go.dev/github.com/rekurt/gost-crypto)

Реализация российских криптографических стандартов ГОСТ на Go с использованием OpenSSL gost-engine: цифровые подписи (ГОСТ Р 34.10-2012), криптографическое хеширование (ГОСТ Р 34.11-2012 Стрибог), блочный шифр (ГОСТ Р 34.12-2015 Кузнечик), аутентифицированное шифрование (ГОСТ Р 34.13-2015 MGM), согласование ключей VKO и иерархическое деривирование ключей HD.

[API Справочник](API.ru.md) | [English](README.md) | [Вклад](CONTRIBUTING.md)

## Возможности

- **ГОСТ Р 34.11-2012 Стрибог** — криптографические хеш-функции 256 и 512 бит
- **ГОСТ Р 34.10-2012** — цифровые подписи на эллиптических кривых со всеми 8 параметрами ТК26
- **ГОСТ Р 34.12-2015 Кузнечик** — 128-битный блочный шифр (интерфейс cipher.Block)
- **ГОСТ Р 34.13-2015 MGM** — аутентифицированное шифрование (интерфейс cipher.AEAD)
- **Согласование ключей VKO** — вычисление общего секрета на основе ECDH
- **HD деривирование ключей** — детерминированное иерархическое деривирование в стиле BIP32
- **Высокоуровневый API** — фасад, объединяющий хеширование и подписание в одном вызове
- **Без внешних Go-зависимостей** — только OpenSSL gost-engine через CGO

## Требования

- Go 1.22 или новее
- OpenSSL 3.x с установленным gost-engine
- CGO включён

## Установка

```bash
go get github.com/rekurt/gost-crypto
```

```go
import (
    gostcrypto "github.com/rekurt/gost-crypto"
)
```

## Поддерживаемые кривые

Поддерживаются все 8 стандартизированных кривых ТК26:

| Кривая | Размер ключа | OID |
|--------|-------------|-----|
| CurveTC26_256_A | 256-бит | 1.2.643.7.1.2.1.1.1 |
| CurveTC26_256_B | 256-бит | 1.2.643.2.2.35.1 (КриптоПро-A) |
| CurveTC26_256_C | 256-бит | 1.2.643.2.2.35.2 (КриптоПро-B) |
| CurveTC26_256_D | 256-бит | 1.2.643.2.2.35.3 (КриптоПро-C) |
| CurveTC26_512_A | 512-бит | 1.2.643.7.1.2.1.2.1 |
| CurveTC26_512_B | 512-бит | 1.2.643.7.1.2.1.2.2 |
| CurveTC26_512_C | 512-бит | 1.2.643.7.1.2.1.2.3 |
| CurveTC26_512_D | 512-бит | 1.2.643.7.1.2.1.2.0 (тестовая) |

## Быстрый старт

### Подписание и проверка

```go
package main

import (
    "fmt"
    gostcrypto "github.com/rekurt/gost-crypto"
)

func main() {
    privKey, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
    if err != nil {
        panic(err)
    }
    defer privKey.Zeroize()

    pubKey := privKey.PublicKey()

    message := []byte("Привет, ГОСТ Р 34.10-2012!")

    // Подпись (автоматически выбирает Стрибог-256 для 256-битной кривой)
    signature, err := gostcrypto.Sign(privKey, message)
    if err != nil {
        panic(err)
    }

    // Проверка
    valid, err := gostcrypto.Verify(pubKey, message, signature)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Подпись верна: %v\n", valid)
}
```

### Согласование ключей VKO

```go
privA, _ := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
privB, _ := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
defer privA.Zeroize()
defer privB.Zeroize()

ukm := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

// Общий секрет симметричен: Agree(A, pubB) == Agree(B, pubA)
secretAB, _ := gostcrypto.Agree(privA, privB.PublicKey(), ukm)
secretBA, _ := gostcrypto.Agree(privB, privA.PublicKey(), ukm)
// secretAB == secretBA
```

### HD деривирование ключей

```go
import (
    gostcrypto "github.com/rekurt/gost-crypto"
    "github.com/rekurt/gost-crypto/pkg/hd"
)

seed := []byte("мой секретный сид - минимум 16 байт")

masterDK, _ := hd.Master(seed, gostcrypto.CurveTC26_256_A)
defer masterDK.Zeroize()

childDK, _ := hd.Derive(masterDK, "m/44'/0'/0", gostcrypto.CurveTC26_256_A)
defer childDK.Zeroize()

sig, _ := gostcrypto.Sign(childDK.Key, []byte("Транзакция HD-кошелька"))
```

### Загрузка ключей из сырых байтов

```go
raw := []byte{...} // 32 байта для 256-битной кривой

priv, err := gostcrypto.LoadPrivKey(gostcrypto.CurveTC26_256_A, raw)
if err != nil {
    panic(err)
}
defer priv.Zeroize()
```

## Структура пакетов

```
gost-crypto/
├── gostcrypto.go       # Высокоуровневый фасад: Sign, Verify, HashSum, Agree
├── keys.go             # GenerateKey, LoadPrivKey, алиасы PrivKey/PubKey
├── curves.go           # Тип Curve, константы TC26, AllCurves
├── errors.go           # Реэкспортированные ошибки
├── pkg/
│   ├── gost3410/       # ГОСТ Р 34.10-2012 подписи (бэкенд OpenSSL)
│   ├── gost3411/       # ГОСТ Р 34.11-2012 хеш Стрибог (бэкенд OpenSSL)
│   ├── gost3412/       # ГОСТ Р 34.12-2015 шифр Кузнечик
│   ├── gost3413/       # ГОСТ Р 34.13-2015 MGM AEAD
│   ├── hd/             # HD деривирование ключей (HKDF, пути BIP32)
│   └── kdf/            # Функции деривирования ключей (HKDF-Стрибог)
├── internal/openssl/   # CGO биндинги для OpenSSL gost-engine
└── _examples/          # Примеры использования
```

## Тестирование

```bash
go test ./...
go test -race ./...
go test -bench=. -benchmem ./pkg/gost3410/ ./pkg/gost3411/
go test -cover ./...
```

## Безопасность

1. Каждая подпись использует криптографически случайный нонс (k) через OpenSSL
2. Приватные ключи должны быть явно зануленны через `Zeroize()` после использования
3. Все входные данные проверяются на корректность размеров и форматов
4. Криптографические операции делегируются OpenSSL gost-engine

## Ограничения

- **Требуется OpenSSL**: OpenSSL 3.x с gost-engine и CGO; нет чисто-Go фоллбэка
- **Нет ASN.1/PEM**: Сериализация ключей в ASN.1/PEM не встроена
- **Устаревший ENGINE API**: Использует OpenSSL ENGINE API (deprecated в 3.0); миграция на provider API запланирована

## Ссылки

- [ГОСТ Р 34.10-2012](https://www.tc26.ru/) — Алгоритм цифровой подписи
- [ГОСТ Р 34.11-2012](https://www.tc26.ru/) — Хеш-функция Стрибог
- [RFC 7091](https://datatracker.ietf.org/doc/html/rfc7091) — GOST R 34.10-2012
- [RFC 6986](https://datatracker.ietf.org/doc/html/rfc6986) — GOST R 34.11-2012
- [ТК26](http://www.tc26.ru/) — Технический комитет 26

## Лицензия

MIT License. Подробнее в [LICENSE](LICENSE).
