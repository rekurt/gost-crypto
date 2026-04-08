# gost-crypto — криптография ГОСТ на Go

[![CI](https://github.com/rekurt/gost-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/rekurt/gost-crypto/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/rekurt/gost-crypto)](https://goreportcard.com/report/github.com/rekurt/gost-crypto)
[![GoDoc](https://pkg.go.dev/badge/github.com/rekurt/gost-crypto)](https://pkg.go.dev/github.com/rekurt/gost-crypto)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)

Библиотека криптографии ГОСТ на Go: цифровые подписи (ГОСТ Р 34.10-2012), хеширование Стрибог (ГОСТ Р 34.11-2012), блочный шифр Кузнечик (ГОСТ Р 34.12-2015), аутентифицированное шифрование MGM (ГОСТ Р 34.13-2015), согласование ключей VKO и иерархическое деривирование ключей HD. Все криптографические операции выполняются через OpenSSL gost-engine. Без внешних Go-зависимостей.

[API Справочник](API.ru.md) | [English](../README.md) | [Вклад](CONTRIBUTING.md)

## Почему gost-crypto?

- **Бэкенд OpenSSL** — все криптографические операции выполняются через OpenSSL gost-engine, обеспечивая выполнение за постоянное время и реализацию промышленного качества
- **Полный набор ГОСТ** — цифровые подписи, хеширование, симметричное шифрование, AEAD, согласование ключей и деривирование ключей в одной библиотеке
- **Стандартные интерфейсы Go** — `hash.Hash`, `cipher.Block`, `cipher.AEAD` — полная совместимость с криптографической экосистемой Go
- **Без Go-зависимостей** — в `go.mod` нет директив `require`; только OpenSSL + CGO при сборке
- **Все 8 кривых ТК26** — параметры эллиптических кривых на 256 и 512 бит
- **HD деривирование ключей** — иерархические детерминированные ключи в стиле BIP32 для кривых ГОСТ

## Возможности

| Стандарт | Пакет | Описание | Go интерфейс |
|----------|-------|----------|--------------|
| ГОСТ Р 34.10-2012 | `pkg/gost3410` | Цифровые подписи на эллиптических кривых | — |
| ГОСТ Р 34.11-2012 | `pkg/gost3411` | Хеш-функция Стрибог (256/512 бит) | `hash.Hash` |
| ГОСТ Р 34.12-2015 | `pkg/gost3412` | Блочный шифр Кузнечик | `cipher.Block` |
| ГОСТ Р 34.13-2015 | `pkg/gost3413` | Аутентифицированное шифрование MGM | `cipher.AEAD` |
| RFC 7836 | `pkg/gost3410` | Согласование ключей VKO (ECDH) | — |
| Р 50.1.113-2016 | `pkg/kdf` | KDF_GOSTR3411, HKDF-Стрибог | — |
| BIP-32 стиль | `pkg/hd` | HD деривирование ключей | — |

## Требования

- Go 1.22 или новее
- OpenSSL 3.x с установленным gost-engine ([инструкция по установке](DEPLOYMENT.md))
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

    message := []byte("Привет, ГОСТ!")

    // Подпись (автоматически выбирает Стрибог-256 для 256-битной кривой)
    signature, err := gostcrypto.Sign(privKey, message)
    if err != nil {
        panic(err)
    }

    // Проверка
    valid, err := gostcrypto.Verify(privKey.PublicKey(), message, signature)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Подпись верна: %v\n", valid) // Подпись верна: true
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

### Шифрование Кузнечик (AEAD)

```go
import "github.com/rekurt/gost-crypto/pkg/gost3413"

aead, _ := gost3413.NewMGMFromKey(key) // 32-байтный ключ

nonce := make([]byte, aead.NonceSize())
rand.Read(nonce)

ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
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

## Поддерживаемые кривые

Поддерживаются все 8 стандартизированных кривых ТК26:

| Кривая | Размер | OID | Примечание |
|--------|--------|-----|------------|
| `CurveTC26_256_A` | 256-бит | 1.2.643.7.1.2.1.1.1 | Рекомендуемая |
| `CurveTC26_256_B` | 256-бит | 1.2.643.2.2.35.1 | КриптоПро-A |
| `CurveTC26_256_C` | 256-бит | 1.2.643.2.2.35.2 | КриптоПро-B |
| `CurveTC26_256_D` | 256-бит | 1.2.643.2.2.35.3 | КриптоПро-C |
| `CurveTC26_512_A` | 512-бит | 1.2.643.7.1.2.1.2.1 | |
| `CurveTC26_512_B` | 512-бит | 1.2.643.7.1.2.1.2.2 | |
| `CurveTC26_512_C` | 512-бит | 1.2.643.7.1.2.1.2.3 | |
| `CurveTC26_512_D` | 512-бит | 1.2.643.7.1.2.1.2.0 | Тестовая |

## Тестирование

```bash
go test ./...
go test -race ./...
go test -bench=. -benchmem ./pkg/gost3410/ ./pkg/gost3411/
go test -cover ./...
```

## Соответствие стандартам

Библиотека реализует следующие российские и международные стандарты:

- **ГОСТ Р 34.10-2012** / [RFC 7091](https://datatracker.ietf.org/doc/html/rfc7091) — Алгоритм цифровой подписи
- **ГОСТ Р 34.11-2012** / [RFC 6986](https://datatracker.ietf.org/doc/html/rfc6986) — Хеш-функция Стрибог
- **ГОСТ Р 34.12-2015** — Блочный шифр Кузнечик
- **ГОСТ Р 34.13-2015** — Режим аутентифицированного шифрования MGM
- **RFC 7836** — Согласование ключей VKO
- **Р 50.1.113-2016** — Функция деривирования ключей KDF_GOSTR3411
- **[ТК26](http://www.tc26.ru/)** — Все 8 стандартизированных параметров эллиптических кривых

## Безопасность

1. Каждая подпись использует криптографически случайный нонс (k) через OpenSSL
2. Приватные ключи должны быть явно занулены через `Zeroize()` после использования
3. Все входные данные проверяются на корректность размеров и форматов
4. Криптографические операции делегируются OpenSSL gost-engine

Сообщить об уязвимости: [SECURITY.md](../SECURITY.md)

## Лицензия

MIT License. Подробнее в [LICENSE](../LICENSE).
