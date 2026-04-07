# Справочник API

Полный справочник API для gost-crypto.

[README](../README.md) | [README (Русский)](README.ru.md)

---

## Содержание

- [Корневой пакет (gostcrypto)](#корневой-пакет-gostcrypto)
- [pkg/gost3410](#pkggost3410)
- [pkg/gost3411](#pkggost3411)
- [pkg/gost3412](#pkggost3412)
- [pkg/gost3413](#pkggost3413)
- [pkg/hd](#pkghd)
- [pkg/kdf](#pkgkdf)
- [Обработка ошибок](#обработка-ошибок)
- [Потокобезопасность](#потокобезопасность)

---

## Корневой пакет (gostcrypto)

`import gostcrypto "github.com/rekurt/gost-crypto"`

Высокоуровневый фасад, реэкспортирующий типы из `pkg/gost3410` и предоставляющий удобные функции Sign/Verify/Hash/Agree.

### Типы

```go
type Curve = gost3410.Curve
type PrivKey = gost3410.PrivKey
type PubKey = gost3410.PubKey
```

### Константы

```go
const (
    CurveTC26_256_A  // id-tc26-gost-3410-2012-256-paramSetA
    CurveTC26_256_B  // КриптоПро-A
    CurveTC26_256_C  // КриптоПро-B
    CurveTC26_256_D  // КриптоПро-C
    CurveTC26_512_A
    CurveTC26_512_B
    CurveTC26_512_C
    CurveTC26_512_D  // тестовая
)
```

### Функции

#### `GenerateKey(c Curve) (*PrivKey, error)`

Генерирует новую пару ключей ГОСТ Р 34.10-2012 для заданной кривой.

#### `LoadPrivKey(c Curve, raw []byte) (*PrivKey, error)`

Создаёт приватный ключ из сырых байт (big-endian). Размер должен точно соответствовать кривой (32 для 256-бит, 64 для 512-бит).

#### `Sign(priv *PrivKey, msg []byte) ([]byte, error)`

Хеширует `msg` Стрибогом (автоматически выбирается по размеру кривой) и подписывает ГОСТ Р 34.10-2012. Возвращает подпись `r||s`.

#### `Verify(pub *PubKey, msg, sig []byte) (bool, error)`

Хеширует `msg` Стрибогом и проверяет подпись ГОСТ Р 34.10-2012.

#### `HashSum256(data []byte) [32]byte`

Возвращает Стрибог-256 дайджест данных.

#### `HashSum512(data []byte) [64]byte`

Возвращает Стрибог-512 дайджест данных.

#### `Agree(priv *PrivKey, pub *PubKey, ukm []byte) ([]byte, error)`

Выполняет согласование ключей VKO. Симметричен: `Agree(A, pubB, ukm) == Agree(B, pubA, ukm)`.

#### `AllCurves() []Curve`

Возвращает все 8 наборов параметров ТК26.

---

## pkg/gost3410

`import "github.com/rekurt/gost-crypto/pkg/gost3410"`

Низкоуровневые операции ГОСТ Р 34.10-2012 через OpenSSL gost-engine.

### `GenerateKey(c Curve) (*PrivKey, error)`

Генерирует случайную пару ключей.

### `LoadPrivKey(c Curve, raw []byte) (*PrivKey, error)`

Создаёт приватный ключ из сырых байт через OpenSSL.

### `SignDigest(priv *PrivKey, digest []byte) ([]byte, error)`

Подписывает предвычисленный дайджест. Размер дайджеста должен точно совпадать с размером ключа.

### `VerifyDigest(pub *PubKey, digest, sig []byte) (bool, error)`

Проверяет подпись над предвычисленным дайджестом.

### Методы PrivKey

- `Bytes() ([]byte, error)` — возвращает сырые байты приватного ключа
- `Curve() Curve` — возвращает набор параметров кривой
- `PublicKey() *PubKey` — выводит публичный ключ
- `Zeroize()` — безопасно стирает ключевой материал

### Методы PubKey

- `Curve() Curve` — возвращает набор параметров кривой
- `Validate() error` — проверяет, что точка лежит на кривой

---

## pkg/gost3411

`import "github.com/rekurt/gost-crypto/pkg/gost3411"`

Хеш-функции ГОСТ Р 34.11-2012 Стрибог через OpenSSL gost-engine.

### `New256() hash.Hash`

Возвращает хешер Стрибог-256, реализующий `hash.Hash`.

### `New512() hash.Hash`

Возвращает хешер Стрибог-512, реализующий `hash.Hash`.

### `Sum256(data []byte) [32]byte`

Вычисляет дайджест Стрибог-256 за один вызов.

### `Sum512(data []byte) [64]byte`

Вычисляет дайджест Стрибог-512 за один вызов.

---

## pkg/gost3412

`import "github.com/rekurt/gost-crypto/pkg/gost3412"`

Блочный шифр ГОСТ Р 34.12-2015 Кузнечик через OpenSSL gost-engine.

### `NewCipher(key []byte) (cipher.Block, error)`

Создаёт блок шифра Кузнечик. Ключ — 32 байта. Размер блока — 16 байт.

---

## pkg/gost3413

`import "github.com/rekurt/gost-crypto/pkg/gost3413"`

Аутентифицированное шифрование ГОСТ Р 34.13-2015 MGM через OpenSSL gost-engine.

### `NewMGM(block cipher.Block) (cipher.AEAD, error)`

Создаёт MGM AEAD из блока шифра Кузнечик.

---

## pkg/hd

`import "github.com/rekurt/gost-crypto/pkg/hd"`

Иерархическое детерминированное деривирование ключей через HKDF-Стрибог.

### `Master(seed []byte, c Curve) (*DerivedKey, error)`

Выводит мастер-ключ из сида (минимум 16 байт). Цепной код и приватный ключ детерминированно выводятся через HKDF-Стрибог.

### `Derive(parent *DerivedKey, path string, c Curve) (*DerivedKey, error)`

Выводит дочерний ключ по пути в стиле BIP-32. Поддерживает усиленное (`'` или `h`) и обычное деривирование.

### DerivedKey

```go
type DerivedKey struct {
    Key       *PrivKey  // Приватный ключ ГОСТ Р 34.10-2012
    ChainCode []byte    // 32-байтный цепной код
}
```

- `Zeroize()` — безопасно стирает ключ и цепной код

---

## pkg/kdf

`import "github.com/rekurt/gost-crypto/pkg/kdf"`

### `HKDF256(salt, ikm, info []byte, length int) []byte`

Выводит `length` байт через HKDF с Стрибог-256.

### `HKDF512(salt, ikm, info []byte, length int) []byte`

Выводит `length` байт через HKDF с Стрибог-512.

---

## Обработка ошибок

| Ошибка | Когда |
|--------|-------|
| `ErrNilKey` | передан nil или зануленный ключ |
| `ErrInvalidKeySize` | несоответствие размера дайджеста/ключа |
| `ErrInvalidSignature` | неверная длина подписи |
| `ErrUnknownCurve` | недопустимый идентификатор кривой |
| `ErrCurveMismatch` | VKO с ключами на разных кривых |
| `ErrEmptyUKM` | VKO без User Keying Material |

---

## Потокобезопасность

- Генерация ключей и подписание потокобезопасны (OpenSSL управляет блокировками)
- Один `*PrivKey` или `*PubKey` не должен разделяться между горутинами без синхронизации
- `Zeroize()` инвалидирует как приватный, так и производные публичные ключи
