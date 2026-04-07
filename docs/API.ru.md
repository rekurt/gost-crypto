# Справочник API

Модуль: `github.com/rekurt/gost-crypto`

## Фасадный пакет `gostcrypto`

### Типы и константы

- `type Curve`
- `type PrivKey`
- `type PubKey`
- Кривые:
  - `CurveTC26_256_A`, `CurveTC26_256_B`, `CurveTC26_256_C`, `CurveTC26_256_D`
  - `CurveTC26_512_A`, `CurveTC26_512_B`, `CurveTC26_512_C`, `CurveTC26_512_D`

### Функции

- `GenerateKey(c Curve) (*PrivKey, error)`
- `AllCurves() []Curve`
- `Sign(priv *PrivKey, msg []byte) ([]byte, error)`
  - автоматически выбирает хеш по размеру кривой (`Streebog-256` для 256-битных, `Streebog-512` для 512-битных)
- `Verify(pub *PubKey, msg, sig []byte) (bool, error)`
- `HashSum256(data []byte) [32]byte`
- `HashSum512(data []byte) [64]byte`
- `Agree(priv *PrivKey, pub *PubKey, ukm []byte) ([]byte, error)`

### Ошибки (реэкспорт)

- `ErrUnknownCurve`
- `ErrPointNotOnCurve`
- `ErrInvalidKeySize`
- `ErrInvalidSignature`
- `ErrNilKey`
- `ErrCurveMismatch`
- `ErrEmptyUKM`

## Пакет `pkg/gost3410`

- Базовые примитивы ключей/подписей/VKO.
- Ключевые методы:
  - `(*PrivKey).PublicKey() *PubKey`
  - `(*PrivKey).Bytes() ([]byte, error)`
  - `(*PrivKey).Zeroize()`
  - `(*PubKey).Validate() error`
- Функции:
  - `GenerateKey(c Curve) (*PrivKey, error)`
  - `SignDigest(priv *PrivKey, digest []byte) ([]byte, error)`
  - `VerifyDigest(pub *PubKey, digest, sig []byte) (bool, error)`
  - `VKO(priv *PrivKey, peerPub *PubKey, ukm []byte) ([]byte, error)`

## Пакет `pkg/gost3411`

- `New256() hash.Hash`
- `New512() hash.Hash`
- `Sum256(data []byte) [32]byte`
- `Sum512(data []byte) [64]byte`
- `NewHMAC256(key []byte) hash.Hash`
- `NewHMAC512(key []byte) hash.Hash`

## Пакет `pkg/gost3412`

- `NewKuznechik(key []byte) (cipher.Block, error)`
- Размер ключа: 32 байта, размер блока: 16 байт.

## Пакет `pkg/gost3413`

- `NewMGMFromKey(key []byte) (cipher.AEAD, error)`
- Параметры AEAD:
  - nonce: 16 байт
  - тег: 16 байт

## Пакет `pkg/kdf`

- `KDF_GOSTR3411_256(key, label, seed []byte) []byte`
- `KDF_GOSTR3411_512(key, label, seed []byte) []byte`
- `HKDF256(salt, ikm, info []byte, length int) []byte`
- `HKDF512(salt, ikm, info []byte, length int) []byte`
- `HKDFExtract256`, `HKDFExtract512`, `HKDFExpand256`, `HKDFExpand512`

## Пакет `pkg/hd`

- `ParsePath(path string) ([]PathComponent, error)`
- `Master(seed []byte, c Curve) (*DerivedKey, error)`
- `Derive(parent *DerivedKey, path string, c Curve) (*DerivedKey, error)`
- `(*DerivedKey).Zeroize()`

> Важное ограничение текущей версии: derivation chain code в `pkg/hd` детерминированный, но сами приватные ключи пока генерируются случайно (см. комментарий пакета в `pkg/hd/hd.go`).
