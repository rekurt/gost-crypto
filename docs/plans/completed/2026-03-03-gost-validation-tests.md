# Валидация GOST-криптобиблиотеки и расширение тестового покрытия

## Overview

Полная валидация реализации GOST R 34.10-2012 и GOST R 34.11-2012 (Streebog) по спецификациям RFC 6986, RFC 7091, и стандартам ТК26. Исправление обнаруженных багов, добавление официальных тестовых векторов, расширение тестового покрытия до 80%+.

## Context

- Files involved: `gost3410/sign.go`, `gost3410/keys.go`, `gost3410/backend_gogost.go`, `gostcrypto/facade.go`, `kdf/hd/hd.go`, все `*_test.go` файлы
- Related patterns: table-driven тесты, property-based проверки, benchmark-тесты
- Dependencies: `github.com/ddulesov/gogost v1.0.0`

## Обнаруженные проблемы

### Баги (исправить обязательно)

1. **BenchmarkVerify256/512 - nil pubKey** (`gost3410/sign_test.go:467,500`): `NewPrivKey()` возвращает `(privKey, nil, nil)`, но бенчмарки используют `pubKey` напрямую. Фактически бенчмарки тестируют error-path (nil key), а не реальную верификацию.

2. **Options hash inference баг** (`gostcrypto/facade.go:23,57`): `Streebog256` = iota = 0, поэтому условие `opt.Hash == gost3410.Streebog256` всегда true для zero-value `Options{}`. Передача `&Options{}` с 512-bit ключом выберет Streebog256 вместо авто-определения из размера ключа.

3. **NewPrivKey возвращает nil PubKey** (`gost3410/keys.go:60`): Сигнатура `(*PrivKey, *PubKey, error)` вводит в заблуждение - PubKey всегда nil. Нужно либо убрать из сигнатуры, либо реально вычислять.

4. **Нет валидации приватного ключа** (`gost3410/keys.go:55-56`): `NewPrivKey` генерирует случайные байты через `rand.Read(d)` без проверки что `0 < d < q` (порядок кривой). Потенциально невалидный ключ.

5. **padToSize не обрезает лишние байты** (`gost3410/backend_gogost.go:127-133`): Если `len(b) > size`, возвращает длинный слайс без обрезки. Нужна защита от переполнения.

### Отсутствующие тестовые вектора

6. **Нет официальных Streebog-векторов из RFC 6986**: Стандарт определяет два тестовых сообщения M1 (63 байта) и M2 (72 байта) с эталонными хешами для обоих вариантов (256/512).

7. **Нет GOST R 34.10-2012 тестовых векторов из ГОСТ Р 34.10-2012**: Стандарт содержит примеры с фиксированным d, e и ожидаемыми r, s для тестовой кривой.

### Недостатки тестового покрытия

8. **gost3410: 67.1%** - ниже целевых 80%. Не покрыты: некоторые error-paths в backend, edge cases для Tonelli-Shanks, все форматы сериализации для 512-bit кривых.

9. **gostcrypto: 76.5%** - близко к 80%, но нет тестов для explicit Options с неправильным hash.

10. **Нет fuzz-тестов** для парсинга путей HD-деривации и десериализации ключей.

## Development Approach

- **Testing approach**: Regular (тесты пишем после фиксов)
- Каждый таск завершается полным прогоном тестов
- **CRITICAL: каждый таск включает новые/обновленные тесты**
- **CRITICAL: все тесты должны проходить перед следующим таском**

## Implementation Steps

### Task 1: Исправить баги в существующем коде

**Files:**
- Modify: `gost3410/keys.go`
- Modify: `gost3410/backend_gogost.go`
- Modify: `gostcrypto/facade.go`
- Modify: `gost3410/sign_test.go`

- [x] Исправить `NewPrivKey`: убрать `*PubKey` из возвращаемого значения (или вычислять реально). Обновить все call-sites.
- [x] Добавить валидацию `padToSize`: если `len(b) > size`, обрезать до size байт (взять младшие big-endian байты).
- [x] Исправить `Options` hash inference в `facade.go`: использовать отдельный флаг или sentinel value для определения "не задано" (например, сделать `Hash *HashID` или добавить `hashSet bool`, или проверять opt.Hash в связке с размером ключа).
- [x] Исправить `BenchmarkVerify256` и `BenchmarkVerify512`: добавить `privKey.Public()` для получения реального pubKey.
- [x] Написать тесты для каждого исправления.
- [x] Запустить `go test ./...` - все тесты должны пройти.

### Task 2: Добавить официальные тестовые вектора Streebog из RFC 6986

**Files:**
- Modify: `streebog/streebog_test.go`

- [x] Добавить тестовые вектора M1 (63 байта: "012345678901234567890123456789012345678901234567890123456789012") и M2 (72 байта binary) из RFC 6986 / ГОСТ Р 34.11-2012 для Streebog-256 и Streebog-512.
- [x] Добавить тест на длинное сообщение (повторение паттерна 1000+ раз).
- [x] Добавить тест на инкрементальное хеширование совпадающее с одноразовым Sum.
- [x] Запустить `go test ./streebog/...` - все тесты должны пройти.

### Task 3: Расширить тестовое покрытие gost3410 до 80%+

**Files:**
- Modify: `gost3410/sign_test.go`
- Modify: `gost3410/backend_test.go`
- Modify: `gost3410/edge_cases_test.go`
- Modify: `gost3410/vectors_test.go`

- [x] Добавить тесты сериализации/десериализации для 512-bit кривых (compressed/uncompressed, with/without prefix) - 4 формата x 3 кривых (512-A/B/C).
- [x] Добавить тест: подпись на одной кривой, верификация на другой - должна быть ошибка или false.
- [x] Добавить тесты для error-paths в `recoverY`: невалидная X-координата (не на кривой).
- [x] Добавить property-test: для рандомного ключа sign-then-verify всегда true (100 итераций).
- [x] Добавить тест: `FromRawPriv` с неправильным размером данных.
- [x] Добавить тест: `FromCompressed`/`FromUncompressed` с некорректными данными (wrong size, wrong prefix).
- [x] Добавить тесты для `Curve.Size()` с невалидными значениями Curve.
- [x] Запустить `go test -cover ./gost3410/...` - покрытие должно быть >= 80%.

### Task 4: Расширить тестовое покрытие gostcrypto и kdf/hd

**Files:**
- Modify: `gostcrypto/facade_test.go`
- Modify: `kdf/hd/hd_test.go`

- [x] gostcrypto: добавить тест с explicit `Options{Hash: Streebog512}` на 512-bit ключе.
- [x] gostcrypto: добавить тест Verify с неправильной подписью (corrupted bytes).
- [x] gostcrypto: добавить тест Sign-Verify roundtrip для каждой поддерживаемой кривой (256-A, 512-A/B/C).
- [x] kdf/hd: добавить тест что `Derive` с path "m/" (пустой путь после m/) работает корректно.
- [x] kdf/hd: добавить тест что два разных seed дают разные master-ключи.
- [x] kdf/hd: добавить fuzz-тест для `parsePath`.
- [x] Запустить `go test -cover ./...` - все пакеты >= 80%.

### Task 5: Verify acceptance criteria

- [x] manual test: запустить `go run ./_examples/sign_verify_256/` и убедиться в корректной работе.
- [x] run full test suite: `go test ./...`
- [x] run linter: `go vet ./...`
- [x] verify test coverage: `go test -cover ./...` - все пакеты >= 80%

### Task 6: Update documentation

- [x] update CLAUDE.md: обновить секцию Implementation Status и Known Issues
- [x] move this plan to `docs/plans/completed/`
