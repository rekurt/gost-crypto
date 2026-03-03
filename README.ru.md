# gost-crypto

Полнофункциональная реализация российских стандартов криптографии ГОСТ на чистом Go, обеспечивающая цифровые подписи, криптографическое хеширование и управление ключами для стандартов ГОСТ Р 34.10-2012 и ГОСТ Р 34.11-2012 Стрибог.

**[🇬🇧 English](README.md)** | **[📚 Индекс документации](DOCUMENTATION.md)** | **[🔧 API Справочник](API.md)** | **[💡 Продвинутые примеры](_examples/EXAMPLES.md)** | **[🤝 Вклад](CONTRIBUTING.md)**

## Возможности

- **ГОСТ Р 34.11-2012 Стрибог**: Криптографические функции хеширования на 256 и 512 бит
- **ГОСТ Р 34.10-2012 Цифровые подписи**: Подписи на эллиптических кривых с параметрами ТК26
- **Управление ключами**: Поддержка сжатого и несжатого кодирования открытых ключей с восстановлением
- **Сериализация ключей**: Несколько форматов сериализации с поддержкой префиксов
- **Иерархическое производное получение ключей (HD)**: HKDF-основанное иерархическое детерминированное производное получение ключей для приложений кошельков
- **Пакетные операции**: Эффективное подписание и проверка нескольких документов
- **Комплексное тестирование**: 76+ тестов, покрывающих интеграцию, граничные случаи и тестовые векторы
- **Высокоуровневый API**: Фасад, объединяющий хеширование и подписание для упрощенного использования

## Установка

```bash
go get -u github.com/ddulesov/gogost
```

Импортируйте в ваш код:

```go
import (
    "gost-crypto/gostcrypto"
    "gost-crypto/gost3410"
)
```

**Требования**: Go 1.24 или позже

## Поддерживаемые кривые

Реализация поддерживает стандартизированные ТК26 эллиптические кривые:

| ID кривой | Размер ключа | Статус |
|-----------|----------|--------|
| TC26_256_A | 256-бит | ✓ Поддерживается |
| TC26_256_B | 256-бит | Недоступна в gogost v1.0.0 |
| TC26_256_C | 256-бит | Недоступна в gogost v1.0.0 |
| TC26_256_D | 256-бит | Недоступна в gogost v1.0.0 |
| TC26_512_A | 512-бит | ✓ Поддерживается |
| TC26_512_B | 512-бит | ✓ Поддерживается |
| TC26_512_C | 512-бит | ✓ Поддерживается |
| TC26_512_D | 512-бит | Недоступна в gogost v1.0.0 |

## Быстрый старт

### Базовое подписание и проверка

Самый простой способ подписать и проверить сообщения:

```go
package main

import (
    "fmt"
    "gost-crypto/gost3410"
    "gost-crypto/gostcrypto"
)

func main() {
    // Генерируем новую пару ключей
    privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
    if err != nil {
        panic(err)
    }

    pubKey, err := privKey.Public()
    if err != nil {
        panic(err)
    }

    // Подписываем сообщение
    message := []byte("Привет, ГОСТ Р 34.10-2012!")
    opts := &gostcrypto.Options{Hash: gost3410.Streebog256}
    signature, err := gostcrypto.Sign(privKey, message, opts)
    if err != nil {
        panic(err)
    }

    // Проверяем подпись
    valid, err := gostcrypto.Verify(pubKey, message, signature, opts)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Подпись действительна: %v\n", valid)
}
```

### Работа с различными кривыми

Используйте 512-битные кривые для повышенной безопасности:

```go
package main

import (
    "fmt"
    "gost-crypto/gost3410"
    "gost-crypto/gostcrypto"
)

func main() {
    // Генерируем пару ключей на 512-бит
    privKey, err := gost3410.NewPrivKey(gost3410.TC26_512_A)
    if err != nil {
        panic(err)
    }

    pubKey, err := privKey.Public()
    if err != nil {
        panic(err)
    }

    message := []byte("Защищённое сообщение")

    // Подписываем с Streebog-512
    opts := &gostcrypto.Options{Hash: gost3410.Streebog512}
    signature, err := gostcrypto.Sign(privKey, message, opts)
    if err != nil {
        panic(err)
    }

    // Проверяем с Streebog-512
    valid, err := gostcrypto.Verify(pubKey, message, signature, opts)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Подпись действительна: %v\n", valid)
}
```

### Сериализация открытых ключей

Сериализуйте открытые ключи в несколько форматов для хранения или передачи:

```go
package main

import (
    "encoding/hex"
    "fmt"
    "gost-crypto/gost3410"
)

func main() {
    // Генерируем пару ключей
    privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
    if err != nil {
        panic(err)
    }

    pubKey, err := privKey.Public()
    if err != nil {
        panic(err)
    }

    // Сжатый формат с префиксом (33 байта всего)
    compressed := pubKey.ToCompressed(true)
    fmt.Printf("Сжатый (с префиксом): %s\n", hex.EncodeToString(compressed))
    fmt.Printf("Размер: %d байт\n", len(compressed))

    // Сжатый формат без префикса (32 байта)
    compressedNoPrefix := pubKey.ToCompressed(false)
    fmt.Printf("Сжатый (без префикса): %s\n", hex.EncodeToString(compressedNoPrefix))
    fmt.Printf("Размер: %d байт\n", len(compressedNoPrefix))

    // Несжатый формат с префиксом (65 байт всего)
    uncompressed := pubKey.ToUncompressed(true)
    fmt.Printf("Несжатый (с префиксом): %s...\n", hex.EncodeToString(uncompressed[:16]))
    fmt.Printf("Размер: %d байт\n", len(uncompressed))

    // Несжатый формат без префикса (64 байта)
    uncompressedNoPrefix := pubKey.ToUncompressed(false)
    fmt.Printf("Несжатый (без префикса): %s...\n", hex.EncodeToString(uncompressedNoPrefix[:16]))
    fmt.Printf("Размер: %d байт\n", len(uncompressedNoPrefix))
}
```

### Восстановление открытых ключей из сериализованных форм

Восстановите открытые ключи из любого формата сериализации:

```go
package main

import (
    "fmt"
    "gost-crypto/gost3410"
    "gost-crypto/gostcrypto"
)

func main() {
    // Генерируем исходную пару ключей
    privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
    if err != nil {
        panic(err)
    }

    originalPubKey, err := privKey.Public()
    if err != nil {
        panic(err)
    }

    message := []byte("Тестовое сообщение")
    opts := &gostcrypto.Options{Hash: gost3410.Streebog256}

    // Подписываем исходным ключом
    signature, err := gostcrypto.Sign(privKey, message, opts)
    if err != nil {
        panic(err)
    }

    // Сериализуем открытый ключ
    compressed := originalPubKey.ToCompressed(true)

    // Восстанавливаем открытый ключ из сжатого формата
    recoveredPubKey, err := gost3410.FromCompressed(gost3410.TC26_256_A, compressed, true)
    if err != nil {
        panic(err)
    }

    // Проверяем подпись восстановленным ключом
    valid, err := gostcrypto.Verify(recoveredPubKey, message, signature, opts)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Восстановленный ключ совпадает с исходным: %v\n", valid)
}
```

### Пакетное подписание нескольких документов

Эффективно подписывайте и проверяйте несколько документов:

```go
package main

import (
    "fmt"
    "gost-crypto/gost3410"
    "gost-crypto/gostcrypto"
)

func main() {
    // Генерируем пару ключей
    privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
    if err != nil {
        panic(err)
    }

    pubKey, err := privKey.Public()
    if err != nil {
        panic(err)
    }

    // Несколько документов для подписания
    documents := []struct {
        name string
        data []byte
    }{
        {"Счёт 001", []byte("Счёт #001 Сумма: 1000 РУБ")},
        {"Счёт 002", []byte("Счёт #002 Сумма: 2500 РУБ")},
        {"Сертификат", []byte("Сертификат подлинности ГОСТ")},
    }

    opts := &gostcrypto.Options{Hash: gost3410.Streebog256}
    signatures := make([][]byte, len(documents))

    // Подписываем все документы
    for i, doc := range documents {
        sig, err := gostcrypto.Sign(privKey, doc.data, opts)
        if err != nil {
            panic(err)
        }
        signatures[i] = sig
        fmt.Printf("Подписан: %s\n", doc.name)
    }

    // Проверяем все подписи
    fmt.Println("\nПроверка подписей:")
    for i, doc := range documents {
        valid, err := gostcrypto.Verify(pubKey, doc.data, signatures[i], opts)
        if err != nil {
            panic(err)
        }
        fmt.Printf("%s: %v\n", doc.name, valid)
    }
}
```

### Иерархическое производное получение ключей (HD кошельки)

Генерируйте детерминированные иерархии ключей из одного семена:

```go
package main

import (
    "encoding/hex"
    "fmt"
    "gost-crypto/gost3410"
    "gost-crypto/gostcrypto"
    "gost-crypto/kdf/hd"
)

func main() {
    // Создаём главный ключ из семени
    seed := []byte("моя секретная фраза семени для кошелька")
    masterKey, chainCode, err := hd.Master(seed, gost3410.Streebog256)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Главный ключ создан\n")
    fmt.Printf("Код цепи: %s\n", hex.EncodeToString(chainCode))

    // Выводим дочерние ключи в разных путях
    paths := []string{"m/0", "m/1", "m/0'/1'", "m/44'/283'/0'/0/0"}

    derivedKeys := make([]*gost3410.PrivKey, len(paths))

    for i, path := range paths {
        childKey, newChainCode, err := hd.Derive(masterKey, chainCode, path, gost3410.Streebog256)
        if err != nil {
            panic(err)
        }

        derivedKeys[i] = childKey
        fmt.Printf("\nПуть: %s\n", path)
        fmt.Printf("Код цепи: %s\n", hex.EncodeToString(newChainCode))

        // Получаем открытый ключ для этого пути
        pubKey, err := childKey.Public()
        if err != nil {
            panic(err)
        }

        // Каждый путь имеет уникальный ключ
        fmt.Printf("Открытый ключ: %s...\n", hex.EncodeToString(pubKey.X[:16]))
    }

    // Используем выведённые ключи для подписания
    message := []byte("Транзакция HD кошелька")
    opts := &gostcrypto.Options{Hash: gost3410.Streebog256}

    for i, path := range paths {
        pubKey, _ := derivedKeys[i].Public()
        signature, _ := gostcrypto.Sign(derivedKeys[i], message, opts)
        valid, _ := gostcrypto.Verify(pubKey, message, signature, opts)

        fmt.Printf("Подпись пути %s действительна: %v\n", path, valid)
    }
}
```

### Формат пути иерархического производного получения ключей

Реализация поддерживает BIP32-подобные пути со следующим форматом:

```
m/путь/к/ключам
  ↓    ↓  ↓
главный дочерний дочерний...

- Защищённое выведение: используйте суффикс ' (например, m/0'/1')
- Обычное выведение: просто число (например, m/0/1)
- Корень: всегда начинайте с 'm/'
```

Примеры:
- `m/0` - дочерний ключ на индексе 0 (обычный)
- `m/0'` - дочерний ключ на индексе 0 (защищённый)
- `m/44'/283'/0'/0/0` - типичный путь учётной записи кошелька
- `m/0'/1'/2'/3'/4'` - глубоко защищённый путь

## Низкоуровневый API

Для большего контроля используйте низкоуровневый API напрямую:

### Прямое подписание с неформатированными дайджестами

```go
package main

import (
    "fmt"
    "gost-crypto/gost3410"
    "gost-crypto/streebog"
)

func main() {
    // Генерируем пару ключей
    privKey, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
    if err != nil {
        panic(err)
    }

    pubKey, err := privKey.Public()
    if err != nil {
        panic(err)
    }

    // Вручную вычисляем дайджест
    message := []byte("Пример прямого подписания")
    digest := streebog.Sum256(message)

    // Подписываем дайджест напрямую
    signature, err := privKey.Sign(digest[:], gost3410.Streebog256)
    if err != nil {
        panic(err)
    }

    // Проверяем подпись
    valid, err := pubKey.Verify(digest[:], signature, gost3410.Streebog256)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Подпись действительна: %v\n", valid)
}
```

### Создание ключей из неформатированных байт

```go
package main

import (
    "encoding/hex"
    "fmt"
    "gost-crypto/gost3410"
)

func main() {
    // Создаём приватный ключ из 32-байтного семени (для 256-битной кривой)
    privKeyBytes, _ := hex.DecodeString(
        "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28")

    privKey, err := gost3410.FromRawPriv(gost3410.TC26_256_A, privKeyBytes)
    if err != nil {
        panic(err)
    }

    pubKey, err := privKey.Public()
    if err != nil {
        panic(err)
    }

    fmt.Printf("Ключ создан из неформатированных байт\n")
    fmt.Printf("Открытый ключ X: %s\n", hex.EncodeToString(pubKey.X[:16]))
    fmt.Printf("Открытый ключ Y: %s\n", hex.EncodeToString(pubKey.Y[:16]))
}
```

## Структура пакета

```
gost-crypto/
├── streebog/           # Реализация хеша Streebog-256/512
├── gost3410/           # Цифровые подписи ГОСТ Р 34.10-2012
│   ├── backend_gogost.go    # Интеграция библиотеки gogost
│   ├── keys.go              # Управление ключами и сериализация
│   ├── sign.go              # Подписание и проверка
│   └── *_test.go            # Комплексный набор тестов
├── gostcrypto/         # API высокоуровневого фасада
│   ├── sign_verify.go       # Объединённые операции хеш и подпись
│   ├── options.go           # Опции конфигурации
│   └── *_test.go            # Интеграционные тесты
├── kdf/hd/             # Производное получение ключей HD
│   └── derive.go        # Иерархическое производное получение ключей
└── _examples/          # Примеры использования
    ├── sign_verify/         # Базовое подписание
    ├── sign_verify_512/     # 512-битное подписание
    ├── hd_derivation/       # Пример HD кошелька
    ├── batch_signing/       # Пакетные операции
    └── key_serialization/   # Примеры форматов ключей
```

## Тестирование

Реализация включает комплексное покрытие тестами:

- **54+ базовых тестов**: Основная функциональность и соответствие стандартам
- **7 интеграционных тестов**: Полные рабочие процессы, объединяющие несколько операций
- **15 тестов граничных случаев**: Граничные условия и обработка ошибок

### Запуск тестов

```bash
# Запустить все тесты
go test ./...

# Запустить с подробным выводом
go test -v ./...

# Запустить тесты для определённого пакета
go test -v ./gost3410
go test -v ./gostcrypto

# Запустить с отчётом о покрытии
go test -cover ./...

# Запустить конкретный тест
go test -run TestIntegrationSignVerifyWithSerialization256 ./gostcrypto
```

### Области покрытия тестами

- **Streebog**: Пустые сообщения, стандартные тестовые векторы, большие сообщения
- **ГОСТ 34.10-2012**: Генерация ключей, подписание, проверка, сериализация
- **Восстановление ключей**: Сжатые/несжатые форматы с/без префикса
- **HD выведение**: Согласованность пути, защищённое/обычное выведение
- **Интеграция**: Полные рабочие процессы, несколько кривых, пакетные операции
- **Граничные случаи**: Минимальные/максимальные ключи, нулевые входы, несоответствие размеров
- **Безопасность**: Обнаружение повреждений, атаки подтверждения подписи

## Детали реализации

### Формат подписи

Подписи хранятся в формате ГОСТ OCTET STRING: `r || s`

Каждый компонент (r и s) хранится как big-endian байты:
- Для 256-битных кривых: по 32 байта каждый, всего 64 байта
- Для 512-битных кривых: по 64 байта каждый, всего 128 байт

### Форматы сериализации ключей

**Сжатый формат** (с префиксом):
- Байт префикса: 0x02 (чётный Y) или 0x03 (нечётный Y)
- Координата X: 32 байта (256-бит) или 64 байта (512-бит)
- Всего: 33 байта (256-бит) или 65 байт (512-бит)

**Несжатый формат** (с префиксом):
- Байт префикса: 0x04
- Координата X: 32 байта (256-бит) или 64 байта (512-бит)
- Координата Y: 32 байта (256-бит) или 64 байта (512-бит)
- Всего: 65 байт (256-бит) или 129 байт (512-бит)

Без префикса соответствующий байт префикса опускается.

### Обработка порядка байт

Реализация использует:
- **Big-endian**: Для хранения ключей и подписей
- **Little-endian**: Для совместимости с backend gogost (обрабатывается внутри)

Это преобразование прозрачно для пользователей публичного API.

## Характеристики производительности

Типичная производительность на современном оборудовании:

- **Генерация ключей**: ~1-2 мс за ключ
- **Подписание**: ~1-2 мс за операцию
- **Проверка**: ~1-2 мс за операцию
- **HD выведение**: ~0.1-0.5 мс за ключ

Пакетные операции выигрывают от:
- Минимального накладного расхода при выделении памяти
- Эффективного повторного использования контекста криптографии
- Отсутствия зависимостей между операциями

## Соображения по безопасности

1. **Случайный Nonce**: Каждая подпись использует уникальный случайный nonce (k)
2. **Защита приватного ключа**: Никогда не логируйте и не сериализуйте приватные ключи
3. **Проверка входов**: Все входы проверяются на размер и формат
4. **Операции в постоянное время**: Проверка использует сравнение в постоянное время
5. **Соответствие стандартам**: Соответствует спецификации ГОСТ Р 34.10-2012

## Правовые и нормативные требования

Эта библиотека реализует стандарты ГОСТ, которые являются российскими криптографическими алгоритмами. Используйте в соответствии с применимыми законами и нормативными актами вашей юрисдикции.

## Ссылки

- [ГОСТ Р 34.10-2012](https://www.tc26.ru/): Алгоритмы подписания и проверки для эллиптических кривых ГОСТ
- [ГОСТ Р 34.11-2012](https://www.tc26.ru/): Криптографическая функция хеш Стрибог
- [RFC 7091](https://datatracker.ietf.org/doc/html/rfc7091): Публичные подписи ГОСТ Р 34.10-2012
- [RFC 6986](https://datatracker.ietf.org/doc/html/rfc6986): Функция хеш ГОСТ Р 34.11-2012 Стрибог
- [github.com/ddulesov/gogost](https://github.com/ddulesov/gogost): Базовая реализация криптографии
- [Официальный веб-сайт ТК26](http://www.tc26.ru/): Технические спецификации


## Лицензия

Эта реализация предоставляется в образовательных целях и для авторизированного тестирования безопасности. Убедитесь, что вы имеете надлежащее разрешение перед использованием в производстве.
