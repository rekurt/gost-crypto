# Индекс документации

Этот индекс перечисляет все **актуальные** документы для `github.com/rekurt/gost-crypto`.

## С чего начать

- [README.md](../README.md) — быстрый старт, поддерживаемые алгоритмы, требования.
- [docs/README.ru.md](README.ru.md) — быстрый старт на русском и ссылки.

## Основные документы

- [API.md](API.md) — экспортируемые пакеты, типы и функции.
- [EXAMPLES.md](EXAMPLES.md) — рабочие паттерны использования на текущем API.
- [DEPLOYMENT.md](DEPLOYMENT.md) — установка OpenSSL + gost-engine.
- [MIGRATION.md](MIGRATION.md) — переход с v0 на v1.
- [THREAT_MODEL.md](THREAT_MODEL.md) — модель угроз и безопасность.
- [CONTRIBUTING.md](CONTRIBUTING.md) — руководство для контрибьюторов.

## Переводы на русский

- [DOCUMENTATION.ru.md](DOCUMENTATION.ru.md)
- [API.ru.md](API.ru.md)
- [EXAMPLES.ru.md](EXAMPLES.ru.md)
- [README.ru.md](README.ru.md)

## Статус валидации

Документация синхронизирована с текущим API:

- фасадный пакет `gostcrypto`
- `pkg/gost3410`, `pkg/gost3411`, `pkg/gost3412`, `pkg/gost3413`, `pkg/kdf`, `pkg/hd`

Все тесты пакетов проходят командой `go test ./...` в этом репозитории.
