# Documentation Index

This index lists all актуальные documents for `github.com/rekurt/gost-crypto`.

## Start here

- [README.md](../README.md) — quick start, supported algorithms, requirements.
- [docs/README.ru.md](README.ru.md) — Russian quick start and links.

## Core docs

- [API.md](API.md) — exported packages, types, and functions.
- [EXAMPLES.md](EXAMPLES.md) — validated usage patterns based on current API.
- [DEPLOYMENT.md](DEPLOYMENT.md) — CryptoPro CSP (CAPILite) + CryptoPro CAdES installation.
- [MIGRATION.md](MIGRATION.md) — v0 → v1 migration notes.
- [THREAT_MODEL.md](THREAT_MODEL.md) — threat model and security design.
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guidelines and development setup.

## Russian translations

- [DOCUMENTATION.ru.md](DOCUMENTATION.ru.md)
- [API.ru.md](API.ru.md)
- [EXAMPLES.ru.md](EXAMPLES.ru.md)
- [README.ru.md](README.ru.md)

## Validation status

This documentation set was synchronized with the CryptoPro CSP migration
(branch `claude/openssl-to-cades-migration-Juqab`):

- top-level facade package `gostcrypto`
- `pkg/gost3410`, `pkg/gost3411`, `pkg/gost3412`, `pkg/gost3413`, `pkg/cms`, `pkg/gostx509`, `pkg/kdf`, `pkg/hd`

**Note**: compilation and tests require CryptoPro CSP 5.0+ for Linux
installed under `/opt/cprocsp/`. Build tag: `-tags cryptopro`.
CI is currently stubbed pending a private base image with the CSP.
