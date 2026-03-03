# Реализация TODO.md: Полный план по результатам аудита gost-crypto

## Overview

Пошаговая реализация всех 33 задач из TODO.md (результат аудита). Задачи сгруппированы в 13 тасков по
зависимостям и связности. Порядок: сначала P0 (блокирующие), затем P1 (безопасность), P2
(архитектура), P4 (тесты), P3 (презентабельность), P5 (улучшения), финальная верификация и
сквозная проверка документации.

## Context

- Repository: github.com/rekurt/gost-crypto
- Branch: gost-validation-tests
- Files involved: go.mod, gost3410/*.go, gostcrypto/*.go, streebog/*.go, kdf/hd/*.go, README.md, README.ru.md, API.md, API.ru.md, .gitignore, all *_test.go
- Current state: All tests pass, go vet clean
- External dependency: github.com/ddulesov/gogost v1.0.0

## Development Approach

- **Testing approach**: Regular (code first, then tests) for fixes; test-first for new features
- Complete each task fully before moving to the next
- **CRITICAL: every task MUST include new/updated tests**
- **CRITICAL: all tests must pass before starting next task**
- **CRITICAL: go vet must pass after each task**

## Implementation Steps

### Task 1: P0 — Fix module path and imports [1.1]

**Files:**
- Modify: `go.mod`
- Modify: `gostcrypto/facade.go`
- Modify: `gostcrypto/facade_test.go`
- Modify: `gostcrypto/integration_test.go`
- Modify: `kdf/hd/hd.go`
- Modify: `kdf/hd/hd_test.go`
- Modify: `gost3410/vectors_test.go`
- Modify: `gost3410/edge_cases_test.go`
- Modify: `_examples/sign_verify_256/main.go`
- Modify: `_examples/sign_verify_512/main.go`
- Modify: `_examples/batch_signing/main.go`
- Modify: `_examples/hd_derivation/main.go`
- Modify: `_examples/key_serialization/main.go`

- [x] Change `go.mod` module line from `module gost-crypto` to `module github.com/rekurt/gost-crypto`
- [x] Replace all `"gost-crypto/` imports with `"github.com/rekurt/gost-crypto/` in every .go file (source + tests + examples)
- [x] Run `go build ./...` to verify compilation
- [x] Run `go test ./...` — all tests must pass
- [x] Run `go vet ./...` — must be clean

### Task 2: P1 — Private key validation [1.2]

**Files:**
- Modify: `gost3410/keys.go`
- Modify: `gost3410/backend_gogost.go` (need curve order access)
- Modify: `gost3410/edge_cases_test.go`

- [x] Add helper function `curveOrder(c Curve) *big.Int` in `backend_gogost.go` that returns the curve's subgroup order `q` from the gogost curve object
- [x] In `NewPrivKey()`: after generating random bytes, convert `d` to `*big.Int`, check `0 < d < q`; if out of range, retry (rejection sampling loop with max attempts)
- [x] In `FromRawPriv()`: convert `d` to `*big.Int`, reject with error if `d == 0` or `d >= q`
- [x] Update `TestEdgeCaseZeroPrivateKey`: assert that `FromRawPriv` with all-zero bytes returns an error (not just log)
- [x] Add test `TestFromRawPrivRangeValidation`: test with d=0, d=q, d=q-1, d=1 to verify range check
- [x] Run `go test ./...` — all tests must pass

### Task 3: P1 — ToCompressed error handling + padToSize copy [1.3, 5a]

**Files:**
- Modify: `gost3410/keys.go`
- Modify: `gost3410/backend_gogost.go`
- Modify: `gost3410/edge_cases_test.go`
- Modify: `gost3410/backend_test.go`

- [x] Change `ToCompressed(prefix bool) []byte` signature to `ToCompressed(prefix bool) ([]byte, error)`
- [x] In `ToCompressed(false)`: if `X[0] >= 0x80`, return `nil, errors.New("X[0] high bit set: use prefix=true for this key")`
- [x] Update all callers of `ToCompressed` throughout codebase to handle the new `([]byte, error)` return
- [x] In `padToSize`: when `len(b) == size`, return `append([]byte(nil), b...)` (copy) instead of returning the original slice
- [x] In `padToSize`: when `len(b) > size`, return a copy of the truncated bytes instead of a subslice
- [x] Update tests for `ToCompressed`: add cases for `X[0] >= 0x80` with `prefix=false` verifying error is returned
- [x] Update serialization roundtrip tests to handle error from `ToCompressed`
- [x] Add test `TestPadToSizeReturnsCopy` verifying modifications to result don't affect input
- [x] Run `go test ./...` — all tests must pass

### Task 4: P1 — Replace custom modSqrt with stdlib [2.5]

**Files:**
- Modify: `gost3410/backend_gogost.go`
- Modify: `gost3410/backend_test.go`

- [x] Replace the custom `modSqrt(a, p *big.Int) *big.Int` function (~60 lines) with a wrapper around `new(big.Int).ModSqrt(a, p)`
- [x] Handle the case where `ModSqrt` returns `nil` (no square root exists) — return `nil`
- [x] Remove the old Tonelli-Shanks implementation entirely
- [x] Run existing `TestRecoverY256`, `TestRecoverY512`, and serialization roundtrip tests to verify correctness
- [x] Run `go test ./...` — all tests must pass

### Task 5: P2 — Architecture: move HashID, remove dead param, isolate gogost [2.1, 2.2, 2.4]

**Files:**
- Modify: `gost3410/sign.go`
- Modify: `gost3410/backend_gogost.go`
- Create: `gost3410/hash.go` (for HashID types)
- Modify: `gostcrypto/facade.go`
- Modify: `kdf/hd/hd.go`
- Modify: all `*_test.go` files that reference `HashID`, `Streebog256`, `Streebog512`

NOTE: Moving HashID to a separate package (e.g., streebog/ or root) would be ideal per the audit, but it creates a circular import issue (kdf/hd imports gost3410 for PrivKey AND needs HashID; gostcrypto imports both gost3410 and streebog). Since the current location works and the alternatives all have trade-offs, the pragmatic approach is to:
1. Extract HashID to its own file `gost3410/hash.go` for better organization
2. Remove the dead `h HashID` parameter from `Sign` and `Verify`
3. Isolate gogost imports in `backend_gogost.go`

- [x] Create `gost3410/hash.go`: move `HashID`, `HashAuto`, `Streebog256`, `Streebog512` constants from `sign.go`
- [x] Remove `h HashID` parameter from `PrivKey.Sign()` — new signature: `Sign(digest []byte) ([]byte, error)`
- [x] Remove `h HashID` parameter from `PubKey.Verify()` — new signature: `Verify(digest, sig []byte) (bool, error)`
- [x] Move gogost `gg.NewPrivateKey` / `gg.NewPublicKey` calls from `sign.go` into new backend functions in `backend_gogost.go`: `backendSign(curve Curve, d, digest []byte) ([]byte, error)` and `backendVerify(curve Curve, x, y, digest, sig []byte) (bool, error)`
- [x] Refactor `sign.go` to call `backendSign` / `backendVerify` — remove `import gg` from `sign.go`
- [x] Update `gostcrypto/facade.go`: remove `h` argument from calls to `priv.Sign(digest, h)` and `pub.Verify(digest, sig, h)`
- [x] Update all test files that call `Sign(digest, HashID)` and `Verify(digest, sig, HashID)` to use new signatures
- [x] Run `go test ./...` — all tests must pass
- [x] Run `go vet ./...` — must be clean

### Task 6: P2 — Implement crypto.Signer for PrivKey [2.3]

**Files:**
- Modify: `gost3410/keys.go`
- Create: `gost3410/signer.go`
- Modify: `gost3410/sign_test.go` or create `gost3410/signer_test.go`

- [x] Rename existing `Public() (*PubKey, error)` to `PublicKey() (*PubKey, error)` — this is the GOST-specific method returning the typed key
- [x] Add new method `Public() crypto.PublicKey` that calls `PublicKey()` internally (returns nil on error, matching `crypto.Signer` convention)
- [x] Add method `Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)` that satisfies `crypto.Signer` — delegates to the existing internal Sign logic (rand parameter is ignored since gogost uses crypto/rand internally)
- [x] Add compile-time interface assertion: `var _ crypto.Signer = (*PrivKey)(nil)`
- [x] Update all callers of `Public()` that expect `(*PubKey, error)` to use `PublicKey()` instead
- [x] Add test `TestCryptoSignerInterface` verifying `PrivKey` satisfies `crypto.Signer`
- [x] Add test `TestCryptoSignerSign` verifying sign-then-verify works through the `crypto.Signer` interface
- [x] Run `go test ./...` — all tests must pass

### Task 7: P4 — Test quality fixes [3.1-3.9]

**Files:**
- Modify: `gost3410/edge_cases_test.go`
- Modify: `gost3410/vectors_test.go`
- Modify: `gostcrypto/facade_test.go`
- Modify: `streebog/streebog_test.go`
- Create: `gost3410/fuzz_test.go`

- [x] **3.1** Fix `TestEdgeCaseZeroPrivateKey`: replace permissive "either error acceptable" with assertion that `FromRawPriv` rejects zero key (this was already handled in Task 2 — verify it's solid)
- [x] **3.2** Rename `TestEdgCase512MinimalKey` to `TestEdgeCaseMinimalKey512` (fix typo)
- [x] **3.5** Delete unused `mustDecodeHex` from `streebog/streebog_test.go` (the one in `vectors_test.go` IS used — keep it)
- [x] **3.7** Fix guard in `TestVerifyCorruptedSignature` subtest `corrupted_byte`: change `if err == nil && valid` to `if valid` (corrupted signature should not validate regardless of error)
- [x] **3.8** Replace `string()` comparison with `bytes.Equal` + `%x` format in `streebog_test.go` lines: `TestStreebog256Incremental`, `TestStreebog512Incremental`, `TestStreebog256Reset`, `TestStreebog512Reset`
- [x] **3.6** Extend `TestPropertySignThenVerify` to run 100 iterations on `TC26_512_A`, `TC26_512_B`, `TC26_512_C` (add sub-tests or table-driven approach)
- [x] **3.9** Add `BenchmarkVerify256` and `BenchmarkVerify512` in `gostcrypto/facade_test.go`
- [x] **3.4** Create `gost3410/fuzz_test.go` with `FuzzFromCompressed` and `FuzzFromUncompressed` fuzz tests
- [x] **3.3** Add `Example*` functions: `ExampleSign` in `gost3410/sign_test.go`, `ExampleVerify` in `gost3410/sign_test.go`, `ExampleSum256` in `streebog/streebog_test.go`, `ExampleMaster` in `kdf/hd/hd_test.go`
- [x] Run `go test ./...` — all tests must pass
- [x] Run `go doc ./...` to verify examples render correctly

### Task 8: P3 — Repo cleanup and CI [4.1, 4.2, 4.3, 4.9, 4.11]

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `SECURITY.md`
- Create: `CONTRIBUTING.md`
- Modify: `.gitignore`
- Modify: `go.mod`
- Remove: `.idea/` from git tracking

- [x] **4.9** Add entries to `.gitignore`: `.idea/`, `*.test`, `*.out`, `coverage.*`, `.DS_Store`
- [x] **4.9** Remove `.idea/` from git tracking: `git rm -r --cached .idea/`
- [x] **4.11** Change `go 1.24` to `go 1.21` in `go.mod` (verify build still works)
- [x] **4.1** Create `.github/workflows/ci.yml`:
  - Trigger on push/PR to master and develop
  - Matrix: Go 1.21, 1.22, latest
  - Steps: checkout, setup-go, `go build ./...`, `go test -race -coverprofile=coverage.out ./...`, `go vet ./...`
  - Optional: golangci-lint step
- [x] **4.2** Create `SECURITY.md`:
  - Security vulnerability reporting policy
  - Contact for private disclosure (email or GitHub Security Advisories)
  - Supported versions
  - Disclosure timeline
- [x] **4.3** Create `CONTRIBUTING.md`:
  - How to contribute (fork, branch, PR)
  - Code style (gofmt, go vet)
  - Testing requirements
  - Commit message conventions
- [x] Run `go build ./...` to verify go 1.21 compatibility
- [x] Run `go test ./...` — all tests must pass

### Task 9: P3 — README and documentation fixes [4.4-4.8, 4.10]

**Files:**
- Modify: `README.md`
- Modify: `README.ru.md`
- Modify: `API.md`
- Modify: `API.ru.md`
- Modify: `gost3410/keys.go` or `gost3410/hash.go` (doc comments)
- Modify: `gostcrypto/facade.go` (doc comment)
- Modify: `streebog/streebog.go` (doc comment)

- [x] **4.5** Fix installation instructions in README.md and README.ru.md: replace `go get -u github.com/ddulesov/gogost` with `go get github.com/rekurt/gost-crypto`
- [x] **4.5** Fix import paths in all README code examples: replace `"gost-crypto/...` with `"github.com/rekurt/gost-crypto/...`
- [x] **4.6** Fix file structure diagram in README.md: remove `options.go` and `sign_verify.go` from gostcrypto/, show only `facade.go`
- [x] **4.6** Fix file structure diagram in README.ru.md: same corrections + replace `derive.go` with `hd.go` in kdf/hd/
- [x] **4.4** Remove broken link to `_examples/EXAMPLES.md` from README.md and README.ru.md (or create the file)
- [x] **4.10** Remove "educational and authorized security testing purposes" disclaimer from README.md License section — replace with standard MIT reference consistent with LICENSE file
- [x] **4.7** Add badges to README.md: build status (GitHub Actions), Go Report Card, GoDoc, coverage (if available)
- [x] **4.8** Add `// Package gost3410 ...` doc comment to `gost3410/` package (in `keys.go` or `hash.go`)
- [x] **4.8** Add `// Package gostcrypto ...` doc comment to `gostcrypto/facade.go`
- [x] **4.8** Add `// Package streebog ...` doc comment to `streebog/streebog.go`
- [x] **5e** Fix `API.md`: remove non-existent constants section (`Streebog256HashSize`, `TC26_256_SignatureSize`, etc.) or add them to code — since they are documented but don't exist, remove the section from API.md and API.ru.md
- [x] Update code examples in README to match new API signatures (e.g., `Sign(digest)` without HashID parameter, `PublicKey()` instead of `Public()`)
- [x] Run `go doc ./...` to verify package comments render

### Task 10: P5 — KDF/HD improvements [5b, 5c, 5d]

**Files:**
- Modify: `kdf/hd/hd.go`
- Modify: `kdf/hd/hd_test.go`

- [ ] **5b** Remove no-op truncation `[:keySize]` from `hkdfExtract` — the HMAC output is already the correct size
- [ ] **5c** Add hash/curve validation in `Derive()`: if caller passes `Streebog256` with a 512-bit parent key (or vice versa), return a clear error like `"hash size does not match key size"`
- [ ] **5d** Improve `parsePath`: detect empty segments (e.g., `"m/0//1"`) and return clear error `"empty path segment"` instead of cryptic parse error
- [ ] Add test `TestDeriveHashCurveMismatch`: verify `Derive` with Streebog256 hash + 512-bit key returns error
- [ ] Add test `TestParsePathEmptySegment`: verify `parsePath("0//1")` returns descriptive error
- [ ] Run `go test ./...` — all tests must pass

### Task 11: Verify acceptance criteria

- [ ] Run `go build ./...` — must compile cleanly
- [ ] Run `go test -race -count=1 ./...` — all tests pass with race detector
- [ ] Run `go vet ./...` — no issues
- [ ] Run `go test -cover ./...` — verify coverage >= 80% per package
- [ ] Verify all 33 TODO.md items are addressed
- [ ] Run `go doc` on each package to verify documentation renders

### Task 12: Final documentation cross-check

- [ ] Перечитать README.md целиком — проверить что все примеры кода компилируются, import paths корректны, ссылки не битые, структура проекта соответствует реальности
- [ ] Перечитать README.ru.md целиком — аналогичная проверка, плюс убедиться что русская версия полностью синхронизирована с английской
- [ ] Перечитать API.md — проверить что все описанные функции, типы, константы существуют в коде; удалить описание несуществующих, добавить описание отсутствующих
- [ ] Перечитать API.ru.md — аналогичная проверка + синхронизация с API.md
- [ ] Проверить SECURITY.md и CONTRIBUTING.md — убедиться что ссылки, имена, контактные данные корректны
- [ ] Проверить все `// Package ...` doc-комментарии — запустить `go doc ./...` и убедиться что описания корректны и полны
- [ ] Проверить все `Example*` функции — запустить `go test -run Example ./...` и убедиться что Output-комментарии совпадают с реальным выводом
- [ ] Проверить что все примеры в `_examples/` компилируются: `go build ./_examples/...`
- [ ] Сверить CLAUDE.md с текущим состоянием кода — обновить сигнатуры функций, покрытие, статус реализации
- [ ] Финальная проверка: нет ли расхождений между документацией и кодом (grep по именам функций в .md файлах и сверка с реальными сигнатурами)

### Task 13: Update project documentation

- [ ] Update CLAUDE.md: reflect new API signatures, updated coverage numbers, completed items
- [ ] Move this plan to `docs/plans/completed/`
