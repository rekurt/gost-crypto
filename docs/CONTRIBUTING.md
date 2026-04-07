# Contributing to gost-crypto

Thank you for your interest in contributing to gost-crypto!

## How to Contribute

1. Fork the repository
2. Create a feature branch from `master`: `git checkout -b feature/my-change`
3. Make your changes
4. Run tests and checks (see below)
5. Commit with a descriptive message
6. Push to your fork and open a Pull Request

## Development Requirements

- Go 1.22 or later
- OpenSSL 3.x with gost-engine installed (see [DEPLOYMENT.md](DEPLOYMENT.md))
- CGO enabled (`CGO_ENABLED=1`)
- Optional: `golangci-lint`

## Code Style

- Format code with `gofmt` (or `goimports`)
- Pass `go vet ./...` with no warnings
- Follow standard Go conventions: https://go.dev/doc/effective_go

## Testing

All changes must include tests. Before submitting a PR:

```bash
go build ./...                                          # Must compile
go test ./...                                           # All tests must pass
go vet ./...                                            # No warnings
go test -race ./...                                     # No race conditions
go test -bench=. -benchmem ./pkg/gost3410/ ./pkg/gost3411/  # Benchmarks
go test -cover ./...                                    # Coverage
```

### What Is Tested

- **Streebog**: RFC 6986 vectors (M1, M2), empty input, large messages, incremental hashing
- **GOST R 34.10-2012**: Sign/verify roundtrip on all 8 curves, property-based tests (100 iterations)
- **LoadPrivKey**: Generate-extract-load roundtrip on all curves, sign/verify with loaded keys
- **HD derivation**: Deterministic key derivation, path parsing, hardened/normal, fuzz tests
- **VKO**: Symmetric key agreement, different UKM values, cross-curve rejection
- **Error handling**: Corruption detection, cross-curve rejection, nil/zeroized keys, size mismatches

## Commit Messages

Use clear, concise commit messages:

- `feat: add compressed key support`
- `fix: handle zero-length input in FromRawPriv`
- `test: add property-based tests for 512-bit curves`
- `docs: update API reference`

## Pull Requests

- Keep PRs focused on a single change
- Reference any related issues
- Ensure CI passes before requesting review
- Be responsive to review feedback

## Cryptographic Changes

Changes to cryptographic operations require extra scrutiny:

- Reference the relevant GOST standard or RFC
- Include test vectors where applicable
- Do not implement custom cryptographic primitives when standard library alternatives exist
