# awesome-go Submission Checklist

Submit after **June 16, 2026** (5 months from first commit).

## Requirements Status

- [x] Open source license (MIT)
- [x] `go.mod` file
- [x] Semantic version release (v0.2.0+)
- [x] English README
- [x] pkg.go.dev documentation with Examples
- [x] Go-style documentation headers on all public types
- [ ] 5+ months of history (eligible June 16, 2026)
- [ ] Test coverage >= 80% (verify with gost-engine in CI)
- [ ] Go Report Card grade A- or above

## PR Template

Open a PR to https://github.com/avelino/awesome-go

**Title:** `Add gost-crypto to Security/Cryptography`

**Body:**

```
- [gost-crypto](https://github.com/rekurt/gost-crypto) - Go library for Russian GOST cryptographic standards (digital signatures, Streebog hash, Kuznechik cipher, MGM AEAD) backed by OpenSSL gost-engine.

**Links:**
- [pkg.go.dev](https://pkg.go.dev/github.com/rekurt/gost-crypto)
- [Go Report Card](https://goreportcard.com/report/github.com/rekurt/gost-crypto)
- [Coverage](https://codecov.io/gh/rekurt/gost-crypto)
```

**Category:** Add under `Security` > `Cryptographic Libraries` section, alphabetically.

## Before Submitting

1. Verify Go Report Card grade: https://goreportcard.com/report/github.com/rekurt/gost-crypto
2. Verify coverage >= 80%: https://codecov.io/gh/rekurt/gost-crypto
3. Ensure all issues are responded to within 2 weeks
