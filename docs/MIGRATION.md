# Migration Guide: v0 to v1

This document covers the breaking changes and migration path from the original gost-crypto (v0, which used a GPL-licensed pure-Go backend) to v1 (backed by CryptoPro CSP (CAPILite) + CryptoPro CAdES, MIT license, zero external Go dependencies).

## Overview of Changes

v1 is a complete rewrite. The module path, API surface, and cryptographic backend have all changed.

| Aspect | v0 | v1 |
|--------|----|----|
| Backend | gogost (pure Go, GPL v3) | CryptoPro CSP 5.0+ for Linux (cgo) |
| Module | v0 packages (removed) | `github.com/rekurt/gost-crypto` |
| Curves | 5 (256A, 512A/B/C + limited) | 8 (all TC26 parameter sets) |
| VKO | Not supported | Supported (GOST VKO key agreement) |
| Kuznechik | Not supported | Supported (GOST R 34.12-2015) |
| MGM (AEAD) | Not supported | Supported (GOST R 34.13-2015) |
| KDF | HKDF only | GOST R KDF + HKDF |
| Key zeroization | Manual byte clearing | Explicit `Zeroize()` with GC finalizer safety net |
| Constant-time | Best-effort in Go | Delegated to CryptoPro CSP |

## Breaking Changes

1. **Module path changed**: Replace all imports of `gost-crypto/gostcrypto`, `gost-crypto/gost3410`, `gost-crypto/streebog`, and `gost-crypto/kdf/hd` with imports from `github.com/rekurt/gost-crypto` and its sub-packages.

2. **API completely rewritten**: Function signatures, types, and error values have changed. There is no backward compatibility.

3. **cgo required**: `CGO_ENABLED=1` must be set. A C compiler and CryptoPro CSP development headers are required at build time.

4. **Runtime dependency on CryptoPro CSP**: CryptoPro CSP must be installed and registered in `CryptoPro CSP config (cpconfig)` on any machine that runs the compiled binary.

## API Mapping

### Key Generation

```go
// v0
privKey, _, err := gost3410.NewPrivKey(gost3410.TC26_256_A)
pubKey, err := privKey.Public()

// v1
priv, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
defer priv.Zeroize()
pub := priv.PublicKey()
```

### Signing

```go
// v0
opts := &gostcrypto.Options{Hash: gost3410.Streebog256}
signature, err := gostcrypto.Sign(privKey, message, opts)

// v1 (hash selection is automatic based on curve)
signature, err := gostcrypto.Sign(priv, message)
```

### Verification

```go
// v0
opts := &gostcrypto.Options{Hash: gost3410.Streebog256}
valid, err := gostcrypto.Verify(pubKey, message, signature, opts)

// v1
valid, err := gostcrypto.Verify(pub, message, signature)
```

### Hashing

```go
// v0
digest := streebog.Sum256(data)

// v1
import "github.com/rekurt/gost-crypto/pkg/gost3411"
digest := gost3411.Sum256(data)
// or via the facade:
digest := gostcrypto.HashSum256(data)
```

### HD Key Derivation

```go
// v0
masterKey, chainCode, err := hd.Master(seed, gost3410.Streebog256)
childKey, newChainCode, err := hd.Derive(masterKey, chainCode, path, gost3410.Streebog256)

// v1
import (
    gostcrypto "github.com/rekurt/gost-crypto"
    "github.com/rekurt/gost-crypto/pkg/hd"
)
masterDK, err := hd.Master(seed, gostcrypto.CurveTC26_256_A)
childDK, err := hd.Derive(masterDK, "m/44'/0'/0", gostcrypto.CurveTC26_256_A)
```

### New in v1 (No v0 Equivalent)

```go
// VKO key agreement
shared, err := gostcrypto.Agree(privA, privB.PublicKey(), ukm)

// Kuznechik block cipher
import "github.com/rekurt/gost-crypto/pkg/gost3412"
cipher, err := gost3412.NewCipher(key)

// MGM authenticated encryption
import "github.com/rekurt/gost-crypto/pkg/gost3413"
aead, err := gost3413.NewMGM(cipher)

// GOST R KDF
import "github.com/rekurt/gost-crypto/pkg/kdf"
derived := kdf.KDF_GOSTR3411_256(key, label, seed)
```

## Migration Steps

1. **Install CryptoPro CSP (CAPILite) + CryptoPro CAdES** on all build and runtime environments. See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed instructions.

2. **Update `go.mod`**:
   ```bash
   go get github.com/rekurt/gost-crypto@latest
   ```

3. **Replace imports**: Update all import paths from the old module to `github.com/rekurt/gost-crypto` and its sub-packages (`pkg/gost3410`, `pkg/gost3411`, `pkg/gost3412`, `pkg/gost3413`, `pkg/kdf`, `pkg/hd`).

4. **Update key lifecycle**: Add `defer priv.Zeroize()` after every `GenerateKey` call.

5. **Remove hash option parameters**: The v1 `Sign` and `Verify` functions automatically select the hash based on the curve size. Remove any `Options` struct usage.

6. **Update error handling**: Error sentinel values have changed. Replace references to old error variables with the new ones exported from `gostcrypto` (e.g., `gostcrypto.ErrNilKey`, `gostcrypto.ErrUnknownCurve`).

7. **Update CI/CD**: Ensure your build environment has `CGO_ENABLED=1`, CryptoPro CSP.headers, and CryptoPro CSP. See the GitHub Actions workflow in `.github/workflows/ci.yml` for a reference setup.
