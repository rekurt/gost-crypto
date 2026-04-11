# Deployment Guide

`gost-crypto` runs on top of **CryptoPro CSP 5.0+ for Linux** and the
**CryptoPro CAdES** library. GOST primitives (Streebog, GOST 34.10-2012
sign / verify / VKO, Kuznechik / Magma raw block cipher, IMIT MAC) are
delegated to CryptoPro CSP via CAPILite; CMS / CAdES-BES signatures are
produced by `libcades`. Cipher modes that CryptoPro CSP does not expose
natively (CTR / CFB / OFB / MGM) are implemented in pure Go in
`pkg/gost3413` on top of the raw block cipher.

## Prerequisites

- Go 1.22+
- A supported Linux distribution (CryptoPro CSP supports Debian / Ubuntu,
  RHEL / CentOS, Alt Linux, Astra Linux — see the CSP release notes)
- **CryptoPro CSP 5.0+ for Linux**, installed under `/opt/cprocsp/`
- A valid CryptoPro licence (`/opt/cprocsp/sbin/amd64/cpconfig -license`)
- CryptoPro **CAdES** library (`libcades.so`) — ships with CryptoPro SDK
- CryptoPro C/C++ development headers under `/opt/cprocsp/include/`
- GCC / Clang for CGO

## Installation

CryptoPro CSP is proprietary software that must be obtained from
<https://cryptopro.ru> under a valid licence. The following outline
covers the Debian / Ubuntu layout; Alt / Astra / RHEL installers share
the same directory structure but use their native package managers.

### 1. Install the CSP

```bash
# Obtain linux-amd64_deb.tgz from cryptopro.ru, extract, and run:
sudo ./install.sh

# After install, register your licence:
sudo /opt/cprocsp/sbin/amd64/cpconfig -license -set <SERIAL>
/opt/cprocsp/sbin/amd64/cpconfig -license -view
```

This deploys:
- `/opt/cprocsp/lib/amd64/libcapi10.so`, `libcapi20.so`, `libssp.so`,
  `librdrsup.so` — core CAPILite runtime
- `/opt/cprocsp/sbin/amd64/cpverify`, `csptest`, `cryptcp` — CLI utilities

### 2. Install the CAdES SDK

The CryptoPro CAdES SDK is distributed separately (cades-linux-\*.tgz).
Install it the same way and confirm that the library is present:

```bash
ls /opt/cprocsp/lib/amd64/libcades.so
ls /opt/cprocsp/include/cades/CAdES.h
```

### 3. Ensure the dynamic linker can find CryptoPro libraries

```bash
echo "/opt/cprocsp/lib/amd64" | sudo tee /etc/ld.so.conf.d/cprocsp.conf
sudo ldconfig
```

### 4. Build `gost-crypto`

```bash
export CGO_ENABLED=1
go build ./...
go test -race -count=1 ./...
```

The CGO preamble in `internal/cryptopro/*.go` declares the default
header and library search paths:

```
#cgo CFLAGS:  -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 \
              -I/opt/cprocsp/include -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/cades
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi10 -lcapi20 -lssp -lrdrsup -lcades
```

If your CSP install lives elsewhere, override via `CGO_CFLAGS` and
`CGO_LDFLAGS` environment variables.

## Verification

```bash
# Smoke test: ask CSP for its version and confirm the licence is live.
/opt/cprocsp/sbin/amd64/cpconfig -license -view
/opt/cprocsp/sbin/amd64/csptest -keyset -verifycontext -provtype 80

# Go-level smoke test from this repository.
CGO_ENABLED=1 go run ./_examples/sign_verify
CGO_ENABLED=1 go run ./_examples/vko_agreement
```

You can also verify directly from Go:

```go
package main

import (
    "fmt"
    "github.com/rekurt/gost-crypto/internal/cryptopro"
)

func main() {
    if err := cryptopro.Init(); err != nil {
        fmt.Println("CryptoPro CSP not available:", err)
        return
    }
    fmt.Println("CryptoPro CSP initialised successfully")
}
```

## Troubleshooting

### `cryptopro: CryptoPro CSP not available`

`cryptopro.Init()` returns this error when `CryptAcquireContextA` fails
for both `PROV_GOST_2012_256` (80) and `PROV_GOST_2012_512` (81). Most
common causes:

1. CryptoPro CSP is not installed or not on `LD_LIBRARY_PATH` — run
   `ldconfig -p | grep cprocsp` and ensure `/opt/cprocsp/lib/amd64`
   is covered.
2. No CryptoPro licence — run
   `/opt/cprocsp/sbin/amd64/cpconfig -license -view`.
3. The process does not have permission to write the CSP's runtime
   directory — check `/var/opt/cprocsp/` ownership.

### `cryptopro: CadesSignMessage failed: ... (0x8009001F)`

`NTE_PROVIDER_DLL_FAIL` — the CAdES library could not load a CSP plug-in.
Verify that both `libcapi10.so` and `libcades.so` are visible to the
dynamic linker, and that their ABI versions match (CryptoPro CAdES SDK
must match the installed CSP major version).

### `cryptopro: CryptSignHashA failed: ... (0x8009000D)`

`NTE_NO_KEY` — the signing operation could not locate a private key
bound to the signer certificate. When calling `pkg/cms.Sign` on a
certificate obtained from `gostx509.ParseDER`, the certificate has no
KeyProvInfo linkage. Either produce the certificate via
`gostx509.CreateSelfSigned` (which binds the key automatically) or set
the `CERT_KEY_PROV_INFO_PROP_ID` property out-of-band before signing.

### `cannot find -lcapi10` / `-lcades`

`/opt/cprocsp/lib/amd64` is not on the linker path. Pass it explicitly:

```bash
CGO_LDFLAGS="-L/opt/cprocsp/lib/amd64 -lcapi10 -lcapi20 -lssp -lrdrsup -lcades" \
go build ./...
```

### Tests skip with "CryptoPro CSP not available"

All tests that depend on the live backend call `cryptopro.Init()` and
skip if it fails. This is expected in environments where CryptoPro CSP
is not present (including most CI runners without a private CSP image).
To make the tests run, install the CSP and provide a licence.

## CI

The CI workflow has not yet been migrated to CryptoPro CSP and will fail
on the `claude/openssl-to-cades-migration-Juqab` branch until a CSP
image is published for the runner. This is expected and will be
addressed in a follow-up PR.
