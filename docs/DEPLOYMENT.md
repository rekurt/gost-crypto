# Deployment Guide

This library requires OpenSSL 3.0+ with [gost-engine](https://github.com/gost-engine/engine) installed and registered. All cryptographic operations are delegated to OpenSSL via cgo.

## Prerequisites

- Go 1.22+
- OpenSSL 3.0+ development headers
- gost-engine v3.0.3+ (built from source)
- C compiler (gcc or clang)
- CMake 3.10+

## Linux (Debian / Ubuntu)

### Install OpenSSL development headers

```bash
sudo apt-get update
sudo apt-get install -y libssl-dev cmake git gcc g++ pkg-config make
```

### Build and install gost-engine

The repository includes a helper script:

```bash
chmod +x scripts/install-gost-engine.sh
sudo scripts/install-gost-engine.sh
```

This clones gost-engine v3.0.3, builds it, and installs `gost.so` into the OpenSSL modules directory.

### Register gost-engine in OpenSSL config

Add the following to `/etc/ssl/openssl.cnf` (or the equivalent path for your distribution):

```ini
# In the [openssl_init] section, add:
engines = engine_section

# Then add these sections at the end of the file:
[engine_section]
gost = gost_section

[gost_section]
engine_id = gost
dynamic_path = /usr/lib/x86_64-linux-gnu/ossl-modules/gost.so
default_algorithms = ALL
init = 1
```

Adjust `dynamic_path` to match where `gost.so` was installed. You can find it with:

```bash
find /usr/lib -name "gost.so" 2>/dev/null
```

## Linux (Alpine)

```bash
apk add openssl-dev cmake git gcc g++ musl-dev make pkgconfig
chmod +x scripts/install-gost-engine.sh
sudo scripts/install-gost-engine.sh
```

The OpenSSL config path on Alpine is typically `/etc/ssl/openssl.cnf`. Register gost-engine as described above.

## macOS

### Install OpenSSL via Homebrew

```bash
brew install openssl@3 cmake pkg-config
```

### Build gost-engine from source

```bash
export OPENSSL_DIR=$(brew --prefix openssl@3)

git clone --depth 1 --branch v3.0.3 https://github.com/gost-engine/engine.git
cd engine
git submodule update --init --depth 1

mkdir -p build && cd build
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR="$OPENSSL_DIR" \
  -DOPENSSL_INCLUDE_DIR="$OPENSSL_DIR/include" \
  -DOPENSSL_CRYPTO_LIBRARY="$OPENSSL_DIR/lib/libcrypto.dylib"
make -j$(sysctl -n hw.ncpu)

# Install gost.so into the OpenSSL modules directory
OSSL_MODULES="$OPENSSL_DIR/lib/ossl-modules"
mkdir -p "$OSSL_MODULES"
cp bin/gost.so "$OSSL_MODULES/"
```

### Register in OpenSSL config

Edit `$(brew --prefix openssl@3)/etc/openssl/openssl.cnf` to add the engine section as described above, using:

```
dynamic_path = /opt/homebrew/opt/openssl@3/lib/ossl-modules/gost.so
```

### Set environment for Go builds

```bash
export CGO_ENABLED=1
export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"
export CGO_CFLAGS="-I$(brew --prefix openssl@3)/include"
export CGO_LDFLAGS="-L$(brew --prefix openssl@3)/lib"
```

## Docker

The repository includes `Dockerfile.ci` which builds a ready-to-use image with OpenSSL + gost-engine:

```bash
docker build -f Dockerfile.ci -t gost-crypto-ci .
docker run --rm -v "$(pwd):/app" -w /app gost-crypto-ci go test ./... -count=1
```

This is the recommended approach for CI and development on systems where building gost-engine locally is impractical.

## Verification

After installation, verify gost-engine is correctly loaded:

```bash
openssl engine -t gost
```

Expected output:

```
(gost) Reference implementation of GOST engine
     [ available ]
```

You can also verify from Go:

```go
package main

import (
    "fmt"
    "github.com/rekurt/gost-crypto/internal/openssl"
)

func main() {
    if err := openssl.Init(); err != nil {
        fmt.Println("gost-engine not available:", err)
    } else {
        fmt.Println("gost-engine initialized successfully")
    }
}
```

## Troubleshooting

### `ENGINE_by_id("gost") failed`

The engine is not registered in `openssl.cnf`. Verify:
1. `gost.so` exists at the path specified in `dynamic_path`
2. The `[openssl_init]` section has `engines = engine_section`
3. Run `openssl engine -t gost` to confirm

### `cannot find -lssl` or `cannot find -lcrypto`

OpenSSL development headers are missing. Install `libssl-dev` (Debian/Ubuntu), `openssl-dev` (Alpine), or `openssl@3` (macOS Homebrew).

### `pkg-config: openssl not found`

On macOS with Homebrew, set `PKG_CONFIG_PATH`:

```bash
export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"
```

### `gost.so: cannot open shared object file`

The `dynamic_path` in `openssl.cnf` is incorrect. Find the actual location:

```bash
find / -name "gost.so" 2>/dev/null
```

### Tests skip with "gost-engine not available"

All tests that depend on gost-engine call `openssl.Init()` and skip if it fails. If all tests are skipping, gost-engine is not properly installed or registered.

### macOS: `ld: library not found for -lssl`

Ensure you have set `CGO_LDFLAGS` and `CGO_CFLAGS` pointing to the Homebrew OpenSSL installation (see macOS section above).
