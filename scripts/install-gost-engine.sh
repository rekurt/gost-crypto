#!/bin/bash
set -euo pipefail

GOST_ENGINE_VERSION="${GOST_ENGINE_VERSION:-v3.0.3}"
GOST_ENGINE_SHA256="${GOST_ENGINE_SHA256:-}"
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "${BUILD_DIR}"' EXIT

echo "==> Building gost-engine ${GOST_ENGINE_VERSION}"
cd "${BUILD_DIR}"
curl -fsSL -o engine.tar.gz \
    "https://codeload.github.com/gost-engine/engine/tar.gz/refs/tags/${GOST_ENGINE_VERSION}"
if [ -n "${GOST_ENGINE_SHA256}" ]; then
    echo "${GOST_ENGINE_SHA256}  engine.tar.gz" | sha256sum -c -
else
    echo "WARNING: GOST_ENGINE_SHA256 is not set; skipping archive checksum verification" >&2
fi
tar -xzf engine.tar.gz
cd "engine-${GOST_ENGINE_VERSION#v}"

mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release

NPROC=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)
make -j"${NPROC}"

OSSL_MODULES=$(find /usr/lib -name "ossl-modules" -type d 2>/dev/null | head -1 || echo "/usr/lib/ossl-modules")

install -Dm755 bin/gost.so "${OSSL_MODULES}/gost.so"
echo "==> gost-engine installed to ${OSSL_MODULES}/gost.so"
