#!/bin/bash
set -euo pipefail

GOST_ENGINE_VERSION="${GOST_ENGINE_VERSION:-v3.0.3}"
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "${BUILD_DIR}"' EXIT

echo "==> Building gost-engine ${GOST_ENGINE_VERSION}"
cd "${BUILD_DIR}"

# Clone with submodules instead of tarball — GitHub tarballs do not
# include git submodule contents (libprov is empty in the tarball).
git clone --depth 1 --branch "${GOST_ENGINE_VERSION}" \
    --recurse-submodules --shallow-submodules \
    https://github.com/gost-engine/engine.git gost-engine
cd gost-engine

mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release

NPROC=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)
make -j"${NPROC}"

# Install engine to OpenSSL engines directory (for ENGINE API).
ENGINES_DIR=$(openssl version -a 2>/dev/null | grep ENGINESDIR | head -1 | sed 's/.*"\(.*\)"/\1/' || echo "")
if [ -z "$ENGINES_DIR" ]; then
    ENGINES_DIR=$(find /usr/lib -name "engines-3" -type d 2>/dev/null | head -1 || echo "/usr/lib/engines-3")
fi
install -Dm755 bin/gost.so "${ENGINES_DIR}/gost.so"
echo "==> gost-engine installed to ${ENGINES_DIR}/gost.so"

# Also install to ossl-modules if it exists (for Provider API).
OSSL_MODULES=$(find /usr/lib -name "ossl-modules" -type d 2>/dev/null | head -1 || echo "")
if [ -n "$OSSL_MODULES" ]; then
    install -Dm755 bin/gost.so "${OSSL_MODULES}/gost.so"
    echo "==> gost-engine also installed to ${OSSL_MODULES}/gost.so"
fi
