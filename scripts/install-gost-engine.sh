#!/bin/bash
set -euo pipefail

GOST_ENGINE_VERSION="${GOST_ENGINE_VERSION:-v3.0.3}"
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "${BUILD_DIR}"' EXIT

echo "==> Building gost-engine ${GOST_ENGINE_VERSION}"
cd "${BUILD_DIR}"
git clone --depth 1 --branch "${GOST_ENGINE_VERSION}" \
    https://github.com/gost-engine/engine.git
cd engine
git submodule update --init --depth 1

mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release

NPROC=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)
make -j"${NPROC}"

OSSL_MODULES=$(find /usr/lib -name "ossl-modules" -type d 2>/dev/null | head -1 || echo "/usr/lib/ossl-modules")

install -Dm755 bin/gost.so "${OSSL_MODULES}/gost.so"
echo "==> gost-engine installed to ${OSSL_MODULES}/gost.so"

# Register gost-engine in openssl.cnf so ENGINE_by_id("gost") can find it.
OPENSSL_CNF=$(openssl version -d 2>/dev/null | awk -F'"' '{print $2}')/openssl.cnf
if [ -f "${OPENSSL_CNF}" ]; then
    if ! grep -q 'engine_section' "${OPENSSL_CNF}"; then
        sed -i '/^\[openssl_init\]/a engines = engine_section' "${OPENSSL_CNF}"
        printf '\n[engine_section]\ngost = gost_section\n\n[gost_section]\nengine_id = gost\ndynamic_path = %s/gost.so\ndefault_algorithms = ALL\ninit = 1\n' "${OSSL_MODULES}" >> "${OPENSSL_CNF}"
        echo "==> Registered gost-engine in ${OPENSSL_CNF}"
    else
        echo "==> engine_section already present in ${OPENSSL_CNF}, skipping"
    fi
else
    echo "WARNING: Could not find ${OPENSSL_CNF} — manual openssl.cnf configuration required"
fi
