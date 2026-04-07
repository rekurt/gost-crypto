FROM debian:bookworm-slim AS gost-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev cmake git gcc g++ make pkg-config ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY scripts/install-gost-engine.sh /tmp/
RUN chmod +x /tmp/install-gost-engine.sh && /tmp/install-gost-engine.sh

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=gost-builder /usr/lib/ossl-modules/gost.so /usr/lib/ossl-modules/

# Register gost-engine in openssl.cnf so ENGINE_by_id("gost") can find it.
RUN OSSL_MODULES=$(find /usr/lib -name "ossl-modules" -type d 2>/dev/null | head -1) && \
    sed -i '/^\[openssl_init\]/a engines = engine_section' /etc/ssl/openssl.cnf && \
    printf '\n[engine_section]\ngost = gost_section\n\n[gost_section]\nengine_id = gost\ndynamic_path = %s/gost.so\ndefault_algorithms = ALL\ninit = 1\n' "$OSSL_MODULES" >> /etc/ssl/openssl.cnf

LABEL org.opencontainers.image.source="https://github.com/rekurt/gost-crypto"
