FROM debian:bookworm-slim AS gost-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev cmake curl gcc g++ make pkg-config ca-certificates && \
    rm -rf /var/lib/apt/lists/*
ARG GOST_ENGINE_SHA256
ENV GOST_ENGINE_SHA256=${GOST_ENGINE_SHA256}
COPY scripts/install-gost-engine.sh /tmp/
RUN chmod +x /tmp/install-gost-engine.sh && /tmp/install-gost-engine.sh

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=gost-builder /usr/lib/ossl-modules/gost.so /usr/lib/ossl-modules/

LABEL org.opencontainers.image.source="https://github.com/rekurt/gost-crypto"
