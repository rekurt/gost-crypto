# TODO(ci): migrate the runtime image to a base that has CryptoPro CSP
# 5.0+ for Linux and CryptoPro CAdES SDK pre-installed under
# /opt/cprocsp/.  CryptoPro CSP is proprietary and its installer is not
# redistributable, so this Dockerfile is a placeholder until a private
# base image is published.
#
# The expected layout of the finished image:
#   /opt/cprocsp/lib/amd64/libcapi10.so
#   /opt/cprocsp/lib/amd64/libcapi20.so
#   /opt/cprocsp/lib/amd64/libssp.so
#   /opt/cprocsp/lib/amd64/librdrsup.so
#   /opt/cprocsp/lib/amd64/libcades.so
#   /opt/cprocsp/include/cpcsp/*.h
#   /opt/cprocsp/include/cades/*.h
# And /etc/ld.so.conf.d/cprocsp.conf referencing /opt/cprocsp/lib/amd64.

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Placeholder — replace with the internal CryptoPro CSP image once the
# registry coordinates are known.
#
# FROM registry.internal.example.com/cryptopro/csp-linux:5.0

LABEL org.opencontainers.image.source="https://github.com/rekurt/gost-crypto"
