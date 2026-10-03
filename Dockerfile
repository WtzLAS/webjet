# syntax=docker/dockerfile:1
#
# Webjet container image (docs/docker.md).
#
#   docker build -t webjet .                    # the deployment image
#   docker build --target test -t webjet:test . # plus debugging tools and test scripts
#
# Build arguments:
#   ANYTLS=1|0     include the AnyTLS transport (BoringSSL; default 1)
#   RUST_IMAGE     the Rust toolchain image for the build stage
#   DEBIAN_IMAGE   the runtime base image
#   VERSION        image version label

ARG RUST_IMAGE=rust:1-bookworm
ARG DEBIAN_IMAGE=debian:bookworm-slim

# ---------------------------------------------------------------- build
FROM ${RUST_IMAGE} AS build
ARG ANYTLS=1
ARG TARGETPLATFORM
# cmake, Go and clang build BoringSSL for the AnyTLS transport.
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake golang clang libclang-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# Small, stripped binaries; the cache mounts keep rebuilds incremental.
ENV CARGO_PROFILE_RELEASE_STRIP=symbols \
    CARGO_PROFILE_RELEASE_LTO=thin
RUN --mount=type=cache,id=webjet-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=webjet-target-${TARGETPLATFORM},target=/src/target \
    set -eu; \
    features=""; \
    if [ "$ANYTLS" = 1 ]; then features="--features webjetd/anytls,webjet-tools/anytls"; fi; \
    cargo build --release --locked --no-default-features $features -p webjetd -p webjet-tools; \
    mkdir -p /out; \
    for b in webjetd webjetctl webjet-root webjet-signer; do cp "target/release/$b" /out/; done

# ---------------------------------------------------------------- runtime contents
FROM ${DEBIAN_IMAGE} AS base
ARG VERSION=dev
LABEL org.opencontainers.image.title="webjet" \
      org.opencontainers.image.description="Webjet overlay network agent and tools" \
      org.opencontainers.image.version="${VERSION}"
# iproute2: routes on the tun interface; iptables: subnet gateway NAT;
# tini: PID 1 that forwards signals and reaps children; tpm2-tools: identity
# keys sealed in a TPM when /dev/tpmrm0 is passed in.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 iptables tini tpm2-tools \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/ /usr/local/bin/
COPY docker/entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY docker/healthcheck.sh /usr/local/bin/docker-healthcheck.sh
ENV WEBJET_CONFIG=/run/webjet/webjetd.toml \
    WEBJET_SOCKET=/run/webjet/control.sock
VOLUME ["/var/lib/webjet"]
# TCP+TLS and UDP+KCP share a port; AnyTLS (if enabled) needs its own TCP port.
EXPOSE 443/tcp 443/udp
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --start-interval=2s --retries=3 \
    CMD ["/usr/local/bin/docker-healthcheck.sh"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
CMD ["webjetd", "run"]

# ---------------------------------------------------------------- test image
# Debugging tools and the scripts used by docker/e2e.sh.
FROM base AS test
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping procps netcat-openbsd dnsutils \
 && rm -rf /var/lib/apt/lists/*
COPY scripts/ /opt/webjet/scripts/
COPY docker/ /opt/webjet/docker/

# ---------------------------------------------------------------- deployment image (default)
FROM base AS runtime
