# Build the Webjet binaries for Linux and package them with the tools the
# agent drives (iproute2, iptables). Used by docker/compose-test.sh.
FROM rust:1-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends cmake golang clang libclang-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --workspace && \
    mkdir -p /out && cp target/release/webjetd target/release/webjetctl target/release/webjet-root target/release/webjet-signer /out/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables iputils-ping procps netcat-openbsd ca-certificates dnsutils && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/ /usr/local/bin/
COPY scripts/ /opt/webjet/scripts/
COPY docker/ /opt/webjet/docker/
