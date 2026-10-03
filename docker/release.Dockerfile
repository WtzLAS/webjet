# syntax=docker/dockerfile:1
# Release binaries for Linux (scripts/release.sh). Built on Debian 11 so the
# binaries run on glibc 2.31 and newer (Debian 11+, Ubuntu 20.04+, RHEL 9+).
#
#   docker buildx build --platform linux/amd64 -f docker/release.Dockerfile \
#     --output type=local,dest=dist/linux-amd64 .
ARG RUST_IMAGE=rust:1-bullseye
FROM ${RUST_IMAGE} AS build
ARG TARGETPLATFORM
# clang/libclang (bindgen) and cmake build BoringSSL (AnyTLS) and aws-lc.
#
# Debian 11 is archived. On amd64, libclang's dependencies include the
# 32-bit multilib libraries (libc6-i386 and friends), which must match the
# installed glibc security update, and that version is no longer served.
# Nothing here builds 32-bit code, so empty stand-in packages satisfy them.
# BoringSSL needs CMake 3.22+, newer than Debian 11's 3.18: use Kitware's.
ARG CMAKE_VERSION=3.31.6
RUN set -eu; \
    if [ "$(dpkg --print-architecture)" = amd64 ]; then \
        for p in libc6-i386 lib32gcc-s1 lib32stdc++6; do \
            mkdir -p /tmp/stub/$p/DEBIAN; \
            printf 'Package: %s\nVersion: 99:0\nArchitecture: amd64\nMaintainer: none\nDescription: unused multilib stand-in\n' "$p" > /tmp/stub/$p/DEBIAN/control; \
            dpkg-deb -b /tmp/stub/$p /tmp/stub/$p.deb >/dev/null; \
            dpkg -i /tmp/stub/$p.deb >/dev/null; \
        done; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends clang libclang-dev; \
    rm -rf /var/lib/apt/lists/* /tmp/stub; \
    curl -fsSL "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar.gz" \
        | tar -xz -C /opt; \
    ln -s "/opt/cmake-${CMAKE_VERSION}-linux-$(uname -m)/bin/cmake" /usr/local/bin/cmake; \
    cmake --version | head -1
WORKDIR /src
COPY . .
ENV CARGO_PROFILE_RELEASE_STRIP=symbols \
    CARGO_PROFILE_RELEASE_LTO=thin
RUN --mount=type=cache,id=webjet-release-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=webjet-release-target-${TARGETPLATFORM},target=/src/target \
    set -eu; \
    cargo build --release --locked -p webjetd -p webjet-tools -p webjetup; \
    mkdir -p /out; \
    for b in webjetd webjetctl webjetup; do cp "target/release/$b" /out/; done; \
    ldd --version | head -1 > /out/.glibc

FROM scratch
COPY --from=build /out/ /
