# syntax=docker/dockerfile:1
#
# The CI image for Webjet (.forgejo/workflows): checks, tests and release
# builds for every target except macOS, on one linux/amd64 runner.
#
#   docker build -f ci/builder.Dockerfile -t forgejo.wolf109909.top/webj8/webjet-builder:1 ci
#   docker push forgejo.wolf109909.top/webj8/webjet-builder:1
#
# (or let .forgejo/workflows/builder-image.yml do it). What it holds:
#
# - Debian 11 (glibc 2.31) with Rust stable, rustfmt and clippy: Linux
#   binaries built here run on Debian 11+, Ubuntu 20.04+, RHEL 9+
# - the aarch64 cross toolchain (gcc-aarch64-linux-gnu, Debian 11's
#   glibc 2.31 for arm64), so the amd64 runner builds Linux arm64 too
# - LLVM 18 from the LLVM release: libclang for bindgen (BoringSSL), and
#   clang-cl, lld-link and llvm-lib for cargo-xwin; NASM for the assembly in
#   BoringSSL and aws-lc on Windows
# - cargo-xwin with the Microsoft CRT and Windows SDK already downloaded
#   (XWIN_CACHE_DIR), for x86_64-pc-windows-msvc. Building this image means
#   accepting Microsoft's license for them, as cargo-xwin does on first use.
# - CMake 3.31 (BoringSSL needs 3.22+; Debian 11 has 3.18)
# - Node.js 20 for JavaScript actions (actions/checkout), plus git, curl,
#   jq, zip, python3
#
# Bump the tag (and WEBJET_BUILDER in the workflows) when changing it.

FROM rust:1-bullseye

ARG CMAKE_VERSION=3.31.6
ARG LLVM_VERSION=18.1.8
ARG NODE_VERSION=20.18.1
ARG XWIN_VERSION=0.23.1

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Debian 11 is archived: its security repository no longer serves every
# update, so only the main archive is used.
RUN sed -i '/security/d' /etc/apt/sources.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross \
      nasm ninja-build libtinfo5 git curl ca-certificates jq zip unzip xz-utils python3 file \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-x86_64.tar.gz" \
      | tar -xz -C /opt \
 && ln -s "/opt/cmake-${CMAKE_VERSION}-linux-x86_64/bin/cmake" /usr/local/bin/cmake \
 && cmake --version | head -n 1

# Only what's used is kept of the LLVM release (about 1 GB unpacked): the
# compiler and linker drivers, llvm-ar/llvm-lib, libclang and its headers.
# Not on PATH as a whole, so `cc` stays Debian's gcc for Linux builds.
RUN curl -fsSL "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu-ubuntu-18.04.tar.xz" \
      | tar -xJ -C /opt \
 && mv "/opt/clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu-ubuntu-18.04" /opt/llvm \
 && cd /opt/llvm \
 && find bin -type f ! -name 'clang-18' ! -name 'lld' ! -name 'llvm-ar' ! -name 'llvm-rc' -delete \
 && find bin -type l ! -name clang ! -name clang-cl ! -name 'clang++' ! -name lld-link ! -name 'ld.lld' ! -name llvm-lib ! -name llvm-dlltool ! -name llvm-ranlib -delete \
 && find lib -maxdepth 1 -type f ! -name 'libclang.so*' -delete \
 && find lib -maxdepth 1 -type l ! -name 'libclang.so*' -delete \
 && rm -rf include share libexec lib/cmake lib/x86_64-unknown-linux-gnu \
 && for t in clang-cl lld-link llvm-lib llvm-dlltool llvm-ar llvm-rc; do ln -s "/opt/llvm/bin/$t" "/usr/local/bin/$t"; done \
 && clang-cl --version | head -n 1 && lld-link --version

RUN curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
      | tar -xJ -C /usr/local --strip-components=1 --exclude='*.md' --exclude=LICENSE \
 && node --version

ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    # bindgen (boring-sys) uses LLVM 18's libclang for every target.
    LIBCLANG_PATH=/opt/llvm/lib \
    # Linux arm64 by cross-compiling.
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
    AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar \
    BINDGEN_EXTRA_CLANG_ARGS_aarch64_unknown_linux_gnu="--sysroot=/usr/aarch64-linux-gnu -I/usr/aarch64-linux-gnu/include" \
    # Windows: the CRT and SDK downloaded below.
    XWIN_CACHE_DIR=/opt/xwin \
    CARGO_TERM_COLOR=always

RUN rustup component add rustfmt clippy \
 && rustup target add aarch64-unknown-linux-gnu x86_64-pc-windows-msvc \
 && cargo install --locked "cargo-xwin@${XWIN_VERSION}" \
 && rm -rf "$CARGO_HOME/registry" "$CARGO_HOME/git" \
 && cargo xwin cache xwin \
 && chmod -R a+rX /opt/xwin "$CARGO_HOME" "$RUSTUP_HOME"

# Smoke test: a C file through each cross toolchain.
RUN printf 'int main(void){return 0;}\n' > /tmp/t.c \
 && aarch64-linux-gnu-gcc /tmp/t.c -o /tmp/t-arm64 && file /tmp/t-arm64 | grep -q aarch64 \
 && rm -f /tmp/t.c /tmp/t-arm64
