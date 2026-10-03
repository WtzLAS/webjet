# syntax=docker/dockerfile:1
#
# The CI image for Webjet (.forgejo/workflows): checks, tests and release
# builds for every target except macOS, on one linux/amd64 runner.
#
#   docker build -f ci/builder.Dockerfile -t forgejo.wolf109909.top/webj8/webjet-builder:2 ci
#   docker push forgejo.wolf109909.top/webj8/webjet-builder:2
#
# What it holds:
#
# - Debian 11 (glibc 2.31) with Rust stable, rustfmt and clippy: Linux
#   binaries built here run on Debian 11+, Ubuntu 20.04+, RHEL 9+
# - the aarch64 cross toolchain (gcc-aarch64-linux-gnu, Debian 11's
#   glibc 2.31 for arm64), so the amd64 runner builds Linux arm64 too
# - LLVM 20 from apt.llvm.org: libclang for bindgen (BoringSSL), and
#   clang-cl, lld-link and llvm-lib for cargo-xwin; NASM for the assembly in
#   BoringSSL and aws-lc on Windows
# - cargo-xwin with the Microsoft CRT and Windows SDK already downloaded
#   (XWIN_CACHE_DIR), for x86_64-pc-windows-msvc. Building this image means
#   accepting Microsoft's license for them, as cargo-xwin does on first use.
# - CMake 3.31 (BoringSSL needs 3.22+; Debian 11 has 3.18)
# - Node.js 20 for JavaScript actions (actions/checkout), plus git, curl,
#   jq, zip, python3
#
# Bump the tag (and the image in .forgejo/workflows/*.yml) when changing it.

FROM rust:1-bullseye

ARG CMAKE_VERSION=3.31.6
ARG LLVM_VERSION=20
ARG NODE_VERSION=20.18.1
ARG CARGO_XWIN_VERSION=0.23.1

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Debian 11 is archived: its security repository no longer serves every
# update, so only the main archive is used.
RUN sed -i '/security/d' /etc/apt/sources.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross \
      nasm ninja-build git curl ca-certificates jq zip unzip xz-utils python3 file \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-x86_64.tar.gz" \
      | tar -xz -C /opt \
 && ln -s "/opt/cmake-${CMAKE_VERSION}-linux-x86_64/bin/cmake" /usr/local/bin/cmake \
 && cmake --version | head -n 1

# LLVM from apt.llvm.org, built for Debian 11. The Windows build needs
# Clang 19 or newer: the Microsoft C++ headers cargo-xwin downloads refuse
# older compilers (STL1000). Its bin directory goes on PATH so bindgen finds
# `clang` for the system include paths; `cc` stays Debian's gcc.
RUN curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key -o /etc/apt/trusted.gpg.d/apt.llvm.org.asc \
 && echo "deb http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-${LLVM_VERSION} main" \
      > /etc/apt/sources.list.d/llvm.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      "clang-${LLVM_VERSION}" "lld-${LLVM_VERSION}" "llvm-${LLVM_VERSION}" "libclang-${LLVM_VERSION}-dev" \
 && rm -rf /var/lib/apt/lists/* \
 && cd "/usr/lib/llvm-${LLVM_VERSION}/bin" \
 && for t in clang-cl:clang lld-link:lld llvm-lib:llvm-ar llvm-dlltool:llvm-ar; do \
      [ -e "${t%%:*}" ] || ln -s "${t#*:}" "${t%%:*}"; \
    done

RUN curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
      | tar -xJ -C /usr/local --strip-components=1 --exclude='*.md' --exclude=LICENSE \
 && node --version

ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH="/usr/lib/llvm-${LLVM_VERSION}/bin:${PATH}" \
    # bindgen (boring-sys) uses this libclang for every target.
    LIBCLANG_PATH="/usr/lib/llvm-${LLVM_VERSION}/lib" \
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
 && cargo install --locked "cargo-xwin@${CARGO_XWIN_VERSION}" \
 && rm -rf "$CARGO_HOME/registry" "$CARGO_HOME/git" \
 && cargo xwin cache xwin \
 && chmod -R a+rX /opt/xwin "$CARGO_HOME" "$RUSTUP_HOME"

# Smoke tests: each toolchain compiles. The C++ one includes <regex> through
# the Microsoft headers (they check the Clang version), and the C one checks
# that clang finds its own headers (bindgen needs stddef.h).
RUN printf 'int main(void){return 0;}\n' > /tmp/t.c \
 && aarch64-linux-gnu-gcc /tmp/t.c -o /tmp/t-arm64 && file /tmp/t-arm64 | grep -q aarch64 \
 && printf '#include <stddef.h>\n' | clang -fsyntax-only -x c - \
 && printf '#include <regex>\nint main(){std::regex r("a");return 0;}\n' > /tmp/t.cpp \
 && clang-cl --target=x86_64-pc-windows-msvc /EHsc -std:c++17 \
      /imsvc /opt/xwin/xwin/crt/include /imsvc /opt/xwin/xwin/sdk/include/ucrt \
      /imsvc /opt/xwin/xwin/sdk/include/um /imsvc /opt/xwin/xwin/sdk/include/shared \
      -c /tmp/t.cpp /Fo/tmp/t.obj \
 && clang-cl --version | head -n 1 && lld-link --version && llvm-lib /? > /dev/null \
 && rm -f /tmp/t.c /tmp/t-arm64 /tmp/t.cpp /tmp/t.obj
