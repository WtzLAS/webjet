#!/bin/sh
# Run cargo for x86_64-unknown-freebsd (FreeBSD, OPNsense), cross-compiled
# with Clang and lld against the FreeBSD sysroot from
# scripts/freebsd-sysroot.sh (downloaded first when missing):
#
#   scripts/freebsd-cargo.sh clippy -p webjetd --all-targets -- -D warnings
#   scripts/freebsd-cargo.sh build --release -p webjetd -p webjet-tools -p webjetup
#
# Output goes to target/x86_64-unknown-freebsd/. Environment:
#   WEBJET_FREEBSD_SYSROOT  the sysroot (default ~/.cache/freebsd-sysroot/x86_64;
#                           the CI builder image sets /opt/freebsd-sysroot)
#   WEBJET_FREEBSD_LLVM     directory with clang, clang++, llvm-ar and ld.lld
#                           (default: Homebrew's llvm and lld on macOS, else PATH)
set -eu

T=x86_64-unknown-freebsd
SR=${WEBJET_FREEBSD_SYSROOT:-${HOME:?}/.cache/freebsd-sysroot/x86_64}
here=$(cd "$(dirname "$0")" && pwd)
sh "$here/freebsd-sysroot.sh" "$SR" >&2

if [ -n "${WEBJET_FREEBSD_LLVM:-}" ]; then
    PATH=$WEBJET_FREEBSD_LLVM:$PATH
elif [ "$(uname -s)" = Darwin ]; then
    # Apple's Clang can't link for FreeBSD: Homebrew's llvm and lld can.
    PATH=/opt/homebrew/opt/llvm/bin:/opt/homebrew/opt/lld/bin:/usr/local/opt/llvm/bin:/usr/local/opt/lld/bin:$PATH
fi
for tool in clang clang++ llvm-ar ld.lld; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "freebsd-cargo: $tool not found (set WEBJET_FREEBSD_LLVM)" >&2
        exit 1
    }
done
export PATH

# C and C++ (aws-lc, BoringSSL): FreeBSD's own headers and libc++. A Clang
# that ships libc++ headers (Homebrew's) would otherwise take those.
export CC_x86_64_unknown_freebsd=clang
export CXX_x86_64_unknown_freebsd=clang++
export AR_x86_64_unknown_freebsd=llvm-ar
export CFLAGS_x86_64_unknown_freebsd="--sysroot=$SR"
export CXXFLAGS_x86_64_unknown_freebsd="--sysroot=$SR -nostdinc++ -isystem $SR/usr/include/c++/v1"
# bindgen (boring-sys) parses BoringSSL's headers with libclang.
export BINDGEN_EXTRA_CLANG_ARGS_x86_64_unknown_freebsd="--sysroot=$SR"
# Linking: clang drives lld with FreeBSD's crt files and libraries, and
# the packaged ones in usr/local/lib (webjet-app's X11 libraries).
export CARGO_TARGET_X86_64_UNKNOWN_FREEBSD_LINKER=clang
export CARGO_TARGET_X86_64_UNKNOWN_FREEBSD_RUSTFLAGS="-C link-arg=--target=$T -C link-arg=--sysroot=$SR -C link-arg=-fuse-ld=lld -L native=$SR/usr/local/lib"
export CARGO_BUILD_TARGET=$T

rustup target list --installed 2>/dev/null | grep -qx "$T" || rustup target add "$T" >&2
# cargo runs one job per core: on the 208-core runner the default limit
# of 1024 open files ran out ("Too many open files"), so raise it.
hard=$(ulimit -Hn)
if [ "$hard" = unlimited ] || [ "$hard" -gt 65536 ]; then hard=65536; fi
[ "$(ulimit -n)" != unlimited ] && [ "$(ulimit -n)" -ge "$hard" ] || ulimit -n "$hard" 2>/dev/null || true
exec cargo "$@"
