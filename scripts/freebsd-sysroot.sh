#!/bin/sh
# Download a FreeBSD sysroot for cross-compiling x86_64-unknown-freebsd:
# the headers and libraries of FreeBSD's base system (base.txz), checked
# against a pinned SHA-256.
#
#   scripts/freebsd-sysroot.sh [DIR]     # default ~/.cache/freebsd-sysroot/x86_64
#
# Programs linked against it run on FreeBSD 14.0 and later 14.x (OPNsense
# 24.7 and later) as long as they use no libc symbol added after 14.0;
# scripts/release.sh checks that. scripts/freebsd-cargo.sh runs it when the
# sysroot is missing. The CI image (webj8-internal/webjet-builder) has a
# copy of this script: keep FREEBSD_VERSION and BASE_SHA256 the same in
# both.
set -eu

FREEBSD_VERSION=14.4-RELEASE
BASE_SHA256=769f60a6eea2938ad6b7943cfbcc17dfaf7d1f7ba59a32b869a00349302df853

DIR=${1:-${HOME:?}/.cache/freebsd-sysroot/x86_64}

die() { echo "freebsd-sysroot: $*" >&2; exit 1; }
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d ' ' -f 1; }

stamp=$DIR/.webjet-sysroot
if [ "$(cat "$stamp" 2>/dev/null)" = "$FREEBSD_VERSION $BASE_SHA256" ]; then
    echo "$DIR: FreeBSD $FREEBSD_VERSION sysroot present"
    exit 0
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
# Releases move to the archive once they are no longer supported.
got=0
for base in https://download.freebsd.org/releases \
    https://ftp-archive.freebsd.org/pub/FreeBSD-Archive/old-releases; do
    url=$base/amd64/$FREEBSD_VERSION/base.txz
    echo "Downloading $url"
    if curl -fsSL --retry 3 -o "$tmp/base.txz" "$url"; then
        got=1
        break
    fi
done
[ $got = 1 ] || die "could not download base.txz for $FREEBSD_VERSION"
[ "$(sha256 "$tmp/base.txz")" = "$BASE_SHA256" ] || die "base.txz checksum mismatch"

rm -rf "$DIR"
mkdir -p "$DIR"
# Only what compiling and linking needs: headers, the libraries and the
# dynamic linker's directory. Without the kernel, programs and docs.
tar -xf "$tmp/base.txz" -C "$DIR" ./lib ./usr/include ./usr/lib
# Absolute symbolic links (/lib/libc.so.7 …) would point outside the
# sysroot; the linker resolves them inside it, but tools that follow links
# don't, so make them relative.
find "$DIR" -type l | while read -r link; do
    target=$(readlink "$link")
    case $target in
        /*)
            rel=$(dirname "${link#"$DIR"}" | sed -e 's#^/##' -e 's#[^/][^/]*#..#g')
            ln -sfn "${rel:-.}$target" "$link"
            ;;
    esac
done
echo "$FREEBSD_VERSION $BASE_SHA256" > "$stamp"
echo "$DIR: FreeBSD $FREEBSD_VERSION sysroot ready"
