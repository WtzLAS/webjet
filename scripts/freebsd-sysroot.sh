#!/bin/sh
# Download a FreeBSD sysroot for cross-compiling x86_64-unknown-freebsd:
# the headers and libraries of FreeBSD's base system (base.txz), plus the
# X11 client libraries webjet-app (GPUI) links against, from FreeBSD's
# package set for the release, all checked against pinned SHA-256s.
#
#   scripts/freebsd-sysroot.sh [DIR]     # default ~/.cache/freebsd-sysroot/x86_64
#
# Programs linked against it run on FreeBSD 14.0 and later 14.x (OPNsense
# 24.7 and later) as long as they use no libc symbol added after 14.0;
# scripts/release.sh checks that. scripts/freebsd-cargo.sh runs it when the
# sysroot is missing or out of date. The CI image
# (webj8-internal/webjet-builder) has a copy of this script: keep it the
# same in both.
#
# Packages are zstd-compressed tar files: macOS tar reads them, GNU tar
# needs the zstd program.
set -eu

FREEBSD_VERSION=14.4-RELEASE
BASE_SHA256=769f60a6eea2938ad6b7943cfbcc17dfaf7d1f7ba59a32b869a00349302df853
# The package set frozen for the release (release_4 = 14.4), not quarterly
# or latest, whose files are replaced. Each package: its file name under
# All/Hashed/ and SHA-256, from the repository's catalogue (data.pkg).
# Only their shared libraries and headers go into the sysroot (usr/local).
# webjet-app needs libxkbcommon, libxkbcommon-x11 and libxcb; the rest are
# what those libraries need in turn.
PKG_REPO=https://pkg.freebsd.org/FreeBSD:14:amd64/release_4
PKGS="
libxkbcommon-1.13.1~b2fac8f475 b2fac8f475c23d44c50612028d6500259ad2fdf81a8dbce7b1e501888cf2176f
libxcb-1.17.0~ad1a7831c4 ad1a7831c47c529284f19eb2056848e40665842cc0e5defe37a89090491181d6
libXau-1.0.12~41099703e1 41099703e17adc521da5f4aa4caf7d6f6b049e6ebe309f96a3d1de50d2313a1d
libXdmcp-1.1.5~dbc6ceb4f2 dbc6ceb4f2f4a58a568030dbf098a96b745806cd56857bdd5b67b29ab2310f77
"

DIR=${1:-${HOME:?}/.cache/freebsd-sysroot/x86_64}

die() { echo "freebsd-sysroot: $*" >&2; exit 1; }
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d ' ' -f 1; }

stamp=$DIR/.webjet-sysroot
want="$FREEBSD_VERSION $BASE_SHA256 $(echo $PKGS)"
if [ "$(cat "$stamp" 2>/dev/null)" = "$want" ]; then
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
    if curl -fsSL --retry 5 --retry-all-errors -o "$tmp/base.txz" "$url"; then
        got=1
        break
    fi
done
[ $got = 1 ] || die "could not download base.txz for $FREEBSD_VERSION"
[ "$(sha256 "$tmp/base.txz")" = "$BASE_SHA256" ] || die "base.txz checksum mismatch"
echo "$PKGS" | while read -r pkg sum; do
    [ -n "$pkg" ] || continue
    url=$PKG_REPO/All/Hashed/$pkg.pkg
    echo "Downloading $url"
    curl -fsSL --retry 5 --retry-all-errors -o "$tmp/$pkg.pkg" "$url" || die "could not download $url"
    [ "$(sha256 "$tmp/$pkg.pkg")" = "$sum" ] || die "$pkg.pkg checksum mismatch"
done

rm -rf "$DIR"
mkdir -p "$DIR"
# Only what compiling and linking needs: headers, the libraries and the
# dynamic linker's directory. Without the kernel, programs and docs.
tar -xf "$tmp/base.txz" -C "$DIR" ./lib ./usr/include ./usr/lib
# From the packages: shared libraries (with their symbolic links) and
# headers, into usr/local as on FreeBSD (freebsd-cargo.sh links with -L).
mkdir -p "$DIR/usr/local/lib" "$DIR/usr/local/include"
for f in "$tmp"/*.pkg; do
    mkdir "$tmp/pkg"
    tar -xf "$f" -C "$tmp/pkg" 2>/dev/null || die "can't unpack $(basename "$f") (GNU tar needs zstd)"
    cp -PR "$tmp"/pkg/usr/local/lib/*.so* "$DIR/usr/local/lib/"
    [ ! -d "$tmp/pkg/usr/local/include" ] || cp -PR "$tmp/pkg/usr/local/include/." "$DIR/usr/local/include/"
    rm -rf "$tmp/pkg"
done
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
echo "$want" > "$stamp"
echo "$DIR: FreeBSD $FREEBSD_VERSION sysroot ready"
