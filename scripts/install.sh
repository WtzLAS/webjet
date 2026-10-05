#!/bin/sh
# Install Webjet: downloads webjetup (the installation manager) for this
# machine, checks it and runs `webjetup install`.
#
#   curl -fsSL https://forgejo.wolf109909.top/webj8/webjet/releases/download/v0.5.1/install.sh | sudo sh
#   curl -fsSL …/install.sh | sudo sh -s -- --enroll 'wj1:…'     # install and enroll
#   curl -fsSL …/install.sh | sudo sh -s -- v0.5.1               # a specific version
#
# Every argument is passed to `webjetup install`. Environment:
#   WEBJET_REPO     repository to install from (default below)
#   WEBJET_VERSION  release to take webjetup from (default: latest)
# Linux and macOS; on Windows download webjetup-<tag>-x86_64-pc-windows-msvc.exe
# from the release page and run `webjetup install` as Administrator.
set -eu

REPO=${WEBJET_REPO:-https://forgejo.wolf109909.top/webj8/webjet}
REPO=${REPO%/}

say() { printf '%s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root, e.g. curl -fsSL …/install.sh | sudo sh"
command -v curl >/dev/null 2>&1 || die "curl is required"

case "$(uname -s)" in
    Linux) os=unknown-linux-gnu ;;
    Darwin) os=apple-darwin ;;
    *) die "unsupported system $(uname -s); see the release page for Windows" ;;
esac
case "$(uname -m)" in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    *) die "unsupported architecture $(uname -m)" ;;
esac
target=$arch-$os

if [ -n "${WEBJET_VERSION:-}" ]; then
    tag=$WEBJET_VERSION
    case $tag in v*) ;; *) tag=v$tag ;; esac
else
    # owner/repo from the repository URL, then the latest release's tag.
    path=${REPO#*://}
    host=${path%%/*}
    scheme=${REPO%%://*}
    tag=$(curl -fsSL "$scheme://$host/api/v1/repos/${path#*/}/releases/latest" |
        tr ',' '\n' | sed -n 's/^.*"tag_name":"\([^"]*\)".*$/\1/p' | head -n 1)
    [ -n "$tag" ] || die "could not find the latest release at $REPO"
fi

file=webjetup-$tag-$target
url=$REPO/releases/download/$tag/$file
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading webjetup $tag for $target"
curl -fsSL "$url" -o "$tmp/webjetup" || die "download failed: $url"
curl -fsSL "$url.sha256" -o "$tmp/webjetup.sha256" || die "download failed: $url.sha256"
want=$(cut -d ' ' -f 1 < "$tmp/webjetup.sha256")
if command -v sha256sum >/dev/null 2>&1; then
    have=$(sha256sum "$tmp/webjetup" | cut -d ' ' -f 1)
else
    have=$(shasum -a 256 "$tmp/webjetup" | cut -d ' ' -f 1)
fi
[ -n "$want" ] && [ "$want" = "$have" ] || die "checksum mismatch for $file"
chmod 0755 "$tmp/webjetup"

# webjetup installs itself next to the programs, so it stays available.
"$tmp/webjetup" --repo "$REPO" install "$@"
