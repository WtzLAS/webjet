#!/bin/sh
# Build, package and publish a Webjet release for scripts/upgrade.sh and
# scripts/upgrade.ps1 (§19.8).
#
#   scripts/release.sh v0.1.0             # build and package into dist/v0.1.0
#   scripts/release.sh v0.1.0 --publish   # also create the Forgejo release
#
# Run from a clean checkout of the release tag on macOS with Docker: macOS
# binaries are built natively, Linux binaries in docker/release.Dockerfile
# (Debian 11, glibc 2.31+), Windows binaries with cargo-xwin (needs
# `cargo install cargo-xwin` and Homebrew's llvm and lld: rustup's rust-lld,
# which cargo-xwin falls back to, can't run standalone). Each archive holds
# webjetd, webjetctl, webjet-root and webjet-signer at the top level, next to
# a `.sha256` file:
#
#   webjet-<tag>-<target>.tar.gz          target: {x86_64,aarch64}-unknown-linux-gnu,
#   webjet-<tag>-<target>.tar.gz.sha256           {x86_64,aarch64}-apple-darwin
#   webjet-<tag>-x86_64-pc-windows-msvc.zip       (.exe files, plus wintun.dll
#   webjet-<tag>-x86_64-pc-windows-msvc.zip.sha256  and its license)
#
# Publishing needs WEBJET_FORGEJO_TOKEN (a token with write access to the
# repository) and uses WEBJET_FORGEJO_API (default: the origin's Forgejo).
# Hosts then install with
#   WEBJET_RELEASE_URL=<forge>/<owner>/<repo>/releases/download scripts/upgrade.sh <tag>
set -eu
cd "$(dirname "$0")/.."
TAG=${1:?usage: scripts/release.sh <tag> [--publish]}
PUBLISH=0
[ "${2:-}" = --publish ] && PUBLISH=1
VERSION=${TAG#v}
DIST=dist/$TAG
BINS="webjetd webjetctl webjet-root webjet-signer"

die() { echo "release: $*" >&2; exit 1; }

# The tag must exist, match the crate version and be what's checked out.
git rev-parse -q --verify "refs/tags/$TAG" >/dev/null || die "no tag $TAG (git tag -a $TAG)"
[ "$(git rev-parse HEAD)" = "$(git rev-parse "$TAG^{commit}")" ] || die "HEAD is not $TAG"
git diff --quiet HEAD -- crates Cargo.toml Cargo.lock || die "uncommitted changes in the sources"
grep -q "^version = \"$VERSION\"" Cargo.toml || die "Cargo.toml version is not $VERSION"

rm -rf "$DIST"
mkdir -p "$DIST"
export CARGO_PROFILE_RELEASE_STRIP=symbols CARGO_PROFILE_RELEASE_LTO=thin

package() { # target directory-with-binaries
    stage=$(mktemp -d)
    for b in $BINS; do
        [ -x "$2/$b" ] || die "$2/$b missing"
        cp "$2/$b" "$stage/"
    done
    f=webjet-$TAG-$1.tar.gz
    # macOS tar would add Apple extended attributes, which GNU tar warns about.
    COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata -czf "$DIST/$f" -C "$stage" $BINS
    (cd "$DIST" && shasum -a 256 "$f" > "$f.sha256")
    rm -rf "$stage"
    echo "packaged $DIST/$f"
}

for t in aarch64-apple-darwin x86_64-apple-darwin; do
    rustup target add "$t" >/dev/null 2>&1 || true
    cargo build --release --locked --target "$t" -p webjetd -p webjet-tools
    package "$t" "target/$t/release"
done

for p in arm64:aarch64 amd64:x86_64; do
    plat=${p%%:*}
    arch=${p##*:}
    out=$(mktemp -d)
    docker buildx build --platform "linux/$plat" -f docker/release.Dockerfile --output "type=local,dest=$out" .
    package "$arch-unknown-linux-gnu" "$out"
    rm -rf "$out"
done

# Windows (scripts/upgrade.ps1 expects a zip with wintun.dll next to the
# programs). Wintun is WireGuard LLC's prebuilt driver, redistributable with
# software that uses it through its API, with its license alongside.
WINTUN_VERSION=0.14.1
WINTUN_SHA256=07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
win=x86_64-pc-windows-msvc
PATH="/opt/homebrew/opt/lld/bin:/opt/homebrew/opt/llvm/bin:$PATH" cargo xwin build --release --locked --target "$win" -p webjetd -p webjet-tools
stage=$(mktemp -d)
curl -fsSL "https://www.wintun.net/builds/wintun-$WINTUN_VERSION.zip" -o "$stage/wintun.zip"
echo "$WINTUN_SHA256  $stage/wintun.zip" | shasum -a 256 -c - >/dev/null || die "wintun-$WINTUN_VERSION.zip checksum mismatch"
unzip -q "$stage/wintun.zip" -d "$stage"
mkdir "$stage/pkg"
for b in $BINS; do cp "target/$win/release/$b.exe" "$stage/pkg/"; done
cp "$stage/wintun/bin/amd64/wintun.dll" "$stage/pkg/"
cp "$stage/wintun/LICENSE.txt" "$stage/pkg/wintun-LICENSE.txt"
f=webjet-$TAG-$win.zip
(cd "$stage/pkg" && zip -q -X "../$f" ./*)
mv "$stage/$f" "$DIST/"
(cd "$DIST" && shasum -a 256 "$f" > "$f.sha256")
rm -rf "$stage"
echo "packaged $DIST/$f"

# A built binary must report the tag's version.
case "$(uname -m)" in arm64) native=aarch64-apple-darwin ;; *) native=x86_64-apple-darwin ;; esac
"target/$native/release/webjetd" --version | grep -q " $VERSION\$" || die "webjetd doesn't report $VERSION"
(cd "$DIST" && cat ./*.sha256)

[ $PUBLISH = 1 ] || exit 0

# ---------------------------------------------------------------- publish
: "${WEBJET_FORGEJO_TOKEN:?set WEBJET_FORGEJO_TOKEN to publish}"
origin=$(git remote get-url origin)
host=$(echo "$origin" | sed -E 's#^(ssh://)?([^@]+@)?([^:/]+).*#\3#')
repo=$(echo "$origin" | sed -E 's#^.*[:/]([^/]+/[^/]+)$#\1#; s#\.git$##; s#^[0-9]+/##')
API=${WEBJET_FORGEJO_API:-https://$host/api/v1}
auth="Authorization: token $WEBJET_FORGEJO_TOKEN"
git push origin "$TAG"
notes=$(git tag -l --format='%(contents)' "$TAG")
body=$(printf '%s' "$notes" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')
id=$(curl -fsS -H "$auth" "$API/repos/$repo/releases/tags/$TAG" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' 2>/dev/null || true)
if [ -z "$id" ]; then
    id=$(curl -fsS -X POST -H "$auth" -H 'Content-Type: application/json' \
        -d "{\"tag_name\":\"$TAG\",\"name\":\"Webjet $TAG\",\"body\":$body,\"draft\":false,\"prerelease\":false}" \
        "$API/repos/$repo/releases" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
fi
for f in "$DIST"/*; do
    name=$(basename "$f")
    curl -fsS -X POST -H "$auth" -F "attachment=@$f" "$API/repos/$repo/releases/$id/assets?name=$name" >/dev/null
    echo "uploaded $name"
done
echo "published: https://$host/$repo/releases/tag/$TAG"
echo "install:   WEBJET_RELEASE_URL=https://$host/$repo/releases/download scripts/upgrade.sh $TAG"
