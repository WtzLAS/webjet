#!/bin/sh
# Build, package and publish a Webjet release for webjetup and install.sh
# (§19.8).
#
#   scripts/release.sh v0.1.0                       # build every target into dist/v0.1.0
#   scripts/release.sh v0.1.0 --publish            # and create the Forgejo release
#   scripts/release.sh v0.1.0 --publish --targets "aarch64-apple-darwin x86_64-apple-darwin"
#
# Targets: x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu,
# x86_64-pc-windows-msvc, aarch64-apple-darwin, x86_64-apple-darwin.
# `--targets` builds and uploads only those, adding them to an existing
# release (assets with the same name are replaced). That's how the macOS
# files join a release that CI published (.forgejo/workflows/release.yml).
#
# Where each target is built:
#   macOS targets    natively; needs a Mac
#   Linux targets    on Linux, with cargo (the CI image, ci/builder.Dockerfile,
#                    has the arm64 cross toolchain); elsewhere in Docker with
#                    docker/release.Dockerfile (Debian 11, glibc 2.31+)
#   Windows          cargo-xwin (in the CI image; on a Mac it needs
#                    `cargo install cargo-xwin` and Homebrew's llvm and lld:
#                    rustup's rust-lld, which cargo-xwin falls back to, can't
#                    run standalone)
#
# Each archive holds webjetd, webjetctl, webjet-root and webjet-signer at the
# top level, next to a `.sha256` file:
#
#   webjet-<tag>-<target>.tar.gz          (Windows: .zip, with wintun.dll and
#   webjet-<tag>-<target>.tar.gz.sha256    its license)
#
# plus the installation manager for each target and the script that fetches
# it, each with a `.sha256`:
#
#   webjetup-<tag>-<target>          (Windows: webjetup-<tag>-<target>.exe)
#   install.sh
#
# Publishing needs WEBJET_FORGEJO_TOKEN (a token with write access to the
# repository). The API and repository come from the origin remote, or from
# WEBJET_FORGEJO_API (https://host/api/v1) and WEBJET_FORGEJO_REPO
# (owner/name). Hosts then install with
#   curl -fsSL <forge>/<owner>/<repo>/releases/download/<tag>/install.sh | sudo sh
set -eu
cd "$(dirname "$0")/.."
usage="usage: scripts/release.sh <tag> [--publish] [--targets \"<target> …\"]"
TAG=${1:?$usage}
shift
PUBLISH=0
ALL="x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-pc-windows-msvc aarch64-apple-darwin x86_64-apple-darwin"
TARGETS=$ALL
while [ $# -gt 0 ]; do
    case $1 in
        --publish) PUBLISH=1 ;;
        --targets) TARGETS=${2:?$usage}; shift ;;
        *) echo "$usage" >&2; exit 2 ;;
    esac
    shift
done
VERSION=${TAG#v}
DIST=dist/$TAG
BINS="webjetd webjetctl webjet-root webjet-signer"
HOST_OS=$(uname -s)

die() { echo "release: $*" >&2; exit 1; }
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
for t in $TARGETS; do
    case " $ALL " in *" $t "*) ;; *) die "unknown target $t" ;; esac
done

# The tag must exist, match the crate version and be what's checked out.
git rev-parse -q --verify "refs/tags/$TAG" >/dev/null || die "no tag $TAG (git tag -a $TAG)"
[ "$(git rev-parse HEAD)" = "$(git rev-parse "$TAG^{commit}")" ] || die "HEAD is not $TAG"
git diff --quiet HEAD -- crates Cargo.toml Cargo.lock || die "uncommitted changes in the sources"
grep -q "^version = \"$VERSION\"" Cargo.toml || die "Cargo.toml version is not $VERSION"

rm -rf "$DIST"
mkdir -p "$DIST"
export CARGO_PROFILE_RELEASE_STRIP=symbols CARGO_PROFILE_RELEASE_LTO=thin

# webjetup for a target, as a plain executable next to the archives.
add_webjetup() { # target path-to-binary
    suffix=""
    case $1 in *windows*) suffix=.exe ;; esac
    f=webjetup-$TAG-$1$suffix
    [ -f "$2" ] || die "$2 missing"
    cp "$2" "$DIST/$f"
    chmod 0755 "$DIST/$f"
    (cd "$DIST" && sha256 "$f" > "$f.sha256")
    echo "packaged $DIST/$f"
}

package() { # target directory-with-binaries
    stage=$(mktemp -d)
    for b in $BINS; do
        [ -f "$2/$b" ] || die "$2/$b missing"
        cp "$2/$b" "$stage/"
        chmod 0755 "$stage/$b"
    done
    f=webjet-$TAG-$1.tar.gz
    if [ "$HOST_OS" = Darwin ]; then
        # macOS tar would add Apple extended attributes, which GNU tar warns about.
        COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata -czf "$DIST/$f" -C "$stage" $BINS
    else
        tar --owner=0 --group=0 -czf "$DIST/$f" -C "$stage" $BINS
    fi
    (cd "$DIST" && sha256 "$f" > "$f.sha256")
    rm -rf "$stage"
    echo "packaged $DIST/$f"
}

build_macos() { # target
    [ "$HOST_OS" = Darwin ] || die "$1 can only be built on a Mac"
    rustup target add "$1" >/dev/null 2>&1 || true
    cargo build --release --locked --target "$1" -p webjetd -p webjet-tools -p webjetup
    package "$1" "target/$1/release"
    add_webjetup "$1" "target/$1/release/webjetup"
}

build_linux() { # target
    if [ "$HOST_OS" = Linux ]; then
        cargo build --release --locked --target "$1" -p webjetd -p webjet-tools -p webjetup
        package "$1" "target/$1/release"
        add_webjetup "$1" "target/$1/release/webjetup"
    else
        case $1 in aarch64-*) plat=arm64 ;; *) plat=amd64 ;; esac
        out=$(mktemp -d)
        docker buildx build --platform "linux/$plat" -f docker/release.Dockerfile --output "type=local,dest=$out" .
        package "$1" "$out"
        add_webjetup "$1" "$out/webjetup"
        rm -rf "$out"
    fi
}

# Windows: webjetup expects a zip with wintun.dll next to the programs.
# Wintun is WireGuard LLC's prebuilt driver, redistributable with software
# that uses it through its API, with its license alongside.
WINTUN_VERSION=0.14.1
WINTUN_SHA256=07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
build_windows() { # target
    if [ "$HOST_OS" = Darwin ]; then
        PATH="/opt/homebrew/opt/lld/bin:/opt/homebrew/opt/llvm/bin:$PATH" \
            cargo xwin build --release --locked --target "$1" -p webjetd -p webjet-tools -p webjetup
    else
        cargo xwin build --release --locked --target "$1" -p webjetd -p webjet-tools -p webjetup
    fi
    stage=$(mktemp -d)
    curl -fsSL "https://www.wintun.net/builds/wintun-$WINTUN_VERSION.zip" -o "$stage/wintun.zip"
    echo "$WINTUN_SHA256  $stage/wintun.zip" | sha256 -c - >/dev/null || die "wintun-$WINTUN_VERSION.zip checksum mismatch"
    unzip -q "$stage/wintun.zip" -d "$stage"
    mkdir "$stage/pkg"
    for b in $BINS; do cp "target/$1/release/$b.exe" "$stage/pkg/"; done
    cp "$stage/wintun/bin/amd64/wintun.dll" "$stage/pkg/"
    cp "$stage/wintun/LICENSE.txt" "$stage/pkg/wintun-LICENSE.txt"
    f=webjet-$TAG-$1.zip
    (cd "$stage/pkg" && zip -q -X "../$f" ./*)
    mv "$stage/$f" "$DIST/"
    (cd "$DIST" && sha256 "$f" > "$f.sha256")
    rm -rf "$stage"
    echo "packaged $DIST/$f"
    add_webjetup "$1" "target/$1/release/webjetup.exe"
}

for t in $TARGETS; do
    echo "==> $t"
    case $t in
        *-apple-darwin) build_macos "$t" ;;
        *-linux-gnu) build_linux "$t" ;;
        *-windows-msvc) build_windows "$t" ;;
    esac
done

cp scripts/install.sh "$DIST/install.sh"
(cd "$DIST" && sha256 install.sh > install.sh.sha256)

# A binary that runs here must report the tag's version.
case "$HOST_OS-$(uname -m)" in
    Darwin-arm64) native=aarch64-apple-darwin ;;
    Darwin-x86_64) native=x86_64-apple-darwin ;;
    Linux-x86_64) native=x86_64-unknown-linux-gnu ;;
    Linux-aarch64) native=aarch64-unknown-linux-gnu ;;
    *) native=none ;;
esac
if [ -x "target/$native/release/webjetd" ] && case " $TARGETS " in *" $native "*) true ;; *) false ;; esac; then
    for b in webjetd webjetup; do
        "target/$native/release/$b" --version | grep -q " $VERSION\$" || die "$b doesn't report $VERSION"
    done
fi
(cd "$DIST" && cat ./*.sha256)

[ $PUBLISH = 1 ] || exit 0

# ---------------------------------------------------------------- publish
: "${WEBJET_FORGEJO_TOKEN:?set WEBJET_FORGEJO_TOKEN to publish}"
origin=$(git remote get-url origin)
host=$(echo "$origin" | sed -E 's#^[a-z+]+://##; s#^[^@/]+@##; s#[:/].*$##')
repo=${WEBJET_FORGEJO_REPO:-$(echo "$origin" | sed -E 's#^.*[:/]([^/]+/[^/]+)$#\1#; s#\.git$##; s#^[0-9]+/##')}
API=${WEBJET_FORGEJO_API:-https://$host/api/v1}
WEB=${API%/api/v1}
auth="Authorization: token $WEBJET_FORGEJO_TOKEN"
json_id() { python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])'; }

# The tag goes to the forge first (CI runs from a tag that is already there).
git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1 || git push origin "$TAG"
notes=$(git tag -l --format='%(contents)' "$TAG")
body=$(printf '%s' "$notes" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')
id=$(curl -fsS -H "$auth" "$API/repos/$repo/releases/tags/$TAG" 2>/dev/null | json_id 2>/dev/null || true)
if [ -z "$id" ]; then
    id=$(curl -fsS -X POST -H "$auth" -H 'Content-Type: application/json' \
        -d "{\"tag_name\":\"$TAG\",\"name\":\"Webjet $TAG\",\"body\":$body,\"draft\":false,\"prerelease\":false}" \
        "$API/repos/$repo/releases" | json_id)
    echo "created release $TAG (id $id)"
else
    echo "adding to release $TAG (id $id)"
fi
existing=$(curl -fsS -H "$auth" "$API/repos/$repo/releases/$id/assets" |
    python3 -c 'import json,sys; [print(a["id"], a["name"]) for a in json.load(sys.stdin)]')
for f in "$DIST"/*; do
    name=$(basename "$f")
    old=$(printf '%s\n' "$existing" | awk -v n="$name" '$2 == n {print $1}')
    if [ -n "$old" ]; then
        curl -fsS -X DELETE -H "$auth" "$API/repos/$repo/releases/$id/assets/$old" >/dev/null
    fi
    curl -fsS -X POST -H "$auth" -F "attachment=@$f" "$API/repos/$repo/releases/$id/assets?name=$name" >/dev/null
    echo "uploaded $name${old:+ (replaced)}"
done
echo "published: $WEB/$repo/releases/tag/$TAG"
echo "install:   curl -fsSL $WEB/$repo/releases/download/$TAG/install.sh | sudo sh"
