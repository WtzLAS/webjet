#!/bin/sh
# Check dependencies with cargo-deny (deny.toml): security advisories,
# licences, banned crates and sources. Installs a pinned cargo-deny release
# (SHA-256 checked) when it isn't on PATH, so it also works in CI images
# that don't have it.
#
#   scripts/deny.sh            # every check
#   scripts/deny.sh advisories # one of: advisories bans licenses sources
set -eu

VERSION=0.20.2
# sha256 of cargo-deny-$VERSION-<target>.tar.gz from
# https://github.com/EmbarkStudios/cargo-deny/releases
SHA_x86_64_unknown_linux_musl=9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f

cd "$(dirname "$0")/.."

if ! command -v cargo-deny >/dev/null 2>&1; then
	case "$(uname -s)-$(uname -m)" in
	Linux-x86_64) target=x86_64-unknown-linux-musl sha=$SHA_x86_64_unknown_linux_musl ;;
	*)
		echo "cargo-deny not found; install it with: cargo install --locked cargo-deny@$VERSION" >&2
		exit 2
		;;
	esac
	dir="${CARGO_HOME:-$HOME/.cargo}/bin"
	mkdir -p "$dir"
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	name="cargo-deny-$VERSION-$target"
	curl -fsSL --retry 3 -o "$tmp/deny.tgz" \
		"https://github.com/EmbarkStudios/cargo-deny/releases/download/$VERSION/$name.tar.gz"
	echo "$sha  $tmp/deny.tgz" | sha256sum -c - >/dev/null
	tar -xzf "$tmp/deny.tgz" -C "$tmp"
	install -m 0755 "$tmp/$name/cargo-deny" "$dir/cargo-deny"
	PATH="$dir:$PATH"
fi

cargo deny --version
exec cargo deny --locked check "$@"
