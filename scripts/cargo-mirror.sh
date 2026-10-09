#!/bin/sh
# Fetch crates from a crates.io mirror instead of crates.io (CI: the runners
# are in China, where crates.io is slow). Tries the sources in order, each
# with one `cargo fetch --locked` of the workspace, and keeps the first that
# has every crate in Cargo.lock:
#
#   1. TUNA (a MirrorZ member, help.mirrors.cernet.edu.cn/crates.io-index/).
#      Its sparse index is synced periodically, so right after a `cargo
#      update` it can miss the newest versions.
#   2. USTC: proxies crates.io live, but rate-limits (HTTP 429).
#   3. crates.io itself.
#
# The choice goes into $CARGO_HOME/config.toml (a source replacement, as on
# the MirrorZ help page), so every cargo run afterwards uses it and finds
# the crates already downloaded: builds, tests, clippy, cargo-xwin,
# cargo-deny, scripts/*-cargo.sh. Cargo.lock keeps naming crates.io and the
# crates' checksums are still checked against it, so --locked builds and
# cargo-deny's source check are unaffected.
#
#   scripts/cargo-mirror.sh                 # the list above
#   scripts/cargo-mirror.sh <index URL>...  # other sparse indexes, in order
#                                           # ("crates.io": no mirror)
set -eu

cd "$(dirname "$0")/.."
if [ $# -eq 0 ]; then
	set -- sparse+https://mirrors.tuna.tsinghua.edu.cn/crates.io-index/ \
		sparse+https://mirrors.ustc.edu.cn/crates.io-index/ \
		crates.io
fi
config="${CARGO_HOME:-$HOME/.cargo}/config.toml"
mkdir -p "$(dirname "$config")"
touch "$config"
begin="# --- cargo-mirror.sh begin"
end="# --- cargo-mirror.sh end"

# Remove an earlier choice of this script; refuse other replacements.
use() {
	sed "/^$begin\$/,/^$end\$/d" "$config" >"$config.tmp"
	mv "$config.tmp" "$config"
	if grep -q '^\[source\.crates-io\]' "$config"; then
		echo "$config already replaces crates.io:" >&2
		cat "$config" >&2
		exit 1
	fi
	[ "$1" = crates.io ] && return
	cat >>"$config" <<EOF
$begin
[source.crates-io]
replace-with = "mirror"

[source.mirror]
registry = "$1"

[registries.mirror]
index = "$1"
$end
EOF
}

log=$(mktemp)
trap 'rm -f "$log"' EXIT
for url in "$@"; do
	use "$url"
	echo "cargo-mirror: trying $url"
	if cargo fetch --locked >"$log" 2>&1; then
		echo "cargo-mirror: using $url ($config)"
		exit 0
	fi
	echo "cargo-mirror: $url failed:" >&2
	grep -v '^ *Downloaded ' "$log" | tail -8 >&2
done
echo "cargo-mirror: no source worked" >&2
exit 1
