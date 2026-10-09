#!/bin/sh
# Fetch crates from a crates.io mirror instead of crates.io (CI: the runners
# are in China, where crates.io and its CDN are slow). Writes the source
# replacement into $CARGO_HOME/config.toml, so every cargo run afterwards
# uses it: builds, tests, clippy, cargo-xwin, cargo-deny, scripts/*-cargo.sh.
# Cargo.lock keeps naming crates.io and the crates' checksums are still
# checked against it, so --locked builds and cargo-deny's source check are
# unaffected.
#
#   scripts/cargo-mirror.sh             # USTC
#   scripts/cargo-mirror.sh <index URL> # another sparse index
set -eu

URL=${1:-sparse+https://mirrors.ustc.edu.cn/crates.io-index/}
config="${CARGO_HOME:-$HOME/.cargo}/config.toml"
mkdir -p "$(dirname "$config")"
if [ -f "$config" ] && grep -q '^\[source\.crates-io\]' "$config"; then
	echo "$config already replaces crates.io:" >&2
	cat "$config" >&2
	exit 1
fi
cat >>"$config" <<EOF

[source.crates-io]
replace-with = "mirror"

[source.mirror]
registry = "$URL"
EOF
echo "crates.io mirror: $URL ($config)"
