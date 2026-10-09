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
# cargo retries a failed request (HTTP 429 from a rate-limited mirror, a
# connection reset) `net.retry` times with backoff.
use() {
	sed "/^$begin\$/,/^$end\$/d" "$config" >"$config.tmp"
	mv "$config.tmp" "$config"
	if grep -q '^\[source\.crates-io\]' "$config"; then
		echo "$config already replaces crates.io:" >&2
		cat "$config" >&2
		exit 1
	fi
	{
		echo "$begin"
		echo "[net]"
		echo "retry = 10"
		if [ "$1" != crates.io ]; then
			cat <<EOF

[source.crates-io]
replace-with = "mirror"

[source.mirror]
registry = "$1"

[registries.mirror]
index = "$1"
EOF
		fi
		echo "$end"
	} >>"$config"
}

# Whether a source answers at all, in a few seconds: a mirror that blocks
# the runner (USTC sometimes stops answering instead of sending a 429)
# would otherwise hold cargo, which waits on a silent connection for
# minutes per request.
answers() {
	case $1 in
	crates.io) probe=https://index.crates.io/config.json ;;
	*) probe="${1#sparse+}config.json" ;;
	esac
	curl -fsS -o /dev/null --connect-timeout 5 --max-time 10 "$probe"
}

# Several jobs start at once and share the runner's address, so a mirror
# can rate-limit all of them: go through the list up to three times, a
# minute apart. A fetch gets at most $FETCH_TIMEOUT seconds (default 10
# minutes); a failed one keeps what it downloaded.
FETCH_TIMEOUT=${FETCH_TIMEOUT:-600}
log=$(mktemp)
trap 'rm -f "$log"' EXIT
for round in 1 2 3; do
	for url in "$@"; do
		echo "cargo-mirror: trying $url"
		if ! answers "$url" 2>"$log"; then
			echo "cargo-mirror: $url doesn't answer: $(cat "$log")" >&2
			continue
		fi
		use "$url"
		if timeout -k 10 "$FETCH_TIMEOUT" cargo fetch --locked >"$log" 2>&1; then
			echo "cargo-mirror: using $url ($config)"
			exit 0
		else
			rc=$?
		fi
		[ $rc = 124 ] && echo "cargo-mirror: $url timed out after ${FETCH_TIMEOUT}s" >&2
		echo "cargo-mirror: $url failed:" >&2
		grep -v '^ *Downloaded ' "$log" | grep -v '^[[:space:]]*<' | tail -6 >&2
	done
	[ $round = 3 ] || sleep 60
done
echo "cargo-mirror: no source worked" >&2
exit 1
