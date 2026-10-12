#!/bin/sh
# Check whether crates.io has a newer gpui, gpui_media, gpui_http_client or
# reed-solomon-erasure than the patched copies in vendor/ (vendor/README.md).
#
#   scripts/gpui-vendor-check.sh           # exit 1 if a newer version exists
#   scripts/gpui-vendor-check.sh --hook    # warn only, at most one lookup a day
#
# Prereleases and yanked versions don't count. --hook is what the pre-commit
# hook (.githooks/pre-commit) runs: it never fails the commit, caches the
# answer for a day in the git directory and gives up after a few seconds
# without network. WEBJET_SKIP_GPUI_CHECK=1 skips it.
set -eu

CRATES="gpui gpui_media gpui_http_client reed-solomon-erasure"
INDEX=https://index.crates.io
CACHE_SECS=86400

hook=0
case ${1:-} in
    --hook) hook=1 ;;
    "") ;;
    -h | --help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "usage: $0 [--hook]" >&2; exit 2 ;;
esac
[ "${WEBJET_SKIP_GPUI_CHECK:-0}" = 1 ] && exit 0

root=$(git rev-parse --show-toplevel 2>/dev/null || (cd "$(dirname "$0")/.." && pwd))

# The package version in a vendored Cargo.toml: the first `version` after
# [package].
vendored() { # crate
    awk '/^\[package\]/ { p = 1; next } /^\[/ { p = 0 } p && /^version *=/ {
        gsub(/^version *= *"|".*$/, ""); print; exit }' "$root/vendor/$1/Cargo.toml"
}

# crates.io's sparse index path: 1/, 2/, 3/<c>/ or <ab>/<cd>/ by name length.
index_path() { # crate
    case ${#1} in
        1) echo "1/$1" ;;
        2) echo "2/$1" ;;
        3) echo "3/$(echo "$1" | cut -c1)/$1" ;;
        *) echo "$(echo "$1" | cut -c1-2)/$(echo "$1" | cut -c3-4)/$1" ;;
    esac
}

# Newest released version: one JSON object per line, in publishing order.
latest() { # crate
    if [ $hook = 1 ]; then quiet=-s; else quiet=-sS; fi
    curl -f $quiet --max-time "${timeout:-20}" "$INDEX/$(index_path "$1")" |
        sed -n 's/^{"name":"[^"]*","vers":"\([^"]*\)".*"yanked":false.*$/\1/p' |
        grep -v -- - | newest
}

# The highest of the versions on stdin (x.y.z, numerically).
newest() {
    awk -F . '{ k = sprintf("%09d%09d%09d", $1, $2, $3); if (k > m) { m = k; v = $0 } }
        END { if (v != "") print v }'
}

newer() { # a b: is a newer than b?
    [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | newest)" = "$1" ]
}

cache=$(git -C "$root" rev-parse --git-path gpui-vendor-check 2>/dev/null || echo "")
[ -z "$cache" ] || case $cache in /*) ;; *) cache=$root/$cache ;; esac
now=$(date +%s)

report=""
for c in $CRATES; do
    have=$(vendored "$c")
    [ -n "$have" ] || { echo "gpui-vendor-check: no version in vendor/$c/Cargo.toml" >&2; exit 2; }
    want=""
    if [ $hook = 1 ] && [ -n "$cache" ] && [ -f "$cache" ]; then
        # Cache lines: <crate> <latest> <unix time looked up>
        want=$(awk -v c="$c" -v now="$now" -v max="$CACHE_SECS" \
            '$1 == c && now - $3 < max { print $2 }' "$cache")
    fi
    if [ -z "$want" ]; then
        [ $hook = 1 ] && timeout=5
        if ! want=$(latest "$c") || [ -z "$want" ]; then
            if [ $hook = 1 ]; then exit 0; fi # offline: say nothing, commit anyway
            echo "gpui-vendor-check: can't read $c from $INDEX" >&2
            exit 2
        fi
        if [ -n "$cache" ]; then
            { [ -f "$cache" ] && awk -v c="$c" '$1 != c' "$cache"; echo "$c $want $now"; } > "$cache.new" || true
            mv "$cache.new" "$cache" 2>/dev/null || true
        fi
    fi
    if newer "$want" "$have"; then
        report="$report  $c: vendored $have, crates.io has $want
"
    elif [ $hook = 0 ]; then
        echo "$c $have is the newest release"
    fi
done

[ -n "$report" ] || exit 0
printf 'gpui-vendor-check: newer releases on crates.io than the patched copies in vendor/:\n%s' "$report" >&2
echo "Update them as vendor/README.md describes (copy, redo the Webjet: changes, cargo update -p <crate>)." >&2
[ $hook = 1 ] && exit 0
exit 1
