#!/bin/sh
# Fuzz every target (fuzz/fuzz_targets) with libFuzzer for a while each.
#
#   scripts/fuzz.sh [SECONDS_PER_TARGET] [TARGET...]
#
# Needs a nightly toolchain and cargo-fuzz:
#   rustup toolchain install nightly --profile minimal
#   cargo install cargo-fuzz
#
# The corpus grows in fuzz/corpus/<target>/ (gitignored); crashes land in
# fuzz/artifacts/<target>/ and make this script exit 1. Reproduce one with
#   cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-...
# and keep it as a regression test by copying it to
# fuzz/regressions/<target>/ (committed; `cargo test` in fuzz/ replays it).
set -eu

cd "$(dirname "$0")/../fuzz"
secs="${1:-60}"
[ $# -gt 0 ] && shift
if [ $# -gt 0 ]; then
	targets="$*"
else
	targets=$(cargo +nightly fuzz list)
fi

# Start from the seeds (valid messages of every kind).
cargo run -q --no-default-features --example seeds >/dev/null

failed=""
for t in $targets; do
	echo "== $t (${secs}s)"
	mkdir -p "corpus/$t"
	if [ -d "regressions/$t" ]; then
		cp regressions/"$t"/* "corpus/$t/" 2>/dev/null || true
	fi
	# -rss_limit_mb: decompression bombs must be stopped by the size caps,
	# so a target using a lot of memory is a bug too.
	log="target/fuzz-$t.log"
	mkdir -p target
	if ! cargo +nightly fuzz run -O "$t" -- \
		-max_total_time="$secs" -rss_limit_mb=1024 -max_len=65536 \
		-print_final_stats=1 >"$log" 2>&1; then
		failed="$failed $t"
	fi
	tail -n 25 "$log"
	if ls "artifacts/$t"/crash-* "artifacts/$t"/oom-* "artifacts/$t"/timeout-* >/dev/null 2>&1; then
		case " $failed " in *" $t "*) ;; *) failed="$failed $t" ;; esac
	fi
done

if [ -n "$failed" ]; then
	echo "failed:$failed (see fuzz/artifacts/)"
	exit 1
fi
echo "all targets ran ${secs}s without a finding"
