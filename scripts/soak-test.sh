#!/bin/sh
# Soak test on the local network: run past the end-to-end re-key interval
# (120 s) and check that every agent still answers its control channel and
# that traffic still flows. Catches deadlocks that only show up on timers,
# like a lock held across a re-key.
#
#   scripts/soak-test.sh [seconds]     # default 200
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
B=${BIN:-$ROOT/target/debug}
W=/tmp/webjet-local
SECS=${1:-200}
to() { perl -e 'alarm shift; exec @ARGV' "$@"; }

"$ROOT/scripts/local-net.sh" stop >/dev/null 2>&1 || true
rm -rf "$W"
"$ROOT/scripts/local-net.sh" 2 | tail -1
export WEBJET_KEYS=$W/keys WEBJET_ACCOUNT_PASSPHRASE=acct-pass
# The nodes need a few seconds to learn about each other.
i=0
until to 20 "$B/webjetctl" --socket $W/node-02/control.sock ping node-03 -c 1 >/dev/null 2>&1; do
    i=$((i + 1))
    [ $i -lt 30 ] || { echo "FAIL: no initial ping"; exit 1; }
    sleep 1
done

echo "== running for $SECS s"
t=0
while [ $t -lt "$SECS" ]; do
    sleep 10
    t=$((t + 10))
    for n in ctl-01 node-02 node-03; do
        if ! to 5 "$B/webjetctl" --socket "$W/$n/control.sock" --json status >/dev/null 2>&1; then
            echo "FAIL: $n stopped answering after ${t} s"
            "$ROOT/scripts/local-net.sh" stop
            exit 1
        fi
    done
done
to 20 "$B/webjetctl" --socket $W/node-02/control.sock ping node-03 -c 2 >/dev/null || { echo "FAIL: no ping after $SECS s"; exit 1; }
"$ROOT/scripts/local-net.sh" stop
echo "SOAK TEST PASSED"
