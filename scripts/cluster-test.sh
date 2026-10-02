#!/bin/sh
# Raft test on the local network: turn node-02 and node-03 into controllers
# (certificate, learner, voter), then stop the leader and check that writes
# still commit and the data plane keeps working.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
B=${BIN:-$ROOT/target/debug}
W=${1:-/tmp/webjet-local}
"$ROOT/scripts/local-net.sh" stop "$W" || true
sleep 1
"$ROOT/scripts/local-net.sh" 2 "$W" | tail -1
cd "$W"
export WEBJET_KEYS=$W/keys WEBJET_ACCOUNT_PASSPHRASE=acct-pass WEBJET_ROOT_PASSPHRASE=root-pass
C() { s=$1; shift; perl -e 'alarm shift; exec @ARGV' 30 "$B/webjetctl" --socket "$W/$s/control.sock" --account alice "$@"; }
sleep 3
for n in node-02 node-03; do
  kill "$(cat $n/webjetd.pid)"; sleep 0.5
  sed -i.bak '/^\[controller\]/,$ s/^enabled = false/enabled = true/' $n/webjetd.toml
  "$B/webjetd" -c $n/webjetd.toml run > $n/log 2>&1 & echo $! > $n/webjetd.pid
done
sleep 4
for n in node-02 node-03; do
  C $n controller cert-request --out $n.req > /dev/null
  "$B/webjet-root" --dir root controller sign $n.req --out $n.cert > /dev/null
  C ctl-01 submit $n.cert > /dev/null 2>&1
  C ctl-01 controller add-learner $n
done
sleep 5
C ctl-01 controller promote node-02
C ctl-01 controller promote node-03
sleep 3
echo "== cluster:"; C ctl-01 controller list | grep -E "role|applied"
for n in node-02 node-03; do echo "== $n:"; C $n controller list | grep -E "role|applied|halted"; done
echo "== stopping the leader ctl-01"
kill "$(cat ctl-01/webjetd.pid)"
sleep 9
for n in node-02 node-03; do echo "== $n:"; C $n controller list | grep -E "  role|applied"; done
cat > policy-v9.yaml <<EOT
version: 9
default: allow
EOT
C node-02 policy apply policy-v9.yaml
C node-02 status | grep tree_version
C node-03 status | grep tree_version
C node-02 ping node-03 -c 2
echo "cluster test passed"
