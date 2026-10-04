#!/bin/sh
# Raft test on the local network: turn node-02 and node-03 into controllers
# (control role, admin-signed certificate, learner, voter), then stop the
# leader and check that writes still commit and the data plane keeps working.
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
# The role starts the controller on the running agents; no restart.
for n in node-02 node-03; do C ctl-01 node update $n --roles data,control > /dev/null; done
sleep 4
# node-02: the admin certifies it (its request is fetched over the overlay);
# node-03: the root signs its request offline.
C ctl-01 controller certify node-02
C node-03 controller cert-request --out node-03.req > /dev/null
"$B/webjetctl" root --dir root controller sign node-03.req --out node-03.cert > /dev/null
C ctl-01 submit node-03.cert > /dev/null 2>&1
for n in node-02 node-03; do C ctl-01 controller add-learner $n; done
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
