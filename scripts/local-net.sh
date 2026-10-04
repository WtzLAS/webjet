#!/bin/sh
# Bring up a small Webjet network on this machine, following runbook 1 of the
# operations guide: a bootstrap controller (also a relay) and N other nodes,
# all on 127.0.0.1 with the tun interface disabled (no root needed).
#
#   scripts/local-net.sh [nodes] [workdir]
#
# Leaves the agents running; stop them with `scripts/local-net.sh stop [workdir]`.
set -eu
BIN=${BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/debug}
if [ "${1:-}" = "stop" ]; then
  W=${2:-/tmp/webjet-local}
  pids=""
  for p in "$W"/*/webjetd.pid; do
    [ -f "$p" ] || continue
    pid=$(cat "$p")
    kill "$pid" 2>/dev/null && pids="$pids $pid"
  done
  # Wait up to 10 s for a clean exit; a hung agent is killed.
  i=0
  for pid in $pids; do
    while kill -0 "$pid" 2>/dev/null && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
    if kill -0 "$pid" 2>/dev/null; then
      echo "agent $pid did not stop; killing it" >&2
      kill -9 "$pid" 2>/dev/null || true
    fi
  done
  exit 0
fi
N=${1:-3}
W=${2:-/tmp/webjet-local}
TUN=${TUN:-false}
# ANYTLS=true adds an AnyTLS listener on port+2000 to every node.
ANYTLS=${ANYTLS:-false}
rm -rf "$W"; mkdir -p "$W"
export WEBJET_ROOT_PASSPHRASE=root-pass WEBJET_ACCOUNT_PASSPHRASE=acct-pass WEBJET_KEYS="$W/keys"
export RUST_LOG=${RUST_LOG:-info}

conf() { # name port
  cat > "$W/$1/webjetd.toml" <<EOT
data_dir = "$W/$1"
control_socket = "$W/$1/control.sock"
[listen]
tls = "127.0.0.1:$2"
kcp = "127.0.0.1:$2"
EOT
  if [ "$ANYTLS" = true ]; then echo "anytls = \"127.0.0.1:$(($2 + 2000))\"" >> "$W/$1/webjetd.toml"; fi
  cat >> "$W/$1/webjetd.toml" <<EOT
[tun]
enabled = $TUN
[dns]
configure_system = false
[metrics]
listen = "127.0.0.1:$(($2 + 1000))"
[controller]
head_lifetime_hours = 24
EOT
}
start() { # name
  "$BIN/webjetd" -c "$W/$1/webjetd.toml" run > "$W/$1/log" 2>&1 &
  echo $! > "$W/$1/webjetd.pid"
}
ctl() { "$BIN/webjetctl" --socket "$W/ctl-01/control.sock" --account alice "$@"; }
wait_sock() { i=0; while [ ! -S "$1" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done; }

echo "== root keys, admin account, genesis"
"$BIN/webjetctl" root --dir "$W/root" init > /dev/null
"$BIN/webjetctl" account keygen --name alice --pub-out "$W/alice.pub" > /dev/null
"$BIN/webjetctl" root --dir "$W/root" admin sign --name alice --key "$W/alice.pub" --out "$W/alice.account" > /dev/null
"$BIN/webjetctl" root --dir "$W/root" genesis --overlay-pool 10.7.0.0/16 --admin "$W/alice.account" --out "$W/genesis.wj" > /dev/null

echo "== first controller"
mkdir -p "$W/ctl-01"; conf ctl-01 17001
"$BIN/webjetctl" init --config "$W/ctl-01/webjetd.toml" --genesis "$W/genesis.wj" > /dev/null
start ctl-01; wait_sock "$W/ctl-01/control.sock"
i=0; until ctl controller list 2>/dev/null | grep -q 'valid_until: [1-9]'; do sleep 0.2; i=$((i+1)); [ $i -lt 100 ] || { echo "controller did not start"; exit 1; }; done
"$BIN/webjetctl" account keygen --name infra --pub-out "$W/infra.pub" > /dev/null
ctl account create --name infra --key "$W/infra.pub"
T=$(ctl node enroll --owner infra --name ctl-01 --ip 10.7.0.1 --roles data,relay,control --tags tag:infra --controller tls:127.0.0.1:17001 2>/dev/null)
"$BIN/webjetctl" enroll --config "$W/ctl-01/webjetd.toml" "$T" > /dev/null
ctl controller certify ctl-01 > /dev/null
cat > "$W/policy.yaml" <<EOT
version: 1
default: deny
rules:
  - id: everyone
    action: allow
    src: ["*"]
    dst: ["*"]
    ports: ["*"]
EOT
ctl policy apply "$W/policy.yaml"
cat > "$W/dns.yaml" <<EOT
version: 1
suffix: internal
resolver_ip: [10.7.255.53]
EOT
ctl dns apply "$W/dns.yaml"
cat > "$W/seeds.yaml" <<EOT
version: 1
seeds:
  - node: ctl-01
    addrs: [tls:127.0.0.1:17001, kcp:127.0.0.1:17001]
EOT
ctl seeds apply "$W/seeds.yaml"

i=2
while [ $i -le $((N+1)) ]; do
  name=node-0$i; port=$((17000+i))
  echo "== $name"
  mkdir -p "$W/$name"; conf $name $port
  T=$(ctl node enroll --owner infra --name $name --ip 10.7.0.$i --roles data --controller tls:127.0.0.1:17001 2>/dev/null)
  "$BIN/webjetctl" enroll --config "$W/$name/webjetd.toml" "$T"
  start $name
  i=$((i+1))
done
echo "network up in $W"
