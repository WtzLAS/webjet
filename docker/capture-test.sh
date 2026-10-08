#!/bin/sh
# Capture (architecture §9.5.2) on four Linux nodes: Minecraft Bedrock
# clients that broadcast from a socket bound to 0.0.0.0, as the real game
# does, so the OS sends the discovery out of eth0, not the overlay. Each
# node runs docker/raknet-lan with -unbound: a RakNet server ("LAN world")
# and a Friends-tab client.
#
# The containers share one Docker network, so to make them strangers on
# separate LANs each drops LAN broadcasts to port 19132 arriving on eth0:
# a world can only be found through the overlay.
#
#   ctl-01 (controller, relay) and p-1 … p-3: data nodes tagged "game";
#   policy lets game nodes reach each other on udp:19132.
#
# Phases:
#   A. No capture: every client broadcasts out of eth0; nobody finds a world.
#   B. `[multicast] capture = ["udp:19132"]`: within seconds every node sees
#      the 3 other worlds, joins them over RakNet and plays; the copies are
#      counted as captured. The LAN still gets the broadcasts too.
#   C. p-3's own configuration sets `capture = []`: p-3's broadcasts stop
#      reaching the overlay (its pongs stop), while it still answers others.
#   D. A bound client on p-1 sending into the overlay as well as an unbound
#      one: each datagram is carried once (duplicates counted).
# Usage: docker build --target test -t webjet:test . && docker/capture-test.sh
#   KEEP=1 keeps the containers; `docker/capture-test.sh clean`.
set -eu
IMG=${IMG:-webjet:test}
P=wjc
NODES="ctl p1 p2 p3"
cleanup() {
  for c in $NODES; do docker rm -f $P-$c >/dev/null 2>&1 || true; done
  docker network rm $P-wan >/dev/null 2>&1 || true
}
cleanup
[ "${1:-}" = "clean" ] && exit 0
[ "${KEEP:-}" = 1 ] || trap cleanup EXIT

echo "== build raknet-lan"
ROOT=$(cd "$(dirname "$0")/.." && pwd)
case $(docker info --format '{{.Architecture}}') in
  aarch64 | arm64) ARCH=arm64 ;;
  *) ARCH=amd64 ;;
esac
mkdir -p "$ROOT/target"
if command -v go >/dev/null 2>&1; then
  (cd "$ROOT/docker/raknet-lan" && CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -o "$ROOT/target/raknet-lan" .)
else
  docker run --rm -v "$ROOT/docker/raknet-lan":/src -v "$ROOT/target":/out -w /src \
    -e CGO_ENABLED=0 -e GOARCH=$ARCH golang:1 go build -o /out/raknet-lan .
fi

docker network create --subnet 172.30.11.0/24 $P-wan >/dev/null
for c in $NODES; do
  case $c in
    ctl) name=ctl-01 ;;
    *) name="p-${c#p}" ;;
  esac
  docker run -d --name $P-$c --hostname $name --network $P-wan --cap-add NET_ADMIN --device /dev/net/tun \
    -e RUST_LOG=info -e WEBJET_ROOT_PASSPHRASE=r -e WEBJET_ACCOUNT_PASSPHRASE=a -e WEBJET_KEYS=/root/keys \
    $IMG /opt/webjet/docker/node.sh $name >/dev/null
  docker cp "$ROOT/target/raknet-lan" $P-$c:/usr/local/bin/raknet-lan
done
sleep 1
x() { c=$1; shift; docker exec $P-$c "$@"; }
bg() { c=$1; shift; docker exec -d $P-$c sh -c "$*"; }
fail() { echo "FAIL: $*"; exit 1; }
CTL_IP=$(x ctl hostname -i | awk '{print $1}')
ip_of() { case $1 in ctl) echo 10.7.0.1 ;; *) echo "10.7.0.1${1#p}" ;; esac; }
host() { case $1 in ctl) echo ctl-01 ;; *) echo "p-${1#p}" ;; esac; }

# Separate LANs: LAN broadcasts to the game port don't arrive.
for c in $NODES; do
  x $c iptables -A INPUT -i eth0 -p udp --dport 19132 -j DROP
done

echo "== bootstrap ctl-01 ($CTL_IP) and three players"
x ctl sh -c 'cd /root && webjetctl root --dir root init >/dev/null && webjetctl network account keygen --name alice --pub-out alice.pub >/dev/null &&
  webjetctl root --dir root admin sign --name alice --key alice.pub --out alice.account >/dev/null &&
  webjetctl root --dir root genesis --overlay-pool 10.7.0.0/16 --admin alice.account --out genesis.wj >/dev/null &&
  webjetctl local init --genesis genesis.wj >/dev/null'
bg ctl 'webjetd run > /var/log/webjetd.log 2>&1'
W() { x ctl webjetctl --account alice "$@"; }
i=0; until W network controller list 2>/dev/null | grep -q 'valid_until: [1-9]'; do sleep 0.5; i=$((i+1)); [ $i -lt 60 ] || { x ctl cat /var/log/webjetd.log; fail "controller did not start"; }; done
x ctl sh -c 'cd /root && webjetctl network account keygen --name infra --pub-out infra.pub >/dev/null'
W network account create --name infra --key /root/infra.pub >/dev/null
T=$(W network node enroll --owner infra --name ctl-01 --ip 10.7.0.1 --tags tag:game --roles data,relay,control --controller tls:$CTL_IP:443 2>/dev/null)
x ctl webjetctl local enroll "$T" >/dev/null
W network controller certify ctl-01 >/dev/null
x ctl sh -c 'cat > /root/network.toml <<EOT
version = 0

[policy]
default = "deny"

[[policy.rule]]
id = "minecraft"
action = "allow"
src = ["tag:game"]
dst = ["tag:game"]
ports = ["icmp", "udp:19132"]

[[seeds]]
node = "ctl-01"
addrs = ["tls:'"$CTL_IP"':443", "kcp:'"$CTL_IP"':443"]
EOT'
W network config apply /root/network.toml >/dev/null
for c in p1 p2 p3; do
  T=$(W network node enroll --owner infra --name $(host $c) --ip $(ip_of $c) --tags tag:game --roles data --controller tls:$CTL_IP:443) || fail "enroll $c"
  x $c webjetctl local enroll "$T" >/dev/null
  bg $c 'webjetd run > /var/log/webjetd.log 2>&1'
done
for c in p1 p2 p3; do
  i=0; until x $c ip -4 addr show 2>/dev/null | grep -q "10\.7\.0\."; do sleep 0.5; i=$((i+1)); [ $i -lt 60 ] || { x $c cat /var/log/webjetd.log; fail "$c has no overlay address"; }; done
done
for c in $NODES; do
  for d in $NODES; do
    [ $c = $d ] && continue
    i=0; until x $c ping -c 1 -W 1 "$(ip_of $d)" >/dev/null 2>&1; do sleep 1; i=$((i+1)); [ $i -lt 30 ] || fail "$c can't ping $d"; done
  done
done
echo "all pairs reach each other"

# ---------------------------------------------------------------- helpers
metric() { # container series label-match
  x $1 webjetctl local metrics | awk -v s="$2{" -v l="$3" 'index($0, s) == 1 && index($0, l) { v = $2 } END { printf "%d\n", v + 0 }'
}
mcap() { metric $1 webjet_multicast_packets_total 'direction="captured"'; }
mtx() { metric $1 webjet_multicast_packets_total 'direction="tx"'; }
mdup() { metric $1 webjet_limit_hits_total 'limit="multicast_duplicate"'; }
st() { # container key
  x $1 awk -v k="$2" '$1 == k { sub(/^[^ ]+ ?/, ""); print; f = 1 } END { if (!f) print 0 }' /tmp/rak.txt
}
start() { # container extra-flags
  bg $1 "exec raknet-lan -name $(host $1) -bind $(ip_of $1) -status /tmp/rak.txt $2 > /tmp/rak.log 2>&1"
}
stop() { for c in $NODES; do x $c pkill -TERM raknet-lan 2>/dev/null || true; done; sleep 1.5; }
lan_tx() { x $1 sh -c "iptables -nvxL OUTPUT | awk '/capture-probe/ {print \$1}'"; }

echo
echo "== A. no capture: unbound clients broadcast out of eth0 only, 15 s"
for c in $NODES; do
  # Count what leaves on eth0 to the game port (the LAN still gets it).
  x $c iptables -A OUTPUT -o eth0 -p udp --dport 19132 -m comment --comment capture-probe
  start $c "-unbound -connect"
done
sleep 15
for c in $NODES; do
  w=$(st $c servers); out=$(lan_tx $c)
  echo "$(host $c): $(st $c pings_sent) pings, $out out of eth0, worlds seen: $w"
  [ "$w" -eq 0 ] || fail "$c found a world without capture"
  [ "$out" -gt 0 ] || fail "$c's pings didn't go out of eth0: the test isn't testing capture"
  [ "$(mcap $c)" -eq 0 ] || fail "$c captured without capture configured"
done
echo "nobody finds anybody: the broadcasts never reach the overlay"

echo
echo "== B. capture = [\"udp:19132\"] for the network"
W network config set multicast.capture '["udp:19132"]' >/dev/null
W network config show | grep -A1 '^\[multicast\]'
T0=$(date +%s)
for c in $NODES; do
  i=0; until [ "$(st $c servers)" -eq 3 ]; do sleep 1; i=$((i+1)); [ $i -lt 30 ] || { x $c webjetctl local status | grep -i -A2 alarm; fail "$c sees $(st $c servers) worlds"; }; done
done
echo "every node sees the 3 other worlds $(( $(date +%s) - T0 )) s after the change"
sleep 20
for c in $NODES; do
  echo "$(host $c): worlds $(st $c worlds); joined $(st $c connected), $(st $c echoes) game messages answered; captured $(mcap $c), copies sent $(mtx $c); LAN still got $(lan_tx $c)"
  [ "$(st $c connected)" -eq 3 ] || fail "$c joined $(st $c connected) of 3 worlds: $(st $c errors)"
  [ "$(st $c echoes)" -ge 10 ] || fail "$c: only $(st $c echoes) game messages answered"
  [ "$(mcap $c)" -gt 0 ] || fail "$c captured nothing"
done
x p1 webjetctl local status | grep -q multicast_capture && fail "multicast_capture alarm on p-1"
echo "captured discovery finds every world; RakNet connections and play work"

echo
echo "== C. p-3's own configuration: capture = []"
p3_pongs=$(st p3 pongs)
W local config --node p-3 set multicast.capture '[]' >/dev/null
sleep 8
c0=$(mcap p3); a=$(st p3 pongs); others=$(st p1 pongs)
sleep 8
echo "p-3: captured $c0 -> $(mcap p3), pongs $a -> $(st p3 pongs); p-1 pongs $others -> $(st p1 pongs)"
[ "$(mcap p3)" -eq "$c0" ] || fail "p-3 still captures"
[ "$(st p3 pongs)" -eq "$a" ] || fail "p-3's broadcasts still reach the overlay"
[ "$(st p1 pongs)" -gt "$others" ] || fail "p-1 stopped finding worlds"
echo "p-3 no longer captures; it still answers the others ($p3_pongs pongs before)"
W local config --node p-3 unset multicast.capture >/dev/null

echo
echo "== D. one app sending both into the overlay and out of eth0"
stop
# The same discovery datagrams sent from a socket bound to the overlay
# address (into the tun interface) and from an unbound one (out of eth0).
x p1 sh -c 'cat > /tmp/both.py <<EOT
import socket, time
ping = bytes([1]) + bytes(8) + bytes.fromhex("00ffff00fefefefefdfdfdfd12345678") + bytes(8)
a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); a.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); a.bind(("10.7.0.11", 0))
b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); b.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); b.bind(("0.0.0.0", 0))
for i in range(20):
    p = ping[:1] + i.to_bytes(8, "big") + ping[9:]
    a.sendto(p, ("255.255.255.255", 19132))
    b.sendto(p, ("255.255.255.255", 19132))
    time.sleep(0.2)
EOT'
d0=$(mdup p1); t0=$(mtx p1)
x p1 python3 /tmp/both.py
sleep 1
dups=$(( $(mdup p1) - d0 )); sent=$(( $(mtx p1) - t0 ))
echo "20 datagrams sent both ways: $sent copies to 3 peers, $dups carried once"
[ "$dups" -eq 20 ] || fail "$dups duplicates detected, not 20"
[ "$sent" -eq 60 ] || fail "$sent copies, not 60"

echo
echo "== metrics on p-1"
x p1 webjetctl local metrics | grep -E "^webjet_(multicast_packets_total|limit_hits_total\{.*multicast)"
echo
echo "CAPTURE TEST PASSED"
