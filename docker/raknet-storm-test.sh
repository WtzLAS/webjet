#!/bin/sh
# Minecraft Bedrock LAN discovery on five nodes, and whether it can turn
# into a broadcast storm (architecture §9.5.1). Each node runs
# docker/raknet-lan: a RakNet server hosting a "LAN world" (go-raknet,
# the library Bedrock proxies use) and a client on the Friends tab that
# broadcasts RakNet unconnected pings to 255.255.255.255:19132.
#
#   ctl-01 (controller, relay) and p-1 … p-4: all data nodes tagged
#   "game"; policy lets game nodes reach each other on udp:19132.
#
# Phases (wire bandwidth is measured on each container's eth0, the
# traffic Webjet itself puts on the network, minus an idle baseline):
#   A. everyone on the Friends tab, 1 ping/s each, 60 s: every node sees
#      the 4 other worlds; each ping becomes exactly 4 copies and each node
#      receives exactly the others' pings, once; bandwidth stays flat.
#   B. everyone joins every world they see: 20 real RakNet connections
#      (MTU discovery, handshake, game messages) through the overlay.
#   C. aggressive clients, 20 pings/s each: the per-node budget caps what
#      each node sends; discovery still sees every world.
#   D. a naive LAN bridge on every node rebroadcasting every ping it hears
#      (a five-way broadcast loop): stopped as echoes, nothing amplified.
#   E. the same bridges, each changing the pings it relays (not an exact
#      echo, the worst case: unbounded exponential growth on a flooding
#      overlay): held at the budget, and gone when the bridges stop.
# Usage: docker build --target test -t webjet:test . && docker/raknet-storm-test.sh
#   KEEP=1 keeps the containers; `docker/raknet-storm-test.sh clean`.
set -eu
IMG=${IMG:-webjet:test}
P=wjr
# WAN_PREFIX: the test network's first two octets (WAN_PREFIX.9.0/24), in
# case 172.30 is taken on the host.
WAN=${WAN_PREFIX:-172.30}
NODES="ctl p1 p2 p3 p4"
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

docker network create --subnet $WAN.9.0/24 $P-wan >/dev/null
for c in $NODES; do
  case $c in
    ctl) name=ctl-01 ;;
    *) name="p-${c#p}" ;;
  esac
  docker run -d --name $P-$c --hostname $name --network $P-wan --cap-add NET_ADMIN --device /dev/net/tun -e WAN_PREFIX=$WAN \
    -e RUST_LOG=info -e WEBJET_ROOT_PASSPHRASE=r -e WEBJET_ACCOUNT_PASSPHRASE=a -e WEBJET_KEYS=/root/keys \
    $IMG /opt/webjet/docker/node.sh $name >/dev/null
  docker cp "$ROOT/target/raknet-lan" $P-$c:/usr/local/bin/raknet-lan
done
sleep 1
x() { c=$1; shift; docker exec $P-$c "$@"; }
bg() { c=$1; shift; docker exec -d $P-$c sh -c "$*"; }
fail() { echo "FAIL: $*"; exit 1; }
CTL_IP=$(x ctl hostname -i | awk '{print $1}')

echo "== bootstrap ctl-01 ($CTL_IP) and four players"
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
for n in 1 2 3 4; do
  T=$(W network node enroll --owner infra --name p-$n --ip 10.7.0.1$n --tags tag:game --roles data --controller tls:$CTL_IP:443) || fail "enroll p-$n"
  x p$n webjetctl local enroll "$T" >/dev/null
  bg p$n 'webjetd run > /var/log/webjetd.log 2>&1'
done
ip_of() { case $1 in ctl) echo 10.7.0.1 ;; *) echo "10.7.0.1${1#p}" ;; esac; }
for c in p1 p2 p3 p4; do
  i=0; until x $c ip -4 addr show 2>/dev/null | grep -q "10\.7\.0\."; do sleep 0.5; i=$((i+1)); [ $i -lt 60 ] || { x $c cat /var/log/webjetd.log; fail "$c has no overlay address"; }; done
done
# Sessions between every pair (a fast "host unreachable" while routes come up).
for c in $NODES; do
  for d in $NODES; do
    [ $c = $d ] && continue
    i=0; until x $c ping -c 1 -W 1 "$(ip_of $d)" >/dev/null 2>&1; do sleep 1; i=$((i+1)); [ $i -lt 30 ] || fail "$c can't ping $d"; done
  done
done
echo "all 20 pairs reach each other"

# ---------------------------------------------------------------- helpers
metric() { # container series label-match
  x $1 webjetctl local metrics | awk -v s="$2{" -v l="$3" 'index($0, s) == 1 && index($0, l) { v = $2 } END { printf "%d\n", v + 0 }'
}
mtx() { metric $1 webjet_multicast_packets_total 'direction="tx"'; }
mrx() { metric $1 webjet_multicast_packets_total 'direction="rx"'; }
mlimited() { metric $1 webjet_limit_hits_total 'limit="multicast_limited"'; }
mecho() { metric $1 webjet_limit_hits_total 'limit="multicast_echo"'; }
wire() { # bytes all five nodes have sent on the network
  t=0; for c in $NODES; do t=$((t + $(x $c cat /sys/class/net/eth0/statistics/tx_bytes))); done; echo $t
}
snap() { # name: multicast counters of every node into variables <name>_<field>_<node>
  for c in $NODES; do
    eval "$1_tx_$c=$(mtx $c) $1_rx_$c=$(mrx $c) $1_lim_$c=$(mlimited $c) $1_echo_$c=$(mecho $c)"
  done
}
d() { eval "echo \$(( \$${2}_$1_$3 - \$${4}_$1_$3 ))"; } # field after node before
st() { # container key: a field of raknet-lan's status file
  x $1 awk -v k="$2" '$1 == k { sub(/^[^ ]+ ?/, ""); print; f = 1 } END { if (!f) print 0 }' /tmp/rak.txt
}
start() { # extra flags for raknet-lan
  for c in $NODES; do
    bg $c "exec raknet-lan -name $(x $c hostname) -bind $(ip_of $c) -status /tmp/rak.txt $* > /tmp/rak.log 2>&1"
  done
}
stop() {
  for c in $NODES; do x $c pkill -TERM raknet-lan 2>/dev/null || true; done
  sleep 1.5 # last copies delivered, counters final
}
# measure SECONDS WINDOWS: bytes/s on the wire per window into $RATES,
# their mean into $MEAN.
measure() {
  RATES=""; sum=0; w=$(($1 / $2))
  last=$(wire)
  for _ in $(seq $2); do
    sleep $w
    now=$(wire); r=$(( (now - last) / w )); last=$now
    RATES="$RATES $r"; sum=$((sum + r))
  done
  MEAN=$((sum / $2))
}
kb() { awk -v b="$1" 'BEGIN { printf "%.1f KB/s", b / 1024 }'; }
# flat: no window more than FACTOR times the first (a storm grows)
flat() {
  first=$(echo $RATES | awk '{print $1}')
  for r in $RATES; do
    [ $((r - BASE)) -le $(( (first - BASE) * $1 / 10 + 2048 )) ] || fail "bandwidth grew: windows (bytes/s) $RATES"
  done
}

echo
echo "== idle baseline (control traffic: keepalives, gossip, metrics), 20 s"
measure 20 2
BASE=$MEAN
echo "baseline: $(kb $BASE) for all five nodes"

echo
echo "== A. five players on the Friends tab, 1 discovery ping/s each, 60 s"
snap a0
start -rate 1
measure 60 6
stop
snap a1
EXTRA_A=$((MEAN - BASE))
echo "wire per 10 s window (bytes/s, all nodes):$RATES"
echo "discovery costs $(kb $EXTRA_A) for all five nodes together"
flat 15
total_pings=0
for c in $NODES; do eval "pings_$c=$(st $c pings_sent)"; total_pings=$((total_pings + $(eval echo \$pings_$c))); done
printf "%-7s %6s %6s %8s %8s %6s  %s\n" node pings pongs "copies" "received" limit "worlds seen"
for c in $NODES; do
  pings=$(eval echo \$pings_$c)
  tx=$(d tx a1 $c a0); rx=$(d rx a1 $c a0); lim=$(d lim a1 $c a0)
  worlds=$(st $c worlds)
  printf "%-7s %6s %6s %8s %8s %6s  %s\n" $(x $c hostname) $pings "$(st $c pongs)" $tx $rx $lim "$worlds"
  [ "$(st $c servers)" -eq 4 ] || fail "$c sees $(st $c servers) worlds, not 4"
  [ "$tx" -eq $((pings * 4)) ] || fail "$c sent $tx copies for $pings pings to 4 peers"
  [ "$rx" -eq $((total_pings - pings)) ] || fail "$c received $rx copies; the others sent $((total_pings - pings)) pings"
  [ "$lim" -eq 0 ] || fail "$c hit the budget"
  [ "$(st $c pongs)" -ge $((pings * 4 * 9 / 10)) ] || fail "$c got too few pongs"
done
echo "every ping: exactly one copy to each of the 4 other nodes, delivered once; no copy forwarded"
[ $EXTRA_A -lt 51200 ] || fail "discovery took $(kb $EXTRA_A)"

echo
echo "== B. every player joins every world it sees: 20 RakNet connections, 30 s"
start -rate 1 -connect
sleep 30
for c in $NODES; do
  n=$(st $c connected); e=$(st $c echoes)
  echo "$(x $c hostname): connected to $n worlds, $e game messages answered, errors: $(st $c errors)"
  [ "$n" -eq 4 ] || fail "$c joined $n of 4 worlds"
  [ "$e" -ge 40 ] || fail "$c: only $e game messages answered"
done
stop

echo
echo "== C. aggressive clients: 20 discovery pings/s each (80 copies/s wanted per node, budget 50), 30 s"
snap c0
T0=$(date +%s)
start -rate 20
measure 30 3
stop
EL=$(( $(date +%s) - T0 + 1 ))
snap c1
echo "wire per 10 s window (bytes/s, all nodes):$RATES  -> $(kb $((MEAN - BASE))) over baseline"
flat 15
for c in $NODES; do
  tx=$(d tx c1 $c c0); lim=$(d lim c1 $c c0); w=$(st $c servers)
  echo "$(x $c hostname): sent $tx copies in ${EL} s ($((tx / EL))/s), $lim refused by the budget, sees $w worlds"
  [ "$tx" -le $((50 * EL + 50)) ] || fail "$c sent $tx copies in $EL s over a budget of 50/s"
  [ "$lim" -gt 0 ] || fail "$c was never limited (80 copies/s wanted)"
  [ "$w" -eq 4 ] || fail "$c sees $w worlds: rotation did not reach every peer"
done
x p1 webjetctl local status | grep -q multicast_limit || fail "no multicast_limit alarm on p-1"
echo "budget held on every node; every world still discovered; multicast_limit alarm raised"

echo
echo "== D. a naive LAN bridge on every node, rebroadcasting every ping it hears, 30 s"
snap d0
start -rate 1 -relay
measure 30 3
stop
snap d1
echo "wire per 10 s window (bytes/s, all nodes):$RATES  -> $(kb $((MEAN - BASE))) over baseline (phase A: $(kb $EXTRA_A))"
flat 15
for c in $NODES; do
  pings=$(st $c pings_sent); relayed=$(st $c relayed)
  tx=$(d tx d1 $c d0); echoes=$(d echo d1 $c d0)
  echo "$(x $c hostname): $pings pings, bridge rebroadcast $relayed, sent $tx copies, $echoes echoes stopped"
  [ "$tx" -eq $((pings * 4)) ] || fail "$c sent $tx copies: the bridge's rebroadcasts went out"
  [ "$echoes" -eq "$relayed" ] || fail "$c: $relayed rebroadcasts but $echoes echoes stopped"
done
echo "every rebroadcast stopped as an echo at the bridge's own node"

echo
echo "== E. bridges that change each ping they relay (no echo to catch; exponential on a flooding overlay), 30 s"
snap e0
T0=$(date +%s)
start -rate 1 -relay -mutate
measure 30 3
EXTRA_E=$((MEAN - BASE))
for c in $NODES; do x $c pkill -TERM raknet-lan || true; done
sleep 2
EL=$(( $(date +%s) - T0 + 1 ))
snap e1
after0=$(wire); sleep 5; after=$(( ($(wire) - after0) / 5 ))
echo "wire per 10 s window (bytes/s, all nodes):$RATES  -> $(kb $EXTRA_E) over baseline"
flat 20
for c in $NODES; do
  tx=$(d tx e1 $c e0); lim=$(d lim e1 $c e0)
  echo "$(x $c hostname): sent $tx copies in ${EL} s ($((tx / EL))/s), $lim refused by the budget, bridge rebroadcast $(st $c relayed)"
  [ "$tx" -le $((50 * EL + 50)) ] || fail "$c sent $tx copies in $EL s over a budget of 50/s"
done
echo "after the bridges stopped: $(kb $after) (baseline $(kb $BASE))"
[ "$after" -le $((BASE * 2 + 4096)) ] || fail "traffic kept going after the bridges stopped"
# The ceiling for five nodes: 5 × 64 KiB/s of copies (plus framing).
[ $EXTRA_E -lt $((5 * 65536 * 2)) ] || fail "the worst case took $(kb $EXTRA_E)"

echo
echo "== summary"
echo "discovery, 5 players, 1 ping/s:           $(kb $EXTRA_A)"
echo "worst case, 5 mutating bridges (capped):  $(kb $EXTRA_E)"
echo "(the EasyTier storm reported: 1536.0 KB/s)"
echo
echo "RAKNET STORM TEST PASSED"
