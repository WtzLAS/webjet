#!/bin/sh
# Broadcast and multicast across five Linux containers with real tun
# interfaces (architecture §9.5.1):
#   ctl-01  controller + relay + data (bootstrap)
#   g-1, g-2, g-3  data nodes tagged "game"
#   o-1     data node tagged "office"
# Policy: game nodes reach each other on udp:19132 (Bedrock LAN discovery)
# and udp:19140-19141 (loop tests); everyone reaches everyone on udp:5353.
#
# Checks:
#  1. A Bedrock-style broadcast ping (255.255.255.255:19132) from g-1 reaches
#     g-2 and g-3 once each, not o-1 or ctl-01 (policy), and their unicast
#     pongs come back. The pool broadcast 10.7.255.255 works the same way.
#  2. Multicast follows IGMP membership: 239.1.2.3:5353 reaches g-2 and o-1
#     (joined), not g-3 (listening, not joined); g-1 stops sending g-3 copies.
#  3. Echo guard: two hosts rebroadcasting everything they hear send nothing
#     on (the classic broadcast loop).
#  4. Budget: a flood is held to the sending node's budget, with the
#     multicast_limit alarm; a loop that changes the packet each time (not
#     an echo) dies out once the budget drops a copy.
#  5. multicast_packets_per_sec = 0 on a node: nothing reaches it, and
#     senders stop sending it copies.
# Usage: docker build --target test -t webjet:test . && docker/multicast-test.sh
set -eu
IMG=${IMG:-webjet:test}
P=wjm
NODES="ctl g1 g2 g3 o1"
cleanup() {
  for c in $NODES; do docker rm -f $P-$c >/dev/null 2>&1 || true; done
  docker network rm $P-wan >/dev/null 2>&1 || true
}
cleanup
[ "${1:-}" = "clean" ] && exit 0
[ "${KEEP:-}" = 1 ] || trap cleanup EXIT
docker network create --subnet 172.30.8.0/24 $P-wan >/dev/null
for c in $NODES; do
  case $c in
    ctl) name=ctl-01 ;;
    g*) name="g-${c#g}" ;;
    *) name="o-${c#o}" ;;
  esac
  docker run -d --name $P-$c --hostname $name --network $P-wan --cap-add NET_ADMIN --device /dev/net/tun \
    -e RUST_LOG=info -e WEBJET_ROOT_PASSPHRASE=r -e WEBJET_ACCOUNT_PASSPHRASE=a -e WEBJET_KEYS=/root/keys \
    $IMG /opt/webjet/docker/node.sh $name >/dev/null
done
sleep 1
x() { c=$1; shift; docker exec $P-$c "$@"; }
bg() { c=$1; shift; docker exec -d $P-$c sh -c "$*"; }
fail() { echo "FAIL: $*"; exit 1; }
CTL_IP=$(x ctl hostname -i | awk '{print $1}')

echo "== bootstrap ctl-01 ($CTL_IP) and four nodes"
x ctl sh -c 'cd /root && webjetctl root --dir root init >/dev/null && webjetctl network account keygen --name alice --pub-out alice.pub >/dev/null &&
  webjetctl root --dir root admin sign --name alice --key alice.pub --out alice.account >/dev/null &&
  webjetctl root --dir root genesis --overlay-pool 10.7.0.0/16 --admin alice.account --out genesis.wj >/dev/null &&
  webjetctl local init --genesis genesis.wj >/dev/null'
bg ctl 'webjetd run > /var/log/webjetd.log 2>&1'
W() { x ctl webjetctl --account alice "$@"; }
i=0; until W network controller list 2>/dev/null | grep -q 'valid_until: [1-9]'; do sleep 0.5; i=$((i+1)); [ $i -lt 60 ] || { x ctl cat /var/log/webjetd.log; fail "controller did not start"; }; done
x ctl sh -c 'cd /root && webjetctl network account keygen --name infra --pub-out infra.pub >/dev/null'
W network account create --name infra --key /root/infra.pub >/dev/null
T=$(W network node enroll --owner infra --name ctl-01 --ip 10.7.0.1 --roles data,relay,control --controller tls:$CTL_IP:443 2>/dev/null)
x ctl webjetctl local enroll "$T" >/dev/null
W network controller certify ctl-01 >/dev/null
x ctl sh -c 'cat > /root/network.toml <<EOT
version = 0

[policy]
default = "deny"

[[policy.rule]]
id = "infra"
action = "allow"
src = ["*"]
dst = ["node:ctl-01"]
ports = ["icmp"]

[[policy.rule]]
id = "lan-games"
action = "allow"
src = ["tag:game"]
dst = ["tag:game"]
ports = ["icmp", "udp:19132", "udp:19140-19141"]

[[policy.rule]]
id = "mdns"
action = "allow"
src = ["*"]
dst = ["*"]
ports = ["udp:5353"]

[[seeds]]
node = "ctl-01"
addrs = ["tls:'"$CTL_IP"':443", "kcp:'"$CTL_IP"':443"]
EOT'
W network config apply /root/network.toml >/dev/null
enroll() { # container name ip tags
  T=$(W network node enroll --owner infra --name $2 --ip $3 --tags $4 --roles data --controller tls:$CTL_IP:443) || fail "enroll $2"
  x $1 webjetctl local enroll "$T" >/dev/null
  bg $1 'webjetd run > /var/log/webjetd.log 2>&1'
}
enroll g1 g-1 10.7.0.11 tag:game
enroll g2 g-2 10.7.0.12 tag:game
enroll g3 g-3 10.7.0.13 tag:game
enroll o1 o-1 10.7.0.14 tag:office
# Every node up, and g-1 with a session to each game node.
for c in g1 g2 g3 o1; do
  i=0; until x $c ip -4 addr show 2>/dev/null | grep -q "10\.7\.0\."; do sleep 0.5; i=$((i+1)); [ $i -lt 60 ] || { x $c cat /var/log/webjetd.log; fail "$c has no overlay address"; }; done
done
for ip in 10.7.0.12 10.7.0.13; do
  # A fast "host unreachable" while routes come up: wait between tries.
  i=0; until x g1 ping -c 1 -W 1 $ip >/dev/null 2>&1; do sleep 1; i=$((i+1)); [ $i -lt 30 ] || fail "g-1 can't ping $ip"; done
done
DEV=$(x g1 sh -c "ip -o -4 addr | awk '/10\.7\.0\.11/ {print \$2}'")
echo "tun interface: $DEV"

M=/opt/webjet/docker/mcast.py
# metric <container> <series-prefix> <label match>: the value, or 0.
metric() {
  x $1 webjetctl local metrics | awk -v s="$2{" -v l="$3" 'index($0, s) == 1 && index($0, l) { v = $2 } END { print v + 0 }'
}
tx() { metric $1 webjet_multicast_packets_total 'direction="tx"'; }
rx() { metric $1 webjet_multicast_packets_total 'direction="rx"'; }
limited() { metric $1 webjet_limit_hits_total 'limit="multicast_limited"'; }
echoes() { metric $1 webjet_limit_hits_total 'limit="multicast_echo"'; }
# count <container> <file>: datagrams a listener got.
count() { x $1 sh -c "cut -d' ' -f1 /tmp/$2 2>/dev/null || echo 0"; }
sources() { x $1 sh -c "cut -d' ' -f2- /tmp/$2 2>/dev/null || true"; }
listen() { # container port file [options]
  c=$1 port=$2 f=$3; shift 3
  bg $c "exec python3 $M listen $port /tmp/$f $* > /tmp/$f.log 2>&1"
}
stop() { for c in $NODES; do x $c pkill -f "$M listen" 2>/dev/null || true; done; sleep 0.3; }

echo
echo "== 1. Bedrock LAN discovery: broadcast pings to 255.255.255.255:19132 from g-1"
for c in g2 g3 o1 ctl; do listen $c 19132 bedrock --pong; done
sleep 1
tx0=$(tx g1)
out=$(x g1 python3 $M send 255.255.255.255 19132 10.7.0.11 20 5 --wait 2)
echo "g-1: $out"
for c in g2 g3; do
  n=$(count $c bedrock); echo "$c got $n from $(sources $c bedrock)"
  [ "$n" -eq 20 ] || fail "$c got $n of 20 pings"
  sources $c bedrock | grep -qx "10.7.0.11" || fail "$c: pings not from g-1's address"
done
for c in o1 ctl; do
  n=$(count $c bedrock); [ "$n" -eq 0 ] || fail "$c got $n pings (policy allows only game nodes)"
done
echo "$out" | grep -q "replies=40 " || fail "expected 40 pongs: $out"
echo "$out" | grep -q "from=10.7.0.12,10.7.0.13$" || fail "pongs from the wrong nodes: $out"
sent=$(( $(tx g1) - tx0 ))
echo "copies sent by g-1: $sent"
[ "$sent" -eq 40 ] || fail "g-1 sent $sent copies for 20 pings to 2 peers"
echo "-- the pool's broadcast 10.7.255.255"
stop; for c in g2 g3; do listen $c 19132 pool; done; sleep 1
x g1 python3 $M send 10.7.255.255 19132 10.7.0.11 5 5 --wait 0.5 >/dev/null
sleep 0.5
for c in g2 g3; do n=$(count $c pool); [ "$n" -eq 5 ] || fail "$c got $n of 5 pool broadcasts"; done
echo "pool broadcast: 5/5 on g-2 and g-3"
stop

echo
echo "== 2. multicast follows group membership: 239.1.2.3:5353"
listen g2 5353 grp --group 239.1.2.3 --iface 10.7.0.12
listen o1 5353 grp --group 239.1.2.3 --iface 10.7.0.14
listen g3 5353 grp
# The joins are seen at once (IGMP report) or within 5 s.
sleep 6
x g2 grep -A3 "$DEV" /proc/net/igmp | grep -qi "030201EF" || { x g2 cat /proc/net/igmp; fail "g-2 did not join 239.1.2.3 on $DEV"; }
# Warm-up, as discovery repeats: g-1 looks up o-1's record (it never sent
# o-1 anything), and ctl-01 and o-1 report their groups on first contact.
x g1 python3 $M send 239.1.2.3 5353 10.7.0.11 2 0.5 --wait 1 >/dev/null
tx0=$(tx g1); rx3=$(rx g3); rxc=$(rx ctl); c2=$(count g2 grp); co=$(count o1 grp)
x g1 python3 $M send 239.1.2.3 5353 10.7.0.11 10 5 --wait 0.5 >/dev/null
sleep 0.5
for c in g2 o1; do
  n=$(( $(count $c grp) - $(if [ $c = g2 ]; then echo $c2; else echo $co; fi) ))
  echo "$c (joined) got $n"; [ "$n" -eq 10 ] || fail "$c got $n of 10"
done
n=$(count g3 grp); echo "g-3 (not joined) got $n"; [ "$n" -eq 0 ] || fail "g-3 got $n"
sent=$(( $(tx g1) - tx0 ))
echo "copies sent by g-1: $sent (g-2 and o-1 10 each; none to ctl-01 or g-3, which reported they didn't join)"
[ "$sent" -eq 20 ] || fail "g-1 sent $sent copies"
[ "$(rx g3)" -eq "$rx3" ] || fail "g-3 delivered copies of a group it never joined"
[ "$(rx ctl)" -eq "$rxc" ] || fail "ctl-01 delivered copies of a group it never joined"
stop

echo
echo "== 3. echo guard: g-2 and g-3 rebroadcast everything they hear on 19140"
for c in g2 g3; do
  ip=$(x $c sh -c "ip -o -4 addr show $DEV | awk '{print \$4}' | cut -d/ -f1")
  bg $c "exec python3 - > /tmp/reflect.log 2>&1 <<'EOF'
import socket
r = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
r.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
r.bind(('0.0.0.0', 19140))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
s.bind(('$ip', 0))
n = 0
while True:
    d, a = r.recvfrom(65535)
    # Linux hands a host its own broadcasts too; a repeater skips them.
    if a[0] == '$ip':
        continue
    n += 1
    open('/tmp/reflect.n', 'w').write(str(n))
    s.sendto(d, ('255.255.255.255', 19140))
EOF"
done
listen g1 19140 loop
sleep 1
e2=$(echoes g2); e3=$(echoes g3); tx2=$(tx g2); tx3=$(tx g3)
x g1 python3 $M send 255.255.255.255 19140 10.7.0.11 1 1 --wait 0 >/dev/null
sleep 3
for c in g2 g3; do
  n=$(x $c cat /tmp/reflect.n 2>/dev/null || echo 0)
  echo "$c heard $n, sent on $(( $(tx $c) - $(eval echo \$tx${c#g}) )) copies, echoes stopped: $(( $(echoes $c) - $(eval echo \$e${c#g}) ))"
  [ "$n" -eq 1 ] || fail "$c heard $n datagrams: the loop wasn't stopped"
done
# (g-1's host hears its own broadcast locally; not from a peer.)
sources g1 loop | grep -q "10.7.0.1[23]" && fail "g-1 got its broadcast back from a peer: $(sources g1 loop)"
[ "$(( $(echoes g2) - e2 + $(echoes g3) - e3 ))" -eq 2 ] || fail "expected one echo stopped on each reflector"
for c in g2 g3; do x $c pkill -f "python3 -" || true; done
stop

echo
echo "== 4. budget: 20 copies/s on the game nodes (default 50)"
for n in g-1 g-2 g-3; do W local config --node $n set limits.value.multicast_packets_per_sec 20 >/dev/null; done
sleep 3
listen g2 19132 flood; listen g3 19132 flood
sleep 1
l0=$(limited g1)
# 300 broadcasts in 3 s to 2 peers: 600 copies wanted.
x g1 python3 $M send 255.255.255.255 19132 10.7.0.11 300 100 --wait 0.5 >/dev/null
total=$(( $(count g2 flood) + $(count g3 flood) ))
echo "flood: g-2 and g-3 got $total copies in total (budget: 20 + 20/s x 3 s = 80)"
[ "$total" -ge 60 ] && [ "$total" -le 90 ] || fail "flood delivered $total copies"
[ "$(count g2 flood)" -ge 25 ] && [ "$(count g3 flood)" -ge 25 ] || fail "the budget wasn't shared: $(count g2 flood) / $(count g3 flood)"
[ $(( $(limited g1) - l0 )) -ge 200 ] || fail "multicast_limited did not count the refused datagrams"
x g1 webjetctl local status | grep -q multicast_limit || { x g1 webjetctl local status; fail "no multicast_limit alarm on g-1"; }
echo "multicast_limit alarm raised on g-1"
stop
echo "-- a loop that changes the packet each time (not an echo): cut off by the budget"
for c in g2 g3; do
  ip=$(x $c sh -c "ip -o -4 addr show $DEV | awk '{print \$4}' | cut -d/ -f1")
  bg $c "exec python3 - > /tmp/reflect.log 2>&1 <<'EOF'
import socket
r = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
r.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
r.bind(('0.0.0.0', 19141))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
s.bind(('$ip', 0))
n = 0
while True:
    d, a = r.recvfrom(65535)
    # Linux hands a host its own broadcasts too; a repeater skips them.
    if a[0] == '$ip':
        continue
    n += 1
    open('/tmp/mut.n', 'w').write(str(n))
    s.sendto(d[:64] + str(n).encode(), ('255.255.255.255', 19141))
EOF"
done
listen g1 19141 mut
sleep 1
tx2=$(tx g2); tx3=$(tx g3)
x g1 python3 $M send 255.255.255.255 19141 10.7.0.11 2 10 --wait 0 >/dev/null
sleep 5
s2=$(( $(tx g2) - tx2 )); s3=$(( $(tx g3) - tx3 )); heard=$(count g1 mut)
echo "in ~5 s: g-2 sent $s2 copies, g-3 sent $s3, g-1 heard $heard"
for s in $s2 $s3; do [ "$s" -le 120 ] || fail "a node sent $s copies in 5 s over a budget of 20/s"; done
[ "$s2" -ge 15 ] || fail "the loop did not run (g-2 sent $s2): the test is not testing anything"
# Each reflection needs the copy before it: once the budget drops one, that
# chain ends. The loop dies out while the reflectors still run.
tx2=$(tx g2); tx3=$(tx g3); sleep 3
[ "$(tx g2)" -eq "$tx2" ] && [ "$(tx g3)" -eq "$tx3" ] || fail "the loop is still running: g-2 $tx2 -> $(tx g2), g-3 $tx3 -> $(tx g3)"
echo "the loop died out at the budget, with both reflectors still running"
for c in g2 g3; do x $c pkill -f "python3 -" || true; done
stop

echo
echo "== 5. multicast_packets_per_sec = 0 on g-3"
W local config --node g-3 set limits.value.multicast_packets_per_sec 0 >/dev/null
sleep 4
listen g2 19132 off; listen g3 19132 off
sleep 1
tx0=$(tx g1)
x g1 python3 $M send 255.255.255.255 19132 10.7.0.11 5 5 --wait 0.5 >/dev/null
sleep 0.5
echo "g-2 got $(count g2 off), g-3 got $(count g3 off); g-1 sent $(( $(tx g1) - tx0 )) copies"
[ "$(count g2 off)" -eq 5 ] || fail "g-2 got $(count g2 off) of 5"
[ "$(count g3 off)" -eq 0 ] || fail "g-3 took broadcasts with multicast off"
[ $(( $(tx g1) - tx0 )) -eq 5 ] || fail "g-1 still sends copies to g-3"
stop

echo
echo "== metrics on g-1"
x g1 webjetctl local metrics | grep -E "^webjet_(multicast_packets_total|limit_hits_total\{.*multicast)"
echo
echo "MULTICAST TEST PASSED"
