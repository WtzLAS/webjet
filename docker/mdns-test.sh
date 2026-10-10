#!/bin/sh
# mDNS / DNS-SD on five nodes with Avahi, the mDNS stack of Linux desktops
# (architecture §9.5.1). Avahi runs on the tun interface only, so every
# mDNS packet a node sees has crossed the overlay; nss-mdns resolves
# "<host>.local" for ordinary programs (getent, ping; Debian's default
# mdns4_minimal answers IPv4 only, so IPv6 names go through avahi-resolve).
#
#   ctl-01 (controller, relay), h-1, h-2, h-3: tagged "home"
#   o-1: tagged "office"
#   Pools 10.7.0.0/16 and fd00:7::/64: mDNS over IPv4 and IPv6.
#   Policy: home nodes reach each other on udp:5353 (mDNS), tcp:8080
#   (the advertised service) and ICMP; o-1 is in no rule.
#
# Phases:
#   A. h-1..3 and o-1 publish "_webjet-demo._tcp" on port 8080. Each home
#      node browses and finds the other two home services, with their
#      overlay addresses (IPv4 and IPv6), resolves "h-N.local" with
#      getent, pings it, and connects to the advertised port. o-1 finds
#      nothing and is found by nobody; it sends and gets no copies.
#   B. Group membership: ctl-01 runs no mDNS stack, hasn't joined
#      224.0.0.251 / ff02::fb, and gets (almost) no copies. Avahi starts:
#      it is found, and finds the others, within seconds.
#   C. h-3's Avahi stops: its goodbye packets remove it from the others.
#   D. 60 s steady state with every node browsing all services:
#      bandwidth stays flat, no budget hit.
# Usage: docker build --target test -t webjet:test . && docker/mdns-test.sh
#   KEEP=1 keeps the containers; `docker/mdns-test.sh clean`.
set -eu
IMG=${IMG:-webjet:mdns}
P=wjd
# WAN_PREFIX: the test network's first two octets (WAN_PREFIX.10.0/24), in
# case 172.30 is taken on the host.
WAN=${WAN_PREFIX:-172.30}
NODES="ctl h1 h2 h3 o1"
cleanup() {
  for c in $NODES; do docker rm -f $P-$c >/dev/null 2>&1 || true; done
  docker network rm $P-wan >/dev/null 2>&1 || true
}
cleanup
[ "${1:-}" = "clean" ] && exit 0
[ "${KEEP:-}" = 1 ] || trap cleanup EXIT

echo "== image $IMG: webjet:test with Avahi, nss-mdns and D-Bus"
docker build -q -t "$IMG" - >/dev/null <<'EOF'
FROM webjet:test
RUN apt-get update && apt-get install -y --no-install-recommends \
      avahi-daemon avahi-utils libnss-mdns dbus \
  && rm -rf /var/lib/apt/lists/*
EOF

docker network create --subnet $WAN.10.0/24 $P-wan >/dev/null
for c in $NODES; do
  case $c in
    ctl) name=ctl-01 ;;
    h*) name="h-${c#h}" ;;
    *) name="o-${c#o}" ;;
  esac
  docker run -d --name $P-$c --hostname $name --network $P-wan --cap-add NET_ADMIN --device /dev/net/tun -e WAN_PREFIX=$WAN \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    -e RUST_LOG=info -e WEBJET_ROOT_PASSPHRASE=r -e WEBJET_ACCOUNT_PASSPHRASE=a -e WEBJET_KEYS=/root/keys \
    $IMG /opt/webjet/docker/node.sh $name >/dev/null
done
sleep 1
x() { c=$1; shift; docker exec $P-$c "$@"; }
bg() { c=$1; shift; docker exec -d $P-$c sh -c "$*"; }
fail() { echo "FAIL: $*"; exit 1; }
CTL_IP=$(x ctl hostname -i | awk '{print $1}')
v4() { case $1 in ctl) echo 10.7.0.1 ;; h*) echo "10.7.0.1${1#h}" ;; *) echo 10.7.0.21 ;; esac; }
v6() { case $1 in ctl) echo fd00:7::1 ;; h*) echo "fd00:7::1${1#h}" ;; *) echo fd00:7::21 ;; esac; }
host() { case $1 in ctl) echo ctl-01 ;; h*) echo "h-${1#h}" ;; *) echo o-1 ;; esac; }

echo "== bootstrap ctl-01 ($CTL_IP) and four nodes"
x ctl sh -c 'cd /root && webjetctl root --dir root init >/dev/null && webjetctl network account keygen --name alice --pub-out alice.pub >/dev/null &&
  webjetctl root --dir root admin sign --name alice --key alice.pub --out alice.account >/dev/null &&
  webjetctl root --dir root genesis --overlay-pool 10.7.0.0/16 --overlay-pool fd00:7::/64 --admin alice.account --out genesis.wj >/dev/null &&
  webjetctl local init --genesis genesis.wj >/dev/null'
bg ctl 'webjetd run > /var/log/webjetd.log 2>&1'
W() { x ctl webjetctl --account alice "$@"; }
i=0; until W network controller list 2>/dev/null | grep -q 'valid_until: [1-9]'; do sleep 0.5; i=$((i+1)); [ $i -lt 60 ] || { x ctl cat /var/log/webjetd.log; fail "controller did not start"; }; done
x ctl sh -c 'cd /root && webjetctl network account keygen --name infra --pub-out infra.pub >/dev/null'
W network account create --name infra --key /root/infra.pub >/dev/null
T=$(W network node enroll --owner infra --name ctl-01 --ip 10.7.0.1 --ip fd00:7::1 --tags tag:home --roles data,relay,control --controller tls:$CTL_IP:443 2>/dev/null)
x ctl webjetctl local enroll "$T" >/dev/null
W network controller certify ctl-01 >/dev/null
x ctl sh -c 'cat > /root/network.toml <<EOT
version = 0

[policy]
default = "deny"

[[policy.rule]]
id = "home"
action = "allow"
src = ["tag:home"]
dst = ["tag:home"]
ports = ["icmp", "udp:5353", "tcp:8080"]

[[seeds]]
node = "ctl-01"
addrs = ["tls:'"$CTL_IP"':443", "kcp:'"$CTL_IP"':443"]
EOT'
W network config apply /root/network.toml >/dev/null
for c in h1 h2 h3 o1; do
  tag=tag:home; [ $c = o1 ] && tag=tag:office
  T=$(W network node enroll --owner infra --name $(host $c) --ip $(v4 $c) --ip $(v6 $c) --tags $tag --roles data --controller tls:$CTL_IP:443) || fail "enroll $c"
  x $c webjetctl local enroll "$T" >/dev/null
  bg $c 'webjetd run > /var/log/webjetd.log 2>&1'
done
for c in h1 h2 h3 o1; do
  i=0; until x $c ip -6 addr show 2>/dev/null | grep -q "fd00:7::"; do sleep 0.5; i=$((i+1)); [ $i -lt 60 ] || { x $c ip addr; x $c cat /var/log/webjetd.log; fail "$c has no overlay addresses"; }; done
done
HOME_NODES="ctl h1 h2 h3"
for c in $HOME_NODES; do
  for d in $HOME_NODES; do
    [ $c = $d ] && continue
    i=0; until x $c ping -c 1 -W 1 "$(v4 $d)" >/dev/null 2>&1; do sleep 1; i=$((i+1)); [ $i -lt 30 ] || fail "$c can't ping $d"; done
  done
done
DEV=$(x h1 sh -c "ip -o -4 addr | awk '/10\.7\.0\.11/ {print \$2}'")
echo "home nodes reach each other; tun interface $DEV:"
x h1 ip addr show "$DEV" | sed 's/^/  /'

# ---------------------------------------------------------------- helpers
metric() { # container series label-match
  x $1 webjetctl local metrics | awk -v s="$2{" -v l="$3" 'index($0, s) == 1 && index($0, l) { v = $2 } END { printf "%d\n", v + 0 }'
}
mtx() { metric $1 webjet_multicast_packets_total 'direction="tx"'; }
mrx() { metric $1 webjet_multicast_packets_total 'direction="rx"'; }
mlimited() { metric $1 webjet_limit_hits_total 'limit="multicast_limited"'; }
wire() { t=0; for c in $NODES; do t=$((t + $(x $c cat /sys/class/net/eth0/statistics/tx_bytes))); done; echo $t; }
kb() { awk -v b="$1" 'BEGIN { printf "%.1f KB/s", b / 1024 }'; }
measure() { # seconds windows -> $RATES, $MEAN
  RATES=""; sum=0; w=$(($1 / $2)); last=$(wire)
  for _ in $(seq $2); do
    sleep $w; now=$(wire); r=$(( (now - last) / w )); last=$now
    RATES="$RATES $r"; sum=$((sum + r))
  done
  MEAN=$((sum / $2))
}
avahi_start() { # container: Avahi on the tun interface only, plus the demo service
  c=$1
  x $c sh -c "cat > /etc/avahi/avahi-daemon.conf <<EOT
[server]
use-ipv4=yes
use-ipv6=yes
allow-interfaces=$DEV
# Linux tun interfaces are point-to-point; Avahi skips those by default.
allow-point-to-point=yes
[wide-area]
enable-wide-area=no
[publish]
publish-workstation=no
[reflector]
enable-reflector=no
EOT
cat > /etc/avahi/services/demo.service <<EOT
<?xml version=\"1.0\" standalone='no'?>
<!DOCTYPE service-group SYSTEM \"avahi-service.dtd\">
<service-group>
  <name>$(host $c) files</name>
  <service><type>_webjet-demo._tcp</type><port>8080</port></service>
</service-group>
EOT
mkdir -p /run/dbus; [ -e /run/dbus/pid ] || dbus-daemon --system --fork
avahi-daemon -D --no-rlimits"
  # The service: answers with the host's name.
  bg $c "while :; do hostname | nc -N -l 8080 >/dev/null 2>&1; done"
}
# browse <container>: resolved demo services as "name address port" lines
# (avahi-browse -p: =;iface;proto;name;type;domain;host;address;port;txt).
browse() {
  x $1 avahi-browse -prt _webjet-demo._tcp 2>/dev/null | awk -F';' '$1 == "=" { gsub(/\\032/, " ", $4); print $4, $8, $9 }' | sort -u
}
# found <container> <other>: does container see other's service, at both
# of its overlay addresses?
found() {
  b=$(browse $1)
  echo "$b" | grep -qx "$(host $2) files $(v4 $2) 8080" && echo "$b" | grep -qx "$(host $2) files $(v6 $2) 8080"
}
wait_found() { # container other seconds
  i=0; until found $1 $2; do sleep 1; i=$((i+1)); [ $i -lt $3 ] || return 1; done
}

echo
echo "== idle baseline, 20 s"
measure 20 2
BASE=$MEAN
echo "baseline: $(kb $BASE) for all five nodes"

echo
echo "== A. h-1, h-2, h-3 and o-1 publish _webjet-demo._tcp"
for c in h1 h2 h3 o1; do eval "tx0_$c=$(mtx $c) rx0_$c=$(mrx $c)"; done
crx0=$(mrx ctl)
for c in h1 h2 h3 o1; do avahi_start $c; done
for c in h1 h2 h3; do
  for d in h1 h2 h3; do
    [ $c = $d ] && continue
    wait_found $c $d 20 || { echo "$(host $c) sees:"; browse $c; fail "$c did not find $d's service"; }
  done
done
for c in h1 h2 h3; do
  echo "$(host $c) browses:"; browse $c | grep -v "^$(host $c) " | sed 's/^/  /'
  browse $c | grep -q "^o-1 " && fail "$c found o-1's service (policy)"
done
o1=$(browse o1 | grep -v "^o-1 " || true)
[ -z "$o1" ] || { echo "$o1"; fail "o-1 found services (policy)"; }
echo "o-1 browses: only its own service"
echo "-- names and connections"
for c in h1 h2 h3; do
  for d in h1 h2 h3; do
    [ $c = $d ] && continue
    a=$(x $c getent ahostsv4 "$(host $d).local" | awk 'NR == 1 {print $1}')
    [ "$a" = "$(v4 $d)" ] || fail "$c: getent $(host $d).local gave '$a'"
    a6=$(x $c avahi-resolve -6 -n "$(host $d).local" | awk '{print $2}')
    [ "$a6" = "$(v6 $d)" ] || fail "$c: IPv6 $(host $d).local gave '$a6'"
    x $c ping -6 -c 1 -W 2 "$a6" >/dev/null || fail "$c can't ping $a6"
    x $c ping -c 1 -W 2 "$(host $d).local" >/dev/null || fail "$c can't ping $(host $d).local"
    got=$(x $c nc -N -w 3 "$(host $d).local" 8080 </dev/null)
    [ "$got" = "$(host $d)" ] || fail "$c: $(host $d).local:8080 answered '$got'"
  done
done
echo "every home node resolves the others' .local names (getent over IPv4 via nss-mdns, Avahi over IPv6), pings them and connects to the advertised port"
# (avahi-resolve exits 0 on a timeout too: look at what it prints.)
r=$(x o1 avahi-resolve -4 -n h-1.local 2>&1 || true)
echo "$r" | grep -q "10\.7\." && fail "o-1 resolved h-1.local (policy): $r"
echo "o-1 can't resolve h-1.local"
for c in h1 h2 h3 o1; do
  echo "$(host $c): $(( $(mtx $c) - $(eval echo \$tx0_$c) )) copies sent, $(( $(mrx $c) - $(eval echo \$rx0_$c) )) delivered"
done
[ "$(mtx o1)" -eq "$tx0_o1" ] || fail "o-1 sent copies: policy lets it reach nobody"
[ "$(mrx o1)" -eq "$rx0_o1" ] || fail "o-1 was delivered copies"

echo
echo "== B. ctl-01 runs no mDNS stack: it hasn't joined 224.0.0.251 / ff02::fb"
x ctl grep -A4 "$DEV" /proc/net/igmp | grep -qi "FB0000E0" && fail "ctl-01 already joined 224.0.0.251"
crx=$(( $(mrx ctl) - crx0 ))
echo "ctl-01 had $crx copies delivered while the others started (should be 0)"
[ "$crx" -eq 0 ] || fail "copies delivered to a host that never joined the group"
echo "-- Avahi starts on ctl-01"
T0=$(date +%s)
avahi_start ctl
for c in h1 h2 h3; do
  wait_found ctl $c 20 || { browse ctl; fail "ctl-01 did not find $c"; }
  wait_found $c ctl 20 || { browse $c; fail "$c did not find ctl-01"; }
done
echo "ctl-01 and the others found each other $(( $(date +%s) - T0 )) s after Avahi started"
x ctl grep -A4 "$DEV" /proc/net/igmp | grep -qi "FB0000E0" || fail "ctl-01 did not join 224.0.0.251"

echo
echo "== C. h-3's Avahi stops: its goodbyes remove it"
x h3 avahi-daemon -k
T0=$(date +%s)
for c in ctl h1 h2; do
  i=0; while browse $c | grep -q "^h-3 "; do sleep 1; i=$((i+1)); [ $i -lt 10 ] || fail "$c still lists h-3"; done
done
echo "h-3 gone from every browser after $(( $(date +%s) - T0 )) s"
avahi_start h3
for c in ctl h1 h2; do wait_found $c h3 20 || fail "$c did not find h-3 again"; done
echo "h-3 back"

echo
echo "== D. steady state: every node browsing all services, 60 s"
for c in $NODES; do
  bg $c "exec avahi-browse -a >/dev/null 2>&1"
  eval "l0_$c=$(mlimited $c) t0_$c=$(mtx $c)"
done
measure 60 6
echo "wire per 10 s window (bytes/s, all nodes):$RATES -> $(kb $((MEAN - BASE))) over baseline"
first=$(echo $RATES | awk '{print $1}')
for r in $RATES; do
  [ $((r - BASE)) -le $(( (first - BASE) * 3 / 2 + 4096 )) ] || fail "bandwidth grew: $RATES"
done
for c in $NODES; do
  echo "$(host $c): $(( $(mtx $c) - $(eval echo \$t0_$c) )) copies in 60 s, budget hits $(( $(mlimited $c) - $(eval echo \$l0_$c) ))"
  [ "$(mlimited $c)" -eq "$(eval echo \$l0_$c)" ] || fail "$c hit the budget"
done
[ $((MEAN - BASE)) -lt 20480 ] || fail "mDNS took $(kb $((MEAN - BASE)))"

echo
echo "== metrics on h-1"
x h1 webjetctl local metrics | grep -E "^webjet_(multicast_packets_total|limit_hits_total\{.*multicast)"
echo
echo "MDNS TEST PASSED"
