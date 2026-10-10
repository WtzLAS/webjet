#!/bin/sh
# Hole punching end to end (architecture §11.7) on Linux containers:
#
#   ctl-01, rly-02   relays on the "internet" ($INET.0/24; INET_PREFIX, default
#                    172.31.0, in case that is taken on the host)
#   nat-a, nat-b     NAT routers between the internet and a private LAN each
#   node-a           data node behind nat-a (10.71.1.0/24), port-restricted
#                    cone NAT (MASQUERADE keeps ports, filters by endpoint)
#   node-b           data node behind nat-b (10.71.2.0/24); MODE=symmetric
#                    makes nat-b a symmetric NAT (random ports per flow) and
#                    checks node-b <-> pub-c instead of node-a <-> node-b
#   pub-c            data node with a public address and no NAT, listening
#                    on nothing (it must still get direct paths)
# node-a and node-b also share a fake VPN subnet 10.99.0.0/24 on interfaces
# named wg0: it must never become their "direct" path.
#
# Checks: node-a <-> node-b and node-a <-> pub-c end up with a direct UDP
# hop that runs through the NAT routers (not the wg0 subnet), the circuit
# in use is direct, and an overlay ping works. Needs the test image:
#   docker build --target test -t webjet:test .
# Usage: docker/nat-test.sh [clean]       MODE=symmetric docker/nat-test.sh
set -eu
IMG=${IMG:-webjet:test}
MODE=${MODE:-cone}
P=wjn
INET=${INET_PREFIX:-172.31.0}
NETS="$P-inet $P-lana $P-lanb $P-vpn"
cleanup() {
  docker rm -f $P-ctl $P-rly $P-nata $P-natb $P-a $P-b $P-c >/dev/null 2>&1 || true
  for n in $NETS; do docker network rm $n >/dev/null 2>&1 || true; done
}
cleanup
[ "${1:-}" = "clean" ] && exit 0
trap 'echo "== logs"; for c in a b c; do echo "-- node-$c"; docker exec $P-$c tail -30 /var/log/webjetd.log 2>/dev/null || true; done' EXIT
docker network create --subnet $INET.0/24 $P-inet >/dev/null
# Not --internal: Docker then drops (bridged) packets leaving the subnet,
# which is all the NAT routers' traffic. The default routes point at them.
docker network create --subnet 10.71.1.0/24 $P-lana >/dev/null
docker network create --subnet 10.71.2.0/24 $P-lanb >/dev/null
docker network create --subnet 10.99.0.0/24 $P-vpn >/dev/null
DNS=${WEBJET_TEST_DNS:+--dns $WEBJET_TEST_DNS}
common="--cap-add NET_ADMIN --device /dev/net/tun -e RUST_LOG=info,webjetd::punch=debug -e WEBJET_ROOT_PASSPHRASE=r -e WEBJET_ACCOUNT_PASSPHRASE=a -e WEBJET_KEYS=/root/keys $DNS"
idle() { docker run -d --name $1 --hostname $2 $3 $common --sysctl net.ipv4.ip_forward=1 $IMG sh -c 'exec sleep infinity' >/dev/null; }
x() { c=$1; shift; docker exec $c "$@"; }
bg() { c=$1; shift; docker exec -d $c sh -c "$* > /var/log/webjetd.log 2>&1"; }

# Relays on the internet.
idle $P-ctl ctl-01 "--network $P-inet --ip $INET.10"
idle $P-rly rly-02 "--network $P-inet --ip $INET.11"
idle $P-c pub-c "--network $P-inet --ip $INET.30"
# NAT routers: WAN on the internet, LAN on the private network.
idle $P-nata nat-a "--network $P-inet --ip $INET.21"
docker network connect --ip 10.71.1.2 $P-lana $P-nata
idle $P-natb nat-b "--network $P-inet --ip $INET.22"
docker network connect --ip 10.71.2.2 $P-lanb $P-natb
# Data nodes behind them, plus the fake VPN between them.
idle $P-a node-a "--network $P-lana --ip 10.71.1.10"
idle $P-b node-b "--network $P-lanb --ip 10.71.2.10"
for c in a b; do
  ip=$([ $c = a ] && echo 10.99.0.10 || echo 10.99.0.20)
  docker network connect --ip $ip $P-vpn $P-$c
  # Name it like a WireGuard interface.
  dev=$(x $P-$c ip -o -4 addr | awk -v p=10.99.0. 'index($4, p) == 1 {print $2}')
  x $P-$c sh -c "ip link set $dev down && ip link set $dev name wg0 && ip link set wg0 up"
done
x $P-a sh -c 'ip route replace default via 10.71.1.2'
x $P-b sh -c 'ip route replace default via 10.71.2.2'
nat() { # router wan-if-ip lan-prefix symmetric?
  wan=$(x $1 ip -o -4 addr | awk -v p="$2" 'index($4, p"/") == 1 {print $2}')
  if [ "$4" = yes ]; then
    x $1 iptables -t nat -A POSTROUTING -s $3 -o $wan -j MASQUERADE --random-fully
  else
    x $1 iptables -t nat -A POSTROUTING -s $3 -o $wan -j MASQUERADE
  fi
  # Like a home router's firewall: no unsolicited inbound traffic, neither
  # to the LAN nor to the router itself. (Dropping in INPUT matters: a
  # packet the router accepts locally leaves a conntrack entry that takes
  # the port its own NAT mapping would need, so it picks another port.)
  x $1 iptables -A FORWARD -i $wan -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  x $1 iptables -A FORWARD -i $wan -j DROP
  x $1 iptables -A INPUT -i $wan -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  x $1 iptables -A INPUT -i $wan -j DROP
}
nat $P-nata $INET.21 10.71.1.0/24 no
SYM=no; [ "$MODE" = symmetric ] && SYM=yes
nat $P-natb $INET.22 10.71.2.0/24 "$SYM"

conf() { # container listen? public-ip
  if [ -n "$3" ]; then
    x $1 sh -c "mkdir -p /etc/webjet /var/lib/webjet && cat > /etc/webjet/webjetd.toml <<EOT
data_dir = \"/var/lib/webjet\"
control_socket = \"/run/webjet/control.sock\"
[listen]
tls = \"0.0.0.0:443\"
kcp = \"0.0.0.0:443\"
[[public]]
addr = \"$3:443\"
transport = \"tls\"
[[public]]
addr = \"$3:443\"
transport = \"kcp\"
[dns]
configure_system = false
EOT"
  else
    x $1 sh -c 'mkdir -p /etc/webjet /var/lib/webjet && cat > /etc/webjet/webjetd.toml <<EOT
data_dir = "/var/lib/webjet"
control_socket = "/run/webjet/control.sock"
[dns]
configure_system = false
EOT'
  fi
}
conf $P-ctl yes $INET.10
conf $P-rly yes $INET.11
conf $P-a "" ""
conf $P-b "" ""
conf $P-c "" ""
for c in ctl rly a b c; do x $P-$c sh -c 'echo "WEBJET_CONFIG=/etc/webjet/webjetd.toml" >> /etc/environment'; done
E="env WEBJET_CONFIG=/etc/webjet/webjetd.toml"

echo "== bootstrap on ctl-01"
x $P-ctl sh -c "cd /root && webjetctl root --dir root init >/dev/null && webjetctl network account keygen --name alice --pub-out alice.pub >/dev/null &&
  webjetctl root --dir root admin sign --name alice --key alice.pub --out alice.account >/dev/null &&
  webjetctl root --dir root genesis --overlay-pool 10.7.0.0/16 --admin alice.account --out genesis.wj >/dev/null &&
  $E webjetctl local init --genesis genesis.wj >/dev/null"
bg $P-ctl $E webjetd run
W() { x $P-ctl $E webjetctl --account alice "$@"; }
i=0; until W --json network controller list 2>/dev/null | grep -q '"valid_until": [1-9]'; do sleep 0.5; i=$((i+1)); [ $i -lt 60 ] || { echo "controller did not start"; x $P-ctl cat /var/log/webjetd.log; exit 1; }; done
x $P-ctl sh -c 'cd /root && webjetctl network account keygen --name infra --pub-out infra.pub >/dev/null'
W network account create --name infra --key /root/infra.pub >/dev/null
T=$(W --json network node enroll --owner infra --name ctl-01 --ip 10.7.0.1 --roles data,relay,control --controller tls:$INET.10:443 | sed -n 's/.*"enroll": "\(.*\)".*/\1/p')
x $P-ctl $E webjetctl local enroll "$T" >/dev/null
W network controller certify ctl-01 >/dev/null
x $P-ctl sh -c 'cat > /root/network.toml <<EOT
version = 0

[policy]
default = "allow"

[[seeds]]
node = "ctl-01"
addrs = ["tls:'"$INET"'.10:443", "kcp:'"$INET"'.10:443"]
EOT'
W network config apply /root/network.toml >/dev/null
enroll() { # container name ip roles
  T=$(W --json network node enroll --owner infra --name $2 --ip $3 --roles $4 --controller tls:$INET.10:443 | sed -n 's/.*"enroll": "\(.*\)".*/\1/p')
  x $1 $E webjetctl local enroll "$T" >/dev/null
  bg $1 $E webjetd run
}
enroll $P-rly rly-02 10.7.0.2 data,relay
sleep 3
# A seed must name an existing node: add rly-02 now.
W network config set seeds "[{node = \"ctl-01\", addrs = [\"tls:$INET.10:443\", \"kcp:$INET.10:443\"]}, {node = \"rly-02\", addrs = [\"tls:$INET.11:443\", \"kcp:$INET.11:443\"]}]" >/dev/null
enroll $P-a node-a 10.7.0.10 data
enroll $P-b node-b 10.7.0.11 data
enroll $P-c pub-c 10.7.0.12 data
sleep 6

echo "== candidates"
for c in a b c; do
  echo "-- node-$c"; x $P-$c $E webjetctl --json local sessions | sed -n '/"punch"/,$p' | grep -E '"mine"|"nat"' -A4 | head -12
done
if x $P-a $E webjetctl --json local sessions | sed -n '/"mine"/,/\]/p' | grep -q '10\.99\.0\.'; then
  echo "FAIL: node-a offers its wg0 address"; exit 1
fi

direct() { # container peer-name: a direct kcp hop to the peer, not via 10.99/
  x $1 $E webjetctl --json local peers | tr -d '\n ' | grep -o "{[^{}]*\"peer\":\"$2\"[^{}]*}" | grep '"transport":"kcp"' | grep -v '10\.99\.0\.' >/dev/null
}
check_pair() { # from-container to-name to-ip
  echo "== $1 -> $2: traffic starts a session, then punching"
  x $1 ping -c 3 -W 2 $3 >/dev/null || true
  i=0
  until direct $1 $2; do
    x $1 ping -c 1 -W 1 $3 >/dev/null 2>&1 || true
    sleep 1; i=$((i+1))
    if [ $i -ge 60 ]; then
      echo "FAIL: no direct hop $1 -> $2"
      x $1 $E webjetctl local peers
      x $1 $E webjetctl --json local sessions | sed -n '/"punch"/,$p'
      exit 1
    fi
  done
  echo "direct hop after ${i}s:"
  x $1 $E webjetctl local peers | grep -E "PEER|$2"
  i=0
  until x $1 $E webjetctl --json local sessions | tr -d '\n ' | grep -o "{[^{}]*\"peer\":\"$2\"[^{}]*}" | grep -q '"direct":true'; do
    x $1 ping -c 1 -W 1 $3 >/dev/null 2>&1 || true
    sleep 1; i=$((i+1)); [ $i -lt 30 ] || { echo "FAIL: no direct circuit $1 -> $2"; x $1 $E webjetctl local sessions; exit 1; }
  done
  x $1 ping -c 3 -W 2 $3
}
check_pair $P-a pub-c 10.7.0.12
if [ "$MODE" = symmetric ]; then
  # A symmetric NAT (random port per flow) behind a filtering NAT can't be
  # punched without a birthday attack; toward a node without NAT it works
  # through the peer-reflexive candidate.
  check_pair $P-b pub-c 10.7.0.12
else
  check_pair $P-a node-b 10.7.0.11
fi
echo "== loopback: node-a pings its own overlay address"
x $P-a ping -c 2 -W 1 10.7.0.10
x $P-a $E webjetctl local ping node-a -c 2
trap - EXIT
echo "NAT TEST PASSED ($MODE)"
