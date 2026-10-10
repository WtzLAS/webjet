#!/bin/sh
# End-to-end test on Linux containers with real tun interfaces:
#   ctl-01  controller + relay (bootstrap)
#   node-a, node-b  data nodes
#   gw      gateway for the LAN 192.168.50.0/24 where lanhost lives
#   cli     a client outside the overlay (plain container on the WAN)
# Checks kernel ping over the overlay, magic DNS, policy, the gateway, and
# reverse proxy ports on node-a (to node-b with the client's real address,
# to node-b by selector without it, UDP datagrams larger than the tun MTU,
# and to lanhost behind the gateway).
set -eu
IMG=${IMG:-webjet:test}
P=wjt
# WAN_PREFIX: the test network's first two octets (WAN_PREFIX.0.0/24), in
# case 172.30 is taken on the host.
WAN=${WAN_PREFIX:-172.30}
cleanup() { docker rm -f $P-ctl $P-a $P-b $P-gw $P-lan $P-cli >/dev/null 2>&1 || true; docker network rm $P-wan $P-lan >/dev/null 2>&1 || true; }
cleanup
[ "${1:-}" = "clean" ] && exit 0
docker network create --subnet $WAN.0.0/24 $P-wan >/dev/null
docker network create --subnet 192.168.50.0/24 $P-lan >/dev/null
run() { # container name gw
  docker run -d --name $1 --hostname $2 --network $P-wan --cap-add NET_ADMIN --device /dev/net/tun \
    --sysctl net.ipv4.ip_forward=1 -e WAN_PREFIX=$WAN -e RUST_LOG=info -e WEBJET_ROOT_PASSPHRASE=r -e WEBJET_ACCOUNT_PASSPHRASE=a -e WEBJET_KEYS=/root/keys \
    $IMG /opt/webjet/docker/node.sh $2 $3 >/dev/null
}
run $P-ctl ctl-01 ""
run $P-a node-a ""
run $P-b node-b ""
docker create --name $P-gw --hostname gw --network $P-wan --cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv4.ip_forward=1 \
  -e WAN_PREFIX=$WAN -e RUST_LOG=info $IMG /opt/webjet/docker/node.sh gw 192.168.50.0/24 >/dev/null
docker network connect --ip 192.168.50.2 $P-lan $P-gw
docker start $P-gw >/dev/null
docker run -d --name $P-lan --network $P-lan --ip 192.168.50.10 --cap-add NET_ADMIN $IMG sh -c 'exec sleep infinity' >/dev/null
docker run -d --name $P-cli --network $P-wan $IMG sh -c 'exec sleep infinity' >/dev/null
sleep 1
x() { c=$1; shift; docker exec $c "$@"; }
bg() { c=$1; shift; docker exec -d $c sh -c "$* > /var/log/webjetd.log 2>&1"; }
CTL_IP=$(x $P-ctl hostname -i | awk '{print $1}')
echo "== bootstrap on ctl-01 ($CTL_IP)"
x $P-ctl sh -c 'cd /root && webjetctl root --dir root init >/dev/null && webjetctl network account keygen --name alice --pub-out alice.pub >/dev/null &&
  webjetctl root --dir root admin sign --name alice --key alice.pub --out alice.account >/dev/null &&
  webjetctl root --dir root genesis --overlay-pool 10.7.0.0/16 --admin alice.account --out genesis.wj >/dev/null &&
  webjetctl local init --genesis genesis.wj >/dev/null'
bg $P-ctl webjetd run
W() { x $P-ctl webjetctl --account alice "$@"; }
i=0; until W network controller list 2>/dev/null | grep -q 'valid_until: [1-9]'; do sleep 0.5; i=$((i+1)); [ $i -lt 60 ] || { echo "controller did not start"; x $P-ctl cat /var/log/webjetd.log; exit 1; }; done
x $P-ctl sh -c 'cd /root && webjetctl network account keygen --name infra --pub-out infra.pub >/dev/null'
W network account create --name infra --key /root/infra.pub
T=$(W network node enroll --owner infra --name ctl-01 --ip 10.7.0.1 --roles data,relay,control --controller tls:$CTL_IP:443 2>/dev/null)
x $P-ctl webjetctl local enroll "$T" >/dev/null
W network controller certify ctl-01 >/dev/null
x $P-ctl sh -c 'cat > /root/network.toml <<EOT
version = 0

[policy]
default = "deny"

[[policy.rule]]
id = "infra"
action = "allow"
src = ["*"]
dst = ["node:ctl-01"]
ports = ["*"]

[[policy.rule]]
id = "a-to-b"
action = "allow"
src = ["node:node-a"]
dst = ["node:node-b"]
ports = ["icmp", "tcp:8080", "udp:5300", "udp:27015"]

[[policy.rule]]
id = "a-to-lan"
action = "allow"
src = ["node:node-a"]
dst = ["cidr:192.168.50.0/24"]
ports = ["icmp", "tcp:9100"]

[[policy.test]]
src = "node:node-b"
dst = "node:node-a"
port = "icmp"
expect = "deny"

[dns]
suffix = "internal"
resolver_ip = ["10.7.255.53"]

[[dns.record]]
name = "web.internal"
type = "CNAME"
value = "node:node-b"

[[seeds]]
node = "ctl-01"
addrs = ["tls:'"$CTL_IP"':443", "kcp:'"$CTL_IP"':443"]
EOT'
W network config apply /root/network.toml
enroll() { # container name ip [routes]
  T=$(W network node enroll --owner infra --name $2 --ip $3 --roles data $4 --controller tls:$CTL_IP:443 2>/dev/null)
  x $1 webjetctl local enroll "$T"
  bg $1 webjetd run
}
enroll $P-a node-a 10.7.0.10 ""
# node-b takes proxied flows with the client's real address.
x $P-b sh -c 'printf "[proxy]\naccept_real_ip = true\n" >> "$WEBJET_CONFIG"'
enroll $P-b node-b 10.7.0.11 ""
enroll $P-gw gw 10.7.0.20 "--route 192.168.50.0/24"
sleep 8
echo "== node-a: peers and routes"
x $P-a webjetctl local peers
x $P-a ip route | grep webjet || true
echo "== kernel ping node-a -> node-b over the overlay"
x $P-a ping -c 3 -W 2 10.7.0.11
echo "== magic DNS"
x $P-a dig +short @10.7.255.53 node-b.internal
x $P-a dig +short @10.7.255.53 web.internal
echo "== policy: node-b -> node-a is denied"
if x $P-b ping -c 2 -W 1 10.7.0.10 >/dev/null 2>&1; then echo "FAIL: deny not enforced"; exit 1; else echo "denied as expected"; fi
echo "== gateway: node-a -> lanhost 192.168.50.10 via gw"
x $P-a ping -c 3 -W 2 192.168.50.10
echo "== sessions on node-a"
x $P-a webjetctl local sessions | grep -E "peer:|established|hops" | head -20

echo "== reverse proxy ports on node-a"
x $P-ctl sh -c 'cat > /root/node-a.toml <<EOT
version = 0

[[proxy]]
name = "web"
protocol = "tcp"
listen_port = 8080
target = ["10.7.0.11"]
target_port = 8080

[[proxy]]
name = "game"
protocol = "udp"
listen_port = 27015
target = ["10.7.0.11"]
target_port = 27015

[[proxy]]
name = "echo"
protocol = "udp"
listen_port = 5353
target = ["node:node-b"]
target_port = 5300
real_ip = false

[[proxy]]
name = "printer"
protocol = "tcp"
listen_port = 9100
target = ["192.168.50.10"]
target_port = 9100
real_ip = false

[[proxy]]
name = "printer-real"
protocol = "tcp"
listen_port = 9101
target = ["192.168.50.10"]
target_port = 9100
EOT'
W local config --node node-a apply /root/node-a.toml
A_IP=$(x $P-a hostname -i | tr " " "\n" | grep -F "$WAN." | head -1)
CLI_IP=$(x $P-cli hostname -i | awk '{print $1}')
i=0; until x $P-a webjetctl --json local proxy | grep -q '"listening on tcp port 8080'; do sleep 1; i=$((i+1)); [ $i -lt 30 ] || { echo "FAIL: node-a does not listen"; x $P-a webjetctl local proxy; exit 1; }; done
x $P-a webjetctl local proxy | sed -n '/^rules:/,/^total:/p'
x $P-a iptables -t nat -S WEBJET-PROXY
# A rule to an address behind a gateway can't keep the client's address.
x $P-a webjetctl --json local proxy | grep -q "real_ip can't work for 192.168.50.10" || { echo "FAIL: no real_ip warning for the gateway target"; exit 1; }
x $P-a webjetctl local status | grep -q proxy_rule || { echo "FAIL: no proxy_rule alarm"; exit 1; }
listen() { # container port reply-text log
  docker exec -d $1 sh -c "echo $3 | nc -lvn $2 > /tmp/$4.out 2> /tmp/$4.err"
  sleep 0.5
}
echo "-- tcp 8080 -> node-b:8080, the client's address kept"
listen $P-b 8080 world web
got=$(x $P-cli sh -c "echo hello | nc -w 10 -q 2 $A_IP 8080" || true)
[ "$got" = "world" ] || { echo "FAIL: client got '$got'"; x $P-a webjetctl local proxy; exit 1; }
x $P-b cat /tmp/web.out | grep -q hello || { echo "FAIL: node-b got nothing"; exit 1; }
x $P-b cat /tmp/web.err
x $P-b grep -q "$CLI_IP" /tmp/web.err || { echo "FAIL: node-b did not see the client's address $CLI_IP"; exit 1; }
echo "-- udp 5353 -> node:node-b port 5300, node-a's address"
docker exec -d $P-b sh -c "nc -lunv 5300 > /tmp/udp.out 2> /tmp/udp.err"
sleep 0.5
x $P-cli sh -c "echo ping | nc -u -w 2 $A_IP 5353" >/dev/null 2>&1 || true
sleep 1
x $P-b cat /tmp/udp.out | grep -q ping || { echo "FAIL: node-b got no datagram"; x $P-b cat /tmp/udp.err; exit 1; }
x $P-b grep -q "10.7.0.10" /tmp/udp.err || { echo "FAIL: the datagram didn't come from node-a's address"; x $P-b cat /tmp/udp.err; exit 1; }
echo "-- udp datagrams over the tun MTU (IP fragments) both ways, with and without the client's address"
x $P-b sh -c 'head -c 1400 /dev/zero | tr "\0" s > /tmp/s1400'
x $P-cli sh -c 'head -c 1400 /dev/zero | tr "\0" c > /tmp/c1400'
for case in "27015 27015" "5353 5300"; do
  set -- $case
  # A first datagram learns the path MTU (the ingress answers "fragmentation
  # needed", and nc quits on the error); then they go in fragments.
  x $P-cli sh -c "cat /tmp/c1400 | timeout 2 nc -u -w 1 $A_IP $1" >/dev/null 2>&1 || true
  docker exec -d $P-b sh -c "timeout 8 nc -lun $2 < /tmp/s1400 > /tmp/frag$2.out 2>/dev/null"
  sleep 0.5
  got=$(x $P-cli sh -c "(cat /tmp/c1400; sleep 3) | timeout 5 nc -u $A_IP $1 | wc -c" || true)
  srv=$(x $P-b sh -c "wc -c < /tmp/frag$2.out")
  [ "$srv" -ge 1400 ] || { echo "FAIL: node-b got $srv of 1400 bytes on port $1"; x $P-a webjetctl local proxy; exit 1; }
  [ "$got" -ge 1400 ] || { echo "FAIL: client got $got of 1400 bytes on port $1"; x $P-b webjetctl local proxy; exit 1; }
  echo "port $1: 1400-byte datagrams through both ways"
done
x $P-b ip rule show priority 22345 | grep -q "sport 27015" || { echo "FAIL: node-b has no reply route for the real-IP UDP flow"; x $P-b ip rule show; exit 1; }
echo "-- tcp 9100 and 9101 -> lanhost behind the gateway"
for port in 9100 9101; do
  listen $P-lan 9100 printed lan$port
  got=$(x $P-cli sh -c "echo job | nc -w 10 -q 2 $A_IP $port" || true)
  [ "$got" = "printed" ] || { echo "FAIL: client got '$got' on $port"; exit 1; }
  x $P-lan grep -q job /tmp/lan$port.out || { echo "FAIL: lanhost got nothing on $port"; exit 1; }
done
echo "-- proxy flows are kept apart from the overlay's"
x $P-a webjetctl local proxy | sed -n '/^flows:/,$p' | head -40
x $P-a webjetctl --json local proxy | grep -q "\"client\": \"$CLI_IP:" || { echo "FAIL: no proxy flow listed"; exit 1; }
if x $P-a webjetctl --json local conntrack | grep -q "$CLI_IP"; then echo "FAIL: a proxy flow is in conntrack"; exit 1; fi
x $P-b webjetctl --json local proxy | grep -q '"side": "target"' || { echo "FAIL: node-b lists no target flow"; exit 1; }
x $P-a webjetctl local metrics | grep '^webjet_proxy_flows_total' || { echo "FAIL: no proxy metrics"; exit 1; }
echo "-- removing the rules removes the capture"
x $P-ctl sh -c 'printf "version = 1\n" > /root/node-a-empty.toml'
W local config --node node-a apply /root/node-a-empty.toml
i=0; while x $P-a iptables -t nat -S PREROUTING | grep -q WEBJET-PROXY; do sleep 1; i=$((i+1)); [ $i -lt 30 ] || { echo "FAIL: capture still in place"; exit 1; }; done
echo "E2E TEST PASSED"
