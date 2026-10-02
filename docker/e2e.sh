#!/bin/sh
# End-to-end test on Linux containers with real tun interfaces:
#   ctl-01  controller + relay (bootstrap)
#   node-a, node-b  data nodes
#   gw      gateway for the LAN 192.168.50.0/24 where lanhost lives
# Checks kernel ping over the overlay, magic DNS, policy, and the gateway.
set -eu
IMG=${IMG:-webjet:test}
P=wjt
cleanup() { docker rm -f $P-ctl $P-a $P-b $P-gw $P-lan >/dev/null 2>&1 || true; docker network rm $P-wan $P-lan >/dev/null 2>&1 || true; }
cleanup
[ "${1:-}" = "clean" ] && exit 0
docker network create --subnet 172.30.0.0/24 $P-wan >/dev/null
docker network create --subnet 192.168.50.0/24 $P-lan >/dev/null
run() { # container name ctl gw
  docker run -d --name $1 --hostname $2 --network $P-wan --cap-add NET_ADMIN --device /dev/net/tun \
    --sysctl net.ipv4.ip_forward=1 -e RUST_LOG=info -e WEBJET_ROOT_PASSPHRASE=r -e WEBJET_ACCOUNT_PASSPHRASE=a -e WEBJET_KEYS=/root/keys \
    $IMG /opt/webjet/docker/node.sh $2 $3 $4 >/dev/null
}
run $P-ctl ctl-01 true ""
run $P-a node-a false ""
run $P-b node-b false ""
docker create --name $P-gw --hostname gw --network $P-wan --cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv4.ip_forward=1 \
  -e RUST_LOG=info $IMG /opt/webjet/docker/node.sh gw false 192.168.50.0/24 >/dev/null
docker network connect --ip 192.168.50.2 $P-lan $P-gw
docker start $P-gw >/dev/null
docker run -d --name $P-lan --network $P-lan --ip 192.168.50.10 --cap-add NET_ADMIN $IMG sh -c 'exec sleep infinity' >/dev/null
sleep 1
x() { c=$1; shift; docker exec $c "$@"; }
bg() { c=$1; shift; docker exec -d $c sh -c "$* > /var/log/webjetd.log 2>&1"; }
CTL_IP=$(x $P-ctl hostname -i | awk '{print $1}')
echo "== bootstrap on ctl-01 ($CTL_IP)"
x $P-ctl sh -c 'cd /root && webjet-root --dir root init >/dev/null && webjetctl account keygen --name alice --pub-out alice.pub >/dev/null &&
  webjet-root --dir root admin sign --name alice --key alice.pub --out alice.account >/dev/null &&
  webjet-root --dir root genesis --overlay-pool 10.7.0.0/16 --admin alice.account --out genesis.wj >/dev/null &&
  webjetd init --genesis genesis.wj >/dev/null'
bg $P-ctl webjetd run
W() { x $P-ctl webjetctl --account alice "$@"; }
i=0; until W controller list 2>/dev/null | grep -q 'valid_until: [1-9]'; do sleep 0.5; i=$((i+1)); [ $i -lt 60 ] || { echo "controller did not start"; x $P-ctl cat /var/log/webjetd.log; exit 1; }; done
x $P-ctl sh -c 'cd /root && webjetctl account keygen --name infra --pub-out infra.pub >/dev/null'
W account create --name infra --key /root/infra.pub
T=$(W node enroll --owner infra --name ctl-01 --ip 10.7.0.1 --roles data,relay --controller tls:$CTL_IP:443 2>/dev/null)
x $P-ctl webjetd enroll "$T" >/dev/null
W controller cert-request --out /root/ctl.req >/dev/null
x $P-ctl webjet-root --dir /root/root controller sign /root/ctl.req --out /root/ctl.cert >/dev/null
W submit /root/ctl.cert >/dev/null 2>&1
x $P-ctl sh -c 'cat > /root/policy.yaml <<EOT
version: 1
default: deny
rules:
  - id: infra
    action: allow
    src: ["*"]
    dst: ["node:ctl-01"]
    ports: ["*"]
  - id: a-to-b
    action: allow
    src: ["node:node-a"]
    dst: ["node:node-b"]
    ports: [icmp, "tcp:8080"]
  - id: a-to-lan
    action: allow
    src: ["node:node-a"]
    dst: ["cidr:192.168.50.0/24"]
    ports: [icmp]
tests:
  - { src: node:node-b, dst: node:node-a, port: icmp, expect: deny }
EOT
cat > /root/dns.yaml <<EOT
version: 1
suffix: internal
resolver_ip: [10.7.255.53]
records:
  - { name: web.internal, type: CNAME, value: node:node-b }
EOT
cat > /root/seeds.yaml <<EOT
version: 1
seeds:
  - node: ctl-01
    addrs: [tls:'"$CTL_IP"':443, kcp:'"$CTL_IP"':443]
EOT'
W policy apply /root/policy.yaml
W dns apply /root/dns.yaml
W seeds apply /root/seeds.yaml
enroll() { # container name ip [routes]
  T=$(W node enroll --owner infra --name $2 --ip $3 --roles data $4 --controller tls:$CTL_IP:443 2>/dev/null)
  x $1 webjetd enroll "$T"
  bg $1 webjetd run
}
enroll $P-a node-a 10.7.0.10 ""
enroll $P-b node-b 10.7.0.11 ""
enroll $P-gw gw 10.7.0.20 "--route 192.168.50.0/24"
sleep 8
echo "== node-a: peers and routes"
x $P-a webjetctl peers
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
x $P-a webjetctl sessions | grep -E "peer:|established|hops" | head -20
echo "E2E TEST PASSED"
