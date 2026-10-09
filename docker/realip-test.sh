#!/bin/sh
# Reverse proxy, real client addresses turned on later: node-b starts
# without `[proxy] accept_real_ip`, node-a proxies to it (node-b sees
# node-a's overlay address), then node-b's webjetd.toml gets
# `accept_real_ip = true` and its agent restarts. New flows must then reach
# node-b with the client's address, and so must flows that kept running
# across the restart: node-a closes them (a UDP flow moves to the client's
# address with its next datagram, a TCP connection is reset and the client
# reconnects). Turned off again, they go back to node-a's address.
#   ctl-01  controller + relay (bootstrap)
#   node-a  ingress, node-b target
#   cli     a client outside the overlay
# Needs `docker build --target test -t webjet:test .`.
set -eu
IMG=${IMG:-webjet:test}
P=wjr
cleanup() { docker rm -f $P-ctl $P-a $P-b $P-cli $P-srv >/dev/null 2>&1 || true; docker network rm $P-wan $P-lan >/dev/null 2>&1 || true; }
cleanup
[ "${1:-}" = "clean" ] && exit 0
# WAN: the test network (WAN_PREFIX.0.0/24), in case 172.30 is taken.
WAN=${WAN_PREFIX:-172.30}
docker network create --subnet $WAN.0.0/24 $P-wan >/dev/null
run() { # container name
  docker run -d --name $1 --hostname $2 --network $P-wan --cap-add NET_ADMIN --device /dev/net/tun \
    --sysctl net.ipv4.ip_forward=1 -e WAN_PREFIX=$WAN -e RUST_LOG=info -e WEBJET_ROOT_PASSPHRASE=r -e WEBJET_ACCOUNT_PASSPHRASE=a -e WEBJET_KEYS=/root/keys \
    $IMG /opt/webjet/docker/node.sh $2 >/dev/null
}
run $P-ctl ctl-01
run $P-a node-a
run $P-b node-b
docker run -d --name $P-cli --network $P-wan $IMG sh -c 'exec sleep infinity' >/dev/null
# A game server in a container on node-b, its port published with DNAT
# (as `docker run -p 27017:27017/udp`), on a network with MTU 1500 > tun MTU.
docker network create --subnet 10.99.0.0/24 $P-lan >/dev/null
docker network connect --ip 10.99.0.2 $P-lan $P-b
docker run -d --name $P-srv --network $P-lan --ip 10.99.0.3 --cap-add NET_ADMIN $IMG sh -c 'exec sleep infinity' >/dev/null
sleep 1
x() { c=$1; shift; docker exec $c "$@"; }
bg() { c=$1; shift; docker exec -d $c sh -c "$* >> /var/log/webjetd.log 2>&1"; }
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
ports = ["icmp", "tcp:8080", "udp:27015", "tcp:8081", "udp:27016", "udp:27017"]

[[seeds]]
node = "ctl-01"
addrs = ["tls:'"$CTL_IP"':443", "kcp:'"$CTL_IP"':443"]
EOT'
W network config apply /root/network.toml
enroll() { # container name ip
  T=$(W network node enroll --owner infra --name $2 --ip $3 --roles data --controller tls:$CTL_IP:443 2>/dev/null)
  x $1 webjetctl local enroll "$T"
  bg $1 webjetd run
}
enroll $P-a node-a 10.7.0.10
enroll $P-b node-b 10.7.0.11
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
target = ["node:node-b"]
target_port = 27015

# For the client that keeps its flows open across the restarts.
[[proxy]]
name = "web-long"
protocol = "tcp"
listen_port = 8081
target = ["10.7.0.11"]
target_port = 8081

[[proxy]]
name = "game-long"
protocol = "udp"
listen_port = 27016
target = ["node:node-b"]
target_port = 27016

# To the container behind the DNAT on node-b.
[[proxy]]
name = "game-docker"
protocol = "udp"
listen_port = 27017
target = ["node:node-b"]
target_port = 27017
EOT'
W local config --node node-a apply /root/node-a.toml
A_IP=$(x $P-a hostname -i | tr " " "\n" | grep "^$WAN\." | head -1)
CLI_IP=$(x $P-cli hostname -i | awk '{print $1}')
i=0; until x $P-a webjetctl --json local proxy | grep -q '"listening on tcp port 8080'; do sleep 1; i=$((i+1)); [ $i -lt 30 ] || { echo "FAIL: node-a does not listen"; x $P-a webjetctl local proxy; exit 1; }; done
i=0; until x $P-a ping -c 1 -W 1 10.7.0.11 >/dev/null 2>&1; do i=$((i+1)); [ $i -lt 30 ] || { echo "FAIL: node-a can't reach node-b"; exit 1; }; done

diag() {
  echo "-- node-a: webjetctl --json local proxy"; x $P-a webjetctl --json local proxy | head -80 || true
  echo "-- node-b: webjetctl --json local proxy"; x $P-b webjetctl --json local proxy | head -60 || true
  echo "-- node-b: mangle"; x $P-b iptables -t mangle -S || true
  echo "-- node-b: ip rule"; x $P-b ip rule show || true
  echo "-- node-b: table 22346"; x $P-b ip route show table 22346 || true
  echo "-- node-b: log"; x $P-b tail -40 /var/log/webjetd.log || true
}
# Who does node-b see? $1 = test label; prints the source address.
tcp_src() {
  x $P-b sh -c 'rm -f /tmp/web.err; pkill -f "[n]c -lvn 8080" || true'
  docker exec -d $P-b sh -c "echo world | nc -lvn 8080 > /tmp/web.out 2> /tmp/web.err"
  sleep 0.5
  got=$(x $P-cli sh -c "echo hello | nc -w 5 -q 1 $A_IP 8080" || true)
  [ "$got" = "world" ] || { echo "client got '$got'" >&2; }
  x $P-b sh -c "grep -o 'from [^ ]*\|Connection received on [^ ]*' /tmp/web.err | awk '{print \$NF}' | head -1" || true
}
udp_src() { # client source port
  x $P-b sh -c 'pkill -f "[n]c -lunv 27015" || true'
  docker exec -d $P-b sh -c "timeout 4 nc -lunv 27015 > /tmp/udp.out 2> /tmp/udp.err"
  sleep 0.5
  x $P-cli sh -c "echo ping | nc -u -w 1 -p $1 $A_IP 27015" >/dev/null 2>&1 || true
  sleep 1
  x $P-b sh -c "grep -o 'from [^ ]*\|Connection received on [^ ]*' /tmp/udp.err | awk '{print \$NF}' | head -1" || true
}

# A server on node-b (python, outside webjetd: it survives the agent's
# restarts) logging each datagram's and connection's source, and a client
# that keeps one UDP flow (fixed source port) and one TCP connection busy,
# reconnecting when it breaks.
docker exec -i $P-b sh -c 'cat > /tmp/srv.py' <<'EOT'
import socket, threading
log = open("/tmp/peers.log", "a", buffering=1)
def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 27016))
    while True:
        d, a = s.recvfrom(2000)
        log.write("udp %s\n" % a[0])
        s.sendto(d, a)
def echo(c):
    try:
        while True:
            d = c.recv(100)
            if not d:
                break
            c.sendall(d)
    except OSError:
        pass
threading.Thread(target=udp, daemon=True).start()
l = socket.socket()
l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.bind(("0.0.0.0", 8081))
l.listen(16)
while True:
    c, a = l.accept()
    log.write("tcp %s\n" % a[0])
    threading.Thread(target=echo, args=(c,), daemon=True).start()
EOT
docker exec -i $P-cli sh -c 'cat > /tmp/cli.py' <<'EOT'
import socket, sys, time
dst = sys.argv[1]
log = open("/tmp/client.log", "a", buffering=1)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.bind(("0.0.0.0", 40100))
t = None
while True:
    u.sendto(b"ping", (dst, 27016))
    try:
        if t is None:
            t = socket.create_connection((dst, 8081), timeout=3)
            # Long enough to ride out node-b's restart: the connection
            # ends by a reset, not by this timeout.
            t.settimeout(60)
            log.write("connected\n")
        t.sendall(b"x")
        if not t.recv(10):
            raise OSError("closed")
    except OSError as e:
        log.write("tcp error: %r\n" % e)
        if t:
            t.close()
        t = None
    time.sleep(0.5)
EOT
docker exec -d $P-b python3 /tmp/srv.py
sleep 0.5
docker exec -d $P-cli python3 /tmp/cli.py "$A_IP"
# Wait until the long-lived flows' last source on node-b is $1.
long_src() {
  i=0; until [ "$(x $P-b sh -c "grep '^udp' /tmp/peers.log | tail -1")" = "udp $1" ] &&
    [ "$(x $P-b sh -c "grep '^tcp' /tmp/peers.log | tail -1")" = "tcp $1" ]; do
    sleep 1; i=$((i+1))
    [ $i -lt 40 ] || { echo "FAIL: long-lived flows don't come from $1"; x $P-b tail -5 /tmp/peers.log; x $P-cli tail -5 /tmp/client.log; diag; exit 1; }
  done
  echo "long-lived flows from $1 after ${i}s"
}
restart_b() {
  x $P-b pkill -TERM -x webjetd
  i=0; while x $P-b pgrep -x webjetd >/dev/null; do sleep 0.5; i=$((i+1)); [ $i -lt 40 ] || { echo "FAIL: webjetd on node-b did not stop"; exit 1; }; done
  bg $P-b webjetd run
}

echo "== 1. node-b without accept_real_ip: it sees node-a's address"
s=$(tcp_src); echo "tcp source: $s"
case "$s" in 10.7.0.10*) ;; *) echo "FAIL: expected 10.7.0.10, got '$s'"; diag; exit 1;; esac
s=$(udp_src 40001); echo "udp source: $s"
case "$s" in 10.7.0.10*) ;; *) echo "FAIL: expected 10.7.0.10, got '$s'"; diag; exit 1;; esac
long_src 10.7.0.10
# The rules are checked every 10 s; the warning comes once node-a knows node-b's features.
i=0; until x $P-a webjetctl --json local proxy | grep -q "real client addresses"; do sleep 1; i=$((i+1)); [ $i -lt 30 ] || { echo "FAIL: no warning on node-a"; diag; exit 1; }; done

echo "== 2. accept_real_ip = true on node-b, restart its agent"
x $P-b sh -c 'printf "[proxy]\naccept_real_ip = true\n" >> "$WEBJET_CONFIG"'
restart_b
i=0; until x $P-b webjetctl --json local proxy 2>/dev/null | grep -q '"real_ip_ready": true'; do sleep 1; i=$((i+1)); [ $i -lt 30 ] || { echo "FAIL: node-b real_ip_ready stays false"; diag; exit 1; }; done
echo "node-b: real_ip_ready after ${i}s"
i=0; while x $P-a webjetctl --json local proxy | grep -q "real client addresses"; do sleep 1; i=$((i+1)); [ $i -lt 60 ] || { echo "FAIL: node-a still thinks node-b doesn't accept real addresses"; diag; exit 1; }; done
echo "node-a: warning gone after ${i}s"
# node-a's hop to the old node-b process lingers until it times out.
i=0; until x $P-a ping -c 1 -W 1 10.7.0.11 >/dev/null 2>&1; do i=$((i+1)); [ $i -lt 40 ] || { echo "FAIL: node-a can't reach node-b again"; diag; exit 1; }; done
echo "node-a reaches node-b again after ${i} tries"

echo "== 3. new flows keep the client's address ($CLI_IP)"
s=$(tcp_src); echo "tcp source: $s"
case "$s" in "$CLI_IP"*) ;; *) echo "FAIL: tcp: expected $CLI_IP, got '$s'"; diag; exit 1;; esac
s=$(udp_src 40002); echo "udp source: $s"
case "$s" in "$CLI_IP"*) ;; *) echo "FAIL: udp: expected $CLI_IP, got '$s'"; diag; exit 1;; esac

echo "== 4. flows that kept running move to the client's address"
long_src "$CLI_IP"
x $P-cli grep -q "ConnectionResetError" /tmp/client.log || { echo "FAIL: the TCP connection wasn't reset"; x $P-cli cat /tmp/client.log; exit 1; }
x $P-cli grep -c connected /tmp/client.log | sed 's/^/client connections: /'

echo "== 4b. a server in a container (DNAT) answers big replies"
# Replies bigger than the tun MTU make node-b send the container ICMP
# "fragmentation needed"; that must reach it, not go into the tun.
x $P-srv ip route replace default via 10.99.0.2
x $P-b iptables -t nat -A PREROUTING -i webjet0 -p udp --dport 27017 -j DNAT --to-destination 10.99.0.3:27017
docker exec -i $P-srv sh -c 'cat > /tmp/dsrv.py' <<'EOT'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 27017))
log = open("/tmp/dsrv.log", "a", buffering=1)
while True:
    d, a = s.recvfrom(65535)
    n = int(d.split(b" ")[1])
    log.write("%s\n" % a[0])
    s.sendto(d[:16].ljust(n, b"r"), a)
EOT
docker exec -d $P-srv python3 /tmp/dsrv.py
docker exec -i $P-cli sh -c 'cat > /tmp/dcli.py' <<'EOT'
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 27007))
s.settimeout(1)
lost = 0
for rnd in range(5):
    for n in (100, 1200, 1400, 3000):
        s.sendto(b"%05d %d" % (rnd, n), (sys.argv[1], 27017))
        try:
            if len(s.recv(65535)) != n:
                lost += 1
        except socket.timeout:
            lost += 1
# The first big reply may be lost while the server learns the path MTU.
print("lost replies:", lost)
sys.exit(lost > 2)
EOT
sleep 0.5
x $P-cli python3 /tmp/dcli.py "$A_IP" || { echo "FAIL: replies from the container are lost"; x $P-b iptables -t mangle -S; x $P-srv ip route get "$CLI_IP"; diag; exit 1; }
s=$(x $P-srv sort -u /tmp/dsrv.log); echo "container sees: $s"
[ "$s" = "$CLI_IP" ] || { echo "FAIL: the container sees '$s', not $CLI_IP"; exit 1; }

echo "== 5. accept_real_ip off again: back to node-a's address"
x $P-b sh -c 'sed -i "/^\[proxy\]/,\$d" "$WEBJET_CONFIG"'
restart_b
long_src 10.7.0.10
s=$(udp_src 40003); echo "udp source: $s"
case "$s" in 10.7.0.10*) ;; *) echo "FAIL: udp: expected 10.7.0.10, got '$s'"; diag; exit 1;; esac
echo "REALIP TEST PASSED"
