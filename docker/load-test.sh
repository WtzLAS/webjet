#!/bin/sh
# Path stability under load (§11.2, §11.4): two data nodes that can only
# reach each other through one of two relays, each on its own shaped access
# link (netem: 15 ms, 20 Mbit/s). A bulk TCP transfer fills the circuit in
# use; it must keep its circuit (no switching to the idle one because the
# loaded one looks slow), its probes must pause while it is busy, and the
# idle circuit must keep being probed.
#
#   ctl-01  controller + relay   on core, net-a, net-b
#   relay-2 relay                on core, net-a, net-b
#   node-a  data                 on net-a only
#   node-b  data                 on net-b only
#
#   docker build --target test -t webjet:test . && docker/load-test.sh
#   SECS=60 docker/load-test.sh        # longer load
#   docker/load-test.sh clean
set -eu
IMG=${IMG:-webjet:test}
SECS=${SECS:-40}
RATE=${RATE:-20mbit}
DELAY=${DELAY:-15ms}
P=wjl
cleanup() {
  docker rm -f $P-ctl $P-r2 $P-a $P-b >/dev/null 2>&1 || true
  docker network rm $P-core $P-na $P-nb >/dev/null 2>&1 || true
}
cleanup
[ "${1:-}" = "clean" ] && exit 0
docker network create --subnet 172.33.0.0/24 $P-core >/dev/null
docker network create --subnet 172.33.1.0/24 $P-na >/dev/null
docker network create --subnet 172.33.2.0/24 $P-nb >/dev/null
x() { c=$1; shift; docker exec $c "$@"; }
bg() { c=$1; shift; docker exec -d $c sh -c "$* > /var/log/webjetd.log 2>&1"; }
start() { # container hostname network [ip]
  docker run -d --name $1 --hostname $2 --network $3 ${4:+--ip $4} --cap-add NET_ADMIN --device /dev/net/tun \
    --sysctl net.ipv4.ip_forward=1 -e RUST_LOG=info -e WEBJET_ROOT_PASSPHRASE=r -e WEBJET_ACCOUNT_PASSPHRASE=a \
    -e WEBJET_KEYS=/root/keys -e WEBJET_CONFIG=/etc/webjet/webjetd.toml $IMG sh -c 'exec sleep infinity' >/dev/null
}
start $P-ctl ctl-01 $P-core 172.33.0.2
start $P-r2 relay-2 $P-core 172.33.0.3
start $P-a node-a $P-na 172.33.1.10
start $P-b node-b $P-nb 172.33.2.10
docker network connect --ip 172.33.1.2 $P-na $P-ctl
docker network connect --ip 172.33.2.2 $P-nb $P-ctl
docker network connect --ip 172.33.1.3 $P-na $P-r2
docker network connect --ip 172.33.2.3 $P-nb $P-r2

conf() { # container public-ip...
  c=$1; shift
  pub=""
  for ip in "$@"; do
    pub="$pub
[[public]]
addr = \"$ip:443\"
transport = \"tls\"
[[public]]
addr = \"$ip:443\"
transport = \"kcp\""
  done
  x $c sh -c "mkdir -p /var/lib/webjet /etc/webjet && cat > /etc/webjet/webjetd.toml <<EOT
data_dir = \"/var/lib/webjet\"
control_socket = \"/run/webjet/control.sock\"
[listen]
tls = \"0.0.0.0:443\"
kcp = \"0.0.0.0:443\"
$pub
[dns]
configure_system = false
EOT"
}
conf $P-ctl 172.33.0.2 172.33.1.2 172.33.2.2
conf $P-r2 172.33.0.3 172.33.1.3 172.33.2.3
conf $P-a 172.33.1.10
conf $P-b 172.33.2.10

# The access links: delay and rate on each data node's only interface.
for c in $P-a $P-b; do
  x $c tc qdisc add dev eth0 root netem delay "$DELAY" rate "$RATE" limit 200
done

echo "== bootstrap on ctl-01"
x $P-ctl sh -c 'cd /root && webjetctl root --dir root init >/dev/null && webjetctl network account keygen --name alice --pub-out alice.pub >/dev/null &&
  webjetctl root --dir root admin sign --name alice --key alice.pub --out alice.account >/dev/null &&
  webjetctl root --dir root genesis --overlay-pool 10.7.0.0/16 --admin alice.account --out genesis.wj >/dev/null &&
  webjetctl local init --genesis genesis.wj >/dev/null'
bg $P-ctl webjetd run
W() { x $P-ctl webjetctl --account alice "$@"; }
i=0; until W network controller list 2>/dev/null | grep -q 'valid_until: [1-9]'; do sleep 0.5; i=$((i+1)); [ $i -lt 60 ] || { echo "controller did not start"; x $P-ctl cat /var/log/webjetd.log; exit 1; }; done
x $P-ctl sh -c 'cd /root && webjetctl network account keygen --name infra --pub-out infra.pub >/dev/null'
W network account create --name infra --key /root/infra.pub
T=$(W network node enroll --owner infra --name ctl-01 --ip 10.7.0.1 --roles data,relay,control --controller tls:172.33.0.2:443 2>/dev/null)
x $P-ctl webjetctl local enroll "$T" >/dev/null
W network controller certify ctl-01 >/dev/null
x $P-ctl sh -c 'cat > /root/network.toml <<EOT
version = 0

[policy]
default = "deny"

[[policy.rule]]
id = "a-to-b"
action = "allow"
src = ["node:node-a"]
dst = ["node:node-b"]
ports = ["icmp", "tcp:9000"]

[[seeds]]
node = "ctl-01"
addrs = ["tls:172.33.0.2:443", "tls:172.33.1.2:443", "tls:172.33.2.2:443"]
EOT'
W network config apply /root/network.toml
enroll() { # container name ip roles controller-ip (on the node's network)
  T=$(W network node enroll --owner infra --name $2 --ip $3 --roles $4 --controller tls:$5:443 2>/dev/null)
  x $1 webjetctl local enroll "$T"
  bg $1 webjetd run
}
enroll $P-r2 relay-2 10.7.0.3 data,relay 172.33.0.2
enroll $P-a node-a 10.7.0.10 data 172.33.1.2
enroll $P-b node-b 10.7.0.11 data 172.33.2.2

# Both relays, a session, and two measured circuits.
echo "== waiting for two circuits node-a -> node-b"
i=0
until [ "$(x $P-a webjetctl --json local sessions 2>/dev/null | python3 -c '
import json, sys
c = json.load(sys.stdin)["circuits"]["local"]
print(sum(1 for x in c if x["peer"] == "node-b" and x["source"] and x["cost"] is not None))' 2>/dev/null)" -ge 2 ] 2>/dev/null; do
  x $P-a ping -c 1 -W 1 10.7.0.11 >/dev/null 2>&1 || true
  i=$((i+1)); [ $i -lt 120 ] || { echo "FAIL: no two measured circuits"; x $P-a webjetctl local sessions; exit 1; }
  sleep 1
done
idle_rtt=$(x $P-a ping -c 10 -i 0.2 -q 10.7.0.11 | awk -F/ '/^rtt/ {print $5}')
echo "idle overlay ping: $idle_rtt ms"

snapshot() {
  x $P-a webjetctl --json local sessions | python3 -c '
import json, sys
d = json.load(sys.stdin)
s = [x for x in d["sessions"] if x["peer"] == "node-b"][0]
cs = sorted((x for x in d["circuits"]["local"] if x["peer"] == "node-b" and x["source"]), key=lambda x: x["label"])
out = {"switches": s["path_switches"], "tx": s["tx_packets"],
       "circuits": [{"via": "+".join(x["hops"]) or "direct", "primary": x["primary"], "cost": x["cost"],
                     "probes": x["probes"], "probe_rtt": round(x["rtt_ms"], 1)} for x in cs]}
print(json.dumps(out))'
}

echo "== bulk transfer node-a -> node-b for $SECS s"
x $P-b sh -c 'nohup nc -lk 9000 >/dev/null 2>&1 &'
sleep 1
before=$(snapshot)
echo "before: $before"
docker exec -d $P-a sh -c "timeout $SECS sh -c 'cat /dev/zero | nc 10.7.0.11 9000' >/dev/null 2>&1"
docker exec -d $P-a sh -c "ping -i 0.5 -w $SECS 10.7.0.11 > /tmp/load-ping.txt 2>&1"
t=0
: > /tmp/$P-snaps.txt
while [ $t -lt "$SECS" ]; do
  sleep 4
  t=$((t + 4))
  s=$(snapshot)
  echo "$s" >> /tmp/$P-snaps.txt
  echo "t=${t}s $s"
done
sleep 2
after=$(snapshot)
load_rtt=$(x $P-a awk -F/ '/^rtt/ {print $5}' /tmp/load-ping.txt)
echo "overlay ping under load: $load_rtt ms (idle $idle_rtt ms)"
echo "after: $after"
python3 - "$before" "$after" /tmp/$P-snaps.txt <<'EOF'
import json, sys
before, after = json.loads(sys.argv[1]), json.loads(sys.argv[2])
snaps = [json.loads(l) for l in open(sys.argv[3]) if l.strip()]
fail = []
moved = after["switches"] - before["switches"]
print(f"path switches during the load: {moved}")
if moved > 1:
    fail.append(f"{moved} path switches under load")
if after["tx"] - before["tx"] < 1000:
    fail.append("the transfer didn't run")
# The primary circuit during the load.
prim = [c for s in snaps for c in s["circuits"] if c["primary"]]
if not prim:
    fail.append("no primary circuit seen")
else:
    via = {c["via"] for c in prim}
    print("primary via:", ", ".join(sorted(via)))
    costs = [c["cost"] for c in prim if c["cost"] is not None]
    if len(costs) < len(prim):
        fail.append("the loaded circuit's cost went infinite")
    elif costs and max(costs) > 3 * min(costs) + 30:
        fail.append(f"the loaded circuit's cost swung from {min(costs):.0f} to {max(costs):.0f}")
    # Probes pause while the circuit is busy; the idle one keeps them.
    def probes(s, primary):
        return sum(c["probes"] for c in s["circuits"] if c["primary"] == primary)
    if len(via) == 1 and len(snaps) >= 3:
        busy = probes(snaps[-1], True) - probes(snaps[0], True)
        idle = probes(snaps[-1], False) - probes(snaps[0], False)
        span = 4 * (len(snaps) - 1)
        print(f"probes over {span} s: loaded circuit {busy}, idle circuit {idle}")
        if busy > span // 4:
            fail.append(f"the busy circuit was probed {busy} times")
        if idle < span // 2:
            fail.append(f"the idle circuit was probed only {idle} times")
if fail:
    print("FAIL: " + "; ".join(fail))
    sys.exit(1)
EOF
echo "LOAD TEST PASSED"
cleanup
