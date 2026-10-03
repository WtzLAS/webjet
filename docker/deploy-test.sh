#!/bin/sh
# Deployment test for the container image (docs/docker.md), using only what
# an operator would: the default image, its entrypoint and WEBJET_*
# variables. It
#   1. creates the root key, an admin account and the genesis in a volume,
#   2. starts the first controller with WEBJET_GENESIS and bootstraps it
#      (runbook 1) through `docker exec`,
#   3. starts a data node with WEBJET_ENROLL and waits for it to be healthy,
#   4. pings across the overlay,
#   5. restarts the node (state survives, no second enrollment),
#   6. stops it (clean shutdown on SIGTERM),
#   7. checks the error for an unenrolled container.
#
#   docker/deploy-test.sh          # build the image and run
#   docker/deploy-test.sh clean    # remove containers, volumes, network
set -eu
cd "$(dirname "$0")/.."
IMG=${IMG:-webjet:deploy-test}
P=wjd
NET=$P-net
CTL_IP=172.31.0.10
A_IP=172.31.0.11

cleanup() {
    docker rm -f "$P-ctl" "$P-a" "$P-bad" >/dev/null 2>&1 || true
    docker volume rm "$P-admin" "$P-ctl-state" "$P-a-state" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
cleanup
[ "${1:-}" = clean ] && exit 0

fail() {
    echo "FAIL: $*"
    for c in "$P-ctl" "$P-a"; do
        echo "--- logs $c"
        docker logs --tail 40 "$c" 2>&1 || true
    done
    exit 1
}

wait_healthy() { # container seconds
    i=0
    while [ $i -lt "$2" ]; do
        s=$(docker inspect -f '{{.State.Health.Status}}' "$1" 2>/dev/null || echo missing)
        [ "$s" = healthy ] && return 0
        [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ] || fail "$1 is not running"
        sleep 1
        i=$((i + 1))
    done
    fail "$1 not healthy after $2 s (status: $s)"
}

echo "== build $IMG"
docker build -q -t "$IMG" . >/dev/null

docker network create --subnet 172.31.0.0/24 "$NET" >/dev/null
ADMIN_ENV="-e WEBJET_ROOT_PASSPHRASE=root-pass -e WEBJET_ACCOUNT_PASSPHRASE=acct-pass -e WEBJET_KEYS=/admin/keys"

echo "== root key, admin account and genesis (offline steps)"
# shellcheck disable=SC2086
docker run --rm -v "$P-admin:/admin" $ADMIN_ENV "$IMG" sh -ec '
    webjetctl root --dir /admin/root init >/dev/null
    webjetctl account keygen --name alice --pub-out /admin/alice.pub >/dev/null
    webjetctl root --dir /admin/root admin sign --name alice --key /admin/alice.pub --out /admin/alice.account >/dev/null
    webjetctl root --dir /admin/root genesis --overlay-pool 10.7.0.0/16 --admin /admin/alice.account --out /admin/genesis.wj >/dev/null
    webjetctl account keygen --name infra --pub-out /admin/infra.pub >/dev/null'

echo "== first controller (WEBJET_GENESIS)"
# shellcheck disable=SC2086
docker run -d --name "$P-ctl" --hostname ctl-01 --network "$NET" --ip "$CTL_IP" \
    --cap-add NET_ADMIN --device /dev/net/tun \
    -v "$P-ctl-state:/var/lib/webjet" -v "$P-admin:/admin" $ADMIN_ENV \
    -e WEBJET_GENESIS=/admin/genesis.wj -e WEBJET_CONTROLLER=true \
    -e WEBJET_PUBLIC="tls:$CTL_IP:443,kcp:$CTL_IP:443" \
    "$IMG" >/dev/null
W() { docker exec "$P-ctl" webjetctl --account alice "$@"; }
i=0
until W controller list 2>/dev/null | grep -q 'valid_until: [1-9]'; do
    sleep 0.5
    i=$((i + 1))
    [ $i -lt 60 ] || fail "controller did not start"
done
W account create --name infra --key /admin/infra.pub >/dev/null
T=$(W node enroll --owner infra --name ctl-01 --ip 10.7.0.1 --roles data,relay --controller "tls:$CTL_IP:443" 2>/dev/null)
docker exec "$P-ctl" webjetctl enroll "$T" >/dev/null
W controller cert-request --out /admin/ctl.req >/dev/null
docker exec -e WEBJET_ROOT_PASSPHRASE=root-pass "$P-ctl" webjetctl root --dir /admin/root controller sign /admin/ctl.req --out /admin/ctl.cert >/dev/null
W submit /admin/ctl.cert >/dev/null 2>&1
docker exec "$P-ctl" sh -c 'cat > /admin/policy.yaml <<EOT
version: 1
default: deny
rules:
  - id: everyone
    action: allow
    src: ["*"]
    dst: ["*"]
    ports: ["*"]
EOT
cat > /admin/seeds.yaml <<EOT
version: 1
seeds:
  - node: ctl-01
    addrs: [tls:'"$CTL_IP"':443, kcp:'"$CTL_IP"':443]
EOT'
W policy apply /admin/policy.yaml >/dev/null
W seeds apply /admin/seeds.yaml >/dev/null
wait_healthy "$P-ctl" 60
echo "controller healthy"

echo "== data node (WEBJET_ENROLL)"
T=$(W node enroll --owner infra --name node-a --ip 10.7.0.10 --roles data --controller "tls:$CTL_IP:443" 2>/dev/null)
docker run -d --name "$P-a" --hostname node-a --network "$NET" --ip "$A_IP" \
    --cap-add NET_ADMIN --device /dev/net/tun \
    -v "$P-a-state:/var/lib/webjet" -e WEBJET_ENROLL="$T" \
    "$IMG" >/dev/null
wait_healthy "$P-a" 90
echo "node-a healthy"
docker exec "$P-a" ip -o addr show | grep -q "10.7.0.10" || fail "node-a has no overlay address on its tun interface"

echo "== ping node-a -> ctl-01 over the overlay"
docker exec "$P-a" webjetctl ping ctl-01 -c 3 | tee /tmp/$P-ping.txt
grep -q "reply from" /tmp/$P-ping.txt || fail "no ping reply"

echo "== restart keeps the node's state"
docker restart "$P-a" >/dev/null
wait_healthy "$P-a" 90
[ "$(docker logs "$P-a" 2>&1 | grep -c 'enrolling this node')" = 1 ] || fail "node-a enrolled again after a restart"
docker exec "$P-a" webjetctl ping ctl-01 -c 1 | grep -q "reply from" || fail "no ping reply after restart"
echo "restart ok"

echo "== clean stop on SIGTERM"
docker stop -t 20 "$P-a" >/dev/null
code=$(docker inspect -f '{{.State.ExitCode}}' "$P-a")
[ "$code" = 0 ] || fail "exit code $code after docker stop"
docker logs "$P-a" 2>&1 | grep -q "shutting down" || fail "no orderly shutdown"
echo "stopped with exit code 0"

echo "== unenrolled container explains itself"
if docker run --name "$P-bad" -e WEBJET_TUN=false "$IMG" >/tmp/$P-bad.txt 2>&1; then
    fail "an unenrolled container should not start"
fi
grep -q "WEBJET_ENROLL" /tmp/$P-bad.txt || fail "unhelpful error: $(cat /tmp/$P-bad.txt)"
grep "error" /tmp/$P-bad.txt

cleanup
echo "DEPLOY TEST PASSED"
