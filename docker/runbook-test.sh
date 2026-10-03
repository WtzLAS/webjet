#!/bin/sh
# Runs the operations guide (docs/webjet-operations-guide.md) on systemd
# machines installed with webjetup, with the guide's commands:
#
#   runbook 1   bootstrap: root keys, admin, genesis, first controller from
#               an empty install, its own enrollment and certificate, the
#               first settings
#   runbook 2   a relay
#   runbook 3   the relay becomes a controller: learner, then voter
#   runbook 5   PSK rotation
#   runbook 8   re-key a reinstalled node
#   runbook 7   revoke a device, offline node tombstone
#
# The offline computer and the admin's machine are directories on ctl-01
# (/offline, /admin); the hosts run as root, so `sudo` is left out.
#
#   docker/runbook-test.sh                 # build this checkout's release files
#   RELEASE=v0.2.2 PORT=8443 docker/runbook-test.sh  # a published release (no build)
#   docker/runbook-test.sh clean           # remove containers, network, images
#
# WEBJET_TEST_DNS sets the containers' DNS server, for Docker setups that
# can't resolve the release server.
set -eu
cd "$(dirname "$0")/.."
P=wjrb
NET=$P-net
SUBNET=172.33.0
FORGE_IP=$SUBNET.5
HOSTIMG=$P-systemd
VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
TAG=v$VERSION
REPO=http://forge.test/webj8/webjet
if [ -n "${RELEASE:-}" ]; then
    TAG=$RELEASE
    REPO=${WEBJET_REPO:-https://forgejo.wolf109909.top/webj8/webjet}
fi
HOSTS="ctl-01 ctl-02 node-03"
# The guide's port. PORT=8443 tests a release whose service can't bind
# ports below 1024 (v0.2.2 and earlier).
PORT=${PORT:-443}

cleanup() {
    for h in forge $HOSTS; do docker rm -f "$P-$h" >/dev/null 2>&1 || true; done
    docker volume rm "$P-www" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
cleanup
if [ "${1:-}" = clean ]; then
    docker rmi "$HOSTIMG" >/dev/null 2>&1 || true
    exit 0
fi

fail() {
    echo "FAIL: $*"
    for h in $HOSTS; do
        echo "--- webjetd on $h"
        docker exec "$P-$h" journalctl -u webjetd --no-pager -n 25 2>&1 || true
    done
    exit 1
}
on() { h=$1; shift; docker exec -e WEBJET_ROOT_PASSPHRASE=root-pass -e WEBJET_ACCOUNT_PASSPHRASE=acct-pass -e WEBJET_BACKUP_PASSPHRASE=backup-pass "$P-$h" sh -ec "$*"; }
# [admin] commands: webjetctl with the admin's keys, against ctl-01's agent.
admin() { on ctl-01 "webjetctl --keys /admin/keys --account alice $*"; }
ip_of() { case $1 in ctl-01) echo "$SUBNET.10" ;; ctl-02) echo "$SUBNET.11" ;; node-03) echo "$SUBNET.12" ;; esac; }
wait_for() { # host command what
    i=0
    until on "$1" "$2" >/dev/null 2>&1; do
        sleep 1
        i=$((i + 1))
        [ $i -lt 90 ] || fail "$3"
    done
}

case "$(docker version -f '{{.Server.Arch}}')" in
    arm64 | aarch64) plat=arm64 target=aarch64-unknown-linux-gnu ;;
    *) plat=amd64 target=x86_64-unknown-linux-gnu ;;
esac

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
docker build -q -t "$HOSTIMG" - >/dev/null <<'EOF'
FROM debian:bookworm
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv curl ca-certificates iproute2 dbus \
 && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
EOF
docker network create --subnet "$SUBNET.0/24" "$NET" >/dev/null

if [ -n "${RELEASE:-}" ]; then
    echo "== release $TAG from $REPO"
else
    echo "== build $TAG for linux/$plat"
    docker buildx build -q --platform "linux/$plat" -f docker/release.Dockerfile --output "type=local,dest=$out" . >/dev/null
    www=$out/www
    dl=$www/webj8/webjet/releases/download/$TAG
    api=$www/api/v1/repos/webj8/webjet/releases
    mkdir -p "$dl" "$api/latest" "$api/tags/$TAG"
    stage=$(mktemp -d)
    for b in webjetd webjetctl; do cp "$out/$b" "$stage/"; done
    COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata -czf "$dl/webjet-$TAG-$target.tar.gz" -C "$stage" webjetd webjetctl
    rm -rf "$stage"
    cp "$out/webjetup" "$dl/webjetup-$TAG-$target"
    cp scripts/install.sh "$dl/install.sh"
    (cd "$dl" && for f in *; do shasum -a 256 "$f" > "$f.sha256"; done)
    printf '{"tag_name":"%s","name":"Webjet %s","published_at":"2026-10-04T00:00:00Z","prerelease":false,"draft":false}' "$TAG" "$TAG" > "$api/latest/index.html"
    printf '[{"tag_name":"%s","published_at":"2026-10-04T00:00:00Z","prerelease":false,"draft":false}]' "$TAG" > "$api/index.html"
    cp "$api/latest/index.html" "$api/tags/$TAG/index.html"
    docker volume create "$P-www" >/dev/null
    docker run --rm -v "$P-www:/www" -v "$www:/src:ro" debian:bookworm cp -a /src/. /www/
fi
[ -n "${RELEASE:-}" ] ||
    docker run -d --name "$P-forge" --network "$NET" --ip "$FORGE_IP" -v "$P-www:/www:ro" -w /www python:3-alpine python -m http.server 80 >/dev/null

for h in $HOSTS; do
    docker run -d --name "$P-$h" --hostname "$h" --network "$NET" --ip "$(ip_of "$h")" \
        --add-host "forge.test:$FORGE_IP" ${WEBJET_TEST_DNS:+--dns "$WEBJET_TEST_DNS"} \
        --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        --tmpfs /run --tmpfs /run/lock "$HOSTIMG" >/dev/null
done
for h in $HOSTS; do wait_for "$h" 'systemctl is-system-running | grep -qE "running|degraded"' "systemd did not boot on $h"; done
install() { on "$1" "curl -fsSL $REPO/releases/download/$TAG/install.sh | WEBJET_REPO=$REPO sh -s -- $2" >/dev/null; }
# [listen] and [[public]] as in runbooks 1 and 2.
public() { printf '[listen]\ntls = "0.0.0.0:%s"\nkcp = "0.0.0.0:%s"\n\n[[public]]\naddr = "%s:%s"\ntransport = "tls"\n[[public]]\naddr = "%s:%s"\ntransport = "kcp"\n\n' "$PORT" "$PORT" "$1" "$PORT" "$1" "$PORT"; }
C1=$(ip_of ctl-01)
C2=$(ip_of ctl-02)

echo "== runbook 1: bootstrap"
# The offline computer and the admin's machine are directories on ctl-01, so
# install the programs there first (step 4's install, without starting).
install ctl-01 --no-start || fail "install on ctl-01"
# 1-3 [offline] and [admin]
on ctl-01 'mkdir -p /offline /admin
webjetctl root --dir /offline/root init >/dev/null
webjetctl root --dir /offline/root backup --out /offline/root-backup.enc >/dev/null
webjetctl --keys /admin/keys account keygen --name alice --pub-out /admin/alice.pub >/dev/null
webjetctl root --dir /offline/root admin sign --name alice --key /admin/alice.pub --out /offline/alice.account >/dev/null
webjetctl root --dir /offline/root genesis --overlay-pool 10.7.0.0/16 --admin /offline/alice.account --out /offline/genesis.wj >/dev/null' ||
    fail "offline steps"
# 4 [node] configure, init, start
on ctl-01 "printf '%s\n' '$(public "$C1")' > /etc/webjet/webjetd.toml; printf '[controller]\nenabled = true\n' >> /etc/webjet/webjetd.toml"
on ctl-01 'webjetctl init --genesis /offline/genesis.wj >/dev/null && systemctl start webjetd' || fail "init"
wait_for ctl-01 'webjetctl controller list | grep -q "valid_until: [1-9]"' "first controller did not start"
on ctl-01 'stat -c %U /var/lib/webjet/node.json' | grep -qx webjet || fail "state not owned by the agent's user"
# 5 [admin] infra account, enroll the controller's node
on ctl-01 'webjetctl --keys /admin/keys account keygen --name infra --pub-out /admin/infra.pub >/dev/null'
admin "account create --name infra --key /admin/infra.pub" >/dev/null || fail "account create"
T=$(admin "node enroll --owner infra --name ctl-01 --ip 10.7.0.1 --roles data,relay --tags tag:infra --controller tls:$C1:$PORT" 2>/dev/null) || fail "node enroll"
on ctl-01 "webjetctl enroll '$T'" >/dev/null || fail "webjetctl enroll on the bootstrap controller"
on ctl-01 'systemctl is-active webjetd' | grep -qx active || fail "agent stopped during the bootstrap enrollment"
# 6 certificate
on ctl-01 'webjetctl controller cert-request --out /offline/ctl-01.req >/dev/null
webjetctl root --dir /offline/root controller sign /offline/ctl-01.req --out /offline/ctl-01.cert >/dev/null' || fail "certificate"
admin "submit /offline/ctl-01.cert" >/dev/null 2>&1 || fail "submit certificate"
# 7 settings
on ctl-01 "cat > /admin/policy.yaml <<EOT
version: 1
default: deny
rules:
  - id: everyone
    action: allow
    src: [\"*\"]
    dst: [\"*\"]
    ports: [\"*\"]
EOT
cat > /admin/dns.yaml <<EOT
version: 1
suffix: internal
resolver_ip: [10.7.255.53]
EOT
cat > /admin/seeds.yaml <<EOT
version: 1
seeds:
  - node: ctl-01
    addrs: [tls:$C1:$PORT, kcp:$C1:$PORT]
EOT"
admin "psk rotate" >/dev/null || fail "psk rotate"
for f in dns seeds policy; do admin "$f apply /admin/$f.yaml" >/dev/null || fail "$f apply"; done
on ctl-01 'webjetctl status' | grep -q "name: ctl-01" || fail "ctl-01 status"

echo "== runbook 2: a relay"
T=$(admin "node enroll --owner infra --name ctl-02 --ip 10.7.0.2 --roles data,relay --tags tag:relay --controller tls:$C1:$PORT" 2>/dev/null) || fail "relay enroll"
install ctl-02 --no-start || fail "install on ctl-02"
on ctl-02 "printf '%s\n' '$(public "$C2")' > /etc/webjet/webjetd.toml"
on ctl-02 "webjetup enroll '$T'" >/dev/null || fail "relay enroll on host"
wait_for ctl-02 'webjetctl ping ctl-01 -c 1 | grep -q "reply from"' "relay can't reach ctl-01"
wait_for ctl-01 'webjetctl peers | grep -q ctl-02' "ctl-01 doesn't list the relay"

echo "== runbook 3: make ctl-02 a controller"
on ctl-02 "printf '[controller]\nenabled = true\n\n' >> /etc/webjet/webjetd.toml && systemctl restart webjetd"
wait_for ctl-02 'webjetctl controller cert-request --out /tmp/ctl-02.req' "cert-request on ctl-02"
docker cp "$P-ctl-02:/tmp/ctl-02.req" "$out/ctl-02.req" && docker cp "$out/ctl-02.req" "$P-ctl-01:/offline/ctl-02.req"
on ctl-01 'webjetctl root --dir /offline/root controller sign /offline/ctl-02.req --out /offline/ctl-02.cert' | grep -q "key id" || fail "sign ctl-02"
admin "submit /offline/ctl-02.cert" >/dev/null 2>&1 || fail "submit ctl-02 cert"
admin "controller add-learner ctl-02" >/dev/null || fail "add-learner"
wait_for ctl-02 'webjetctl controller list | grep -q "role: Learner"' "ctl-02 not a learner"
admin "controller promote ctl-02" >/dev/null || fail "promote"
wait_for ctl-01 'webjetctl controller list | grep -A3 "voters:" | grep -c "^  *- " | grep -qx 2' "two voters"

echo "== runbook 5: rotate the PSK"
before=$(on ctl-02 'webjetctl status' | sed -n 's/^psk_epoch: //p')
admin "psk rotate" >/dev/null || fail "psk rotate"
wait_for ctl-02 "webjetctl status | grep -q '^psk_epoch: $((before + 1))'" "new PSK epoch didn't arrive"

echo "== runbook 8: re-key a reinstalled node"
T=$(admin "node enroll --owner infra --name node-03 --roles data --controller tls:$C1:$PORT" 2>/dev/null) || fail "node-03 enroll"
install node-03 "--enroll '$T'" || fail "install node-03"
wait_for node-03 'webjetctl ping ctl-01 -c 1 | grep -q "reply from"' "node-03 can't reach ctl-01"
old_ip=$(on node-03 'webjetctl status' | sed -n '/^ips:/{n;s/^- //p;}')
on node-03 'webjetup nuke --yes' >/dev/null || fail "nuke node-03"
T=$(admin "node rekey node-03 --controller tls:$C1:$PORT" 2>/dev/null) || fail "rekey token"
install node-03 "--enroll '$T'" || fail "reinstall node-03"
wait_for node-03 'webjetctl status | grep -q "name: node-03"' "re-keyed node-03 lost its name"
[ "$(on node-03 'webjetctl status' | sed -n '/^ips:/{n;s/^- //p;}')" = "$old_ip" ] || fail "re-keyed node-03 lost its address"

echo "== runbook 7: revoke a device; offline tombstone"
admin "node revoke node-03 --reason lost" >/dev/null || fail "node revoke"
wait_for ctl-02 '! webjetctl node list | grep -q "^node-03 "' "revocation didn't spread"
id=$(admin "node show ctl-02" | sed -n 's/^id: //p')
on ctl-01 "webjetctl root --dir /offline/root node revoke --node $id --out /offline/ctl-02.tomb" >/dev/null || fail "offline tombstone"
on ctl-01 'test -s /offline/ctl-02.tomb' || fail "no tombstone file"

cleanup
echo "RUNBOOK TEST PASSED"
