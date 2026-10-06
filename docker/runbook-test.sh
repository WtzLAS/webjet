#!/bin/sh
# Runs the operations guide (docs/webjet-operations-guide.md) on systemd
# machines installed with webjetup, with the guide's commands:
#
#   2.1  bootstrap: root keys, admin, genesis, first controller from an empty
#        install, its own enrollment (control role) and admin-signed
#        certificate, the first network configuration
#   1.1  a member account;  2.2  a device for it: policy with tests,
#        enrollment, install with --enroll; the owner renames it, can't
#        retag it
#   2.3  a relay;  2.4  the relay becomes a controller: control role,
#        root-signed certificate (the offline alternative), learner, voter
#   3.1  PSK rotation;  3.5  one network setting;  3.6  one node's setting;
#        3.7  an admin changes a node's tags
#   2.7  re-key a reinstalled node (the owner issues the token)
#   1.4  a member's new key: the old key is refused, the new one works
#   2.6  revoke a device;  4.2  an offline node tombstone
#   1.2  admins: a new person, and a member promoted (from the .pub that
#        1.4 rewrote); submitted without an account key
#   1.3  a member account revoked by an admin; an admin revoked by the root
#        without --revoke-issued (the accounts it made stay)
#   1.4  an admin's new key from the root (--replaces): its controller
#        certificate becomes void and is certified again with the new key
#   2.1  (on ctl-02, before 2.4) the signer service: webjetup install --signer
#   3.8  the controller state exported to an encrypted snapshot
#   4.1  step 3: both controllers stopped, the learner ctl-02 forced to be
#        the only voter of a new cluster, which commits; step 4: then ctl-02
#        lost too, and the snapshot restored on ctl-01, above ctl-02's
#        versions
#   Releases without these commands skip them.
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
# Section 1.4 gives alice a new key in /admin/keys2 at the end.
AKEYS=/admin/keys
admin() { on ctl-01 "webjetctl --keys $AKEYS --account alice $*"; }
ip_of() { case $1 in ctl-01) echo "$SUBNET.10" ;; ctl-02) echo "$SUBNET.11" ;; node-03) echo "$SUBNET.12" ;; esac; }
# The key in an account's .pub file on ctl-01.
pubkey() { on ctl-01 "sed -n 's/.*\"key\": \"\\(.*\\)\".*/\\1/p' $1"; }
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
# [listen] and [[public]] as in sections 2.1 and 2.3.
public() { printf '[listen]\ntls = "0.0.0.0:%s"\nkcp = "0.0.0.0:%s"\n\n[[public]]\naddr = "%s:%s"\ntransport = "tls"\n[[public]]\naddr = "%s:%s"\ntransport = "kcp"\n\n' "$PORT" "$PORT" "$1" "$PORT" "$1" "$PORT"; }
C1=$(ip_of ctl-01)
C2=$(ip_of ctl-02)

echo "== 2.1: bootstrap"
# The offline computer and the admin's machine are directories on ctl-01, so
# install the programs there first (step 4's install, without starting).
install ctl-01 --no-start || fail "install on ctl-01"
# 1-3 [offline] and [admin]
on ctl-01 'mkdir -p /offline /admin
webjetctl root --dir /offline/root init >/dev/null
webjetctl root --dir /offline/root backup --out /offline/root-backup.enc >/dev/null
webjetctl --keys /admin/keys network account keygen --name alice --pub-out /admin/alice.pub >/dev/null
webjetctl root --dir /offline/root admin sign --name alice --key /admin/alice.pub --out /offline/alice.account >/dev/null
webjetctl root --dir /offline/root genesis --overlay-pool 10.7.0.0/16 --admin /offline/alice.account --out /offline/genesis.wj >/dev/null' ||
    fail "offline steps"
# 4 [node] configure, init, start
on ctl-01 "printf '%s\n' '$(public "$C1")' > /etc/webjet/webjetd.toml"
on ctl-01 'webjetctl local init --genesis /offline/genesis.wj >/dev/null && systemctl start webjetd' || fail "init"
wait_for ctl-01 'webjetctl network controller list | grep -q "valid_until: [1-9]"' "first controller did not start"
on ctl-01 'stat -c %U /var/lib/webjet/node.json' | grep -qx webjet || fail "state not owned by the agent's user"
# 5 [admin] infra account, enroll the controller's node
on ctl-01 'webjetctl --keys /admin/keys network account keygen --name infra --pub-out /admin/infra.pub >/dev/null'
admin "network account create --name infra --key /admin/infra.pub" >/dev/null || fail "account create"
T=$(admin "network node enroll --owner infra --name ctl-01 --ip 10.7.0.1 --roles data,relay,control --tags tag:infra --controller tls:$C1:$PORT" 2>/dev/null) || fail "node enroll"
on ctl-01 "webjetctl local enroll '$T'" >/dev/null || fail "webjetctl local enroll on the bootstrap controller"
on ctl-01 'systemctl is-active webjetd' | grep -qx active || fail "agent stopped during the bootstrap enrollment"
# 6 certificate, signed by the admin
admin "network controller certify ctl-01" | grep -q "certified ctl-01" || fail "certify ctl-01"
wait_for ctl-01 'webjetctl network node list | grep ctl-01 | grep -q "data,relay,control "' "ctl-01 doesn't show CONTROL"
# 7 settings
on ctl-01 "cat > /admin/network.toml <<EOT
version = 0

[policy]
default = \"deny\"

[[policy.rule]]
id = \"everyone\"
action = \"allow\"
src = [\"*\"]
dst = [\"*\"]
ports = [\"*\"]

[dns]
suffix = \"internal\"
resolver_ip = [\"10.7.255.53\"]

[[seeds]]
node = \"ctl-01\"
addrs = [\"tls:$C1:$PORT\", \"kcp:$C1:$PORT\"]
EOT"
admin "network psk rotate" >/dev/null || fail "psk rotate"
admin "network config check /admin/network.toml" | grep -q "is valid" || fail "network config check"
admin "network config apply /admin/network.toml" | grep -q "version 1 applied" || fail "network config apply"
admin "network config show" | grep -q '^version = 1$' || fail "network config show"
# A file made from an older version is refused (someone applied meanwhile).
! admin "network config apply /admin/network.toml" >/dev/null 2>&1 || fail "stale network config applied"
on ctl-01 'webjetctl local status' | grep -q "name: ctl-01" || fail "ctl-01 status"

echo "== 1.1, 2.2: a member account and a device for it"
# [person] makes the key on their own machine (/bob on ctl-01 here).
bob() { docker exec -e WEBJET_ACCOUNT_PASSPHRASE=bob-pass "$P-ctl-01" sh -ec "webjetctl --keys /bob/keys --account bob $*"; }
on ctl-01 'mkdir -p /bob' && bob "network account keygen --name bob --pub-out /bob/bob.pub" >/dev/null || fail "bob keygen"
admin "network account create --name bob --key /bob/bob.pub" >/dev/null || fail "account create bob"
admin "network account list" | grep -E "^bob +false +true" >/dev/null || fail "bob not a valid normal account"
admin "network config show" > /dev/null || fail "show"
on ctl-01 "webjetctl --keys /admin/keys --account alice network config show > /admin/network.toml && cat >> /admin/network.toml <<EOT

[[policy.test]]
src = \"tag:laptop\"
dst = \"tag:infra\"
port = \"tcp:443\"
expect = \"allow\"
EOT"
admin "network config check /admin/network.toml" | grep -q "is valid" || fail "policy test check"
admin "network config apply /admin/network.toml" >/dev/null || fail "policy apply"
admin "network config get policy.test.0.expect" | grep -qx allow || fail "policy test not stored"
T=$(admin "network node enroll --owner bob --name node-03 --tags tag:laptop --controller tls:$C1:$PORT" 2>/dev/null) || fail "node-03 enroll"
install node-03 "--enroll '$T'" || fail "install node-03"
wait_for node-03 'webjetctl local ping ctl-01 -c 1 | grep -q "reply from"' "node-03 can't reach ctl-01"
on node-03 'webjetctl local status' | grep -q "name: node-03" || fail "node-03 status"
admin "network node list" | grep -E "^node-03 .* data .*tag:laptop +bob +true" >/dev/null || fail "node-03 not listed with its owner"
bob "network node rename node-03 bob-laptop" >/dev/null || fail "owner rename"
bob "network node rename bob-laptop node-03" >/dev/null || fail "owner rename back"
! bob "network node update node-03 --tags tag:infra" >/dev/null 2>&1 || fail "the owner could change tags"

echo "== 2.3: a relay"
T=$(admin "network node enroll --owner infra --name ctl-02 --roles data,relay --tags tag:relay --controller tls:$C1:$PORT" 2>/dev/null) || fail "relay enroll"
install ctl-02 --no-start || fail "install on ctl-02"
on ctl-02 "printf '%s\n' '$(public "$C2")' > /etc/webjet/webjetd.toml"
on ctl-02 "webjetup enroll '$T'" >/dev/null || fail "relay enroll on host"
wait_for ctl-02 'webjetctl local ping ctl-01 -c 1 | grep -q "reply from"' "relay can't reach ctl-01"
wait_for ctl-01 'webjetctl local peers | grep -q ctl-02' "ctl-01 doesn't list the relay"

if on ctl-02 'webjetup install --help' | grep -q -- --signer; then
    echo "== 2.1: the signer service on ctl-02"
    on ctl-02 "webjetup --repo $REPO install --signer" >/dev/null || fail "webjetup install --signer"
    on ctl-02 'systemctl is-active webjet-signer' | grep -qx active || fail "webjet-signer not active"
    on ctl-02 'systemctl show -p MainPID --value webjet-signer | xargs -I{} stat -c %U /proc/{}' | grep -qx webjet-signer || fail "the signer doesn't run as webjet-signer"
    on ctl-02 'grep -q "^signer_socket = \"/var/run/webjet-signer/signer.sock\"" /etc/webjet/webjetd.toml' || fail "signer_socket not set"
    on ctl-02 'grep -q "^\[\[public\]\]" /etc/webjet/webjetd.toml' || fail "webjetd.toml lost its settings"
    on ctl-02 'test "$(stat -c %a /var/run/webjet-signer/signer.sock)" = 660' || fail "signer socket mode"
    ! on ctl-02 'su -s /bin/sh webjet -c "cat /var/lib/webjet-signer/signing.key"' >/dev/null 2>&1 || fail "the agent's user can read the signing key"
    wait_for ctl-02 'webjetctl local ping ctl-01 -c 1 | grep -q "reply from"' "relay lost ctl-01 after the signer install"
    SIGNER=1
fi

echo "== 2.4: make ctl-02 a controller"
admin "network node update ctl-02 --roles data,relay,control" >/dev/null || fail "grant the control role"
admin "network node list" | grep ctl-02 | grep -q "control(uncertified)" || fail "role not shown as uncertified"
wait_for ctl-02 'webjetctl network controller cert-request --out /tmp/ctl-02.req' "cert-request on ctl-02"
docker cp "$P-ctl-02:/tmp/ctl-02.req" "$out/ctl-02.req" && docker cp "$out/ctl-02.req" "$P-ctl-01:/offline/ctl-02.req"
on ctl-01 'webjetctl root --dir /offline/root controller sign /offline/ctl-02.req --out /offline/ctl-02.cert' | grep -q "key id" || fail "sign ctl-02"
admin "network submit /offline/ctl-02.cert" >/dev/null 2>&1 || fail "submit ctl-02 cert"
# Automatic membership (§7.5): the leader adds the certified controller as
# a learner by itself; with two controllers one voter stays (an odd count).
# (ctl-02 calls itself a learner before it is a member, so ask the leader.)
ctl_voters() { on ctl-01 'webjetctl network controller list' | sed -n '/^  voters:/,/^ \{0,2\}[a-z_]*:/p' | grep -c "^  *- "; }
ctl_learners() { on ctl-01 'webjetctl network controller list' | sed -n '/^  learners:/,/^ \{0,2\}[a-z_]*:/p' | grep -c "^  *- " || true; }
i=0
until [ "$(ctl_learners)" = 1 ]; do
    sleep 1
    i=$((i + 1))
    [ $i -lt 120 ] || fail "ctl-02 not added as a learner automatically"
done
sleep 3
[ "$(ctl_voters)" = 1 ] || fail "two controllers should keep one voter"
# By hand, with automatic membership off.
admin "network config set controllers.auto_membership false" >/dev/null || fail "turn automatic membership off"
admin "network controller promote ctl-02" >/dev/null || fail "promote"
wait_for ctl-01 '[ "$(webjetctl network controller list | sed -n "/^  voters:/,/^ \{0,2\}[a-z_]*:/p" | grep -c "^  *- ")" = 2 ]' "two voters"
admin "network controller demote ctl-02" >/dev/null || fail "demote"
admin "network config unset controllers.auto_membership" >/dev/null || fail "turn automatic membership back on"
admin "network config show" | grep -q "built-in values in force: auto_membership = true" || fail "[controllers] not back to built-in"

echo "== 3.1: rotate the PSK"
before=$(on ctl-02 'webjetctl local status' | sed -n 's/^psk_epoch: //p')
admin "network psk rotate" >/dev/null || fail "psk rotate"
wait_for ctl-02 "webjetctl local status | grep -q '^psk_epoch: $((before + 1))'" "new PSK epoch didn't arrive"

echo "== 3.5, 3.6, 3.7: network setting, node setting, tags"
admin "network config set dns.record '[{name = \"web.internal\", type = \"CNAME\", value = \"node:ctl-01\"}]'" >/dev/null || fail "network config set"
admin "network config get dns.record.0.value" | grep -qx node:ctl-01 || fail "dns record not stored"
admin "local config --node ctl-02 set limits.value.relay_capacity_mbps 1000" >/dev/null || fail "local config set"
admin "local config --node ctl-02 show --effective" | grep -q "relay_capacity_mbps = 1000" || fail "node setting not in effect"
admin "network node update node-03 --tags tag:laptop,tag:dev" >/dev/null || fail "tag change"
admin "network node list" | grep -E "^node-03 .*tag:dev,tag:laptop" >/dev/null || fail "new tags not shown"

echo "== 2.7: re-key a reinstalled node"
old_ip=$(on node-03 'webjetctl local status' | sed -n '/^ips:/{n;s/^- //p;}')
on node-03 'webjetup nuke --yes' >/dev/null || fail "nuke node-03"
T=$(bob "network node rekey node-03 --controller tls:$C1:$PORT" 2>/dev/null) || fail "rekey token from the owner"
install node-03 "--enroll '$T'" || fail "reinstall node-03"
wait_for node-03 'webjetctl local status | grep -q "name: node-03"' "re-keyed node-03 lost its name"
[ "$(on node-03 'webjetctl local status' | sed -n '/^ips:/{n;s/^- //p;}')" = "$old_ip" ] || fail "re-keyed node-03 lost its address"

echo "== 1.4: a member's new key"
# The person keeps the old key aside here, to show it is refused.
on ctl-01 'mkdir -p /bob/old && mv /bob/keys/bob.key /bob/keys/bob.pub /bob/old/ && cp /bob/keys/bob.seq /bob/old/ 2>/dev/null; true'
bob "network account keygen --name bob --pub-out /bob/bob.pub" >/dev/null || fail "bob's new key"
admin "network account rekey bob --key /bob/bob.pub" | grep -q "has a new key" || fail "account rekey"
k=$(pubkey /bob/bob.pub)
wait_for ctl-01 "webjetctl network account list | grep '^bob ' | grep -qF '$k'" "bob's new key not committed"
! docker exec -e WEBJET_ACCOUNT_PASSPHRASE=bob-pass "$P-ctl-01" webjetctl --keys /bob/old --account bob network node rename node-03 bob-laptop >/dev/null 2>&1 || fail "the old key still signs"
bob "network node rename node-03 bob-laptop" >/dev/null 2>&1 || fail "the new key doesn't sign"
bob "network node rename bob-laptop node-03" >/dev/null || fail "rename back"

echo "== 2.6, 4.2: revoke a device; offline tombstone"
admin "network node revoke node-03 --reason lost" >/dev/null || fail "node revoke"
wait_for ctl-02 '! webjetctl network node list | grep -q "^node-03 "' "revocation didn't spread"
id=$(admin "network node show ctl-02" | sed -n 's/^id: //p')
on ctl-01 "webjetctl root --dir /offline/root node revoke --node $id --out /offline/ctl-02.tomb" >/dev/null || fail "offline tombstone"
on ctl-01 'test -s /offline/ctl-02.tomb' || fail "no tombstone file"

echo "== 1.2: add an admin"
# 1 [person] carol's key on her own machine (/carol on ctl-01 here)
carol() { docker exec -e WEBJET_ACCOUNT_PASSPHRASE=carol-pass "$P-ctl-01" sh -ec "webjetctl --keys /carol/keys --account carol $*"; }
on ctl-01 'mkdir -p /carol' && carol "network account keygen --name carol --pub-out /carol/carol.pub" >/dev/null || fail "carol keygen"
# 2 [offline] root-signed admin record
on ctl-01 'webjetctl root --dir /offline/root admin sign --name carol --key /carol/carol.pub --out /offline/carol.account' >/dev/null || fail "root admin sign"
# 3 submitted through another node, without any account key
docker cp "$P-ctl-01:/offline/carol.account" "$out/carol.account" && docker cp "$out/carol.account" "$P-ctl-02:/tmp/carol.account"
on ctl-02 'webjetctl --keys /nonexistent network submit /tmp/carol.account' >/dev/null 2>&1 || fail "submit the admin record"
wait_for ctl-01 'webjetctl --keys /admin/keys --account alice network account list | grep -qE "^carol +true +true"' "carol not a valid admin"
! on ctl-02 'webjetctl --keys /nonexistent network submit /tmp/carol.account' >/dev/null 2>&1 || fail "the same record was accepted twice"
carol "network account keygen --name dave --pub-out /carol/dave.pub" >/dev/null && carol "network account create --name dave --key /carol/dave.pub" >/dev/null || fail "the new admin can't create an account"
# an existing account becomes an admin, from its own .pub (rewritten by
# `account rekey` in 1.4 with the account's ID, so it names bob's account)
on ctl-01 'webjetctl root --dir /offline/root admin sign --name bob --key /bob/bob.pub --out /offline/bob.account' >/dev/null || fail "root admin sign bob"
admin "network submit /offline/bob.account" >/dev/null 2>&1 || fail "submit bob's admin record"
wait_for ctl-01 'webjetctl --keys /admin/keys --account alice network account list | grep -qE "^bob +true +true"' "bob not promoted"
bob "network node update ctl-02 --tags tag:relay,tag:infra" >/dev/null || fail "bob can't act as an admin"

echo "== 1.3: revoke accounts"
# carol made dave; the root revokes carol without --revoke-issued: dave stays.
on ctl-01 'webjetctl root --dir /offline/root admin revoke --key /carol/carol.pub --reason left --out /offline/carol.tomb' >/dev/null || fail "root admin revoke"
admin "network submit /offline/carol.tomb" >/dev/null 2>&1 || fail "submit carol's tombstone"
wait_for ctl-01 '! webjetctl --keys /admin/keys --account alice network account list | grep -q "^carol "' "carol not revoked"
admin "network account list" | grep -E "^dave +false +true" >/dev/null || fail "dave went with carol"
admin "network account revoke dave --reason left" >/dev/null || fail "account revoke"
wait_for ctl-01 '! webjetctl --keys /admin/keys --account alice network account list | grep -q "^dave "' "dave not revoked"

echo "== 1.4: an admin's new key"
on ctl-01 'webjetctl --keys /admin/keys2 network account keygen --name alice --pub-out /admin/alice-new.pub' >/dev/null || fail "alice's new key"
on ctl-01 'webjetctl root --dir /offline/root admin sign --name alice --key /admin/alice-new.pub --replaces /admin/alice.pub --out /offline/alice2.account' | grep -q "new key" || fail "root admin sign --replaces"
on ctl-01 'webjetctl --keys /nonexistent network submit /offline/alice2.account' >/dev/null 2>&1 || fail "submit alice's new key"
AKEYS=/admin/keys2
k=$(pubkey /admin/alice-new.pub)
wait_for ctl-01 "webjetctl network account list | grep '^alice ' | grep -qF '$k'" "alice's new key not committed"
# ctl-01's certificate was signed with alice's old key: void now.
wait_for ctl-01 'webjetctl network node list | grep "^ctl-01 " | grep -q "control(uncertified)"' "ctl-01's certificate still valid"
! on ctl-01 'webjetctl --keys /admin/keys --account alice network node update ctl-02 --tags tag:relay' >/dev/null 2>&1 || fail "alice's old key still signs"
admin "network controller certify ctl-01" | grep -q "certified ctl-01" || fail "certify ctl-01 with the new key"
wait_for ctl-01 'webjetctl network node list | grep "^ctl-01 " | grep -q "data,relay,control "' "ctl-01 not certified again"

if [ -n "${SIGNER:-}" ]; then
    on ctl-02 'test ! -e /var/lib/webjet/signing.key' || fail "ctl-02's agent made its own signing key"
    on ctl-02 'webjetup status' | grep -q "^signer    active" || fail "webjetup status: signer"
fi

if on ctl-01 'webjetctl local controller --help' >/dev/null 2>&1; then
    echo "== 3.8: a snapshot of the controller state"
    admin "network controller snapshot --out /admin/ctl.snap" | grep -q "controller state at index" || fail "snapshot export"
    on ctl-01 'head -c 4 /admin/ctl.snap | grep -q WJE1' || fail "the snapshot file isn't encrypted"

    echo "== 4.1 step 3: the voter is lost; force a new cluster on the learner"
    [ "$(ctl_learners)" = 1 ] || fail "ctl-02 is not a learner"
    v=$(on ctl-01 'webjetctl local status' | sed -n 's/^tree_version: //p')
    ! on ctl-02 'webjetctl local controller force-new-cluster --reason test' >/dev/null 2>&1 || fail "force-new-cluster ran while the agent ran"
    on ctl-01 'systemctl stop webjetd'
    on ctl-02 'systemctl stop webjetd'
    on ctl-02 "webjetctl local controller force-new-cluster --reason 'ctl-01 lost' --min-version $v" | grep -q "only voter of a new cluster" || fail "force-new-cluster"
    on ctl-02 'stat -c %U /var/lib/webjet/raft/log.bin' | grep -qx webjet || fail "Raft log not owned by the agent's user"
    on ctl-02 'systemctl start webjetd'
    wait_for ctl-02 'webjetctl network controller list | grep -q "role: Leader"' "ctl-02 did not become leader"
    docker cp "$P-ctl-01:$AKEYS" "$out/akeys" && docker cp "$out/akeys" "$P-ctl-02:/tmp/akeys"
    on ctl-02 'webjetctl --keys /tmp/akeys --account alice network psk rotate' >/dev/null || fail "the new cluster doesn't commit"
    wait_for ctl-02 "[ \"\$(webjetctl local status | sed -n 's/^tree_version: //p')\" -gt $v ]" "no tree heads above the old versions"

    echo "== 4.1 step 4: no controller survives; restore the snapshot on ctl-01"
    v=$(on ctl-02 'webjetctl local status' | sed -n 's/^tree_version: //p')
    on ctl-02 'systemctl stop webjetd'
    ! on ctl-01 'webjetctl local controller restore --from /admin/ctl.snap --reason test' >/dev/null 2>&1 || fail "restore over controller state without --replace"
    on ctl-01 "webjetctl local controller restore --from /admin/ctl.snap --replace --reason 'all lost' --min-version $v" | grep -q "restored the controller state" || fail "restore"
    on ctl-01 'systemctl start webjetd'
    wait_for ctl-01 'webjetctl network controller list | grep -q "role: Leader"' "restored ctl-01 did not become leader"
    admin "network psk rotate" >/dev/null || fail "the restored cluster doesn't commit"
    wait_for ctl-01 "[ \"\$(webjetctl local status | sed -n 's/^tree_version: //p')\" -gt $v ]" "restored heads not above ctl-02's versions"
    admin "network account list" | grep -qE "^bob +true +true" || fail "the snapshot's accounts are gone"
fi

cleanup
echo "RUNBOOK TEST PASSED"
