#!/bin/sh
# End-to-end test of webjetup and install.sh before a release is published.
#
# Builds this checkout's Linux release files for the Docker host's
# architecture, serves them from a stand-in for the Forgejo release pages
# (same URLs and API), starts a Webjet controller, and on a systemd machine
# (a container booting systemd) runs what an operator runs:
#
#   1. curl …/install.sh | sh -s -- --enroll <string>   install and enroll
#   2. the agent runs under systemd and reaches the controller (ping)
#   3. webjetup install again: "already installed"; --force reinstalls
#   4. webjetup remove: programs and service gone, identity kept
#   5. webjetup install: back up without enrolling again
#   6. webjetup nuke --dry-run changes nothing; nuke removes everything
#
#   docker/webjetup-test.sh          # run
#   docker/webjetup-test.sh clean    # remove containers, network, images
set -eu
cd "$(dirname "$0")/.."
P=wjup
NET=$P-net
CTL_IP=172.32.0.10
HOST_IP=172.32.0.20
FORGE_IP=172.32.0.5
IMG=webjet:$P
HOSTIMG=$P-systemd
VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
TAG=v$VERSION
REPO=http://forge.test/webj8/webjet

cleanup() {
    docker rm -f "$P-forge" "$P-ctl" "$P-host" >/dev/null 2>&1 || true
    docker volume rm "$P-admin" "$P-www" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
cleanup
if [ "${1:-}" = clean ]; then
    docker rmi "$IMG" "$HOSTIMG" >/dev/null 2>&1 || true
    exit 0
fi

fail() {
    echo "FAIL: $*"
    echo "--- webjetd on the host"
    docker exec "$P-host" journalctl -u webjetd --no-pager -n 30 2>&1 || true
    exit 1
}
on_host() { docker exec "$P-host" sh -c "$*"; }

case "$(docker version -f '{{.Server.Arch}}')" in
    arm64 | aarch64) plat=arm64 target=aarch64-unknown-linux-gnu ;;
    *) plat=amd64 target=x86_64-unknown-linux-gnu ;;
esac

echo "== build $TAG for linux/$plat (release build) and the controller image"
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
docker buildx build -q --platform "linux/$plat" -f docker/release.Dockerfile --output "type=local,dest=$out" . >/dev/null
docker build -q -t "$IMG" . >/dev/null
docker build -q -t "$HOSTIMG" - >/dev/null <<'EOF'
FROM debian:bookworm
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv curl ca-certificates iproute2 dbus \
 && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
EOF

echo "== release pages at $REPO"
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

docker network create --subnet 172.32.0.0/24 "$NET" >/dev/null
docker run -d --name "$P-forge" --network "$NET" --ip "$FORGE_IP" -v "$P-www:/www:ro" -w /www python:3-alpine python -m http.server 80 >/dev/null

echo "== controller"
ADMIN_ENV="-e WEBJET_ROOT_PASSPHRASE=root-pass -e WEBJET_ACCOUNT_PASSPHRASE=acct-pass -e WEBJET_KEYS=/admin/keys"
# shellcheck disable=SC2086
docker run --rm -v "$P-admin:/admin" $ADMIN_ENV "$IMG" sh -ec '
    webjetctl root --dir /admin/root init >/dev/null
    webjetctl account keygen --name alice --pub-out /admin/alice.pub >/dev/null
    webjetctl root --dir /admin/root admin sign --name alice --key /admin/alice.pub --out /admin/alice.account >/dev/null
    webjetctl root --dir /admin/root genesis --overlay-pool 10.7.0.0/16 --admin /admin/alice.account --out /admin/genesis.wj >/dev/null
    webjetctl account keygen --name infra --pub-out /admin/infra.pub >/dev/null'
# shellcheck disable=SC2086
docker run -d --name "$P-ctl" --hostname ctl-01 --network "$NET" --ip "$CTL_IP" \
    --cap-add NET_ADMIN --device /dev/net/tun -v "$P-admin:/admin" $ADMIN_ENV \
    -e WEBJET_GENESIS=/admin/genesis.wj -e WEBJET_CONTROLLER=true \
    -e WEBJET_PUBLIC="tls:$CTL_IP:443,kcp:$CTL_IP:443" "$IMG" >/dev/null
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
docker exec "$P-ctl" sh -c 'printf "version: 1\ndefault: allow\nrules: []\n" > /admin/policy.yaml
printf "version: 1\nseeds:\n  - node: ctl-01\n    addrs: [tls:'"$CTL_IP"':443, kcp:'"$CTL_IP"':443]\n" > /admin/seeds.yaml'
W policy apply /admin/policy.yaml >/dev/null
W seeds apply /admin/seeds.yaml >/dev/null
T=$(W node enroll --owner infra --name laptop --ip 10.7.0.20 --roles data --controller "tls:$CTL_IP:443" 2>/dev/null)

echo "== systemd host"
docker run -d --name "$P-host" --hostname laptop --network "$NET" --ip "$HOST_IP" \
    --add-host "forge.test:$FORGE_IP" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --tmpfs /run --tmpfs /run/lock "$HOSTIMG" >/dev/null
i=0
until on_host 'systemctl is-system-running 2>/dev/null | grep -qE "running|degraded"'; do
    sleep 0.5
    i=$((i + 1))
    [ $i -lt 60 ] || fail "systemd did not boot in the host container"
done

echo "== 1. curl install.sh | sh -s -- --enroll"
on_host "curl -fsSL $REPO/releases/download/$TAG/install.sh | WEBJET_REPO=$REPO sh -s -- --enroll '$T'" || fail "install.sh"

echo "== 2. the agent runs under systemd and reaches the controller"
on_host 'systemctl is-active webjetd' | grep -qx active || fail "webjetd is not active"
on_host 'systemctl show -p MainPID --value webjetd | xargs -I{} stat -c %U /proc/{}' | grep -qx webjet || fail "webjetd does not run as user webjet"
i=0
until on_host 'webjetctl ping ctl-01 -c 1' 2>/dev/null | grep -q "reply from"; do
    sleep 1
    i=$((i + 1))
    [ $i -lt 60 ] || fail "no ping reply from ctl-01"
done
on_host 'webjetup status' | tee /tmp/$P-status.txt
grep -q "service   active" /tmp/$P-status.txt || fail "status: service"
grep -q "node      laptop" /tmp/$P-status.txt || fail "status: node"

echo "== 3. reinstall"
on_host "webjetup --repo $REPO install" | grep -q "already installed" || fail "second install should be a no-op"
on_host "webjetup --repo $REPO install --force" >/dev/null || fail "forced reinstall"
on_host 'systemctl is-active webjetd' | grep -qx active || fail "webjetd not active after reinstall"

echo "== 4. remove keeps the identity"
on_host 'webjetup remove --yes' >/dev/null || fail "remove"
on_host 'test ! -e /usr/local/bin/webjetd && test ! -e /etc/systemd/system/webjetd.service' || fail "programs or unit left after remove"
on_host 'test -f /var/lib/webjet/node.json && test -x /usr/local/bin/webjetup' || fail "remove deleted the identity or webjetup"

echo "== 5. install again: no new enrollment needed"
on_host "webjetup --repo $REPO install" >/dev/null || fail "reinstall after remove"
on_host 'systemctl is-active webjetd' | grep -qx active || fail "webjetd not active after reinstall"
i=0
until on_host 'webjetctl ping ctl-01 -c 1' 2>/dev/null | grep -q "reply from"; do
    sleep 1
    i=$((i + 1))
    [ $i -lt 60 ] || fail "no ping reply after reinstall"
done

echo "== 6. nuke"
before=$(on_host 'ls /usr/local/bin /var/lib/webjet /etc/webjet | md5sum')
on_host 'webjetup nuke --dry-run' | grep -q "would remove /var/lib/webjet" || fail "dry run doesn't list the state"
[ "$before" = "$(on_host 'ls /usr/local/bin /var/lib/webjet /etc/webjet | md5sum')" ] || fail "dry run changed something"
on_host 'webjetup nuke' >/dev/null 2>&1 && fail "nuke without a terminal must ask (and refuse)"
on_host 'webjetup nuke --yes' >/dev/null || fail "nuke"
for p in /usr/local/bin/webjetd /usr/local/bin/webjetctl /usr/local/bin/webjetup /var/lib/webjet /etc/webjet /etc/systemd/system/webjetd.service; do
    on_host "test ! -e $p" || fail "$p still exists after nuke"
done
on_host 'id webjet' >/dev/null 2>&1 && fail "user webjet still exists after nuke"
on_host 'systemctl status webjetd' >/dev/null 2>&1 && fail "webjetd unit still known after nuke"

cleanup
echo "WEBJETUP TEST PASSED"
