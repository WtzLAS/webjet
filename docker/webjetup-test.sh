#!/bin/sh
# End-to-end test of webjetup and install.sh before a release is published.
#
# Builds this checkout's Linux release files for the Docker host's
# architecture, serves them from a stand-in for the Forgejo release pages
# (same URLs and API), starts a Webjet controller, and on a systemd machine
# (a container booting systemd) runs what an operator runs:
#
#   1. curl …/install.sh | sh -s -- --enroll <string>   install and enroll
#   2. the agent runs under systemd and reaches the controller (ping);
#      an ordinary user can use webjetctl
#   3. webjetup install again: "already installed"; --force reinstalls
#   4. webjetup remove: programs and service gone, identity kept
#   5. webjetup install: back up without enrolling again
#   6. remote upgrades (§19.8) from the controller with webjetctl network
#      node upgrade: to a newer release (a second build of this checkout
#      with the patch version raised); a "release" whose agent reports the
#      wrong version is rolled back; nothing older is sent; opted out
#      (--no-remote-upgrade) it is refused
#   7. webjetup nuke --dry-run changes nothing; nuke removes everything
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
# Two more "releases" for the remote upgrade: a real newer build, and one
# whose files are this version's (its agent reports the wrong version).
NEXT=$(echo "$VERSION" | awk -F. '{printf "%d.%d.%d", $1, $2, $3 + 1}')
BAD=$(echo "$VERSION" | awk -F. '{printf "%d.%d.%d", $1, $2, $3 + 2}')
# A plain-http test server: the containers set WEBJET_ALLOW_HTTP=1.
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
echo "== build v$NEXT (this checkout, version raised) for the remote upgrade"
next_src=$(mktemp -d)
tar --exclude ./target --exclude ./target-linux --exclude ./.git --exclude ./.pi --exclude ./dist -cf - . | tar -xf - -C "$next_src"
perl -pi -e 's/^version = "\Q'"$VERSION"'\E"$/version = "'"$NEXT"'"/' "$next_src/Cargo.toml"
perl -0pi -e 's/(name = "webjet[^"]*"\nversion = )"\Q'"$VERSION"'\E"/$1"'"$NEXT"'"/g' "$next_src/Cargo.lock"
mkdir -p "$out/next"
docker buildx build -q --platform "linux/$plat" -f docker/release.Dockerfile --output "type=local,dest=$out/next" "$next_src" >/dev/null
rm -rf "$next_src"
"$out/next/webjetd" --version 2>/dev/null | grep -q "$NEXT" || [ "$(uname -s)" != Linux ] || fail "the v$NEXT build reports another version"
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
api=$www/api/v1/repos/webj8/webjet/releases
publish() { # tag directory-with-binaries
    dl=$www/webj8/webjet/releases/download/$1
    mkdir -p "$dl" "$api/tags/$1"
    stage=$(mktemp -d)
    for b in webjetd webjetctl; do cp "$2/$b" "$stage/"; done
    COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata -czf "$dl/webjet-$1-$target.tar.gz" -C "$stage" webjetd webjetctl
    rm -rf "$stage"
    cp "$2/webjetup" "$dl/webjetup-$1-$target"
    cp scripts/install.sh "$dl/install.sh"
    (cd "$dl" && for f in *; do shasum -a 256 "$f" > "$f.sha256"; done)
    printf '{"tag_name":"%s","name":"Webjet %s","published_at":"2026-10-04T00:00:00Z","prerelease":false,"draft":false}' "$1" "$1" > "$api/tags/$1/index.html"
}
publish "$TAG" "$out"
publish "v$NEXT" "$out/next"
publish "v$BAD" "$out"
# "latest" stays $TAG: install.sh installs it.
mkdir -p "$api/latest"
cp "$api/tags/$TAG/index.html" "$api/latest/index.html"
printf '[{"tag_name":"%s","published_at":"2026-10-04T00:00:00Z","prerelease":false,"draft":false}]' "$TAG" > "$api/index.html"
docker volume create "$P-www" >/dev/null
docker run --rm -v "$P-www:/www" -v "$www:/src:ro" debian:bookworm cp -a /src/. /www/

docker network create --subnet 172.32.0.0/24 "$NET" >/dev/null
docker run -d --name "$P-forge" --network "$NET" --ip "$FORGE_IP" -v "$P-www:/www:ro" -w /www python:3-alpine python -m http.server 80 >/dev/null

echo "== controller"
ADMIN_ENV="-e WEBJET_ALLOW_HTTP=1 -e WEBJET_ROOT_PASSPHRASE=root-pass -e WEBJET_ACCOUNT_PASSPHRASE=acct-pass -e WEBJET_KEYS=/admin/keys"
# shellcheck disable=SC2086
docker run --rm -v "$P-admin:/admin" $ADMIN_ENV "$IMG" sh -ec '
    webjetctl root --dir /admin/root init >/dev/null
    webjetctl network account keygen --name alice --pub-out /admin/alice.pub >/dev/null
    webjetctl root --dir /admin/root admin sign --name alice --key /admin/alice.pub --out /admin/alice.account >/dev/null
    webjetctl root --dir /admin/root genesis --overlay-pool 10.7.0.0/16 --admin /admin/alice.account --out /admin/genesis.wj >/dev/null
    webjetctl network account keygen --name infra --pub-out /admin/infra.pub >/dev/null'
# shellcheck disable=SC2086
docker run -d --name "$P-ctl" --hostname ctl-01 --network "$NET" --ip "$CTL_IP" \
    --add-host "forge.test:$FORGE_IP" --cap-add NET_ADMIN --device /dev/net/tun -v "$P-admin:/admin" $ADMIN_ENV \
    -e WEBJET_GENESIS=/admin/genesis.wj \
    -e WEBJET_PUBLIC="tls:$CTL_IP:443,kcp:$CTL_IP:443" "$IMG" >/dev/null
W() { docker exec "$P-ctl" webjetctl --account alice "$@"; }
i=0
until W network controller list 2>/dev/null | grep -q 'valid_until: [1-9]'; do
    sleep 0.5
    i=$((i + 1))
    [ $i -lt 60 ] || fail "controller did not start"
done
W network account create --name infra --key /admin/infra.pub >/dev/null
T=$(W network node enroll --owner infra --name ctl-01 --ip 10.7.0.1 --roles data,relay,control --controller "tls:$CTL_IP:443" 2>/dev/null)
docker exec "$P-ctl" webjetctl local enroll "$T" >/dev/null
W network controller cert-request --out /admin/ctl.req >/dev/null
docker exec -e WEBJET_ROOT_PASSPHRASE=root-pass "$P-ctl" webjetctl root --dir /admin/root controller sign /admin/ctl.req --out /admin/ctl.cert >/dev/null
W network submit /admin/ctl.cert >/dev/null 2>&1
W network config set policy.default allow >/dev/null
W network config set seeds '[{node = "ctl-01", addrs = ["tls:'"$CTL_IP"':443", "kcp:'"$CTL_IP"':443"]}]' >/dev/null
T=$(W network node enroll --owner infra --name laptop --ip 10.7.0.20 --roles data --controller "tls:$CTL_IP:443" 2>/dev/null)

echo "== systemd host"
docker run -d --name "$P-host" --hostname laptop --network "$NET" --ip "$HOST_IP" \
    --add-host "forge.test:$FORGE_IP" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -e WEBJET_ALLOW_HTTP=1 --tmpfs /run --tmpfs /run/lock "$HOSTIMG" >/dev/null
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
until on_host 'webjetctl local ping ctl-01 -c 1' 2>/dev/null | grep -q "reply from"; do
    sleep 1
    i=$((i + 1))
    [ $i -lt 60 ] || fail "no ping reply from ctl-01"
done
# The control socket is open to every local user (no sudo for webjetctl).
on_host 'useradd -m wjuser 2>/dev/null; su wjuser -c "webjetctl local status"' | grep -q "^name: laptop" ||
    fail "an unprivileged user can't use the control socket"
on_host 'webjetup status' | tee /tmp/$P-status.txt
grep -q "service   active" /tmp/$P-status.txt || fail "status: service"
grep -q "node      laptop" /tmp/$P-status.txt || fail "status: node"
grep -q "remote    on" /tmp/$P-status.txt || fail "status: remote upgrades should be on by default"
on_host 'systemctl is-active webjet-upgrade.path' | grep -qx active || fail "the upgrade helper's path unit is not active"
on_host 'stat -c %U /var/lib/webjet-upgrade/queue; stat -c %U /var/lib/webjet-upgrade' | tr '\n' ' ' | grep -qx "webjet root " ||
    fail "the queue must be the agent's and the rest of the spool root's"
on_host 'grep -q "\"node_id\"" /var/lib/webjet-upgrade/trust.json' || fail "trust.json not written after enrolling"

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
until on_host 'webjetctl local ping ctl-01 -c 1' 2>/dev/null | grep -q "reply from"; do
    sleep 1
    i=$((i + 1))
    [ $i -lt 60 ] || fail "no ping reply after reinstall"
done

echo "== 6. remote upgrades"
U() { docker exec "$P-ctl" webjetctl --account alice network node "$@" --repo "$REPO" --yes; }
U upgrade "v$NEXT" laptop --dry-run | grep -q "laptop" || fail "dry run doesn't list the node"
U upgrade "v$NEXT" laptop | tee /tmp/$P-up.txt || fail "remote upgrade to v$NEXT"
grep -q "laptop: runs v$NEXT" /tmp/$P-up.txt || fail "the rollout didn't see v$NEXT running"
on_host 'webjetd --version' | grep -q "$NEXT" || fail "webjetd is not $NEXT after the remote upgrade"
on_host 'webjetup --version' | grep -q "$NEXT" || fail "webjetup was not replaced by the release's"
on_host 'webjetctl --json local status' | grep -q "\"version\": \"$NEXT\"" || fail "the agent doesn't run $NEXT"
on_host 'grep -q "\"state\": \"done\"" /var/lib/webjet-upgrade/status.json' || fail "helper status is not done"
docker exec "$P-ctl" webjetctl network node upgrade-status laptop | grep -q "state: done" || fail "upgrade-status over the overlay"
# Nothing older or equal is sent (and nodes would refuse it).
U upgrade "$TAG" laptop | grep -q "laptop: runs $NEXT already" || fail "a downgrade must be skipped"
echo "== 6b. an unhealthy release is rolled back (takes the helper's 2 min health timeout)"
U upgrade "v$BAD" laptop >/tmp/$P-bad.txt 2>&1 && fail "the bad release should fail"
grep -q "rolled_back" /tmp/$P-bad.txt || { cat /tmp/$P-bad.txt; fail "the bad release was not rolled back"; }
on_host 'webjetd --version' | grep -q "$NEXT" || fail "the rollback didn't restore $NEXT"
on_host 'systemctl is-active webjetd' | grep -qx active || fail "webjetd not active after the rollback"
echo "== 6c. a local downgrade needs --force"
on_host "webjetup --repo $REPO install $TAG" >/tmp/$P-down.txt 2>&1 && fail "a downgrade without --force"
grep -q "older than the installed" /tmp/$P-down.txt || { cat /tmp/$P-down.txt; fail "downgrade: wrong error"; }
on_host 'webjetd --version' | grep -q "$NEXT" || fail "a refused downgrade changed webjetd"
on_host 'systemctl is-active webjetd' | grep -qx active || fail "a refused downgrade stopped webjetd"
echo "== 6d. opted out"
on_host "webjetup --repo $REPO install v$NEXT --no-remote-upgrade" >/dev/null || fail "install --no-remote-upgrade"
on_host 'grep -q "remote = false" /etc/webjet/webjetd.toml' || fail "[upgrade] remote = false not written"
on_host 'test ! -e /var/lib/webjet-upgrade && test ! -e /etc/systemd/system/webjet-upgrade.path' || fail "the helper is still installed"
i=0
until on_host 'webjetctl local status' >/dev/null 2>&1; do
    sleep 1
    i=$((i + 1))
    [ $i -lt 30 ] || fail "webjetd didn't come back after opting out"
done
U upgrade "v$BAD" laptop >/tmp/$P-off.txt 2>&1 && fail "an opted-out node must refuse"
grep -q "turned off" /tmp/$P-off.txt || { cat /tmp/$P-off.txt; fail "opted out: wrong error"; }
on_host 'webjetup status' | grep -q "remote    off" || fail "status should say remote upgrades are off"

echo "== 7. nuke"
before=$(on_host 'ls /usr/local/bin /var/lib/webjet /etc/webjet | md5sum')
on_host 'webjetup nuke --dry-run' | grep -q "would remove /var/lib/webjet" || fail "dry run doesn't list the state"
[ "$before" = "$(on_host 'ls /usr/local/bin /var/lib/webjet /etc/webjet | md5sum')" ] || fail "dry run changed something"
on_host 'webjetup nuke' >/dev/null 2>&1 && fail "nuke without a terminal must ask (and refuse)"
on_host 'webjetup nuke --yes' >/dev/null || fail "nuke"
for p in /usr/local/bin/webjetd /usr/local/bin/webjetctl /usr/local/bin/webjetup /var/lib/webjet /etc/webjet /etc/systemd/system/webjetd.service /var/lib/webjet-upgrade /etc/systemd/system/webjet-upgrade.service; do
    on_host "test ! -e $p" || fail "$p still exists after nuke"
done
on_host 'id webjet' >/dev/null 2>&1 && fail "user webjet still exists after nuke"
on_host 'systemctl status webjetd' >/dev/null 2>&1 && fail "webjetd unit still known after nuke"

cleanup
echo "WEBJETUP TEST PASSED"
