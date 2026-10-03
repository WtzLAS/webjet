#!/bin/sh
# Check a published release the way a host installs it: in fresh Linux
# containers (the oldest supported glibc and a current one, both
# architectures), pipe the release's install.sh to sh, then check the
# installed programs, the service setup, `webjetup remove` and
# `webjetup nuke`.
#
#   docker/release-test.sh v0.2.0
#   WEBJET_REPO=https://forge/owner/repo docker/release-test.sh v0.2.0
#
# systemd doesn't run in these containers, so `systemctl` is a stub that
# records its calls; the test checks the unit file and the calls instead.
# docker/webjetup-test.sh covers a real systemd host before a release.
set -eu
cd "$(dirname "$0")/.."
TAG=${1:?usage: docker/release-test.sh <tag>}
REPO=${WEBJET_REPO:-https://forgejo.wolf109909.top/webj8/webjet}
VERSION=${TAG#v}
rc=0
for img in ${WEBJET_TEST_IMAGES:-debian:bullseye ubuntu:20.04 debian:bookworm}; do
    for plat in linux/amd64 linux/arm64; do
        printf '%-16s %-12s ' "$img" "$plat"
        # WEBJET_TEST_DNS: some Docker setups' resolver can't see every host.
        # shellcheck disable=SC2086
        if docker run --rm --platform "$plat" ${WEBJET_TEST_DNS:+--dns "$WEBJET_TEST_DNS"} \
            -e REPO="$REPO" -e TAG="$TAG" -e VERSION="$VERSION" -e DEBIAN_FRONTEND=noninteractive "$img" sh -ec '
            # Archived releases (Debian 11) list security updates the mirror no
            # longer serves; the test only needs curl, so use the main archive.
            if grep -q bullseye /etc/os-release; then sed -i "/security/d" /etc/apt/sources.list; fi
            apt-get update -qq >/dev/null
            apt-get install -y -qq curl ca-certificates passwd >/dev/null 2>&1 || { echo "cannot install curl"; exit 1; }
            printf "#!/bin/sh\necho \"\$*\" >> /tmp/systemctl.log\n" > /usr/local/sbin/systemctl
            chmod +x /usr/local/sbin/systemctl

            curl -fsSL "$REPO/releases/download/$TAG/install.sh" | WEBJET_REPO="$REPO" WEBJET_VERSION="$TAG" sh -s -- "$TAG" > /tmp/out.txt 2>&1 ||
                { cat /tmp/out.txt; exit 1; }
            for b in webjetd webjetctl webjet-root webjet-signer webjetup; do
                /usr/local/bin/$b --version >/dev/null || { echo "$b does not run"; exit 1; }
            done
            /usr/local/bin/webjetd --version | grep -q " $VERSION\$" || { echo "wrong webjetd version"; exit 1; }
            /usr/local/bin/webjetup --version | grep -q " $VERSION\$" || { echo "wrong webjetup version"; exit 1; }
            grep -q "ExecStart=/usr/local/bin/webjetd run" /etc/systemd/system/webjetd.service || { echo "no unit"; exit 1; }
            grep -q "enable webjetd" /tmp/systemctl.log || { echo "unit not enabled"; exit 1; }
            id webjet >/dev/null || { echo "no webjet user"; exit 1; }
            webjetup status | grep -q "enrolled  no" || { echo "status"; exit 1; }

            webjetup remove --yes >/dev/null || { echo "remove failed"; exit 1; }
            test ! -e /usr/local/bin/webjetd && test ! -e /etc/systemd/system/webjetd.service || { echo "left after remove"; exit 1; }
            test -d /var/lib/webjet && test -x /usr/local/bin/webjetup || { echo "remove took too much"; exit 1; }
            webjetup nuke --yes >/dev/null || { echo "nuke failed"; exit 1; }
            for p in /usr/local/bin/webjetup /var/lib/webjet /etc/webjet; do
                test ! -e $p || { echo "$p left after nuke"; exit 1; }
            done
            ! id webjet >/dev/null 2>&1 || { echo "user left after nuke"; exit 1; }
            echo ok
        '; then :; else
            echo "FAILED"
            rc=1
        fi
    done
done
exit $rc
