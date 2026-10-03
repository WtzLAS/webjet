#!/bin/sh
# Check a published release the way a host installs it: in fresh Linux
# containers (the oldest supported glibc and a current one, both
# architectures), run scripts/upgrade.sh <tag> against WEBJET_RELEASE_URL
# and check the installed binaries.
#
#   WEBJET_RELEASE_URL=https://forge/owner/repo/releases/download docker/release-test.sh v0.1.0
#
# systemd doesn't run in these containers, so `systemctl` is a stub that
# records its calls; the test checks the unit file and the calls instead.
set -eu
cd "$(dirname "$0")/.."
TAG=${1:?usage: docker/release-test.sh <tag>}
: "${WEBJET_RELEASE_URL:?set WEBJET_RELEASE_URL}"
VERSION=${TAG#v}
rc=0
for img in ${WEBJET_TEST_IMAGES:-debian:bullseye ubuntu:20.04 debian:bookworm}; do
    for plat in linux/amd64 linux/arm64; do
        printf '%-16s %-12s ' "$img" "$plat"
        # WEBJET_TEST_DNS: some Docker setups' resolver can't see every host.
        # shellcheck disable=SC2086
        if docker run --rm --platform "$plat" ${WEBJET_TEST_DNS:+--dns "$WEBJET_TEST_DNS"} \
            -v "$PWD/scripts:/scripts:ro" \
            -e WEBJET_RELEASE_URL -e DEBIAN_FRONTEND=noninteractive "$img" sh -ec '
            # Archived releases (Debian 11) list security updates the mirror no
            # longer serves; the test only needs curl, so use the main archive.
            if grep -q bullseye /etc/os-release; then sed -i "/security/d" /etc/apt/sources.list; fi
            apt-get update -qq >/dev/null
            apt-get install -y -qq curl ca-certificates passwd >/dev/null 2>&1 || { echo "cannot install curl"; exit 1; }
            printf "#!/bin/sh\necho \"\$*\" >> /tmp/systemctl.log\n" > /usr/local/sbin/systemctl
            chmod +x /usr/local/sbin/systemctl
            sh /scripts/upgrade.sh '"$TAG"' > /tmp/out.txt 2>&1 || { cat /tmp/out.txt; exit 1; }
            for b in webjetd webjetctl webjet-root webjet-signer; do
                /usr/local/bin/$b --version >/dev/null || { echo "$b does not run"; exit 1; }
            done
            /usr/local/bin/webjetd --version | grep -q " '"$VERSION"'$" || { echo "wrong version"; exit 1; }
            grep -q "ExecStart=/usr/local/bin/webjetd run" /etc/systemd/system/webjetd.service
            grep -q "enable --now webjetd" /tmp/systemctl.log
            id webjet >/dev/null
            tail -1 /tmp/out.txt
        '; then :; else
            echo "FAILED"
            rc=1
        fi
    done
done
exit $rc
