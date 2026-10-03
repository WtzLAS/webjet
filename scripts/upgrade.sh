#!/bin/sh
# Install or upgrade Webjet on Linux or macOS (§19.8). Run as root from a
# checkout of the release tag:
#
#   scripts/upgrade.sh v2.4.0                      # fetch from $WEBJET_RELEASE_URL
#   scripts/upgrade.sh v2.4.0 --source ./dist      # binaries already here
#   scripts/upgrade.sh --uninstall [--purge]
set -eu
VERSION=""; SOURCE=""; UNINSTALL=0; PURGE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --source) SOURCE=$2; shift ;;
    --uninstall) UNINSTALL=1 ;;
    --purge) PURGE=1 ;;
    *) VERSION=$1 ;;
  esac
  shift
done
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
OS=$(uname -s)
BIN=/usr/local/bin
if [ "$OS" = Darwin ]; then
  STATE="/Library/Application Support/Webjet/state"; PLIST=/Library/LaunchDaemons/net.webjet.webjetd.plist
else
  STATE=/var/lib/webjet; UNIT=/etc/systemd/system/webjetd.service
fi
stop() { if [ "$OS" = Darwin ]; then launchctl bootout system "$PLIST" 2>/dev/null || true; else systemctl stop webjetd 2>/dev/null || true; fi; }
if [ $UNINSTALL = 1 ]; then
  stop
  if [ "$OS" = Darwin ]; then
    rm -f "$PLIST"
    # Split DNS left behind by an unclean stop (§20.8).
    for f in /etc/resolver/*; do
      if [ -f "$f" ] && grep -q "^# webjet" "$f"; then rm -f "$f"; fi
    done
  else
    systemctl disable webjetd 2>/dev/null || true
    rm -f "$UNIT"
    systemctl daemon-reload
  fi
  rm -f $BIN/webjetd $BIN/webjetctl $BIN/webjet-signer $BIN/webjet-root
  [ $PURGE = 1 ] && rm -rf "$STATE"
  echo "Webjet removed."; exit 0
fi
[ -n "$VERSION$SOURCE" ] || { echo "give a release tag or --source" >&2; exit 1; }
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
if [ -z "$SOURCE" ]; then
  : "${WEBJET_RELEASE_URL:?set WEBJET_RELEASE_URL to where releases are published}"
  ARCH=$(uname -m); [ "$ARCH" = arm64 ] && ARCH=aarch64
  case $OS in Darwin) T=$ARCH-apple-darwin ;; *) T=$ARCH-unknown-linux-gnu ;; esac
  F=webjet-$VERSION-$T.tar.gz
  curl -fsSL "$WEBJET_RELEASE_URL/$VERSION/$F" -o "$TMP/$F"
  curl -fsSL "$WEBJET_RELEASE_URL/$VERSION/$F.sha256" -o "$TMP/$F.sha256"
  if command -v sha256sum >/dev/null; then
    (cd "$TMP" && sha256sum -c "$F.sha256")
  else
    (cd "$TMP" && shasum -a 256 -c "$F.sha256")
  fi
  tar -xzf "$TMP/$F" -C "$TMP"; SOURCE=$TMP
fi
stop
for b in webjetd webjetctl webjet-signer webjet-root; do [ -f "$SOURCE/$b" ] && install -m 0755 "$SOURCE/$b" $BIN/$b; done
mkdir -p "$STATE"; chmod 700 "$STATE"
if [ "$OS" = Darwin ]; then
  [ -f "$PLIST" ] || cat > "$PLIST" <<EOT
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>net.webjet.webjetd</string>
  <key>ProgramArguments</key><array><string>$BIN/webjetd</string><string>run</string></array>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/var/log/webjetd.log</string>
</dict></plist>
EOT
  launchctl bootstrap system "$PLIST"
else
  [ -f "$UNIT" ] || cat > "$UNIT" <<'EOT'
[Unit]
Description=Webjet agent
Wants=network-online.target time-sync.target
After=network-online.target time-sync.target

[Service]
ExecStart=/usr/local/bin/webjetd run
Restart=on-failure
User=webjet
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
StateDirectory=webjet
StateDirectoryMode=0700
RuntimeDirectory=webjet
RuntimeDirectoryMode=0750
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
LimitCORE=0
LimitMEMLOCK=1M

[Install]
WantedBy=multi-user.target
EOT
  id webjet >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin webjet
  chown webjet: "$STATE"
  systemctl daemon-reload; systemctl enable --now webjetd
fi
echo "Webjet $($BIN/webjetd --version) installed."
