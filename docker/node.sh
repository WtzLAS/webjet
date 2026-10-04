#!/bin/sh
# Test-container command for docker/e2e.sh: write webjetd.toml for this
# container and idle; the test starts the agent with `docker exec`.
# Usage: node.sh <name> [gateway-prefix]
set -eu
NAME=$1; GW=${2:-}
CONF=${WEBJET_CONFIG:-/etc/webjet/webjetd.toml}
IP=$(hostname -i | tr " " "\n" | grep "^172\.30\." | head -1)
mkdir -p /var/lib/webjet "$(dirname "$CONF")"
cat > "$CONF" <<EOT
data_dir = "/var/lib/webjet"
control_socket = "/run/webjet/control.sock"
[listen]
tls = "0.0.0.0:443"
kcp = "0.0.0.0:443"
[[public]]
addr = "$IP:443"
transport = "tls"
[[public]]
addr = "$IP:443"
transport = "kcp"
[dns]
configure_system = false
EOT
if [ -n "$GW" ]; then
  LANIF=$(ip -o -4 addr | awk -v p="$(echo "$GW" | cut -d. -f1-3)." 'index($4, p) == 1 {print $2}')
  cat >> "$CONF" <<EOT
[[gateway.route]]
published = "$GW"
interface = "$LANIF"
EOT
fi
echo "$NAME ready at $IP"
exec sleep infinity
