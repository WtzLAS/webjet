#!/bin/sh
# Container entrypoint: write webjetd.toml for this container and keep the
# agent running. Usage: node.sh <name> [controller] [gateway-prefix]
set -eu
NAME=$1; CTL=${2:-false}; GW=${3:-}
IP=$(hostname -i | tr " " "\n" | grep "^172\.30\." | head -1)
mkdir -p /var/lib/webjet /etc/webjet
cat > /etc/webjet/webjetd.toml <<EOT
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
[controller]
enabled = $CTL
EOT
if [ -n "$GW" ]; then
  LANIF=$(ip -o -4 addr | awk -v p="$(echo "$GW" | cut -d. -f1-3)." 'index($4, p) == 1 {print $2}')
  cat >> /etc/webjet/webjetd.toml <<EOT
[[gateway.route]]
published = "$GW"
interface = "$LANIF"
EOT
fi
echo "$NAME ready at $IP"
exec sleep infinity
