#!/bin/bash
set -e

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

# Apply iptables rules if the file exists
if [ -f /etc/iptables/rules.v4 ]; then
    iptables-restore < /etc/iptables/rules.v4 2>/dev/null || echo "Warning: failed to restore iptables rules (expected outside Docker with NET_ADMIN)"
fi

exec "$@"
