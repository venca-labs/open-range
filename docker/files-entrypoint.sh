#!/bin/bash
set -e

# Start SSH
service ssh start

# Start rsyslog for log forwarding
service rsyslog start 2>/dev/null || true

# Start Samba daemons
service smbd start
service nmbd start

# Keep container running
exec tail -f /dev/null
