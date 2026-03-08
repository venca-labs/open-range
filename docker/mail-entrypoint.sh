#!/bin/bash
set -e

# Start SSH
service ssh start

# Start rsyslog for mail logging
service rsyslog start 2>/dev/null || true

# Start Dovecot
service dovecot start

# Start Postfix in foreground
exec postfix start-fg
