#!/bin/bash
set -e

# Start SSH
service ssh start

# Start PHP-FPM (find the installed version dynamically)
PHP_FPM=$(ls /etc/init.d/php*-fpm 2>/dev/null | head -1)
if [ -n "$PHP_FPM" ]; then
    "$PHP_FPM" start
fi

# Start rsyslog for log forwarding
service rsyslog start 2>/dev/null || true

# Run nginx in foreground
exec nginx -g 'daemon off;'
