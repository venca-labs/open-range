#!/bin/bash
set -e

# Start SSH
service ssh start

# Start rsyslog in foreground
exec rsyslogd -n
