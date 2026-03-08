#!/usr/bin/env bash
# Level 0 NPC: SSH traffic generator (sshpass loop)
#
# Simulates admin SSH sessions -- login, run a few commands, logout.
# Generates auth log entries that Blue must distinguish from Red's SSH activity.
#
# Environment variables:
#   WEB_HOST   - hostname to SSH into (default: web)
#   DB_HOST    - secondary host (default: db)
#   RATE_LAMBDA - sessions per minute (default: 2)

set -euo pipefail

WEB_HOST="${WEB_HOST:-web}"
DB_HOST="${DB_HOST:-db}"
RATE_LAMBDA="${RATE_LAMBDA:-2}"

INTERVAL=$(awk "BEGIN {printf \"%.1f\", 60.0 / $RATE_LAMBDA}")

# Admin commands that a normal sysadmin would run
COMMANDS=(
    "uptime"
    "df -h"
    "free -m"
    "tail -5 /var/log/syslog"
    "ps aux | head -10"
    "ls /var/www/html/"
    "cat /etc/hostname"
    "systemctl status nginx"
    "id"
    "w"
)

# Credentials for benign SSH sessions
SSH_USER="admin"
SSH_PASS="Adm1n!2024"

HOSTS=("${WEB_HOST}" "${DB_HOST}")

echo "[NPC-SSH] Starting SSH traffic at ${RATE_LAMBDA} sessions/min"

while true; do
    # Pick a random host
    IDX=$(( RANDOM % ${#HOSTS[@]} ))
    HOST="${HOSTS[$IDX]}"

    # Pick a random command
    CMD_IDX=$(( RANDOM % ${#COMMANDS[@]} ))
    CMD="${COMMANDS[$CMD_IDX]}"

    sshpass -p "${SSH_PASS}" \
        ssh -o StrictHostKeyChecking=no \
            -o ConnectTimeout=5 \
            "${SSH_USER}@${HOST}" \
            "${CMD}" 2>/dev/null || true

    sleep "${INTERVAL}"
done
