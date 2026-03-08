#!/usr/bin/env bash
# Level 0 NPC: Database traffic generator (mysql query loop)
#
# Simulates application database queries -- SELECT, INSERT operations
# that a normal web application backend would generate.
#
# Environment variables:
#   DB_HOST    - hostname of the database server (default: db)
#   RATE_LAMBDA - queries per minute (default: 20)

set -euo pipefail

DB_HOST="${DB_HOST:-db}"
RATE_LAMBDA="${RATE_LAMBDA:-20}"

INTERVAL=$(awk "BEGIN {printf \"%.1f\", 60.0 / $RATE_LAMBDA}")

# Application-level queries that a normal app would run
QUERIES=(
    "SELECT id, username FROM app.users LIMIT 5"
    "SELECT name, price FROM app.products ORDER BY RAND() LIMIT 3"
    "SELECT COUNT(*) FROM app.sessions WHERE active=1"
    "INSERT INTO app.access_log (user_id, page, ts) VALUES (1, '/dashboard', NOW())"
    "SELECT * FROM app.products WHERE category='electronics'"
    "UPDATE app.sessions SET last_seen=NOW() WHERE user_id=1"
    "SELECT username, last_login FROM app.users WHERE last_login > DATE_SUB(NOW(), INTERVAL 1 HOUR)"
    "SELECT page, COUNT(*) AS hits FROM app.access_log GROUP BY page ORDER BY hits DESC LIMIT 5"
)

# App database credentials (non-privileged)
DB_USER="app_user"
DB_PASS="AppUs3r!2024"

echo "[NPC-DB] Starting DB traffic to ${DB_HOST} at ${RATE_LAMBDA} queries/min"

while true; do
    IDX=$(( RANDOM % ${#QUERIES[@]} ))
    QUERY="${QUERIES[$IDX]}"

    mysql -h "${DB_HOST}" \
          -u "${DB_USER}" \
          -p"${DB_PASS}" \
          -e "${QUERY}" 2>/dev/null || true

    sleep "${INTERVAL}"
done
