#!/usr/bin/env bash
# Level 0 NPC: Database traffic generator (mysql query loop)
#
# Simulates application database queries. Discovers available databases
# and tables dynamically so it adapts to any LLM-generated environment.
#
# Environment variables:
#   DB_HOST    - hostname of the database server (default: db)
#   RATE_LAMBDA - queries per minute (default: 20)

set -euo pipefail

DB_HOST="${DB_HOST:-db}"
RATE_LAMBDA="${RATE_LAMBDA:-20}"

INTERVAL=$(awk "BEGIN {printf \"%.1f\", 60.0 / $RATE_LAMBDA}")

# App database credentials -- resolved from env or defaults
DB_USER="${DB_USER:-app_user}"
DB_PASS="${DB_PASS:-AppUs3r!2024}"

# Discover databases (skip system DBs)
discover_db() {
    mysql -h "${DB_HOST}" -u "${DB_USER}" -p"${DB_PASS}" \
        -N -e "SHOW DATABASES" 2>/dev/null \
        | grep -v -E '^(information_schema|mysql|performance_schema|sys)$' \
        | head -1
}

# Discover tables in a database
discover_tables() {
    local db="$1"
    mysql -h "${DB_HOST}" -u "${DB_USER}" -p"${DB_PASS}" \
        -N -e "SHOW TABLES FROM ${db}" 2>/dev/null \
        | head -10
}

# Wait for DB to be ready
for i in $(seq 1 10); do
    DB_NAME=$(discover_db) && [ -n "$DB_NAME" ] && break
    sleep 3
done

if [ -z "${DB_NAME:-}" ]; then
    echo "[NPC-DB] No application database found, exiting"
    exit 0
fi

# Get available tables
mapfile -t TABLES < <(discover_tables "$DB_NAME")
if [ ${#TABLES[@]} -eq 0 ]; then
    echo "[NPC-DB] No tables found in ${DB_NAME}, exiting"
    exit 0
fi

echo "[NPC-DB] Starting DB traffic to ${DB_HOST}/${DB_NAME} at ${RATE_LAMBDA} queries/min (${#TABLES[@]} tables)"

while true; do
    IDX=$(( RANDOM % ${#TABLES[@]} ))
    TABLE="${TABLES[$IDX]}"

    # Alternate between safe read queries
    case $(( RANDOM % 3 )) in
        0) QUERY="SELECT * FROM ${DB_NAME}.${TABLE} LIMIT 5" ;;
        1) QUERY="SELECT COUNT(*) FROM ${DB_NAME}.${TABLE}" ;;
        2) QUERY="DESCRIBE ${DB_NAME}.${TABLE}" ;;
    esac

    mysql -h "${DB_HOST}" \
          -u "${DB_USER}" \
          -p"${DB_PASS}" \
          -e "${QUERY}" 2>/dev/null || true

    sleep "${INTERVAL}"
done
