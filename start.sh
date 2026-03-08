#!/usr/bin/env bash
# =============================================================================
# OpenRange — Snapshot-Driven Service Startup
# =============================================================================
# Called by RangeEnvironment.reset() to start services defined in a snapshot.
# NOT called at container boot — the Dockerfile starts only uvicorn.
#
# Usage:  start.sh <snapshot_dir>
#   snapshot_dir must contain a spec.json with a topology.hosts list.
#   Each host name maps to a known service (nginx, mysql, slapd, etc.).
#
# Services are started based on what the snapshot requires, not hardcoded.
# =============================================================================

set -uo pipefail

SNAPSHOT_DIR="${1:?Usage: start.sh <snapshot_dir>}"
LOGDIR="/var/log/siem"
CONSOLIDATED="${LOGDIR}/consolidated"

# Track background PIDs for cleanup
PIDS=()

cleanup() {
    echo "[start.sh] Shutting down services..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    echo "[start.sh] All services stopped."
}
trap cleanup EXIT INT TERM

# ── Parse snapshot topology ───────────────────────────────────────────────────

mkdir -p "${CONSOLIDATED}"

if [ ! -f "${SNAPSHOT_DIR}/spec.json" ]; then
    echo "[start.sh] ERROR: No spec.json found in ${SNAPSHOT_DIR}"
    exit 1
fi

# Extract host list from topology
HOSTS=$(python3 -c "
import json, sys
with open('${SNAPSHOT_DIR}/spec.json') as f:
    spec = json.load(f)
hosts = spec.get('topology', {}).get('hosts', [])
print(' '.join(hosts))
" 2>/dev/null || echo "")

echo "[start.sh] Snapshot hosts: ${HOSTS:-none}"

# ── Service starters (called only if snapshot needs them) ─────────────────────

start_mysql() {
    local MYSQLD=$(command -v mariadbd || command -v mysqld || echo "")
    if [ -z "$MYSQLD" ]; then echo "[start.sh]   mysql: not installed"; return; fi

    mkdir -p /var/run/mysqld && chown mysql:mysql /var/run/mysqld 2>/dev/null || true
    mkdir -p /var/log/mysql && chown mysql:mysql /var/log/mysql 2>/dev/null || true

    if [ ! -d /var/lib/mysql/mysql ]; then
        if command -v mariadb-install-db >/dev/null 2>&1; then
            mariadb-install-db --user=mysql 2>&1 | tee "${LOGDIR}/mysql.log"
        else
            $MYSQLD --initialize-insecure --user=mysql 2>&1 | tee "${LOGDIR}/mysql.log"
        fi
    fi

    $MYSQLD --user=mysql --log-error="${LOGDIR}/mysql.log" &
    PIDS+=($!)

    local ADMIN=$(command -v mariadb-admin || command -v mysqladmin || echo "")
    for i in $(seq 1 30); do
        if [ -n "$ADMIN" ] && $ADMIN ping --silent 2>/dev/null; then
            echo "[start.sh]   mysql: ready (${i}s)"; return
        fi
        sleep 1
    done
    echo "[start.sh]   mysql: timeout"
}

start_nginx() {
    if ! command -v nginx >/dev/null 2>&1; then echo "[start.sh]   nginx: not installed"; return; fi
    mkdir -p /var/log/nginx
    nginx -g "daemon off;" > "${LOGDIR}/nginx.log" 2>&1 &
    PIDS+=($!)
    for i in $(seq 1 10); do
        if curl -sf http://localhost:80/ >/dev/null 2>&1; then
            echo "[start.sh]   nginx: ready (${i}s)"; return
        fi
        sleep 1
    done
    echo "[start.sh]   nginx: timeout"
}

start_slapd() {
    if ! command -v slapd >/dev/null 2>&1; then echo "[start.sh]   slapd: not installed"; return; fi
    mkdir -p /var/run/slapd
    slapd -h "ldap:/// ldapi:///" -u openldap -g openldap > "${LOGDIR}/slapd.log" 2>&1 &
    PIDS+=($!)
    for i in $(seq 1 10); do
        if ldapsearch -x -H ldap://localhost -b "" -s base namingContexts >/dev/null 2>&1; then
            echo "[start.sh]   slapd: ready (${i}s)"; return
        fi
        sleep 1
    done
    echo "[start.sh]   slapd: timeout"
}

start_rsyslog() {
    if ! command -v rsyslogd >/dev/null 2>&1; then echo "[start.sh]   rsyslog: not installed"; return; fi
    rsyslogd -n > "${LOGDIR}/rsyslog.log" 2>&1 &
    PIDS+=($!)
    echo "[start.sh]   rsyslog: started"
}

start_samba() {
    if ! command -v smbd >/dev/null 2>&1; then echo "[start.sh]   samba: not installed"; return; fi
    mkdir -p /var/lib/samba/private
    smbd --foreground --no-process-group > "${LOGDIR}/smbd.log" 2>&1 &
    PIDS+=($!)
    for i in $(seq 1 10); do
        if smbclient -L localhost -N >/dev/null 2>&1; then
            echo "[start.sh]   samba: ready (${i}s)"; return
        fi
        sleep 1
    done
    echo "[start.sh]   samba: timeout"
}

start_postfix() {
    if ! command -v postfix >/dev/null 2>&1; then echo "[start.sh]   postfix: not installed"; return; fi
    postfix start > "${LOGDIR}/postfix.log" 2>&1 || true
    echo "[start.sh]   postfix: started"
}

start_sshd() {
    if ! command -v sshd >/dev/null 2>&1; then echo "[start.sh]   sshd: not installed"; return; fi
    mkdir -p /var/run/sshd
    /usr/sbin/sshd -E "${LOGDIR}/sshd.log" &
    PIDS+=($!)
    echo "[start.sh]   sshd: started"
}

# ── Map host names to services ────────────────────────────────────────────────
# The manifest topology uses logical host names. Map them to service starters.

declare -A HOST_SERVICE_MAP=(
    [web]=start_nginx
    [db]=start_mysql
    [ldap]=start_slapd
    [siem]=start_rsyslog
    [files]=start_samba
    [mail]=start_postfix
    [firewall]=start_rsyslog  # firewall host uses rsyslog for logging
)

# SSH is started if any host needs remote access
SSH_NEEDED=false

for host in $HOSTS; do
    starter="${HOST_SERVICE_MAP[$host]:-}"
    if [ -n "$starter" ]; then
        echo "[start.sh] Starting service for host: $host"
        $starter
    else
        echo "[start.sh] Host '$host' has no mapped service (may be agent-only)"
    fi
    # Any host beyond attacker/siem might need SSH
    if [ "$host" != "attacker" ] && [ "$host" != "siem" ]; then
        SSH_NEEDED=true
    fi
done

if $SSH_NEEDED; then
    echo "[start.sh] Starting SSH (needed for host access)"
    start_sshd
fi

echo "============================================================"
echo "[start.sh] Services started for snapshot. PIDs: ${PIDS[*]:-none}"
echo "[start.sh] Logs at: ${LOGDIR}/"
echo "============================================================"
