#!/usr/bin/env bash
# bootstrap-vault.sh -- Initialize Vault for OpenRange
#
# Enables the Transit and KV v2 engines, creates the transit key for
# credential encryption, applies the openrange policy, and optionally
# seeds the initial LLM API key.
#
# Adapted from k3s-istio-vault-platform configure-vault.sh.
#
# Usage:
#   # Against a local dev-mode Vault (default):
#   ./bootstrap-vault.sh
#
#   # Against a remote Vault:
#   VAULT_ADDR=https://vault.example.com:8200 VAULT_TOKEN=s.xxx ./bootstrap-vault.sh
#
# Environment variables:
#   VAULT_ADDR                  Vault address (default: http://127.0.0.1:8200)
#   VAULT_TOKEN                 Vault root/admin token (default: dev-root-token)
#   OPENRANGE_VAULT_KV_MOUNT    KV v2 mount path (default: secret)
#   OPENRANGE_VAULT_TRANSIT_MOUNT Transit mount path (default: transit)
#   OPENRANGE_VAULT_TRANSIT_KEY Transit key name (default: openrange/credentials)
#   OPENRANGE_LLM_API_KEY       If set, stored in Vault as the OPENAI_API_KEY
#   OPENRANGE_LLM_API_KEY_NAME  Env-var-style name for the key (default: OPENAI_API_KEY)
#   VAULT_DEV_MODE              Set to "true" to start a dev server (default: false)

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"

# Defaults
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-dev-root-token}"
KV_MOUNT="${OPENRANGE_VAULT_KV_MOUNT:-secret}"
TRANSIT_MOUNT="${OPENRANGE_VAULT_TRANSIT_MOUNT:-transit}"
TRANSIT_KEY="${OPENRANGE_VAULT_TRANSIT_KEY:-openrange/credentials}"
POLICY_FILE="${SCRIPT_DIR}/policy.hcl"
VAULT_DEV_MODE="${VAULT_DEV_MODE:-false}"

export VAULT_ADDR
export VAULT_TOKEN

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() { printf '[openrange-vault] %s\n' "$*"; }

check_vault_cli() {
    if command -v vault >/dev/null 2>&1; then
        return 0
    fi
    echo "ERROR: HashiCorp Vault CLI is required but not found on PATH." >&2
    echo "Install: https://developer.hashicorp.com/vault/install" >&2
    exit 1
}

wait_for_vault() {
    local attempts=0
    local max_attempts=30
    log "Waiting for Vault at ${VAULT_ADDR} ..."
    while ! vault status >/dev/null 2>&1; do
        attempts=$((attempts + 1))
        if [ "$attempts" -ge "$max_attempts" ]; then
            echo "ERROR: Vault did not become ready within ${max_attempts}s" >&2
            exit 1
        fi
        sleep 1
    done
    log "Vault is ready."
}

# ---------------------------------------------------------------------------
# Optional: start dev server
# ---------------------------------------------------------------------------

start_dev_server() {
    if [ "${VAULT_DEV_MODE}" != "true" ]; then
        return
    fi
    log "Starting Vault in dev mode (root token: ${VAULT_TOKEN}) ..."
    vault server -dev \
        -dev-root-token-id="${VAULT_TOKEN}" \
        -dev-listen-address="127.0.0.1:8200" &
    VAULT_DEV_PID=$!
    # shellcheck disable=SC2064
    trap "kill ${VAULT_DEV_PID} 2>/dev/null || true" EXIT HUP INT TERM
    sleep 2
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

check_vault_cli
start_dev_server
wait_for_vault

# -- Enable Transit engine --------------------------------------------------
log "Enabling Transit secrets engine at ${TRANSIT_MOUNT}/ ..."
vault secrets enable -path="${TRANSIT_MOUNT}" transit 2>/dev/null \
    && log "Transit engine enabled." \
    || log "Transit engine already enabled (skipped)."

# -- Enable KV v2 engine ---------------------------------------------------
log "Enabling KV v2 secrets engine at ${KV_MOUNT}/ ..."
vault secrets enable -path="${KV_MOUNT}" -version=2 kv 2>/dev/null \
    && log "KV v2 engine enabled." \
    || log "KV v2 engine already enabled (skipped)."

# -- Create Transit key -----------------------------------------------------
log "Creating Transit key '${TRANSIT_KEY}' ..."
vault read "${TRANSIT_MOUNT}/keys/${TRANSIT_KEY}" >/dev/null 2>&1 \
    || vault write -f "${TRANSIT_MOUNT}/keys/${TRANSIT_KEY}" type="aes256-gcm96"
log "Transit key '${TRANSIT_KEY}' is ready."

# -- Apply policy -----------------------------------------------------------
if [ -f "${POLICY_FILE}" ]; then
    log "Writing Vault policy 'openrange' from ${POLICY_FILE} ..."
    vault policy write openrange "${POLICY_FILE}"
    log "Policy 'openrange' applied."
else
    log "WARNING: Policy file not found at ${POLICY_FILE}; skipping policy write."
fi

# -- Seed LLM API key (optional) -------------------------------------------
if [ -n "${OPENRANGE_LLM_API_KEY:-}" ]; then
    KEY_NAME="${OPENRANGE_LLM_API_KEY_NAME:-OPENAI_API_KEY}"
    log "Storing LLM API key (${KEY_NAME}) in Vault KV at ${KV_MOUNT}/openrange/llm-api-keys ..."
    vault kv put "${KV_MOUNT}/openrange/llm-api-keys" "${KEY_NAME}=${OPENRANGE_LLM_API_KEY}"
    log "LLM API key stored."
else
    log "OPENRANGE_LLM_API_KEY not set; skipping initial LLM key seeding."
fi

# -- Seed empty range-credentials path (ensures it exists) ------------------
vault kv get "${KV_MOUNT}/openrange/range-credentials" >/dev/null 2>&1 || {
    log "Initializing empty range-credentials path ..."
    vault kv put "${KV_MOUNT}/openrange/range-credentials" _init="true"
}

# -- Enable audit logging (dev convenience) ---------------------------------
vault audit list 2>/dev/null | grep -q '^stdout/' || {
    log "Enabling stdout audit device ..."
    vault audit enable -path=stdout file file_path=stdout 2>/dev/null || true
}

# -- Summary ----------------------------------------------------------------
log ""
log "=== OpenRange Vault Bootstrap Complete ==="
log "  Vault address:     ${VAULT_ADDR}"
log "  KV v2 mount:       ${KV_MOUNT}/"
log "  Transit mount:     ${TRANSIT_MOUNT}/"
log "  Transit key:       ${TRANSIT_KEY}"
log "  Policy:            openrange"
log ""
log "Export these to configure the Python client:"
log "  export VAULT_ADDR=${VAULT_ADDR}"
log "  export VAULT_TOKEN=${VAULT_TOKEN}"
log ""
