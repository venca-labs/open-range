#!/usr/bin/env sh
# k3d-up.sh -- Bootstrap a multi-node k3d cluster for open-range.
#
# Creates a k3d cluster with CNI disabled (for future Cilium support),
# configurable worker agents, and DMZ NodePort mappings.  Pre-pulls
# chart images into the cluster so pods start quickly.
#
# Usage:
#   ./k3d-up.sh                    # uses defaults / k3d.env
#   K3D_AGENTS=4 ./k3d-up.sh      # override worker count
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ENV_FILE=${ENV_FILE:-"$SCRIPT_DIR/k3d.env"}
CONFIG_TEMPLATE=${CONFIG_TEMPLATE:-"$SCRIPT_DIR/k3d-config.yaml.tpl"}

# ---------------------------------------------------------------------------
# Source optional env file
# ---------------------------------------------------------------------------
if [ -f "$ENV_FILE" ]; then
  set -a
  . "$ENV_FILE"
  set +a
fi

# ---------------------------------------------------------------------------
# Defaults (all overridable via environment or k3d.env)
# ---------------------------------------------------------------------------
: "${CLUSTER_NAME:=openrange}"
: "${K3D_K3S_IMAGE:=rancher/k3s:v1.31.6-k3s1}"
: "${K3D_AGENTS:=2}"
: "${K3D_API_HOST:=127.0.0.1}"
: "${K3D_API_PORT:=6550}"
: "${K3D_SUBNET:=172.29.0.0/16}"
: "${K3S_TOKEN:=openrange-bootstrap-token}"
: "${K3D_HTTP_PORT:=8080}"
: "${K3D_HTTPS_PORT:=8443}"
: "${K3D_DMZ_PORT_START:=30080}"
: "${K3D_DMZ_PORT_END:=30089}"
: "${K3D_WAIT_TIMEOUT:=300s}"

export CLUSTER_NAME K3D_K3S_IMAGE K3D_AGENTS K3D_API_HOST K3D_API_PORT
export K3D_SUBNET K3S_TOKEN K3D_HTTP_PORT K3D_HTTPS_PORT
export K3D_DMZ_PORT_START K3D_DMZ_PORT_END K3D_WAIT_TIMEOUT

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
for required_command in docker k3d kubectl envsubst; do
  command -v "$required_command" >/dev/null 2>&1 || {
    echo "ERROR: $required_command is required but not found on PATH" >&2
    exit 1
  }
done

# Abort if cluster already exists
if k3d cluster list -o json 2>/dev/null | grep -q "\"name\":\"${CLUSTER_NAME}\""; then
  echo "Cluster '${CLUSTER_NAME}' already exists. Run k3d-down.sh first or:" >&2
  echo "  k3d cluster delete ${CLUSTER_NAME}" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Render k3d config from template
# ---------------------------------------------------------------------------
if [ ! -f "$CONFIG_TEMPLATE" ]; then
  echo "ERROR: missing config template: $CONFIG_TEMPLATE" >&2
  echo "Copy k3d-config.yaml.tpl from the deploy/k3d directory." >&2
  exit 1
fi

TMP_CONFIG=$(mktemp)
trap 'rm -f "$TMP_CONFIG"' EXIT HUP INT TERM
envsubst < "$CONFIG_TEMPLATE" > "$TMP_CONFIG"

echo "Creating k3d cluster '${CLUSTER_NAME}' (${K3D_AGENTS} agents, subnet ${K3D_SUBNET}) ..."

# ---------------------------------------------------------------------------
# Create cluster
# ---------------------------------------------------------------------------
k3d cluster create --config "$TMP_CONFIG"
kubectl config use-context "k3d-${CLUSTER_NAME}" >/dev/null

# ---------------------------------------------------------------------------
# Wait for nodes to be Ready
# ---------------------------------------------------------------------------
echo "Waiting for all nodes to become Ready ..."
kubectl wait --for=condition=Ready nodes --all --timeout="${K3D_WAIT_TIMEOUT}"

# ---------------------------------------------------------------------------
# Pre-load images (best-effort)
# ---------------------------------------------------------------------------
# If OPENRANGE_PRELOAD_IMAGES is set (comma-separated), import them.
if [ -n "${OPENRANGE_PRELOAD_IMAGES:-}" ]; then
  echo "Pre-loading images into cluster ..."
  # Split comma-separated list
  OLD_IFS="$IFS"
  IFS=","
  set -- $OPENRANGE_PRELOAD_IMAGES
  IFS="$OLD_IFS"
  for img in "$@"; do
    img=$(echo "$img" | xargs)  # trim whitespace
    if [ -n "$img" ]; then
      echo "  Importing: $img"
      k3d image import -c "$CLUSTER_NAME" "$img" 2>/dev/null || \
        echo "  WARNING: failed to import $img (may need docker pull first)" >&2
    fi
  done
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "k3d cluster '${CLUSTER_NAME}' is ready."
echo "  Context:       k3d-${CLUSTER_NAME}"
echo "  API server:    https://${K3D_API_HOST}:${K3D_API_PORT}"
echo "  Agents:        ${K3D_AGENTS}"
echo "  Subnet:        ${K3D_SUBNET}"
echo "  DMZ NodePorts: ${K3D_DMZ_PORT_START}-${K3D_DMZ_PORT_END}"
echo "  HTTP ingress:  http://${K3D_API_HOST}:${K3D_HTTP_PORT}"
echo "  HTTPS ingress: https://${K3D_API_HOST}:${K3D_HTTPS_PORT}"
echo ""
echo "To tear down:  ${SCRIPT_DIR}/k3d-down.sh"
