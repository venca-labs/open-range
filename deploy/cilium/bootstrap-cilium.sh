#!/usr/bin/env sh
# bootstrap-cilium.sh -- Install Cilium + Hubble on an open-range cluster.
#
# Adapted from k3s-istio-vault-platform/bootstrap/bootstrap-cilium.sh for the
# open-range cybersecurity gymnasium. Works with both Kind and k3d clusters.
#
# Environment variables (all optional):
#   CILIUM_CHART_VERSION  Cilium Helm chart version  (default: 1.16.5)
#   CILIUM_NAMESPACE      Install namespace           (default: kube-system)
#   CILIUM_VALUES_FILE    Path to Helm values file    (default: <script_dir>/cilium-values.yaml)
#   CLUSTER_TYPE          "kind" or "k3d"             (default: kind)
#   KIND_CLUSTER_NAME     Kind cluster name            (default: openrange)
#   K3D_CLUSTER_NAME      k3d cluster name             (default: openrange)
#   HUBBLE_RELAY_HOST_NETWORK  Force hostNetwork on hubble-relay ("true"/"false")
#   CILIUM_K8S_SERVICE_HOST    Override API server host
#   CILIUM_K8S_SERVICE_PORT    Override API server port
#   CILIUM_WAIT_TIMEOUT        Helm --timeout value     (default: 300s)
#   HUBBLE_PORT_FORWARD        Start port-forward after install ("true"/"false", default: false)
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
CILIUM_CHART_VERSION="${CILIUM_CHART_VERSION:-1.16.5}"
CILIUM_NAMESPACE="${CILIUM_NAMESPACE:-kube-system}"
CILIUM_VALUES_FILE="${CILIUM_VALUES_FILE:-$SCRIPT_DIR/cilium-values.yaml}"
CLUSTER_TYPE="${CLUSTER_TYPE:-kind}"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-openrange}"
K3D_CLUSTER_NAME="${K3D_CLUSTER_NAME:-openrange}"
CILIUM_WAIT_TIMEOUT="${CILIUM_WAIT_TIMEOUT:-300s}"
HUBBLE_PORT_FORWARD="${HUBBLE_PORT_FORWARD:-false}"

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------
for tool in helm kubectl; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "required tool not found: $tool" >&2
    exit 1
  }
done

if ! [ -f "$CILIUM_VALUES_FILE" ]; then
  echo "Cilium values file not found: $CILIUM_VALUES_FILE" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Ensure kubeconfig context is set for the target cluster
# ---------------------------------------------------------------------------
case "$CLUSTER_TYPE" in
  kind)
    if command -v kind >/dev/null 2>&1; then
      kubectl cluster-info --context "kind-${KIND_CLUSTER_NAME}" >/dev/null 2>&1 || true
    fi
    ;;
  k3d)
    if command -v k3d >/dev/null 2>&1; then
      kubectl cluster-info --context "k3d-${K3D_CLUSTER_NAME}" >/dev/null 2>&1 || true
    fi
    ;;
  *)
    echo "Unsupported CLUSTER_TYPE: $CLUSTER_TYPE (expected 'kind' or 'k3d')" >&2
    exit 1
    ;;
esac

echo "Installing Cilium ${CILIUM_CHART_VERSION} into ${CILIUM_NAMESPACE} (cluster type: ${CLUSTER_TYPE})..."

# ---------------------------------------------------------------------------
# Add / update Helm repo
# ---------------------------------------------------------------------------
helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1 || true
helm repo update cilium >/dev/null

# ---------------------------------------------------------------------------
# Build Helm arguments
# ---------------------------------------------------------------------------
set -- \
  cilium/cilium \
  --namespace "$CILIUM_NAMESPACE" \
  --version "$CILIUM_CHART_VERSION" \
  --values "$CILIUM_VALUES_FILE"

if [ -n "${CILIUM_K8S_SERVICE_HOST:-}" ]; then
  set -- "$@" --set "k8sServiceHost=${CILIUM_K8S_SERVICE_HOST}"
fi

if [ -n "${CILIUM_K8S_SERVICE_PORT:-}" ]; then
  set -- "$@" --set "k8sServicePort=${CILIUM_K8S_SERVICE_PORT}"
fi

set -- "$@" --wait --timeout "$CILIUM_WAIT_TIMEOUT"

# ---------------------------------------------------------------------------
# Install / upgrade Cilium
# ---------------------------------------------------------------------------
helm upgrade --install cilium "$@"

echo "Cilium Helm release installed."

# ---------------------------------------------------------------------------
# Hubble relay hostNetwork patch (needed for k3d and optionally Kind)
# ---------------------------------------------------------------------------
use_hubble_relay_hostnetwork="${HUBBLE_RELAY_HOST_NETWORK:-}"
if [ -z "$use_hubble_relay_hostnetwork" ] && [ "$CLUSTER_TYPE" = "k3d" ]; then
  use_hubble_relay_hostnetwork=true
fi

HUBBLE_PATCH_FILE="$SCRIPT_DIR/hubble-relay-patch.yaml"
if [ "$use_hubble_relay_hostnetwork" = "true" ] && [ -f "$HUBBLE_PATCH_FILE" ]; then
  echo "Applying Hubble relay hostNetwork patch..."
  kubectl -n "$CILIUM_NAMESPACE" patch deployment hubble-relay \
    --type=merge \
    --patch-file "$HUBBLE_PATCH_FILE" >/dev/null
  echo "Hubble relay patch applied."
fi

# ---------------------------------------------------------------------------
# Wait for Cilium to report healthy
# ---------------------------------------------------------------------------
if command -v cilium >/dev/null 2>&1; then
  echo "Waiting for Cilium to become ready..."
  cilium status --wait --wait-duration 120s 2>/dev/null || {
    echo "Warning: 'cilium status --wait' failed -- Cilium may still be starting." >&2
  }
else
  echo "Cilium CLI not found; skipping 'cilium status --wait'."
  echo "Falling back to kubectl rollout status..."
  kubectl -n "$CILIUM_NAMESPACE" rollout status daemonset/cilium --timeout=120s || true
  kubectl -n "$CILIUM_NAMESPACE" rollout status deployment/cilium-operator --timeout=60s || true
  kubectl -n "$CILIUM_NAMESPACE" rollout status deployment/hubble-relay --timeout=60s || true
fi

# ---------------------------------------------------------------------------
# Optional: port-forward Hubble relay for local access
# ---------------------------------------------------------------------------
if [ "$HUBBLE_PORT_FORWARD" = "true" ]; then
  echo "Starting Hubble relay port-forward on localhost:4245..."
  kubectl -n "$CILIUM_NAMESPACE" port-forward svc/hubble-relay 4245:80 &
  HUBBLE_PF_PID=$!
  echo "Hubble relay port-forward PID: $HUBBLE_PF_PID"
fi

echo ""
echo "Cilium + Hubble installation complete."
echo "  Cilium version : ${CILIUM_CHART_VERSION}"
echo "  Namespace      : ${CILIUM_NAMESPACE}"
echo "  Cluster type   : ${CLUSTER_TYPE}"
echo ""
echo "Verify with:  cilium status"
echo "Hubble UI:    cilium hubble ui"
echo "Hubble flows: hubble observe --namespace <zone-namespace>"
