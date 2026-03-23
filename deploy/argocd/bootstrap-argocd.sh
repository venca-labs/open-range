#!/usr/bin/env sh
# ---------------------------------------------------------------------------
# Bootstrap Argo CD for open-range GitOps workflow.
#
# Adapted from k3s-istio-vault-platform/bootstrap/bootstrap-argocd.sh for the
# open-range cybersecurity gymnasium.  Installs Argo CD via Helm into a local
# k3d/Kind cluster and optionally creates a root Application pointing at the
# GitOps repository that holds rendered snapshot charts.
#
# Configuration (environment variables):
#   ARGOCD_NAMESPACE          - namespace for Argo CD        (default: argocd)
#   ARGOCD_CHART_VERSION      - argo-cd Helm chart version   (default: 7.7.11)
#   ARGOCD_ADMIN_PASSWORD     - initial admin password        (auto-generated)
#   GITOPS_REPO_URL           - GitOps repository URL         (optional)
#   GITOPS_TARGET_REVISION    - branch / tag to track         (default: main)
#   ARGOCD_VALUES_FILE        - path to Helm values           (auto-detected)
#   ROOT_APP_TEMPLATE         - path to root Application tpl  (auto-detected)
# ---------------------------------------------------------------------------
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# --- Defaults ---------------------------------------------------------------

ARGOCD_NAMESPACE="${ARGOCD_NAMESPACE:-argocd}"
ARGOCD_CHART_VERSION="${ARGOCD_CHART_VERSION:-7.7.11}"
ARGOCD_VALUES_FILE="${ARGOCD_VALUES_FILE:-$SCRIPT_DIR/argocd-values.yaml}"
ROOT_APP_TEMPLATE="${ROOT_APP_TEMPLATE:-$SCRIPT_DIR/snapshot-application.yaml.tpl}"
GITOPS_TARGET_REVISION="${GITOPS_TARGET_REVISION:-main}"

# --- Pre-flight checks ------------------------------------------------------

if [ ! -f "$ARGOCD_VALUES_FILE" ]; then
  echo "ERROR: missing Argo CD values file: $ARGOCD_VALUES_FILE" >&2
  exit 1
fi

for cmd in helm kubectl; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "ERROR: $cmd is required but not found in PATH" >&2
    exit 1
  }
done

# --- Install Argo CD --------------------------------------------------------

echo "==> Creating namespace ${ARGOCD_NAMESPACE}"
kubectl create namespace "$ARGOCD_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

echo "==> Adding Argo Helm repo"
helm repo add argo https://argoproj.github.io/argo-helm >/dev/null
helm repo update argo >/dev/null

echo "==> Installing Argo CD ${ARGOCD_CHART_VERSION} into ${ARGOCD_NAMESPACE}"
helm upgrade --install argocd argo/argo-cd \
  --namespace "$ARGOCD_NAMESPACE" \
  --create-namespace \
  --version "$ARGOCD_CHART_VERSION" \
  --values "$ARGOCD_VALUES_FILE" \
  --set crds.install=true \
  --wait

# --- Wait for readiness -----------------------------------------------------

echo "==> Waiting for argocd-server rollout"
kubectl -n "$ARGOCD_NAMESPACE" rollout status deploy/argocd-server --timeout=5m

# --- Set admin password (optional) ------------------------------------------

if [ -n "${ARGOCD_ADMIN_PASSWORD:-}" ]; then
  echo "==> Setting initial admin password"
  BCRYPT_HASH=$(htpasswd -nbBC 10 "" "$ARGOCD_ADMIN_PASSWORD" | tr -d ':\n' | sed 's/$2y/$2a/')
  kubectl -n "$ARGOCD_NAMESPACE" patch secret argocd-secret \
    -p "{\"stringData\":{\"admin.password\":\"${BCRYPT_HASH}\",\"admin.passwordMtime\":\"$(date -u +%FT%TZ)\"}}" \
    2>/dev/null || echo "  (htpasswd not available -- skipping password set)"
else
  echo "==> Retrieving auto-generated admin password"
  ARGOCD_ADMIN_PASSWORD=$(kubectl -n "$ARGOCD_NAMESPACE" get secret argocd-initial-admin-secret \
    -o jsonpath='{.data.password}' 2>/dev/null | base64 -d) || true
  if [ -n "$ARGOCD_ADMIN_PASSWORD" ]; then
    echo "  Admin password: $ARGOCD_ADMIN_PASSWORD"
  fi
fi

# --- Create root Application (optional) ------------------------------------

if [ -n "${GITOPS_REPO_URL:-}" ]; then
  if [ ! -f "$ROOT_APP_TEMPLATE" ]; then
    echo "WARNING: GITOPS_REPO_URL set but root Application template not found: $ROOT_APP_TEMPLATE" >&2
    echo "  Skipping root Application creation."
  else
    command -v envsubst >/dev/null 2>&1 || {
      echo "WARNING: envsubst not found -- skipping root Application creation" >&2
      exit 0
    }
    echo "==> Creating root Application from ${ROOT_APP_TEMPLATE}"
    export GITOPS_REPO_URL GITOPS_TARGET_REVISION ARGOCD_NAMESPACE
    envsubst < "$ROOT_APP_TEMPLATE" | kubectl apply -f -
  fi
else
  echo "==> GITOPS_REPO_URL not set -- skipping root Application creation"
  echo "  Set GITOPS_REPO_URL and re-run, or apply snapshot Applications manually."
fi

echo ""
echo "==> Argo CD bootstrap complete."
echo "  Namespace : ${ARGOCD_NAMESPACE}"
echo "  UI        : kubectl port-forward svc/argocd-server -n ${ARGOCD_NAMESPACE} 8080:443"
echo "  Login     : argocd login localhost:8080 --username admin --password <password>"
