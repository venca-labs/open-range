#!/usr/bin/env bash
# deploy-monitoring.sh -- Deploy kube-prometheus-stack for OpenRange
#
# Installs the Prometheus observability stack into the 'monitoring' namespace.
# This is entirely optional; the training pipeline works without it.
#
# Usage:
#   ./deploy/monitoring/deploy-monitoring.sh
#
# Prerequisites:
#   - Helm 3 installed
#   - kubectl configured for the target cluster
#   - Cluster running (kind, k3s, etc.)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="${MONITORING_NAMESPACE:-monitoring}"
RELEASE_NAME="${MONITORING_RELEASE:-kube-prometheus-stack}"
CHART_REPO="https://prometheus-community.github.io/helm-charts"
CHART_NAME="kube-prometheus-stack"
CHART_VERSION="${MONITORING_CHART_VERSION:-80.13.3}"
VALUES_FILE="${SCRIPT_DIR}/prometheus-values.yaml"
TIMEOUT="${MONITORING_TIMEOUT:-300s}"

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

info()  { echo "[INFO]  $*"; }
warn()  { echo "[WARN]  $*" >&2; }
error() { echo "[ERROR] $*" >&2; exit 1; }

command_exists() { command -v "$1" &>/dev/null; }

# -----------------------------------------------------------------------
# Pre-flight
# -----------------------------------------------------------------------

command_exists helm  || error "helm is not installed"
command_exists kubectl || error "kubectl is not installed"

if [ ! -f "${VALUES_FILE}" ]; then
    error "Values file not found: ${VALUES_FILE}"
fi

# -----------------------------------------------------------------------
# Add / update Helm repo
# -----------------------------------------------------------------------

info "Adding prometheus-community Helm repo..."
helm repo add prometheus-community "${CHART_REPO}" 2>/dev/null || true
helm repo update prometheus-community

# -----------------------------------------------------------------------
# Create namespace
# -----------------------------------------------------------------------

info "Ensuring namespace '${NAMESPACE}' exists..."
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

# -----------------------------------------------------------------------
# Install / upgrade the chart
# -----------------------------------------------------------------------

info "Installing ${RELEASE_NAME} (chart ${CHART_NAME} v${CHART_VERSION}) into ${NAMESPACE}..."
helm upgrade --install "${RELEASE_NAME}" "${CHART_NAME}" \
    --repo "${CHART_REPO}" \
    --version "${CHART_VERSION}" \
    --namespace "${NAMESPACE}" \
    --values "${VALUES_FILE}" \
    --timeout "${TIMEOUT}" \
    --wait

# -----------------------------------------------------------------------
# Apply OpenRange-specific ServiceMonitor and PrometheusRules
# -----------------------------------------------------------------------

if [ -f "${SCRIPT_DIR}/servicemonitor.yaml" ]; then
    info "Applying OpenRange ServiceMonitor..."
    kubectl apply -f "${SCRIPT_DIR}/servicemonitor.yaml" -n "${NAMESPACE}"
fi

if [ -f "${SCRIPT_DIR}/alert-rules.yaml" ]; then
    info "Applying OpenRange alert rules..."
    kubectl apply -f "${SCRIPT_DIR}/alert-rules.yaml" -n "${NAMESPACE}"
fi

# -----------------------------------------------------------------------
# Wait for Prometheus to become ready
# -----------------------------------------------------------------------

info "Waiting for Prometheus pods to be ready..."
kubectl rollout status statefulset/"${RELEASE_NAME}-prometheus" \
    -n "${NAMESPACE}" \
    --timeout="${TIMEOUT}" 2>/dev/null || \
kubectl wait pod \
    -l "app.kubernetes.io/name=prometheus" \
    -n "${NAMESPACE}" \
    --for=condition=Ready \
    --timeout="${TIMEOUT}" 2>/dev/null || \
    warn "Could not verify Prometheus readiness -- check pods manually."

info "Waiting for Grafana deployment to be ready..."
kubectl rollout status deployment/"${RELEASE_NAME}-grafana" \
    -n "${NAMESPACE}" \
    --timeout="${TIMEOUT}" 2>/dev/null || \
    warn "Could not verify Grafana readiness -- check pods manually."

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------

info ""
info "Monitoring stack deployed successfully."
info ""
info "  Prometheus:    kubectl port-forward -n ${NAMESPACE} svc/${RELEASE_NAME}-prometheus 9090:9090"
info "  Grafana:       kubectl port-forward -n ${NAMESPACE} svc/${RELEASE_NAME}-grafana 3000:80"
info "  AlertManager:  kubectl port-forward -n ${NAMESPACE} svc/${RELEASE_NAME}-alertmanager 9093:9093"
info ""
info "Grafana default credentials: admin / prom-operator (change immediately)"
