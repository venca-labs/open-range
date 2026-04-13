#!/usr/bin/env sh
# k3d-down.sh -- Tear down the open-range k3d cluster.
#
# Usage:
#   ./k3d-down.sh                         # uses default cluster name
#   CLUSTER_NAME=my-cluster ./k3d-down.sh # override cluster name
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ENV_FILE=${ENV_FILE:-"$SCRIPT_DIR/k3d.env"}

# Source optional env file for CLUSTER_NAME
if [ -f "$ENV_FILE" ]; then
  set -a
  . "$ENV_FILE"
  set +a
fi

: "${CLUSTER_NAME:=openrange}"

command -v k3d >/dev/null 2>&1 || {
  echo "ERROR: k3d is required but not found on PATH" >&2
  exit 1
}

if ! k3d cluster list -o json 2>/dev/null | grep -q "\"name\":\"${CLUSTER_NAME}\""; then
  echo "Cluster '${CLUSTER_NAME}' does not exist. Nothing to delete."
  exit 0
fi

echo "Deleting k3d cluster '${CLUSTER_NAME}' ..."
k3d cluster delete "$CLUSTER_NAME"
echo "Cluster '${CLUSTER_NAME}' deleted."
