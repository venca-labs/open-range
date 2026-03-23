# Argo CD GitOps for open-range

This directory contains everything needed to add Argo CD-based GitOps
deployment to the open-range cybersecurity gymnasium.  GitOps support is
**completely optional** -- the existing `build -> render -> deploy` CLI
workflow continues to work unchanged.

## Overview

With GitOps enabled the deployment pipeline becomes:

```
build  ->  render  ->  publish (git commit)  ->  auto-deploy (Argo CD)
```

Rendered snapshot Helm charts are committed to a dedicated Git repository.
Argo CD watches that repository and automatically reconciles each snapshot
into a live Kubernetes range, handling creation, updates, and teardown.

This is especially useful for RL training loops where rapid, automated
environment turnover is required.

## Quick start

### 1. Install Argo CD

```bash
# From the repository root
./deploy/argocd/bootstrap-argocd.sh
```

The script installs Argo CD via Helm into the `argocd` namespace using
resource-light settings suitable for local k3d / Kind clusters.

Access the UI:

```bash
kubectl port-forward svc/argocd-server -n argocd 8080:443
# Open https://localhost:8080  (accept the self-signed cert)
# Username: admin
# Password: printed by the bootstrap script, or:
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d
```

### 2. Create the GitOps repository

Create a Git repository that will hold rendered snapshot charts.  The
publisher places each snapshot under `ranges/<snapshot-id>/`.

```
gitops-repo/
  ranges/
    tier1-web-app-abc123/
      Chart.yaml
      values.yaml
      templates/
        ...
    tier2-lateral-move-def456/
      Chart.yaml
      values.yaml
      templates/
        ...
```

### 3. Configure environment variables

```bash
# Required
export OPENRANGE_GITOPS_ENABLED=true
export OPENRANGE_GITOPS_REPO_URL=https://github.com/your-org/openrange-gitops.git
export OPENRANGE_GITOPS_BRANCH=main            # default: main
export OPENRANGE_GITOPS_BASE_PATH=ranges       # default: ranges

# Optional
export OPENRANGE_GITOPS_WORK_DIR=/tmp/gitops   # default: auto temp dir
export OPENRANGE_GITOPS_ARGOCD_NAMESPACE=argocd
export OPENRANGE_GITOPS_SYNC_TIMEOUT=300
export OPENRANGE_GITOPS_COMMIT_AUTHOR_NAME=open-range
export OPENRANGE_GITOPS_COMMIT_AUTHOR_EMAIL=open-range@localhost
```

### 4. Publish a snapshot

From Python (e.g. in a training loop):

```python
from open_range.server.gitops_publisher import GitOpsConfig, GitOpsPublisher

config = GitOpsConfig.from_env()
publisher = GitOpsPublisher.from_config(config)

# After rendering a snapshot
sha = await publisher.publish("tier1-web-app-abc123", Path("/tmp/rendered/tier1-web-app-abc123"))

# Wait for Argo CD to deploy it
healthy = await publisher.wait_for_sync("tier1-web-app-abc123", timeout=180)

# When the episode is done, tear it down
await publisher.unpublish("tier1-web-app-abc123")
```

## File reference

| File | Purpose |
|------|---------|
| `bootstrap-argocd.sh` | Installs Argo CD via Helm into the cluster |
| `argocd-values.yaml` | Helm values optimised for local dev (minimal resources, no HA) |
| `snapshot-application.yaml.tpl` | Argo CD Application template for a single snapshot (envsubst) |
| `src/open_range/server/gitops_publisher.py` | Python module for publishing snapshots to the GitOps repo |

## Environment variables reference

### Bootstrap script

| Variable | Default | Description |
|----------|---------|-------------|
| `ARGOCD_NAMESPACE` | `argocd` | Kubernetes namespace for Argo CD |
| `ARGOCD_CHART_VERSION` | `7.7.11` | Helm chart version |
| `ARGOCD_ADMIN_PASSWORD` | auto-generated | Initial admin password |
| `GITOPS_REPO_URL` | *(none)* | GitOps repo URL (enables root Application) |
| `GITOPS_TARGET_REVISION` | `main` | Branch / tag to track |

### GitOps publisher (`OPENRANGE_GITOPS_` prefix)

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLED` | `false` | Master switch |
| `REPO_URL` | *(none)* | GitOps repository clone URL |
| `BRANCH` | `main` | Branch to push to |
| `BASE_PATH` | `ranges` | Directory for snapshot charts |
| `WORK_DIR` | *(temp)* | Local working copy path |
| `ARGOCD_NAMESPACE` | `argocd` | Argo CD namespace |
| `SYNC_TIMEOUT` | `300` | Seconds to wait for sync |
| `COMMIT_AUTHOR_NAME` | `open-range` | Git commit author |
| `COMMIT_AUTHOR_EMAIL` | `open-range@localhost` | Git commit email |

## Integration with the training pipeline

The `GitOpsPublisher` is designed to slot into the `ManagedSnapshotRuntime`
training loop.  A typical integration:

1. The runtime calls `builder.build()` to generate a snapshot spec.
2. The renderer produces Helm chart artifacts in a local directory.
3. If `OPENRANGE_GITOPS_ENABLED=true`, the publisher commits the artifacts
   to the GitOps repo and waits for Argo CD to reconcile.
4. The environment runs the training episode against the live range.
5. After the episode, the publisher removes the snapshot from the GitOps
   repo, and Argo CD prunes the resources.

This replaces the direct `helm install` path with a declarative, auditable
Git history of every range that was deployed.

## Manually deploying a snapshot

If you prefer not to use the Python publisher, you can deploy a snapshot
manually using the Application template:

```bash
export SNAPSHOT_ID=my-snapshot
export CHART_PATH=ranges/my-snapshot
export GITOPS_REPO_URL=https://github.com/your-org/openrange-gitops.git
export TARGET_REVISION=main

envsubst < deploy/argocd/snapshot-application.yaml.tpl | kubectl apply -f -
```
