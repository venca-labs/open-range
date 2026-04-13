# Argo CD Application for an open-range rendered snapshot.
#
# This template is processed with envsubst.  Required variables:
#   SNAPSHOT_ID         - unique identifier for the snapshot (e.g. "tier1-web-app-1a2b3c")
#   CHART_PATH          - path inside the GitOps repo to the rendered Helm chart
#   GITOPS_REPO_URL     - URL of the GitOps repository
#   TARGET_REVISION     - branch / tag / commit to track (e.g. "main")
#
# Optional variables:
#   ARGOCD_NAMESPACE    - Argo CD namespace (default: argocd)
#   SNAPSHOT_NAMESPACE  - target namespace for the range (default: or-${SNAPSHOT_ID})
#
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: openrange-${SNAPSHOT_ID}
  namespace: ${ARGOCD_NAMESPACE:-argocd}
  labels:
    app.kubernetes.io/part-of: openrange
    app.kubernetes.io/component: range-snapshot
    openrange.dev/snapshot-id: "${SNAPSHOT_ID}"
  finalizers:
    - resources-finalizer.argocd.argoproj.io
spec:
  project: default
  source:
    repoURL: ${GITOPS_REPO_URL}
    targetRevision: ${TARGET_REVISION}
    path: ${CHART_PATH}
    helm:
      releaseName: or-${SNAPSHOT_ID}
      valueFiles:
        - values.yaml
  destination:
    server: https://kubernetes.default.svc
    namespace: ${SNAPSHOT_NAMESPACE:-or-${SNAPSHOT_ID}}
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
      - ServerSideApply=true
    retry:
      limit: 3
      backoff:
        duration: 10s
        factor: 2
        maxDuration: 3m
