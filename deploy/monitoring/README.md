# OpenRange Monitoring Stack

Prometheus-based observability for the OpenRange cybersecurity training gymnasium.

## Overview

The monitoring stack deploys [kube-prometheus-stack](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack) into a Kubernetes cluster running OpenRange. It provides:

- **Prometheus** for metrics collection and alerting
- **Grafana** for dashboards and visualization
- **AlertManager** for alert routing
- **ServiceMonitor** resources for automatic target discovery
- **PrometheusRule** resources with cybersecurity-relevant alerts

The stack is **entirely optional**. OpenRange trains agents without it; enabling it adds Prometheus-derived reward signals and operational visibility.

## Deploying

### Prerequisites

- A running Kubernetes cluster (kind, k3s, or equivalent)
- Helm 3 installed
- kubectl configured for the target cluster

### Quick start

```bash
./deploy/monitoring/deploy-monitoring.sh
```

The script will:

1. Add the `prometheus-community` Helm repo
2. Create the `monitoring` namespace
3. Install kube-prometheus-stack with OpenRange-tuned values
4. Apply the OpenRange ServiceMonitor and alert rules
5. Wait for Prometheus and Grafana to become ready

### Accessing services

```bash
# Prometheus UI
kubectl port-forward -n monitoring svc/kube-prometheus-stack-prometheus 9090:9090

# Grafana (default: admin / prom-operator)
kubectl port-forward -n monitoring svc/kube-prometheus-stack-grafana 3000:80

# AlertManager
kubectl port-forward -n monitoring svc/kube-prometheus-stack-alertmanager 9093:9093
```

### Configuration

Environment variables accepted by `deploy-monitoring.sh`:

| Variable | Default | Description |
|---|---|---|
| `MONITORING_NAMESPACE` | `monitoring` | Target namespace |
| `MONITORING_RELEASE` | `kube-prometheus-stack` | Helm release name |
| `MONITORING_CHART_VERSION` | `80.13.3` | Chart version |
| `MONITORING_TIMEOUT` | `300s` | Helm install timeout |

Edit `prometheus-values.yaml` to tune resource requests, retention, scrape intervals, or enable additional components.

## How Blue Agents Use Prometheus Metrics

The `PrometheusRewardDataSource` class in `src/open_range/server/prometheus_rewards.py` queries Prometheus to produce supplementary reward signals for Blue agent training.

### Reward signals

| Method | Signal | Description |
|---|---|---|
| `service_availability(service)` | 0.0 - 1.0 | Fraction of `up` targets for a given service |
| `detection_score(window_minutes)` | 0.0 - 1.0 | Proportion of security alerts currently firing |
| `error_rate(namespace)` | 0.0 - 1.0 | Aggregate HTTP 5xx error rate |
| `unauthorized_request_count(...)` | integer | Count of 401/403 responses in a window |
| `pod_restart_count(...)` | integer | Pod restarts in a window |

### Integration with training

The data source is designed to complement `CompositeBlueReward` in `src/open_range/server/rewards.py`. A training harness can combine signals:

```python
from open_range.server.prometheus_rewards import (
    PrometheusConfig,
    PrometheusRewardDataSource,
)
from open_range.server.rewards import CompositeBlueReward

source = PrometheusRewardDataSource(config=PrometheusConfig(
    url="http://localhost:9090",
))

availability = await source.service_availability("web")
detection = await source.detection_score()

# Feed into composite reward or use independently
blue_reward = CompositeBlueReward()
```

When Prometheus is unavailable, all methods return safe defaults (configurable via `PrometheusConfig`) so training is never blocked.

## Alert Rules

Defined in `alert-rules.yaml`, these alerts serve dual purposes: operational monitoring and Blue agent input signals.

### Range health alerts

| Alert | Severity | Fires when |
|---|---|---|
| `OpenRangeServiceDown` | critical | A range service pod is not ready for > 2 minutes |
| `OpenRangeHighErrorRate` | warning | HTTP 5xx rate exceeds 10% over 5 minutes |
| `OpenRangePodRestart` | warning | A container restarts > 3 times in 15 minutes |

### Security signal alerts

| Alert | Severity | Fires when |
|---|---|---|
| `OpenRangeUnauthorizedAccess` | warning | > 20 unauthorized (401/403) requests in 5 minutes |
| `OpenRangeSuspiciousProcess` | warning | > 50 process spawns in a container within 5 minutes |
| `OpenRangeHighNetworkEgress` | info | Sustained network transmit > 1 MiB/s for 3 minutes |

Security signal alerts carry a `signal` label (`unauthorized_access`, `suspicious_process`, `data_exfiltration`, `instability`) that the Blue agent can use for classification.

## Integration with the Training Pipeline

The monitoring stack integrates at three levels:

1. **Metrics collection** -- The ServiceMonitor discovers any service labelled `app.kubernetes.io/part-of: openrange` and scrapes its `/metrics` endpoint.

2. **Alert generation** -- PrometheusRule evaluates PromQL expressions against collected metrics and fires alerts when thresholds are breached.

3. **Reward computation** -- `PrometheusRewardDataSource` queries the Prometheus API to translate alerts and metrics into numerical reward signals that guide Blue agent learning.

This creates a feedback loop: Red agent actions cause metric changes, Prometheus detects anomalies, and the Blue agent receives reward signals for correct detections.

## File Reference

| File | Purpose |
|---|---|
| `deploy-monitoring.sh` | Deployment script |
| `prometheus-values.yaml` | Helm values for kube-prometheus-stack |
| `servicemonitor.yaml` | ServiceMonitor for OpenRange services |
| `alert-rules.yaml` | PrometheusRule with security and health alerts |
| `src/open_range/server/prometheus_rewards.py` | Python reward data source |
