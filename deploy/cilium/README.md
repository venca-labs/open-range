# Cilium + Hubble for open-range

This directory contains deployment manifests for installing [Cilium](https://cilium.io/) as the CNI and [Hubble](https://docs.cilium.io/en/stable/observability/hubble/) for network flow observability on open-range clusters.

Cilium is **completely optional**. When not installed, open-range uses standard Kubernetes NetworkPolicy resources enforced by the cluster's default CNI (e.g. kindnetd). Cilium enhances the platform with eBPF-enforced network segmentation and Hubble provides real-time flow visibility for Blue agent training.

## Files

| File | Purpose |
|------|---------|
| `bootstrap-cilium.sh` | Install Cilium + Hubble via Helm |
| `cilium-values.yaml` | Helm values optimized for Kind/k3d |
| `hubble-relay-patch.yaml` | Patch for Hubble relay hostNetwork access |

## Installation

### Prerequisites

- A running Kind or k3d cluster (the `deploy/kind-config.yaml` works as-is)
- `helm` CLI installed
- `kubectl` configured for the target cluster
- Optionally, the `cilium` CLI for status checks

### Quick start

```bash
# From the repository root
./deploy/cilium/bootstrap-cilium.sh
```

### Configuration via environment variables

```bash
# Override Cilium version
export CILIUM_CHART_VERSION=1.16.5

# Use with k3d instead of Kind
export CLUSTER_TYPE=k3d
export K3D_CLUSTER_NAME=openrange

# Custom cluster name
export KIND_CLUSTER_NAME=my-cluster

# Force hostNetwork on Hubble relay (auto-enabled for k3d)
export HUBBLE_RELAY_HOST_NETWORK=true

# Start Hubble port-forward automatically
export HUBBLE_PORT_FORWARD=true

./deploy/cilium/bootstrap-cilium.sh
```

## How Hubble enhances Blue agent training

Without Hubble, the Blue agent relies on application-level logs (syslog, web server access logs, SIEM alerts) to detect attacker activity. Hubble adds a network-layer observation channel:

1. **Flow visibility**: The Blue agent can observe all network flows between zones, including source/destination pods, ports, protocols, and L7 HTTP details (method, path, status code).

2. **Policy enforcement feedback**: Dropped flows tell the Blue agent which connections are being blocked by policy, confirming that isolation is working.

3. **Anomaly detection**: By comparing current flows against a baseline captured during known-good operation, the Blue agent can detect:
   - New connection paths not seen before
   - Traffic on unexpected ports
   - Policy violation attempts (dropped flows)
   - Volume spikes indicating scanning or exfiltration

4. **Verification**: The Blue agent can programmatically verify zone isolation -- confirming that the attacker in the DMZ cannot reach the management zone.

### Python integration

The `hubble_observer.py` module provides an async Python API:

```python
from open_range.hubble_observer import HubbleObserver, HubbleConfig

observer = HubbleObserver(config=HubbleConfig(
    hubble_addr="localhost:4245",
    namespace_prefix="or-my-range",
))

# Get recent flows
flows = await observer.get_flows(namespace="or-my-range-dmz", since="5m")

# Check zone isolation
isolated = await observer.check_isolation("dmz", "management")

# Detect anomalies
anomalies = await observer.detect_anomalies(baseline_flows)

# Get observation-space summary
summary = await observer.get_flow_summary()
```

When Hubble is not available, all methods return empty results rather than raising exceptions.

## CiliumNetworkPolicy vs standard NetworkPolicy

| Feature | NetworkPolicy | CiliumNetworkPolicy |
|---------|--------------|-------------------|
| Enforcement | CNI-dependent (iptables) | eBPF datapath |
| L7 rules | Not supported | HTTP path/method filtering |
| DNS policies | Not supported | FQDN-based egress rules |
| Identity-based | Namespace/pod labels only | Cilium security identities |
| Visibility | None built-in | Hubble flow logs |
| Performance | iptables rules scale linearly | eBPF maps scale efficiently |

The `cilium_policies.py` module generates CiliumNetworkPolicy resources from the same zone/firewall configuration used for standard NetworkPolicy:

```python
from open_range.cilium_policies import CiliumPolicyGenerator

gen = CiliumPolicyGenerator(name_prefix="or-my-range")
policies = gen.generate_zone_policies(zones, firewall_rules)
l7_policies = gen.generate_l7_policies(services)
```

## Verifying zone isolation

### Using the Hubble CLI

```bash
# Watch all dropped flows (policy violations)
hubble observe --verdict DROPPED --server localhost:4245

# Check flows into the management zone
hubble observe --namespace or-myrange-management --server localhost:4245

# Filter by source zone
hubble observe --from-namespace or-myrange-dmz --to-namespace or-myrange-internal
```

### Using the Cilium CLI

```bash
# Verify Cilium is healthy
cilium status

# List all CiliumNetworkPolicy resources
kubectl get ciliumnetworkpolicies --all-namespaces

# Test connectivity between zones
cilium connectivity test
```

### Using the Python API

```python
from open_range.hubble_observer import HubbleObserver

observer = HubbleObserver()

# Verify DMZ cannot reach management
assert await observer.check_isolation("dmz", "management")

# Verify DMZ can reach internal (if firewall rule allows)
# check_isolation returns True when traffic is BLOCKED
# so False means traffic is flowing (which may be expected)
can_reach = not await observer.check_isolation("dmz", "internal")
```

## Architecture notes

- Cilium runs as a DaemonSet in `kube-system`, replacing or augmenting the default CNI
- Hubble relay aggregates flow data from all Cilium agents
- Hubble UI provides a browser-based flow visualization (optional)
- The Kind cluster config (`deploy/kind-config.yaml`) already sets `disableDefaultCNI: true` for Cilium compatibility
- When Cilium is not installed, open-range falls back to standard NetworkPolicy resources generated by the Helm chart templates
