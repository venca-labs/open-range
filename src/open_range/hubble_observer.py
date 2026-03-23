"""Query Hubble for network flow data, useful for Blue agent training.

This module provides a Python interface to Cilium Hubble's network flow
observability. The Blue (defensive) agent can use this data to:

- Monitor real-time network flows between zones
- Verify that zone isolation policies are correctly enforced
- Detect anomalous traffic patterns during an episode
- Build a network activity baseline and compare against it

The module is completely optional. When Hubble is not installed or
unavailable, all methods return empty results gracefully.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class HubbleBackend(str, Enum):
    """Method used to query Hubble flows."""

    CLI = "cli"
    GRPC = "grpc"


class HubbleConfig(BaseModel):
    """Configuration for the Hubble observer."""

    hubble_addr: str = Field(
        default="localhost:4245",
        description="Hubble relay address (host:port)",
    )
    backend: HubbleBackend = Field(
        default=HubbleBackend.CLI,
        description="How to query Hubble: 'cli' uses the hubble binary, "
        "'grpc' uses the relay gRPC API via subprocess",
    )
    timeout_s: float = Field(
        default=10.0,
        description="Timeout in seconds for Hubble queries",
    )
    hubble_binary: str = Field(
        default="hubble",
        description="Path to the hubble CLI binary",
    )
    kubectl_binary: str = Field(
        default="kubectl",
        description="Path to kubectl binary (used for port-forward fallback)",
    )
    namespace_prefix: str = Field(
        default="",
        description="Namespace prefix for open-range zones (e.g. 'or-myrange')",
    )


# ---------------------------------------------------------------------------
# Flow data model
# ---------------------------------------------------------------------------


class FlowRecord(BaseModel):
    """Normalized representation of a single Hubble network flow."""

    time: str = ""
    verdict: str = ""  # FORWARDED, DROPPED, ERROR, AUDIT
    source_namespace: str = ""
    source_pod: str = ""
    source_labels: list[str] = Field(default_factory=list)
    destination_namespace: str = ""
    destination_pod: str = ""
    destination_labels: list[str] = Field(default_factory=list)
    destination_port: int = 0
    protocol: str = ""  # TCP, UDP, ICMP
    l7_type: str = ""  # HTTP, DNS, etc.
    http_method: str = ""
    http_url: str = ""
    http_status: int = 0
    dns_query: str = ""
    drop_reason: str = ""
    summary: str = ""

    @property
    def source_zone(self) -> str:
        """Extract zone name from source namespace (strip prefix)."""
        return _extract_zone(self.source_namespace)

    @property
    def destination_zone(self) -> str:
        """Extract zone name from destination namespace (strip prefix)."""
        return _extract_zone(self.destination_namespace)


class AnomalyRecord(BaseModel):
    """A detected anomaly compared to baseline traffic."""

    anomaly_type: str = (
        ""  # new_connection, unexpected_port, policy_violation, volume_spike
    )
    severity: str = "medium"  # low, medium, high, critical
    description: str = ""
    flow: FlowRecord | None = None
    baseline_comparison: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Observer
# ---------------------------------------------------------------------------


class HubbleObserver:
    """Query Hubble for network flow data, useful for Blue agent training.

    All methods are async and degrade gracefully when Hubble is unavailable.
    This makes the observer safe to use in environments where Cilium is not
    installed -- methods simply return empty results.

    Usage::

        observer = HubbleObserver(config=HubbleConfig(
            hubble_addr="localhost:4245",
            namespace_prefix="or-my-range",
        ))

        # Get recent flows for a zone
        flows = await observer.get_flows(namespace="or-my-range-dmz", since="5m")

        # Verify zone isolation
        isolated = await observer.check_isolation("dmz", "management")

        # Detect anomalies against a baseline
        anomalies = await observer.detect_anomalies(baseline_flows)
    """

    def __init__(
        self,
        config: HubbleConfig | None = None,
        hubble_addr: str = "localhost:4245",
    ) -> None:
        if config is not None:
            self.config = config
        else:
            self.config = HubbleConfig(hubble_addr=hubble_addr)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def is_available(self) -> bool:
        """Check whether Hubble is reachable.

        Returns True if the hubble CLI exists and can connect to the relay.
        """
        if not shutil.which(self.config.hubble_binary):
            return False
        try:
            proc = await asyncio.create_subprocess_exec(
                self.config.hubble_binary,
                "status",
                "--server",
                self.config.hubble_addr,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=self.config.timeout_s
            )
            return proc.returncode == 0
        except (asyncio.TimeoutError, OSError):
            return False

    async def get_flows(
        self,
        namespace: str = "",
        since: str = "5m",
        limit: int = 100,
        verdict: str = "",
        protocol: str = "",
    ) -> list[FlowRecord]:
        """Get recent network flows from Hubble.

        Parameters
        ----------
        namespace:
            Filter flows to this Kubernetes namespace. Empty string means all
            namespaces.
        since:
            Time window for flows (e.g. "5m", "1h", "30s").
        limit:
            Maximum number of flow records to return.
        verdict:
            Filter by verdict: "FORWARDED", "DROPPED", "ERROR", "AUDIT".
            Empty string means all verdicts.
        protocol:
            Filter by protocol: "TCP", "UDP", "ICMP".
            Empty string means all protocols.

        Returns
        -------
        list[FlowRecord]:
            Parsed flow records. Empty list if Hubble is unavailable.
        """
        args = self._build_observe_args(
            namespace=namespace,
            since=since,
            limit=limit,
            verdict=verdict,
            protocol=protocol,
        )
        raw_flows = await self._run_hubble(args)
        return [self._parse_flow(f) for f in raw_flows]

    async def get_dropped_flows(
        self,
        namespace: str = "",
        since: str = "5m",
        limit: int = 100,
    ) -> list[FlowRecord]:
        """Get flows that were dropped by network policy.

        Convenience wrapper around :meth:`get_flows` with verdict=DROPPED.
        Useful for the Blue agent to verify that isolation policies are
        working.
        """
        return await self.get_flows(
            namespace=namespace,
            since=since,
            limit=limit,
            verdict="DROPPED",
        )

    async def check_isolation(
        self,
        from_zone: str,
        to_zone: str,
        since: str = "5m",
    ) -> bool:
        """Verify that traffic between two zones is blocked by policy.

        Returns True if no FORWARDED flows exist from ``from_zone`` to
        ``to_zone`` in the given time window. Returns True (assumed
        isolated) if Hubble is unavailable.

        Parameters
        ----------
        from_zone:
            Source zone name (without namespace prefix).
        to_zone:
            Destination zone name (without namespace prefix).
        since:
            Time window to check.
        """
        to_namespace = (
            f"{self.config.namespace_prefix}-{to_zone}"
            if self.config.namespace_prefix
            else to_zone
        )
        flows = await self.get_flows(
            namespace=to_namespace,
            since=since,
            limit=1000,
            verdict="FORWARDED",
        )

        from_namespace = (
            f"{self.config.namespace_prefix}-{from_zone}"
            if self.config.namespace_prefix
            else from_zone
        )

        # Check if any forwarded flow originated from the source zone
        for flow in flows:
            if flow.source_namespace == from_namespace:
                logger.warning(
                    "Isolation violation: flow from %s to %s (pod %s -> %s port %d)",
                    from_zone,
                    to_zone,
                    flow.source_pod,
                    flow.destination_pod,
                    flow.destination_port,
                )
                return False

        return True

    async def detect_anomalies(
        self,
        baseline_flows: list[FlowRecord | dict[str, Any]],
        since: str = "5m",
        namespace: str = "",
    ) -> list[AnomalyRecord]:
        """Compare current flows against a baseline to detect anomalous traffic.

        Anomaly detection heuristics:
        1. **New connections**: source->destination pairs not seen in baseline.
        2. **Unexpected ports**: destination ports not seen in baseline.
        3. **Policy violations**: DROPPED flows indicate policy-blocked attempts.
        4. **Volume spikes**: significantly more flows than baseline average.

        Parameters
        ----------
        baseline_flows:
            List of flow records (or dicts) representing "normal" traffic.
            Typically captured during a known-good period.
        since:
            Time window for current flow query.
        namespace:
            Namespace filter for current flows.

        Returns
        -------
        list[AnomalyRecord]:
            Detected anomalies. Empty list if Hubble is unavailable or no
            anomalies found.
        """
        current_flows = await self.get_flows(
            namespace=namespace, since=since, limit=1000
        )
        if not current_flows:
            return []

        # Normalize baseline
        baseline: list[FlowRecord] = []
        for entry in baseline_flows:
            if isinstance(entry, FlowRecord):
                baseline.append(entry)
            elif isinstance(entry, dict):
                baseline.append(FlowRecord(**entry))

        # Build baseline fingerprints
        baseline_pairs: set[tuple[str, str]] = set()
        baseline_ports: set[int] = set()
        for flow in baseline:
            baseline_pairs.add((flow.source_namespace, flow.destination_namespace))
            if flow.destination_port > 0:
                baseline_ports.add(flow.destination_port)

        anomalies: list[AnomalyRecord] = []

        for flow in current_flows:
            pair = (flow.source_namespace, flow.destination_namespace)

            # 1) Policy violations (dropped flows)
            if flow.verdict == "DROPPED":
                anomalies.append(
                    AnomalyRecord(
                        anomaly_type="policy_violation",
                        severity="high",
                        description=(
                            f"Blocked traffic: {flow.source_pod} ({flow.source_namespace}) "
                            f"-> {flow.destination_pod} ({flow.destination_namespace}) "
                            f"port {flow.destination_port}: {flow.drop_reason}"
                        ),
                        flow=flow,
                    )
                )
                continue

            # 2) New connection pair
            if baseline_pairs and pair not in baseline_pairs:
                anomalies.append(
                    AnomalyRecord(
                        anomaly_type="new_connection",
                        severity="medium",
                        description=(
                            f"New traffic path: {flow.source_namespace} -> "
                            f"{flow.destination_namespace} "
                            f"(not seen in baseline)"
                        ),
                        flow=flow,
                        baseline_comparison={
                            "known_pairs": len(baseline_pairs),
                        },
                    )
                )

            # 3) Unexpected port
            if (
                baseline_ports
                and flow.destination_port > 0
                and flow.destination_port not in baseline_ports
            ):
                anomalies.append(
                    AnomalyRecord(
                        anomaly_type="unexpected_port",
                        severity="medium",
                        description=(
                            f"Unexpected port {flow.destination_port}: "
                            f"{flow.source_pod} -> {flow.destination_pod}"
                        ),
                        flow=flow,
                        baseline_comparison={
                            "known_ports": sorted(baseline_ports),
                        },
                    )
                )

        # 4) Volume spike detection
        if baseline and len(current_flows) > 3 * len(baseline):
            anomalies.append(
                AnomalyRecord(
                    anomaly_type="volume_spike",
                    severity="high",
                    description=(
                        f"Traffic volume spike: {len(current_flows)} flows "
                        f"vs baseline {len(baseline)} (>{3}x)"
                    ),
                    baseline_comparison={
                        "current_count": len(current_flows),
                        "baseline_count": len(baseline),
                        "ratio": round(len(current_flows) / max(len(baseline), 1), 2),
                    },
                )
            )

        return anomalies

    async def get_flow_summary(
        self,
        namespace: str = "",
        since: str = "10m",
    ) -> dict[str, Any]:
        """Get a summary of network flows suitable for an observation space.

        Returns a dict with:
        - ``total_flows``: total number of flows observed
        - ``forwarded``: number of allowed flows
        - ``dropped``: number of policy-blocked flows
        - ``connections``: list of unique (src_ns, dst_ns, dst_port) tuples
        - ``drop_sources``: list of (src_ns, src_pod) that had dropped flows

        This is designed to be included in the Blue agent's observation
        without overwhelming context windows.
        """
        flows = await self.get_flows(namespace=namespace, since=since, limit=500)

        forwarded = [f for f in flows if f.verdict == "FORWARDED"]
        dropped = [f for f in flows if f.verdict == "DROPPED"]

        connections: set[tuple[str, str, int]] = set()
        for f in forwarded:
            connections.add(
                (f.source_namespace, f.destination_namespace, f.destination_port)
            )

        drop_sources: set[tuple[str, str]] = set()
        for f in dropped:
            drop_sources.add((f.source_namespace, f.source_pod))

        return {
            "total_flows": len(flows),
            "forwarded": len(forwarded),
            "dropped": len(dropped),
            "connections": [
                {
                    "src_namespace": c[0],
                    "dst_namespace": c[1],
                    "dst_port": c[2],
                }
                for c in sorted(connections)
            ],
            "drop_sources": [
                {"namespace": s[0], "pod": s[1]} for s in sorted(drop_sources)
            ],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_observe_args(
        self,
        namespace: str = "",
        since: str = "5m",
        limit: int = 100,
        verdict: str = "",
        protocol: str = "",
    ) -> list[str]:
        """Build CLI arguments for ``hubble observe``."""
        args = [
            "observe",
            "--server",
            self.config.hubble_addr,
            "--since",
            since,
            "--last",
            str(limit),
            "--output",
            "json",
        ]

        if namespace:
            args.extend(["--namespace", namespace])
        if verdict:
            args.extend(["--verdict", verdict])
        if protocol:
            args.extend(["--protocol", protocol])

        return args

    async def _run_hubble(self, args: list[str]) -> list[dict[str, Any]]:
        """Execute a hubble CLI command and return parsed JSON lines."""
        binary = self.config.hubble_binary
        if not shutil.which(binary):
            logger.debug("Hubble binary %r not found; returning empty results", binary)
            return []

        full_cmd = [binary] + args
        try:
            proc = await asyncio.create_subprocess_exec(
                *full_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.config.timeout_s
            )
        except asyncio.TimeoutError:
            logger.warning(
                "Hubble command timed out after %.1fs", self.config.timeout_s
            )
            return []
        except OSError as exc:
            logger.debug("Failed to run hubble: %s", exc)
            return []

        if proc.returncode != 0:
            err_msg = (stderr or b"").decode(errors="replace").strip()
            logger.debug(
                "Hubble command failed (exit %d): %s", proc.returncode, err_msg
            )
            return []

        raw = (stdout or b"").decode(errors="replace")
        results: list[dict[str, Any]] = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict) and "flow" in obj:
                    results.append(obj["flow"])
                elif isinstance(obj, dict):
                    results.append(obj)
            except json.JSONDecodeError:
                continue

        return results

    @staticmethod
    def _parse_flow(raw: dict[str, Any]) -> FlowRecord:
        """Parse a raw Hubble JSON flow into a FlowRecord."""
        source = raw.get("source", {})
        destination = raw.get("destination", {})
        l4 = raw.get("l4", {})
        l7 = raw.get("l7", {})

        # Extract port from L4 (TCP or UDP)
        dest_port = 0
        proto = ""
        if "TCP" in l4:
            dest_port = l4["TCP"].get("destination_port", 0)
            proto = "TCP"
        elif "UDP" in l4:
            dest_port = l4["UDP"].get("destination_port", 0)
            proto = "UDP"
        elif "ICMPv4" in l4 or "ICMPv6" in l4:
            proto = "ICMP"

        # Extract L7 info
        l7_type = l7.get("type", "")
        http_method = ""
        http_url = ""
        http_status = 0
        dns_query = ""

        http_info = l7.get("http", {})
        if http_info:
            l7_type = l7_type or "HTTP"
            http_method = http_info.get("method", "")
            http_url = http_info.get("url", "")
            http_status = http_info.get("code", 0)

        dns_info = l7.get("dns", {})
        if dns_info:
            l7_type = l7_type or "DNS"
            dns_query = dns_info.get("query", "")

        return FlowRecord(
            time=raw.get("time", ""),
            verdict=raw.get("verdict", ""),
            source_namespace=source.get("namespace", ""),
            source_pod=source.get("pod_name", ""),
            source_labels=source.get("labels", []),
            destination_namespace=destination.get("namespace", ""),
            destination_pod=destination.get("pod_name", ""),
            destination_labels=destination.get("labels", []),
            destination_port=dest_port,
            protocol=proto,
            l7_type=l7_type,
            http_method=http_method,
            http_url=http_url,
            http_status=http_status,
            dns_query=dns_query,
            drop_reason=raw.get("drop_reason_desc", ""),
            summary=raw.get("Summary", ""),
        )


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _extract_zone(namespace: str) -> str:
    """Extract zone name from a prefixed namespace.

    E.g. ``"or-myrange-dmz"`` -> ``"dmz"`` (assuming the last segment is
    the zone). Returns the full namespace if no prefix separator is found.
    """
    parts = namespace.rsplit("-", 1)
    return parts[-1] if len(parts) > 1 else namespace
