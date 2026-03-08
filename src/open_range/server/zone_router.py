"""Zone-based network routing enforcement.

Replaces iptables in the all-in-one container deployment.
All services run on localhost; this module enforces which
zones can reach which other zones on which ports.

The agent experiences identical training signal to a
multi-container setup with real iptables rules.

All routing data comes from the snapshot/manifest topology.
No hardcoded infrastructure constants.
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ZoneRouter:
    """Enforces network zone routing policy.

    Must be constructed via ``from_snapshot()`` or ``from_manifest()``
    to load topology-driven routes and host-zone mappings.  The bare
    constructor creates an empty (deny-all) router.
    """

    routes: dict[tuple[str, str], set[int]] = field(default_factory=dict)
    host_zones: dict[str, str] = field(default_factory=dict)

    # ------------------------------------------------------------------ #
    # Constructors
    # ------------------------------------------------------------------ #

    @classmethod
    def from_snapshot(cls, topology: dict[str, Any]) -> "ZoneRouter":
        """Build router from snapshot topology and firewall rules.

        This is the primary constructor.  It reads ``hosts`` and
        ``firewall_rules`` from the topology dict to populate
        ``host_zones`` and ``routes``.

        If ``firewall_rules`` is missing or empty, a permissive default
        is generated: same-zone traffic is always allowed (handled by
        ``can_reach``), and all cross-zone traffic is denied.

        If a host entry lacks a ``zone`` field, its zone is inferred as
        ``"unknown"``.
        """
        router = cls()

        # Build host_zones from topology hosts list
        for host in topology.get("hosts", []):
            if isinstance(host, dict):
                name = host.get("name", "")
                zone = host.get("zone", "unknown")
                if name:
                    router.host_zones[name] = zone
            elif isinstance(host, str):
                # String-only entries get zone inferred as "unknown"
                router.host_zones[host] = "unknown"

        # Build routes from firewall_rules
        rules = topology.get("firewall_rules", [])
        if rules:
            for rule in rules:
                action = rule.get("action", "deny")
                if action != "allow":
                    continue
                from_z = rule.get("from_zone", rule.get("from", ""))
                to_z = rule.get("to_zone", rule.get("to", ""))
                ports = set(rule.get("ports", []))
                if from_z and to_z:
                    key = (from_z, to_z)
                    router.routes[key] = router.routes.get(key, set()) | ports
        # else: no firewall_rules → routes stays empty → cross-zone denied,
        #       same-zone allowed (handled by can_reach)

        return router

    @classmethod
    def from_manifest(cls, manifest: dict[str, Any]) -> "ZoneRouter":
        """Build a ZoneRouter from a raw manifest dict.

        Used during validation before a snapshot exists.  Extracts
        topology from the manifest and delegates to ``from_snapshot``.
        """
        topology = manifest.get("topology", manifest)
        return cls.from_snapshot(topology)

    # ------------------------------------------------------------------ #
    # Query methods
    # ------------------------------------------------------------------ #

    def can_reach(self, from_zone: str, to_zone: str, port: int) -> bool:
        """Check if a connection from one zone to another on a port is allowed."""
        if from_zone == to_zone:
            return True  # same zone always allowed
        allowed_ports = self.routes.get((from_zone, to_zone), set())
        return port in allowed_ports

    def get_zone(self, host: str) -> str:
        """Get the zone for a host."""
        return self.host_zones.get(host, "unknown")

    def check_command_access(self, from_host: str, target_host: str, port: int = 0) -> tuple[bool, str]:
        """Check if from_host can access target_host on port.

        Returns (allowed, reason).
        Unknown zones are denied (fail-closed).
        """
        from_zone = self.get_zone(from_host)
        to_zone = self.get_zone(target_host)

        if from_zone == "unknown" or to_zone == "unknown":
            unknown = from_zone if from_zone == "unknown" else to_zone
            return False, f"unknown zone: {unknown}"

        if self.can_reach(from_zone, to_zone, port):
            logger.debug("ALLOW %s(%s) -> %s(%s):%d", from_host, from_zone, target_host, to_zone, port)
            return True, "allowed"
        else:
            logger.info("BLOCK %s(%s) -> %s(%s):%d", from_host, from_zone, target_host, to_zone, port)
            return False, f"Zone {from_zone} cannot reach {to_zone} on port {port}"
