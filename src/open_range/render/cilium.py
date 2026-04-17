"""Generate CiliumNetworkPolicy manifests from open-range zone topology.

This module translates open-range's zone/firewall configuration into Cilium's
eBPF-enforced network policies, providing stronger isolation than standard
Kubernetes NetworkPolicy resources.

Key differences from standard NetworkPolicy:
- ``CiliumNetworkPolicy`` uses Cilium's eBPF datapath for enforcement
- L7 HTTP rules allow path-based and method-based filtering
- DNS-aware policies enable FQDN-based egress controls
- Identity-based selectors provide efficient pod-to-pod filtering

This module is completely optional. When Cilium is not installed, open-range
falls back to the standard NetworkPolicy templates in the Helm chart.
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration model
# ---------------------------------------------------------------------------


class CiliumPolicyConfig(BaseModel):
    """Configuration for CiliumNetworkPolicy generation."""

    enable_l7: bool = Field(
        default=True,
        description="Enable L7 HTTP rules for web services",
    )
    enable_dns: bool = Field(
        default=True,
        description="Enable DNS-aware egress policies",
    )
    dns_match_pattern: str = Field(
        default="*.cluster.local",
        description="DNS pattern for in-cluster service discovery",
    )
    default_deny_egress: bool = Field(
        default=False,
        description="Apply default-deny egress in addition to ingress",
    )
    zone_label: str = Field(
        default="openrange/zone",
        description="Label key used to identify zone namespaces",
    )
    name_prefix_label: str = Field(
        default="app.kubernetes.io/instance",
        description="Label key used to identify release instance",
    )


# ---------------------------------------------------------------------------
# Policy generator
# ---------------------------------------------------------------------------


class CiliumPolicyGenerator:
    """Generate CiliumNetworkPolicy manifests from open-range zone topology.

    Produces YAML-serializable dicts representing CiliumNetworkPolicy
    resources.  These are Cilium-specific CRDs that extend standard
    NetworkPolicy with L7 HTTP rules, DNS-aware egress, and identity-based
    selectors.

    Usage::

        gen = CiliumPolicyGenerator(name_prefix="or-my-range")
        zones = {"dmz": [...], "internal": [...], "management": [...]}
        fw_rules = [
            {"action": "allow", "fromZone": "dmz", "toZone": "internal", "ports": [80, 443]},
        ]
        policies = gen.generate_zone_policies(zones, fw_rules)

        services = {
            "web": {"ports": [80, 443], "paths": ["/api/*", "/health"]},
            "db":  {"ports": [3306]},
        }
        l7_policies = gen.generate_l7_policies(services)
    """

    API_VERSION = "cilium.io/v2"
    KIND = "CiliumNetworkPolicy"

    def __init__(
        self,
        name_prefix: str = "openrange",
        config: CiliumPolicyConfig | None = None,
    ) -> None:
        self.name_prefix = name_prefix
        self.config = config or CiliumPolicyConfig()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_zone_policies(
        self,
        zones: dict[str, Any],
        firewall_rules: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Generate default-deny + zone-allow + cross-zone CiliumNetworkPolicy resources.

        Parameters
        ----------
        zones:
            Mapping of zone name to list of hosts/services in that zone.
            Example: ``{"dmz": ["web", "proxy"], "internal": ["db", "app"]}``
        firewall_rules:
            List of firewall rule dicts with keys ``action``, ``fromZone``,
            ``toZone``, and optionally ``ports``.

        Returns
        -------
        list[dict]:
            List of CiliumNetworkPolicy manifest dicts ready for YAML
            serialization or ``kubectl apply``.
        """
        policies: list[dict[str, Any]] = []

        for zone_name in zones:
            namespace = f"{self.name_prefix}-{zone_name}"

            # 1) Default deny all ingress (and optionally egress)
            policies.append(self._default_deny(zone_name, namespace))

            # 2) Allow intra-zone traffic
            policies.append(self._allow_same_zone(zone_name, namespace))

            # 3) Allow DNS egress for service discovery
            if self.config.enable_dns:
                policies.append(self._dns_egress(zone_name, namespace))

        # 4) Cross-zone allow rules from firewall configuration
        for rule in firewall_rules:
            action = rule.get("action", "deny")
            if action != "allow":
                continue
            from_zone = rule.get("fromZone") or rule.get("from_zone", "")
            to_zone = rule.get("toZone") or rule.get("to_zone", "")
            ports = rule.get("ports", [])
            if from_zone and to_zone:
                policies.append(
                    self._cross_zone_ingress_allow(
                        from_zone,
                        to_zone,
                        f"{self.name_prefix}-{to_zone}",
                        ports,
                    )
                )
                policies.append(
                    self._cross_zone_egress_allow(
                        from_zone,
                        to_zone,
                        f"{self.name_prefix}-{from_zone}",
                        ports,
                    )
                )

        return policies

    def generate_l7_policies(
        self,
        services: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Generate L7 HTTP policies for web services.

        Parameters
        ----------
        services:
            Mapping of service name to config dict.  Each config may contain:
            - ``zone`` (str): Zone the service belongs to.
            - ``ports`` (list[int]): TCP ports the service listens on.
            - ``paths`` (list[str]): Allowed HTTP paths (e.g. ``["/api/*", "/health"]``).
            - ``methods`` (list[str]): Allowed HTTP methods (e.g. ``["GET", "POST"]``).

        Returns
        -------
        list[dict]:
            List of CiliumNetworkPolicy manifest dicts with L7 HTTP rules.
        """
        if not self.config.enable_l7:
            logger.debug("L7 policies disabled via config; returning empty list")
            return []

        policies: list[dict[str, Any]] = []

        for svc_name, svc_config in services.items():
            zone = svc_config.get("zone", "")
            ports = svc_config.get("ports", [])
            paths = svc_config.get("paths", [])
            methods = svc_config.get("methods", [])

            if not ports:
                continue

            namespace = f"{self.name_prefix}-{zone}" if zone else self.name_prefix

            ingress_rules: list[dict[str, Any]] = []

            for port in ports:
                port_rule: dict[str, Any] = {
                    "fromEndpoints": [{"matchLabels": {}}],
                    "toPorts": [
                        {
                            "ports": [
                                {"port": str(port), "protocol": "TCP"},
                            ],
                        }
                    ],
                }

                # Add L7 HTTP rules if paths or methods are specified
                if paths or methods:
                    http_rules: list[dict[str, str]] = []
                    if paths and methods:
                        for path in paths:
                            for method in methods:
                                http_rules.append({"path": path, "method": method})
                    elif paths:
                        for path in paths:
                            http_rules.append({"path": path})
                    elif methods:
                        for method in methods:
                            http_rules.append({"method": method})

                    port_rule["toPorts"][0]["rules"] = {"http": http_rules}

                ingress_rules.append(port_rule)

            policy: dict[str, Any] = {
                "apiVersion": self.API_VERSION,
                "kind": self.KIND,
                "metadata": {
                    "name": f"l7-{svc_name}",
                    "namespace": namespace,
                },
                "spec": {
                    "endpointSelector": {
                        "matchLabels": {"app": svc_name},
                    },
                    "ingress": ingress_rules,
                },
            }
            policies.append(policy)

        return policies

    def generate_all(
        self,
        zones: dict[str, Any],
        firewall_rules: list[dict[str, Any]],
        services: dict[str, dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Generate all policy types in a single call.

        Convenience method that combines :meth:`generate_zone_policies` and
        :meth:`generate_l7_policies`.
        """
        policies = self.generate_zone_policies(zones, firewall_rules)
        if services:
            policies.extend(self.generate_l7_policies(services))
        return policies

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _default_deny(
        self,
        zone_name: str,
        namespace: str,
    ) -> dict[str, Any]:
        """Default-deny ingress (and optionally egress) for a zone namespace."""
        spec: dict[str, Any] = {
            "endpointSelector": {},
            "ingress": [],
        }
        if self.config.default_deny_egress:
            spec["egress"] = []

        return {
            "apiVersion": self.API_VERSION,
            "kind": self.KIND,
            "metadata": {
                "name": "default-deny-ingress",
                "namespace": namespace,
                "labels": {
                    self.config.zone_label: zone_name,
                    "openrange/policy-type": "default-deny",
                },
            },
            "spec": spec,
        }

    def _allow_same_zone(
        self,
        zone_name: str,
        namespace: str,
    ) -> dict[str, Any]:
        """Allow all traffic within the same zone namespace."""
        return {
            "apiVersion": self.API_VERSION,
            "kind": self.KIND,
            "metadata": {
                "name": "allow-same-zone",
                "namespace": namespace,
                "labels": {
                    self.config.zone_label: zone_name,
                    "openrange/policy-type": "intra-zone",
                },
            },
            "spec": {
                "endpointSelector": {},
                "ingress": [
                    {
                        "fromEndpoints": [
                            {
                                "matchLabels": {
                                    "k8s:io.kubernetes.pod.namespace": namespace,
                                },
                            },
                        ],
                    },
                ],
                "egress": [
                    {
                        "toEndpoints": [
                            {
                                "matchLabels": {
                                    "k8s:io.kubernetes.pod.namespace": namespace,
                                },
                            },
                        ],
                    },
                ],
            },
        }

    def _cross_zone_ingress_allow(
        self,
        from_zone: str,
        to_zone: str,
        namespace: str,
        ports: list[int],
    ) -> dict[str, Any]:
        """Allow cross-zone traffic based on firewall rules."""
        from_namespace = f"{self.name_prefix}-{from_zone}"

        ingress_from: dict[str, Any] = {
            "fromEndpoints": [
                {
                    "matchLabels": {
                        "k8s:io.kubernetes.pod.namespace": from_namespace,
                    },
                },
            ],
        }

        if ports:
            ingress_from["toPorts"] = [
                {
                    "ports": [{"port": str(p), "protocol": "TCP"} for p in ports],
                }
            ]

        return {
            "apiVersion": self.API_VERSION,
            "kind": self.KIND,
            "metadata": {
                "name": f"allow-{from_zone}-to-{to_zone}",
                "namespace": namespace,
                "labels": {
                    self.config.zone_label: to_zone,
                    "openrange/policy-type": "cross-zone-ingress",
                    "openrange/from-zone": from_zone,
                },
            },
            "spec": {
                "endpointSelector": {},
                "ingress": [ingress_from],
            },
        }

    def _cross_zone_egress_allow(
        self,
        from_zone: str,
        to_zone: str,
        namespace: str,
        ports: list[int],
    ) -> dict[str, Any]:
        """Allow cross-zone egress based on firewall rules."""
        to_namespace = f"{self.name_prefix}-{to_zone}"

        egress_to: dict[str, Any] = {
            "toEndpoints": [
                {
                    "matchLabels": {
                        "k8s:io.kubernetes.pod.namespace": to_namespace,
                    },
                },
            ],
        }

        if ports:
            egress_to["toPorts"] = [
                {
                    "ports": [{"port": str(p), "protocol": "TCP"} for p in ports],
                }
            ]

        return {
            "apiVersion": self.API_VERSION,
            "kind": self.KIND,
            "metadata": {
                "name": f"allow-egress-to-{to_zone}",
                "namespace": namespace,
                "labels": {
                    self.config.zone_label: from_zone,
                    "openrange/policy-type": "cross-zone-egress",
                    "openrange/to-zone": to_zone,
                },
            },
            "spec": {
                "endpointSelector": {},
                "egress": [egress_to],
            },
        }

    def _dns_egress(
        self,
        zone_name: str,
        namespace: str,
    ) -> dict[str, Any]:
        """Allow DNS egress for Kubernetes service discovery."""
        return {
            "apiVersion": self.API_VERSION,
            "kind": self.KIND,
            "metadata": {
                "name": "allow-dns-egress",
                "namespace": namespace,
                "labels": {
                    self.config.zone_label: zone_name,
                    "openrange/policy-type": "dns-egress",
                },
            },
            "spec": {
                "endpointSelector": {},
                "egress": [
                    {
                        "toEndpoints": [
                            {
                                "matchLabels": {
                                    "k8s:io.kubernetes.pod.namespace": "kube-system",
                                    "k8s:k8s-app": "kube-dns",
                                },
                            },
                        ],
                        "toPorts": [
                            {
                                "ports": [
                                    {"port": "53", "protocol": "UDP"},
                                    {"port": "53", "protocol": "TCP"},
                                ],
                            },
                        ],
                    },
                ],
            },
        }
