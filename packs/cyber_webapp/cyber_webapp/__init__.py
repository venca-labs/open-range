"""Cyber webapp pack — procedural builder + codegen realize.

This package IS the pack. It owns:
  - ``ontology.py`` — typed graph language (10 node types, 12 edge
    types, 3 constraints)
  - ``priors.py`` — default sampling distributions
  - ``sampling.py`` — fresh-graph sampler against the ontology
  - ``mutation.py`` — curriculum-driven mutations of an existing graph
  - ``checks.py`` — admission probe + verifier source rendering
  - ``builder.py`` — ``ProceduralBuilder`` orchestrating the four-stage
    Builder protocol over the modules above
  - ``codegen/`` — ``realize_graph(graph, manifest)`` that turns a
    world graph into a runnable ``app.py`` + ``Entrypoint`` for the
    built-in HTTP runtime backing
  - ``vulnerabilities/`` — shared vuln catalog used by codegen

The pack class itself is small — ontology / priors / realize / default
builder are wired here and exported via the ``openrange.packs``
entry-point group declared in this package's pyproject.toml.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING

from cyber_webapp.ontology import ONTOLOGY
from cyber_webapp.priors import PRIORS
from openrange.core.builder_protocol import Builder
from openrange.core.graph import RuntimeBundle, WorldGraph, WorldSchema
from openrange.core.manifest import Manifest
from openrange.core.pack import Pack

if TYPE_CHECKING:
    from openrange.core.builder import BuildContext


class CyberWebappPack(Pack):
    """Cyber webapp pack — procedural + codegen.

    Ships no on-disk source; everything is generated at build time
    from the graph. ``dir`` is therefore ``None``.
    """

    id = "cyber.webapp"
    version = "v1"

    def __init__(self, dir: Path | None = None) -> None:
        del dir
        self.dir = None

    @property
    def ontology(self) -> WorldSchema:
        return ONTOLOGY

    def default_builder(self, context: BuildContext) -> Builder | None:
        from cyber_webapp.builder import ProceduralBuilder

        seed = 0
        if context.curriculum is not None:
            seed_value = context.curriculum.get("seed", 0)
            if isinstance(seed_value, int):
                seed = seed_value
        return ProceduralBuilder(seed=seed)

    def realize(self, graph: WorldGraph, manifest: Manifest) -> RuntimeBundle:
        from cyber_webapp.codegen import realize_graph

        return realize_graph(graph, manifest)

    def generation_priors(self) -> Mapping[str, object]:
        return PRIORS

    def project_world(self, graph: WorldGraph) -> Mapping[str, object]:
        """Project the graph back to a flat world dict.

        Surfaces the flag (for the verifier) plus a topology view
        (services + edges + zones + users) the dashboard renders. The
        dashboard auto-redacts ``flag`` / ``secret`` / ``password`` /
        ``token`` keys, so the projected topology is safe to publish.
        """
        flag = ""
        for node in graph.nodes:
            if node.type == "secret" and node.attrs.get("kind") == "flag":
                flag = str(node.attrs.get("value_ref", ""))
                break

        services: list[dict[str, object]] = []
        zones: set[str] = set()
        host_zone: dict[str, str] = {}
        for node in graph.nodes:
            if node.type == "host":
                zone = str(node.attrs.get("zone", ""))
                if zone:
                    host_zone[node.id] = zone
                    zones.add(zone)
        service_host: dict[str, str] = {}
        for edge in graph.edges:
            if edge.relation == "runs_on":
                service_host[edge.source] = edge.target
        endpoints_by_service: dict[str, list[str]] = {}
        for edge in graph.edges:
            if edge.relation == "exposes":
                endpoints_by_service.setdefault(edge.source, []).append(edge.target)
        endpoint_path: dict[str, str] = {
            n.id: str(n.attrs.get("path", "")) for n in graph.nodes if n.type == "endpoint"
        }
        vuln_targets: dict[str, str] = {}
        vuln_kind: dict[str, str] = {}
        for n in graph.nodes:
            if n.type == "vulnerability":
                vuln_kind[n.id] = str(n.attrs.get("kind", ""))
        for edge in graph.edges:
            if edge.relation == "affects":
                vuln_targets[edge.source] = edge.target

        for node in graph.nodes:
            if node.type != "service":
                continue
            host_id = service_host.get(node.id)
            zone = host_zone.get(host_id, "")
            paths = sorted(endpoint_path.get(ep, "") for ep in endpoints_by_service.get(node.id, []))
            vulns_on_service = [
                vuln_kind[vid] for vid, target in vuln_targets.items()
                if target == node.id and vid in vuln_kind
            ]
            vulns_on_endpoints = [
                vuln_kind[vid] for vid, target in vuln_targets.items()
                if target in endpoints_by_service.get(node.id, []) and vid in vuln_kind
            ]
            services.append({
                "id": str(node.attrs.get("name", node.id)),
                "kind": str(node.attrs.get("kind", "")),
                "zone": zone or "default",
                "exposure": str(node.attrs.get("exposure", "")),
                "ports": [],
                "paths": paths,
                "vulns": sorted(set(vulns_on_service + vulns_on_endpoints)),
            })

        edges: list[dict[str, object]] = []
        service_name_by_id: dict[str, str] = {
            n.id: str(n.attrs.get("name", n.id)) for n in graph.nodes if n.type == "service"
        }
        for edge in graph.edges:
            if edge.relation == "backed_by":
                src = service_name_by_id.get(edge.source)
                if src:
                    edges.append({"source": src, "target": str(edge.target), "relation": "backed_by"})

        users: list[dict[str, object]] = [
            {
                "id": str(n.attrs.get("username", n.id)),
                "role": str(n.attrs.get("role", "user")),
            }
            for n in graph.nodes if n.type == "account"
        ]

        return MappingProxyType({
            "flag": flag,
            "topology": {
                "services": services,
                "edges": edges,
                "zones": sorted(zones),
                "users": users,
            },
        })


__all__ = ["CyberWebappPack"]
