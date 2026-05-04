"""Snapshot topology normalization and world redaction.

The dashboard owns the topology view shape (services / edges / zones /
users / green_personas). Three sources feed it, in priority order:

1. An embedded ``topology.json`` artifact shipped by the pack.
2. ``snapshot.world["topology"]`` or top-level ``world["services"]`` etc.
3. A graph-aware fallback that projects ``snapshot.world_graph`` —
   nodes typed ``service`` become services, ``account`` become users,
   ``host.zone`` attributes become zones, ``backed_by`` edges between
   services become edges, vulnerabilities annotate the services they
   affect. Pack-agnostic: any v1-shaped ontology gets a render for
   free without the pack having to know the dashboard's view shape.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import cast

from openrange.core import Snapshot
from openrange.core.graph import WorldGraph
from openrange.core.snapshot import json_safe


def empty_runtime_topology() -> dict[str, object]:
    return {
        "services": [],
        "edges": [],
        "zones": [],
        "users": [],
        "green_personas": [],
    }


def normalized_runtime_topology(snapshot: Snapshot) -> dict[str, object]:
    raw = embedded_topology(snapshot)
    services = normalized_rows(raw.get("services"))
    known_services = {str(service.get("id", "")) for service in services}

    world_service = snapshot.world.get("service")
    if isinstance(world_service, str) and world_service not in known_services:
        services.append(
            {
                "id": world_service,
                "kind": "service",
                "zone": "episode",
                "ports": [],
            },
        )
        known_services.add(world_service)

    for task in snapshot.tasks:
        for entrypoint in task.entrypoints:
            if entrypoint.target in known_services:
                continue
            services.append(
                {
                    "id": entrypoint.target,
                    "kind": entrypoint.kind,
                    "zone": "episode",
                    "ports": [],
                },
            )
            known_services.add(entrypoint.target)

    zones = normalized_strings(raw.get("zones"))
    service_zones = sorted(
        {
            str(service["zone"])
            for service in services
            if isinstance(service.get("zone"), str)
        },
    )
    if not zones:
        zones = service_zones
    else:
        zones.extend(zone for zone in service_zones if zone not in zones)

    return {
        "services": services,
        "edges": normalized_rows(raw.get("edges")),
        "zones": zones,
        "users": normalized_rows(raw.get("users")),
        "green_personas": normalized_rows(raw.get("green_personas")),
    }


def embedded_topology(snapshot: Snapshot) -> dict[str, object]:
    raw: dict[str, object] = {}
    for path, content in snapshot.artifacts.items():
        if not path.endswith("topology.json"):
            continue
        try:
            loaded = json.loads(content)
        except json.JSONDecodeError:
            continue
        if isinstance(loaded, Mapping):
            raw.update(loaded)
            break

    world_topology = snapshot.world.get("topology")
    if isinstance(world_topology, Mapping):
        raw.update(world_topology)
    for key in ("services", "edges", "zones", "users", "green_personas"):
        value = snapshot.world.get(key)
        if value is not None:
            raw[key] = value

    if not raw.get("services"):
        graph_view = topology_from_world_graph(snapshot.world_graph)
        for key, value in graph_view.items():
            raw.setdefault(key, value)
    return raw


def topology_from_world_graph(graph: WorldGraph) -> dict[str, object]:
    """Project a world graph into the dashboard's topology view shape.

    Pack-agnostic. Reads only standard v1 ontology node/edge types
    (``service`` / ``host`` / ``endpoint`` / ``vulnerability`` /
    ``account``). Returns an empty view when the graph carries none of
    them — non-cyber packs that don't fit this shape can either ship
    their own ``topology.json`` artifact or surface ``world.topology``.
    """
    if not graph.nodes:
        return {}
    services = _services_from_graph(graph)
    if not services:
        return {}
    return {
        "services": services,
        "edges": _edges_from_graph(graph),
        "zones": sorted({str(s["zone"]) for s in services if s.get("zone")}),
        "users": _users_from_graph(graph),
    }


def _services_from_graph(graph: WorldGraph) -> list[dict[str, object]]:
    host_zone = {
        n.id: str(n.attrs.get("zone", "")) for n in graph.nodes if n.type == "host"
    }
    service_host: dict[str, str] = {}
    endpoints_by_service: dict[str, list[str]] = {}
    for edge in graph.edges:
        if edge.relation == "runs_on":
            service_host[edge.source] = edge.target
        elif edge.relation == "exposes":
            endpoints_by_service.setdefault(edge.source, []).append(edge.target)
    endpoint_path = {
        n.id: str(n.attrs.get("path", "")) for n in graph.nodes if n.type == "endpoint"
    }
    vuln_kind = {
        n.id: str(n.attrs.get("kind", ""))
        for n in graph.nodes
        if n.type == "vulnerability"
    }
    vuln_target: dict[str, str] = {}
    for edge in graph.edges:
        if edge.relation == "affects":
            vuln_target[edge.source] = edge.target

    services: list[dict[str, object]] = []
    for node in graph.nodes:
        if node.type != "service":
            continue
        endpoints = endpoints_by_service.get(node.id, [])
        zone = host_zone.get(service_host.get(node.id, ""), "")
        vulns = sorted(
            {
                vuln_kind[vid]
                for vid, target in vuln_target.items()
                if target == node.id or target in endpoints
                if vid in vuln_kind
            },
        )
        services.append(
            {
                "id": str(node.attrs.get("name", node.id)),
                "kind": str(node.attrs.get("kind", "")),
                "zone": zone or "default",
                "exposure": str(node.attrs.get("exposure", "")),
                "ports": [],
                "paths": sorted(endpoint_path.get(ep, "") for ep in endpoints),
                "vulns": vulns,
            },
        )
    return services


def _edges_from_graph(graph: WorldGraph) -> list[dict[str, object]]:
    service_name = {
        n.id: str(n.attrs.get("name", n.id)) for n in graph.nodes if n.type == "service"
    }
    edges: list[dict[str, object]] = []
    for edge in graph.edges:
        if edge.relation != "backed_by":
            continue
        source = service_name.get(edge.source)
        if source is None:
            continue
        edges.append(
            {"source": source, "target": str(edge.target), "relation": "backed_by"},
        )
    return edges


def _users_from_graph(graph: WorldGraph) -> list[dict[str, object]]:
    return [
        {
            "id": str(n.attrs.get("username", n.id)),
            "role": str(n.attrs.get("role", "user")),
        }
        for n in graph.nodes
        if n.type == "account"
    ]


def normalized_rows(value: object) -> list[dict[str, object]]:
    if isinstance(value, Mapping):
        iterable = tuple(value.items())
    elif isinstance(value, Sequence) and not isinstance(value, str | bytes):
        iterable = tuple((None, item) for item in value)
    else:
        return []

    rows: list[dict[str, object]] = []
    for key, item in iterable:
        if isinstance(item, Mapping):
            row = dict(cast(Mapping[str, object], json_safe(item)))
            if "id" not in row:
                row["id"] = "" if key is None else str(key)
            rows.append(row)
        elif isinstance(item, str):
            rows.append({"id": item})
    return rows


def normalized_strings(value: object) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        return []
    return [item for item in value if isinstance(item, str)]


def public_world(world: Mapping[str, object]) -> dict[str, object]:
    redacted: dict[str, object] = {}
    for key, value in world.items():
        if sensitive_world_key(key):
            redacted[key] = "[redacted]"
        else:
            redacted[key] = value
    return redacted


def sensitive_world_key(key: str) -> bool:
    normalized = key.lower()
    return normalized == "flag" or any(
        marker in normalized for marker in ("secret", "password", "token")
    )


def stored_entrypoints(tasks: Sequence[object]) -> list[dict[str, object]]:
    entrypoints: list[dict[str, object]] = []
    for task in tasks:
        if not isinstance(task, Mapping):
            continue
        task_id = task.get("id")
        for entrypoint in stored_task_entrypoints(task):
            entrypoints.append({"task_id": str(task_id), **entrypoint})
    return entrypoints


def stored_missions(tasks: Sequence[object]) -> list[dict[str, object]]:
    missions: list[dict[str, object]] = []
    for task in tasks:
        if not isinstance(task, Mapping):
            continue
        missions.append(
            {
                "task_id": str(task.get("id", "")),
                "instruction": str(task.get("instruction", "")),
            },
        )
    return missions


def stored_task_entrypoints(task: Mapping[str, object]) -> list[dict[str, object]]:
    rows = task.get("entrypoints")
    if not isinstance(rows, list):
        return []
    entrypoints: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        entrypoints.append(
            {
                "kind": str(row.get("kind", "")),
                "target": str(row.get("target", "")),
            },
        )
    return entrypoints
