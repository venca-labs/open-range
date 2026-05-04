"""Curriculum-driven mutation of an existing world graph.

These functions implement the "patch + evolve" workflow: take a parent
graph and a curriculum directive, return a child graph with the
requested change applied. The Builder pipes them in when
``BuildContext.previous`` is set; pure data-in / data-out so they can
be tested in isolation.

v1 directives:
  ``patch``: drop named vulnerability kinds.
  ``add``:   add named vulnerability kinds (placed on the first
             endpoint / service that doesn't already carry that kind).

Future directives (harden, narrow_chain, widen_chain) attach here.
"""

from __future__ import annotations

import random
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import TYPE_CHECKING

from cyber_webapp.sampling import default_vuln_params
from cyber_webapp.vulnerabilities import CATALOG as VULN_CATALOG
from openrange.core.curriculum import Mutation
from openrange.core.graph import Edge, Node, WorldGraph

if TYPE_CHECKING:
    from openrange.core.episode import EpisodeReport
    from openrange.core.snapshot import Snapshot

# Tiny baseline so a "harden" pick is always available even when the agent
# passed without our path-hit heuristic detecting the exploit.
_PATCH_RELEVANCE_FLOOR = 0.05
# Static relevance for "introduce a new kind" — no agent-data signal possible
# for a vuln that doesn't exist in the world yet.
_ADD_ABSENT_RELEVANCE = 0.5
# Static relevance for "another instance of an already-present kind" — gives
# the agent a parallel target without changing the attack surface dramatically.
_ADD_PRESENT_RELEVANCE = 0.2


def coerce_string_list(value: object) -> list[str]:
    """Normalize a curriculum string-list field (string, list, set, tuple)."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list | tuple | frozenset | set):
        return [str(v) for v in value]
    return []


def apply_curriculum(
    parent: WorldGraph,
    curriculum: Mapping[str, object],
    *,
    rng: random.Random,
) -> WorldGraph:
    """Mutate ``parent`` per curriculum directives. Returns a new graph."""
    nodes = list(parent.nodes)
    edges = list(parent.edges)

    patch_kinds = coerce_string_list(curriculum.get("patch", ()))
    if patch_kinds:
        nodes, edges = _drop_vulns_by_kind(nodes, edges, patch_kinds)

    add_kinds = coerce_string_list(curriculum.get("add", ()))
    if add_kinds:
        nodes, edges = _add_vulns_by_kind(nodes, edges, add_kinds, rng=rng)

    return WorldGraph(nodes=tuple(nodes), edges=tuple(edges))


def _drop_vulns_by_kind(
    nodes: list[Node],
    edges: list[Edge],
    kinds: list[str],
) -> tuple[list[Node], list[Edge]]:
    drop_ids = {
        node.id
        for node in nodes
        if node.type == "vulnerability" and str(node.attrs.get("kind")) in kinds
    }
    if not drop_ids:
        return nodes, edges
    new_nodes = [n for n in nodes if n.id not in drop_ids]
    new_edges = [
        e for e in edges if e.source not in drop_ids and e.target not in drop_ids
    ]
    return new_nodes, new_edges


def available_mutations(
    snapshot: Snapshot,
    reports: Sequence[EpisodeReport],
) -> tuple[Mutation, ...]:
    """Procedural enumeration of v1 cyber-pack mutations.

    For each vuln kind currently in the world, emit a ``patch`` Mutation
    tagged ``harden`` with relevance scored by how much agent traffic
    landed on the endpoints those vulns affect. For each catalog kind,
    emit an ``add`` Mutation tagged ``soften`` (kind not present) or
    ``diversify`` (already present) with static relevance.
    """
    graph = snapshot.world_graph
    vulns_by_kind = _vulns_by_kind(graph)
    paths_per_vuln = _affected_paths_per_vuln(graph)
    path_hits = _successful_path_hits(reports)

    options: list[Mutation] = []
    for kind, node_ids in vulns_by_kind.items():
        score = _exploitation_score(node_ids, paths_per_vuln, path_hits)
        relevance = max(score, _PATCH_RELEVANCE_FLOOR)
        options.append(
            Mutation(
                directive=MappingProxyType({"patch": [kind]}),
                direction="harden",
                relevance=relevance,
                note=(
                    f"patch {kind} ({len(node_ids)} instance(s); "
                    f"exploit score {score:.2f})"
                ),
            ),
        )

    for kind in VULN_CATALOG:
        if kind in vulns_by_kind:
            options.append(
                Mutation(
                    directive=MappingProxyType({"add": [kind]}),
                    direction="diversify",
                    relevance=_ADD_PRESENT_RELEVANCE,
                    note=f"add another {kind} on a fresh target",
                ),
            )
        else:
            options.append(
                Mutation(
                    directive=MappingProxyType({"add": [kind]}),
                    direction="soften",
                    relevance=_ADD_ABSENT_RELEVANCE,
                    note=f"introduce {kind}",
                ),
            )

    return tuple(options)


def _vulns_by_kind(graph: WorldGraph) -> dict[str, list[str]]:
    by_kind: dict[str, list[str]] = {}
    for node in graph.nodes:
        if node.type != "vulnerability":
            continue
        kind = str(node.attrs.get("kind", ""))
        if kind:
            by_kind.setdefault(kind, []).append(node.id)
    return by_kind


def _affected_paths_per_vuln(graph: WorldGraph) -> dict[str, set[str]]:
    """Map each vuln node id to the set of HTTP paths of endpoints it affects."""
    nodes_by_id = {n.id: n for n in graph.nodes}
    paths: dict[str, set[str]] = {}
    for edge in graph.edges:
        if edge.relation != "affects":
            continue
        vuln = nodes_by_id.get(edge.source)
        target = nodes_by_id.get(edge.target)
        if vuln is None or vuln.type != "vulnerability" or target is None:
            continue
        path = str(target.attrs.get("path", ""))
        if path:
            paths.setdefault(edge.source, set()).add(path)
    return paths


def _successful_path_hits(
    reports: Sequence[EpisodeReport],
) -> dict[str, int]:
    """Count non-error path hits across reports.

    Filters 4xx/5xx — we want paths the agent successfully interacted
    with, not paths it probed and got rejected on.
    """
    counts: dict[str, int] = {}
    for report in reports:
        requests = report.final_state.get("requests")
        if not isinstance(requests, list | tuple):
            continue
        for row in requests:
            if not isinstance(row, Mapping):
                continue
            try:
                status = int(row.get("status", 0))
            except TypeError, ValueError:
                continue
            if status >= 400:
                continue
            path = str(row.get("path", ""))
            if path:
                counts[path] = counts.get(path, 0) + 1
    return counts


def _exploitation_score(
    vuln_node_ids: Sequence[str],
    paths_per_vuln: Mapping[str, set[str]],
    path_hits: Mapping[str, int],
) -> float:
    """Fraction of successful agent requests that hit endpoints carrying
    a vuln of the given kind. 0..1; 0 if no signal."""
    if not path_hits:
        return 0.0
    affected: set[str] = set()
    for node_id in vuln_node_ids:
        affected.update(paths_per_vuln.get(node_id, ()))
    hits = sum(path_hits.get(p, 0) for p in affected)
    total = sum(path_hits.values())
    return min(1.0, hits / max(1, total))


def _add_vulns_by_kind(
    nodes: list[Node],
    edges: list[Edge],
    kinds: list[str],
    *,
    rng: random.Random,
) -> tuple[list[Node], list[Edge]]:
    endpoints = [n for n in nodes if n.type == "endpoint"]
    services = [n for n in nodes if n.type == "service"]
    if not endpoints and not services:
        return nodes, edges
    existing_ids = {n.id for n in nodes}
    existing_kinds_by_target: set[tuple[str, str]] = set()
    nodes_by_id: dict[str, Node] = {n.id: n for n in nodes}
    for edge in edges:
        if edge.relation != "affects":
            continue
        source_node = nodes_by_id.get(edge.source)
        if source_node is None or source_node.type != "vulnerability":
            continue
        existing_kinds_by_target.add(
            (str(source_node.attrs.get("kind")), edge.target),
        )
    new_nodes = list(nodes)
    new_edges = list(edges)
    for kind in kinds:
        if kind not in VULN_CATALOG:
            continue
        catalog_entry = VULN_CATALOG[kind]
        target_kinds = catalog_entry.target_kinds
        candidate_targets: list[Node]
        if "endpoint" in target_kinds:
            candidate_targets = endpoints
        elif "service" in target_kinds:
            candidate_targets = services
        else:
            continue
        target = next(
            (
                t
                for t in candidate_targets
                if (kind, t.id) not in existing_kinds_by_target
            ),
            None,
        )
        if target is None:
            continue
        index = 0
        while f"vuln_{kind}_{index}" in existing_ids:
            index += 1
        vuln_id = f"vuln_{kind}_{index}"
        existing_ids.add(vuln_id)
        new_nodes.append(
            Node(
                id=vuln_id,
                type="vulnerability",
                attrs=MappingProxyType(
                    {
                        "kind": kind,
                        "family": catalog_entry.family,
                        "params": default_vuln_params(kind, target, rng),
                    },
                ),
            ),
        )
        new_edges.append(
            Edge(
                source=vuln_id,
                relation="affects",
                target=target.id,
                attrs=MappingProxyType(
                    {"injection_site": str(target.attrs.get("path", "service"))},
                ),
            ),
        )
        existing_kinds_by_target.add((kind, target.id))
    return new_nodes, new_edges
