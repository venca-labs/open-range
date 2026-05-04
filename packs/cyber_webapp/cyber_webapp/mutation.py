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
from collections.abc import Mapping
from types import MappingProxyType

from cyber_webapp.sampling import default_vuln_params
from cyber_webapp.vulnerabilities import CATALOG as VULN_CATALOG
from openrange.core.graph import Edge, Node, WorldGraph


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
                t for t in candidate_targets
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
