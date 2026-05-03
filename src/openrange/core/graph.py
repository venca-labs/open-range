"""Graph and runtime-bundle types shared across packs and builders.

These types define the shape that flows through the build pipeline:
builders produce a ``WorldGraph`` that conforms to a pack's ``WorldSchema``;
packs realize that graph into a ``RuntimeBundle`` containing the concrete
artifacts and entrypoints the runtime needs to start the world.

Core never inspects node or edge attribute contents — interpretation lives
inside packs. Validation is delegated to the pack-supplied schema.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class ValidationError:
    """A schema or constraint violation reported by a pack."""

    message: str
    node_id: str | None = None
    edge: tuple[str, str, str] | None = None  # (source, relation, target)


@dataclass(frozen=True, slots=True)
class Ref:
    """Pointer to an asset shipped inside a pack package.

    Resolved by the owning pack's ``realize()`` — Core never resolves Refs.
    Packs may also use plain strings for code references; ``Ref`` is the
    typed option for packs that want it.
    """

    pack_id: str
    asset_path: str


@dataclass(frozen=True, slots=True)
class Node:
    id: str
    type: str
    attrs: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Edge:
    source: str
    relation: str
    target: str
    attrs: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class NodeType:
    name: str
    attrs_schema: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EdgeType:
    source_type: str
    relation: str
    target_type: str
    attrs_schema: Mapping[str, Any] = field(default_factory=dict)


class GraphConstraint(Protocol):
    """Pack-defined invariant beyond per-node attr validation.

    Examples: 'every secret must be reachable from at least one record',
    'no orphan nodes'. Implementations return zero or more
    ``ValidationError``s describing what failed.
    """

    def validate(self, graph: WorldGraph) -> list[ValidationError]: ...


@dataclass(frozen=True, slots=True)
class WorldSchema:
    """A pack's ontology: node types, edge types, and structural constraints."""

    node_types: tuple[NodeType, ...] = ()
    edge_types: tuple[EdgeType, ...] = ()
    constraints: tuple[GraphConstraint, ...] = ()

    def validate(self, graph: WorldGraph) -> list[ValidationError]:
        errors: list[ValidationError] = []
        node_type_names = {nt.name for nt in self.node_types}
        edge_signatures = {
            (et.source_type, et.relation, et.target_type) for et in self.edge_types
        }
        node_index: dict[str, Node] = {}
        for node in graph.nodes:
            if node.type not in node_type_names:
                errors.append(
                    ValidationError(
                        f"unknown node type {node.type!r}",
                        node_id=node.id,
                    ),
                )
            if node.id in node_index:
                errors.append(
                    ValidationError(
                        f"duplicate node id {node.id!r}",
                        node_id=node.id,
                    ),
                )
            node_index[node.id] = node
        for edge in graph.edges:
            source = node_index.get(edge.source)
            target = node_index.get(edge.target)
            if source is None or target is None:
                errors.append(
                    ValidationError(
                        "edge references unknown node",
                        edge=(edge.source, edge.relation, edge.target),
                    ),
                )
                continue
            signature = (source.type, edge.relation, target.type)
            if edge_signatures and signature not in edge_signatures:
                errors.append(
                    ValidationError(
                        f"edge {signature!r} does not match any declared edge type",
                        edge=(edge.source, edge.relation, edge.target),
                    ),
                )
        for constraint in self.constraints:
            errors.extend(constraint.validate(graph))
        return errors


@dataclass(frozen=True, slots=True)
class WorldGraph:
    """A typed graph of nodes and edges produced by a builder."""

    nodes: tuple[Node, ...] = ()
    edges: tuple[Edge, ...] = ()

    def node(self, node_id: str) -> Node:
        for node in self.nodes:
            if node.id == node_id:
                return node
        raise KeyError(f"unknown node id {node_id!r}")

    def nodes_of(self, type_name: str) -> tuple[Node, ...]:
        return tuple(node for node in self.nodes if node.type == type_name)


@dataclass(frozen=True, slots=True)
class RuntimeArtifact:
    """One realized piece of a world: a file, container, process, etc.

    The ``kind`` is a string, not an enum, so packs can introduce new
    artifact kinds without Core changes. Core does not interpret
    ``metadata`` — the runtime backing for each kind reads it.
    """

    id: str
    kind: str
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RuntimeBundle:
    """The output of ``Pack.realize()``: artifacts plus their entrypoints.

    Carries everything the runtime needs to start the world. The
    ``entrypoints`` field is typed loosely so existing ``Entrypoint``
    instances from ``openrange.core.pack`` can flow through unchanged
    while richer entrypoint types are introduced incrementally.
    """

    artifacts: tuple[RuntimeArtifact, ...] = ()
    entrypoints: tuple[Any, ...] = ()

    def files(self) -> Mapping[str, str]:
        """Path-to-content view of the bundle's filesystem artifacts."""
        from types import MappingProxyType

        return MappingProxyType(
            {
                str(artifact.metadata["path"]): str(artifact.metadata["content"])
                for artifact in self.artifacts
                if artifact.kind == "file"
            },
        )
