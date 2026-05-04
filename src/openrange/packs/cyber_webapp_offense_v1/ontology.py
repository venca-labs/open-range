"""Cyber webapp offense ontology v1.

Defines the typed graph language the procedural builder samples over to
produce realistic cyber worlds. Multi-node-type structure that admits
real generation and combination.

Scope: HTTP-shaped web-offense scenarios at business scale (3-10
services, multi-host topologies, vulnerability chains across services).
Out of scope for v1: kubernetes-native primitives (CRDs, operators),
cloud-IAM-shaped permission graphs, defender NPCs, scheduled jobs.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from openrange.core.graph import (
    EdgeType,
    GraphConstraint,
    NodeType,
    ValidationError,
    WorldGraph,
    WorldSchema,
)

# ---------------------------------------------------------------------------
# Attribute schemas
# ---------------------------------------------------------------------------

# Schemas are nominal in v1 (Core does not enforce them deeply). Intent is
# documentation-as-code: a procedural builder consults these to know what
# attrs each node type expects, and tests can reject malformed graphs.

_HOST_ATTRS: Mapping[str, type] = {
    "hostname": str,
    "os": str,  # "linux" | "windows" | "container"
    "zone": str,  # "dmz" | "corp" | "data" | "management" | "external"
}

_SERVICE_ATTRS: Mapping[str, type] = {
    "name": str,
    "kind": str,  # "web" | "api" | "auth" | "db" | "queue" | "mail" | "fileshare"
    "language": str,  # "python" | "node" | "go" | ...
    "exposure": str,  # "public" | "internal" | "management"
}

_ENDPOINT_ATTRS: Mapping[str, type] = {
    "path": str,
    "method": str,  # "GET" | "POST" | ...
    "auth_required": bool,
    "behavior_ref": str,  # template ref the realizer renders
}

_ACCOUNT_ATTRS: Mapping[str, type] = {
    "username": str,
    "role": str,  # "user" | "admin" | "service"
    "active": bool,
}

_CREDENTIAL_ATTRS: Mapping[str, type] = {
    "kind": str,  # "password" | "api_key" | "session" | "token"
    "value_ref": str,  # opaque ref the realizer resolves
}

_SECRET_ATTRS: Mapping[str, type] = {
    "kind": str,  # "flag" | "api_key" | "password" | "private_key"
    "value_ref": str,
    "description": str,
}

_VULNERABILITY_ATTRS: Mapping[str, type] = {
    "kind": str,  # catalog id: "sql_injection", "ssrf", "broken_authz", ...
    "family": str,  # "code_web" | "config_identity" | "secret_exposure" | ...
    "params": dict,  # vuln-specific tuning (e.g. SQLi target column)
}

_NETWORK_ATTRS: Mapping[str, type] = {
    "name": str,
    "isolation": str,  # "bridge" | "host" | "isolated"
    "zone": str,
}

_DATA_STORE_ATTRS: Mapping[str, type] = {
    "name": str,
    "kind": str,  # "sql" | "kv" | "file" | "object"
    "engine": str,  # "sqlite" | "postgres" | "redis" | ...
}

_RECORD_ATTRS: Mapping[str, type] = {
    "key": str,
    "fields": dict,  # column name -> seed value (or value_ref for secrets)
}


# ---------------------------------------------------------------------------
# Node + edge type tables
# ---------------------------------------------------------------------------


NODE_TYPES: tuple[NodeType, ...] = (
    NodeType("host", _HOST_ATTRS),
    NodeType("service", _SERVICE_ATTRS),
    NodeType("endpoint", _ENDPOINT_ATTRS),
    NodeType("account", _ACCOUNT_ATTRS),
    NodeType("credential", _CREDENTIAL_ATTRS),
    NodeType("secret", _SECRET_ATTRS),
    NodeType("vulnerability", _VULNERABILITY_ATTRS),
    NodeType("network", _NETWORK_ATTRS),
    NodeType("data_store", _DATA_STORE_ATTRS),
    NodeType("record", _RECORD_ATTRS),
)


# Edge attribute schemas
_EXPOSES_ATTRS: Mapping[str, type] = {}
_BACKED_BY_ATTRS: Mapping[str, type] = {"mode": str}  # "read" | "write" | "readwrite"
_CONTAINS_ATTRS: Mapping[str, type] = {}
_HOLDS_ATTRS: Mapping[str, type] = {"field": str}
_HAS_CREDENTIAL_ATTRS: Mapping[str, type] = {}
_CAN_ACCESS_ATTRS: Mapping[str, type] = {"auth_method": str}
_RUNS_ON_ATTRS: Mapping[str, type] = {}
_CONNECTED_TO_ATTRS: Mapping[str, type] = {}
_AFFECTS_ATTRS: Mapping[str, type] = {"injection_site": str}  # path / param / handler
_ENABLES_ATTRS: Mapping[str, type] = {}  # vuln chain: vuln A enables vuln B
_DERIVES_ATTRS: Mapping[str, type] = {}  # credential derives from secret


EDGE_TYPES: tuple[EdgeType, ...] = (
    EdgeType("service", "exposes", "endpoint", _EXPOSES_ATTRS),
    EdgeType("service", "backed_by", "data_store", _BACKED_BY_ATTRS),
    EdgeType("data_store", "contains", "record", _CONTAINS_ATTRS),
    EdgeType("record", "holds", "secret", _HOLDS_ATTRS),
    EdgeType("account", "has_credential", "credential", _HAS_CREDENTIAL_ATTRS),
    EdgeType("account", "can_access", "endpoint", _CAN_ACCESS_ATTRS),
    EdgeType("service", "runs_on", "host", _RUNS_ON_ATTRS),
    EdgeType("service", "connected_to", "network", _CONNECTED_TO_ATTRS),
    EdgeType("vulnerability", "affects", "endpoint", _AFFECTS_ATTRS),
    EdgeType("vulnerability", "affects", "service", _AFFECTS_ATTRS),
    EdgeType("vulnerability", "enables", "vulnerability", _ENABLES_ATTRS),
    EdgeType("credential", "derives", "secret", _DERIVES_ATTRS),
)


# ---------------------------------------------------------------------------
# Graph constraints
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NoOrphanNodesConstraint(GraphConstraint):
    """Every node must be referenced by at least one edge.

    Exemptions: ``host`` and ``network`` may be orphaned (they're scaffolding;
    a graph with one isolated host is still valid). The intent is to catch
    accidentally dropped references — accounts with no credentials, vulns
    affecting nothing, etc.
    """

    exempt_types: frozenset[str] = frozenset({"host", "network"})

    def validate(self, graph: WorldGraph) -> list[ValidationError]:
        referenced: set[str] = set()
        for edge in graph.edges:
            referenced.add(edge.source)
            referenced.add(edge.target)
        errors: list[ValidationError] = []
        for node in graph.nodes:
            if node.type in self.exempt_types:
                continue
            if node.id not in referenced:
                errors.append(
                    ValidationError(
                        f"orphan node {node.id!r} (type {node.type!r})",
                        node_id=node.id,
                    ),
                )
        return errors


@dataclass(frozen=True)
class SecretReachableConstraint(GraphConstraint):
    """Every secret must be reachable from a record via ``holds``.

    A secret floating in the graph with no record holding it is a bug —
    the realizer wouldn't know where to seed the value.
    """

    def validate(self, graph: WorldGraph) -> list[ValidationError]:
        held_secrets = {
            edge.target
            for edge in graph.edges
            if edge.relation == "holds"
        }
        errors: list[ValidationError] = []
        for node in graph.nodes:
            if node.type == "secret" and node.id not in held_secrets:
                errors.append(
                    ValidationError(
                        f"secret {node.id!r} is not held by any record",
                        node_id=node.id,
                    ),
                )
        return errors


@dataclass(frozen=True)
class OraclePathExistsConstraint(GraphConstraint):
    """At least one secret must be reachable through an attack chain.

    Concrete check (v1, deliberately permissive):
        - There exists a flag-kind secret S
        - S is held by record R in data_store D
        - Some service V is backed_by D
        - V exposes some endpoint E
        - Some vulnerability affects E (or affects V directly)

    This doesn't prove the chain works at runtime; it proves the graph
    *describes* a feasible chain. Runtime feasibility is checked by the
    admission probe.
    """

    def validate(self, graph: WorldGraph) -> list[ValidationError]:
        flags = [
            n
            for n in graph.nodes
            if n.type == "secret" and n.attrs.get("kind") == "flag"
        ]
        if not flags:
            return [
                ValidationError(
                    "no flag-kind secret in graph; agents cannot complete a task",
                ),
            ]
        # Build adjacency once.
        holds_by_secret: dict[str, str] = {}
        contains_by_record: dict[str, str] = {}
        backed_by_store: dict[str, list[str]] = {}
        exposes_by_service: dict[str, list[str]] = {}
        vuln_targets: set[str] = set()
        for edge in graph.edges:
            if edge.relation == "holds":
                holds_by_secret[edge.target] = edge.source
            elif edge.relation == "contains":
                contains_by_record[edge.target] = edge.source
            elif edge.relation == "backed_by":
                backed_by_store.setdefault(edge.target, []).append(edge.source)
            elif edge.relation == "exposes":
                exposes_by_service.setdefault(edge.source, []).append(edge.target)
            elif edge.relation == "affects":
                vuln_targets.add(edge.target)
        errors: list[ValidationError] = []
        for flag in flags:
            record_id = holds_by_secret.get(flag.id)
            if record_id is None:
                # SecretReachable will already complain; skip duplicate
                continue
            store_id = contains_by_record.get(record_id)
            if store_id is None:
                errors.append(
                    ValidationError(
                        f"flag {flag.id!r}: holding record {record_id!r} not contained "
                        f"in any data_store",
                        node_id=flag.id,
                    ),
                )
                continue
            services = backed_by_store.get(store_id, [])
            if not services:
                errors.append(
                    ValidationError(
                        f"flag {flag.id!r}: data_store {store_id!r} has no service "
                        f"backing it (no attack surface)",
                        node_id=flag.id,
                    ),
                )
                continue
            chain_found = False
            for service_id in services:
                if service_id in vuln_targets:
                    chain_found = True
                    break
                for endpoint_id in exposes_by_service.get(service_id, []):
                    if endpoint_id in vuln_targets:
                        chain_found = True
                        break
                if chain_found:
                    break
            if not chain_found:
                errors.append(
                    ValidationError(
                        f"flag {flag.id!r}: no vulnerability affects any service or "
                        f"endpoint in the path (no oracle chain)",
                        node_id=flag.id,
                    ),
                )
        return errors


# ---------------------------------------------------------------------------
# Composed schema
# ---------------------------------------------------------------------------


ONTOLOGY = WorldSchema(
    node_types=NODE_TYPES,
    edge_types=EDGE_TYPES,
    constraints=(
        NoOrphanNodesConstraint(),
        SecretReachableConstraint(),
        OraclePathExistsConstraint(),
    ),
)


__all__ = [
    "EDGE_TYPES",
    "NODE_TYPES",
    "ONTOLOGY",
    "NoOrphanNodesConstraint",
    "OraclePathExistsConstraint",
    "SecretReachableConstraint",
]
