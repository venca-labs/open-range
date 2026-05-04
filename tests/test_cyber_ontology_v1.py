"""Cyber ontology v1 tests.

Validates the schema's structural shape and exercises each ``GraphConstraint``
with an example world that passes and one that fails.
"""

from __future__ import annotations

from openrange.core.graph import Edge, Node, WorldGraph
from openrange.packs.cyber_ontology import (
    CYBER_EDGE_TYPES,
    CYBER_NODE_TYPES,
    CYBER_WEBAPP_ONTOLOGY_V1,
    NoOrphanNodesConstraint,
    OraclePathExistsConstraint,
    SecretReachableConstraint,
)


def _node(id_: str, type_: str, **attrs: object) -> Node:
    return Node(id=id_, type=type_, attrs=attrs)


def _edge(source: str, relation: str, target: str, **attrs: object) -> Edge:
    return Edge(source=source, relation=relation, target=target, attrs=attrs)


def _minimal_valid_world() -> WorldGraph:
    """A two-service flag-retrieval world that passes all v1 constraints.

    Topology:
      web (kind=web) exposes /search; vulnerability:sqli affects /search
      web backed_by db (sqlite); db contains record:flag_row; record holds flag
      account:user has_credential password; can_access /search

    The flag is reachable via SQLi on /search → db read → flag exfiltration.
    """
    return WorldGraph(
        nodes=(
            _node("web", "service", name="web", kind="web", language="python",
                  exposure="public"),
            _node("ep_search", "endpoint", path="/search", method="GET",
                  auth_required=False, behavior_ref="handlers.search"),
            _node("db", "data_store", name="appdb", kind="sql", engine="sqlite"),
            _node("flag_row", "record", key="rows/admin",
                  fields={"value": "{flag}"}),
            _node("flag", "secret", kind="flag", value_ref="flag-1",
                  description="admin flag"),
            _node("user_a", "account", username="alice", role="user", active=True),
            _node("cred_a", "credential", kind="password", value_ref="alice-pw"),
            _node("vuln_sqli", "vulnerability", kind="sql_injection",
                  family="code_web", params={"target_param": "q"}),
        ),
        edges=(
            _edge("web", "exposes", "ep_search"),
            _edge("web", "backed_by", "db", mode="readwrite"),
            _edge("db", "contains", "flag_row"),
            _edge("flag_row", "holds", "flag", field="value"),
            _edge("user_a", "has_credential", "cred_a"),
            _edge("user_a", "can_access", "ep_search", auth_method="session"),
            _edge("vuln_sqli", "affects", "ep_search", injection_site="param.q"),
        ),
    )


def test_minimal_world_passes_all_constraints() -> None:
    graph = _minimal_valid_world()
    errors = CYBER_WEBAPP_ONTOLOGY_V1.validate(graph)
    assert errors == [], f"expected no errors, got: {[e.message for e in errors]}"


def test_orphan_account_rejected() -> None:
    graph = _minimal_valid_world()
    # Add an orphan account that references nothing.
    graph = WorldGraph(
        nodes=(
            *graph.nodes,
            _node("orphan", "account", username="bob", role="user", active=True),
        ),
        edges=graph.edges,
    )
    errors = NoOrphanNodesConstraint().validate(graph)
    assert any("orphan" in e.message for e in errors), errors


def test_orphan_host_allowed() -> None:
    """Hosts and networks are exempt from orphan check (scaffolding)."""
    graph = WorldGraph(
        nodes=(
            _node(
                "scratch_host", "host",
                hostname="dev", os="linux", zone="management",
            ),
        ),
    )
    errors = NoOrphanNodesConstraint().validate(graph)
    assert errors == []


def test_unheld_secret_rejected() -> None:
    graph = WorldGraph(
        nodes=(
            _node("dangling", "secret", kind="flag", value_ref="x",
                  description="unheld"),
        ),
    )
    errors = SecretReachableConstraint().validate(graph)
    assert len(errors) == 1
    assert "not held by any record" in errors[0].message


def test_oracle_path_no_flag_rejected() -> None:
    graph = WorldGraph(nodes=(), edges=())
    errors = OraclePathExistsConstraint().validate(graph)
    assert any("no flag-kind secret" in e.message for e in errors)


def test_oracle_path_no_vulnerability_rejected() -> None:
    """Flag exists, record exists, store exists, service exists — but no vuln."""
    graph = WorldGraph(
        nodes=(
            _node("svc", "service", name="web", kind="web", language="python",
                  exposure="public"),
            _node("ds", "data_store", name="db", kind="sql", engine="sqlite"),
            _node("rec", "record", key="row", fields={}),
            _node("flag", "secret", kind="flag", value_ref="x", description="f"),
            _node("ep", "endpoint", path="/", method="GET", auth_required=False,
                  behavior_ref="x"),
        ),
        edges=(
            _edge("svc", "backed_by", "ds", mode="read"),
            _edge("svc", "exposes", "ep"),
            _edge("ds", "contains", "rec"),
            _edge("rec", "holds", "flag"),
        ),
    )
    errors = OraclePathExistsConstraint().validate(graph)
    assert any("no oracle chain" in e.message for e in errors)


def test_oracle_path_disconnected_store_rejected() -> None:
    """Flag is held but the data_store has no service backing it."""
    graph = WorldGraph(
        nodes=(
            _node("ds", "data_store", name="db", kind="sql", engine="sqlite"),
            _node("rec", "record", key="row", fields={}),
            _node("flag", "secret", kind="flag", value_ref="x", description="f"),
        ),
        edges=(
            _edge("ds", "contains", "rec"),
            _edge("rec", "holds", "flag"),
        ),
    )
    errors = OraclePathExistsConstraint().validate(graph)
    assert any(
        "no service backing" in e.message
        for e in errors
    ), [e.message for e in errors]


def test_schema_node_and_edge_types_complete() -> None:
    """Sanity: all expected node and edge types are declared."""
    expected_nodes = {
        "host", "service", "endpoint", "account", "credential",
        "secret", "vulnerability", "network", "data_store", "record",
    }
    declared = {nt.name for nt in CYBER_NODE_TYPES}
    assert declared == expected_nodes

    expected_edges = {
        ("service", "exposes", "endpoint"),
        ("service", "backed_by", "data_store"),
        ("data_store", "contains", "record"),
        ("record", "holds", "secret"),
        ("account", "has_credential", "credential"),
        ("account", "can_access", "endpoint"),
        ("service", "runs_on", "host"),
        ("service", "connected_to", "network"),
        ("vulnerability", "affects", "endpoint"),
        ("vulnerability", "affects", "service"),
        ("vulnerability", "enables", "vulnerability"),
        ("credential", "derives", "secret"),
    }
    declared_edges = {
        (et.source_type, et.relation, et.target_type)
        for et in CYBER_EDGE_TYPES
    }
    assert declared_edges == expected_edges


def test_schema_validate_unknown_node_type_caught() -> None:
    graph = WorldGraph(nodes=(_node("x", "imaginary"),))
    errors = CYBER_WEBAPP_ONTOLOGY_V1.validate(graph)
    assert any("unknown node type" in e.message for e in errors)


def test_realistic_two_service_chain_passes() -> None:
    """Two services, vuln chain spanning them — the C0 'business shape' target.

    web exposes /fetch (vulnerable to SSRF) → ssrf vuln enables credential leak
    on internal admin service → admin service has flag in its data store.
    """
    graph = WorldGraph(
        nodes=(
            # Two services on different hosts, on a shared internal network.
            _node("web", "service", name="web", kind="web", language="python",
                  exposure="public"),
            _node("admin", "service", name="admin", kind="api", language="python",
                  exposure="internal"),
            _node("net_int", "network", name="internal", isolation="bridge",
                  zone="corp"),
            _node("host_dmz", "host", hostname="dmz-01", os="linux", zone="dmz"),
            _node("host_corp", "host", hostname="corp-01", os="linux", zone="corp"),
            # Endpoints
            _node("ep_fetch", "endpoint", path="/fetch", method="GET",
                  auth_required=False, behavior_ref="handlers.fetch"),
            _node("ep_admin_secret", "endpoint", path="/admin/secret", method="GET",
                  auth_required=True, behavior_ref="handlers.admin_secret"),
            # Data + flag
            _node("admin_db", "data_store", name="admin_db", kind="kv",
                  engine="redis"),
            _node("flag_rec", "record", key="config/master",
                  fields={"flag": "{flag}"}),
            _node("flag", "secret", kind="flag", value_ref="flag-2",
                  description="master api key"),
            # Vuln chain: SSRF on web enables admin endpoint hit
            _node("vuln_ssrf", "vulnerability", kind="ssrf", family="code_web",
                  params={"target_param": "url"}),
            _node("vuln_authz", "vulnerability", kind="broken_authz",
                  family="code_web",
                  params={"trust_header": "X-Internal-Origin"}),
        ),
        edges=(
            _edge("web", "exposes", "ep_fetch"),
            _edge("admin", "exposes", "ep_admin_secret"),
            _edge("admin", "backed_by", "admin_db", mode="read"),
            _edge("admin_db", "contains", "flag_rec"),
            _edge("flag_rec", "holds", "flag", field="flag"),
            _edge("web", "runs_on", "host_dmz"),
            _edge("admin", "runs_on", "host_corp"),
            _edge("web", "connected_to", "net_int"),
            _edge("admin", "connected_to", "net_int"),
            _edge("vuln_ssrf", "affects", "ep_fetch", injection_site="param.url"),
            _edge("vuln_authz", "affects", "ep_admin_secret",
                  injection_site="header.X-Internal-Origin"),
            _edge("vuln_ssrf", "enables", "vuln_authz"),
        ),
    )
    errors = CYBER_WEBAPP_ONTOLOGY_V1.validate(graph)
    assert errors == [], [e.message for e in errors]
