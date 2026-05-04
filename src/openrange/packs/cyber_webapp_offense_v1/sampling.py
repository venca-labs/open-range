"""Graph sampling for the v1 cyber procedural builder.

Pure functions. Given an rng + priors, produce a fresh ``WorldGraph``
that conforms to the v1 ontology. Separate from the Builder class so
sampling logic can be tested in isolation and swapped out (an MCTS-
driven sampler would replace this module's ``sample_graph`` while
keeping the surrounding Builder unchanged).
"""

from __future__ import annotations

import random
from collections.abc import Mapping, Sequence
from types import MappingProxyType

from openrange.core.errors import PackError
from openrange.core.graph import Edge, Node, WorldGraph
from openrange.packs.cyber_vulnerabilities import CATALOG as VULN_CATALOG

_FLAG_NOUNS: tuple[str, ...] = (
    "atlas", "beacon", "cinder", "drift", "echo", "falcon",
    "gravity", "harbor", "ion", "jade", "krypton", "lattice",
    "meridian", "nimbus", "obsidian", "prism", "quartz", "raven",
    "summit", "tundra", "umbra", "vector", "wraith", "xenon",
    "yarrow", "zephyr",
)

# Endpoint path pool, sampled per-service. Small but realistic.
ENDPOINT_PATHS_BY_KIND: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "web": ("/", "/search", "/dashboard", "/profile"),
        "api": ("/api/items", "/api/orders", "/api/notes", "/api/health"),
        "auth": ("/login", "/token", "/users", "/me"),
        "db": ("/records", "/query", "/stats"),
    },
)


def generate_flag(rng: random.Random) -> str:
    """Generate a per-build flag of the form ``ORANGE{<word>_<word>_<n>}``.

    Deterministic given the rng. Distinct across rng seeds, so two
    builds with different seeds don't share a flag.
    """
    a = rng.choice(_FLAG_NOUNS)
    b = rng.choice(_FLAG_NOUNS)
    n = rng.randint(100, 999)
    return f"ORANGE{{{a}_{b}_{n}}}"


def sample_graph(rng: random.Random, priors: Mapping[str, object]) -> WorldGraph:
    """Draw one full world graph using the supplied priors."""
    nodes: list[Node] = []
    edges: list[Edge] = []
    network = Node(
        id="net_main",
        type="network",
        attrs=MappingProxyType(
            {"name": "main", "isolation": "bridge", "zone": "dmz"},
        ),
    )
    nodes.append(network)

    services = _sample_services(rng, priors)
    for index, service in enumerate(services):
        host = Node(
            id=f"host_{index}",
            type="host",
            attrs=MappingProxyType(
                {
                    "hostname": f"{service['name']}.example.test",
                    "os": "linux",
                    "zone": "dmz" if service["exposure"] == "public" else "corp",
                },
            ),
        )
        nodes.append(host)
        service_node = Node(
            id=f"svc_{service['name']}",
            type="service",
            attrs=MappingProxyType(dict(service)),
        )
        nodes.append(service_node)
        edges.append(Edge(source=service_node.id, relation="runs_on", target=host.id))
        edges.append(
            Edge(
                source=service_node.id,
                relation="connected_to",
                target=network.id,
            ),
        )
        for endpoint in _sample_endpoints(rng, priors, service):
            nodes.append(endpoint)
            edges.append(
                Edge(
                    source=service_node.id,
                    relation="exposes",
                    target=endpoint.id,
                ),
            )

    deepest = _pick_deepest_service(services)
    data_store = Node(
        id=f"ds_{deepest['name']}",
        type="data_store",
        attrs=MappingProxyType(
            {"name": deepest["name"], "kind": "kv", "engine": "in_memory"},
        ),
    )
    nodes.append(data_store)
    edges.append(
        Edge(
            source=f"svc_{deepest['name']}",
            relation="backed_by",
            target=data_store.id,
            attrs=MappingProxyType({"mode": "readwrite"}),
        ),
    )
    flag_value = generate_flag(rng)
    flag_record = Node(
        id="rec_admin_flag",
        type="record",
        attrs=MappingProxyType(
            {"key": "admin_flag", "fields": {"value": flag_value}},
        ),
    )
    nodes.append(flag_record)
    edges.append(
        Edge(source=data_store.id, relation="contains", target=flag_record.id),
    )
    flag_secret = Node(
        id="secret_flag",
        type="secret",
        attrs=MappingProxyType(
            {
                "kind": "flag",
                "value_ref": flag_value,
                "description": "admin flag awarded for retrieval",
            },
        ),
    )
    nodes.append(flag_secret)
    edges.append(
        Edge(
            source=flag_record.id,
            relation="holds",
            target=flag_secret.id,
            attrs=MappingProxyType({"field": "value"}),
        ),
    )

    account_nodes, credential_nodes, account_edges = _sample_accounts(rng, priors)
    nodes.extend(account_nodes)
    nodes.extend(credential_nodes)
    edges.extend(account_edges)

    deepest_service_id = f"svc_{deepest['name']}"
    vuln_nodes, vuln_edges = _sample_vulnerabilities(
        rng, priors, nodes, edges, oracle_service_id=deepest_service_id,
    )
    nodes.extend(vuln_nodes)
    edges.extend(vuln_edges)
    return WorldGraph(nodes=tuple(nodes), edges=tuple(edges))


def _sample_services(
    rng: random.Random, priors: Mapping[str, object],
) -> list[dict[str, str]]:
    count = sample_int(rng, priors, "service_count")
    kinds_pool = weighted_pool(priors, "service_kinds", exclude=("web",))
    services: list[dict[str, str]] = [
        {
            "name": "web",
            "kind": "web",
            "language": "python",
            "exposure": "public",
        },
    ]
    used_names = {"web"}
    for _ in range(count - 1):
        kind = rng.choice(kinds_pool) if kinds_pool else "api"
        name = _unique_name(kind, used_names)
        used_names.add(name)
        services.append(
            {
                "name": name,
                "kind": kind,
                "language": "python",
                "exposure": "internal",
            },
        )
    return services


def _sample_endpoints(
    rng: random.Random,
    priors: Mapping[str, object],
    service: Mapping[str, str],
) -> list[Node]:
    """Sample distinct endpoint paths for one service.

    Count is clamped to ``len(pool)`` — duplicate paths on the same
    service would silently shadow each other in the codegen route
    table. Prefer fewer endpoints over collisions.
    """
    count = sample_int(rng, priors, "endpoints_per_service")
    pool = list(ENDPOINT_PATHS_BY_KIND.get(service["kind"], ("/",)))
    rng.shuffle(pool)
    selected = pool[: min(count, len(pool))]
    endpoints: list[Node] = []
    for i, path in enumerate(selected):
        endpoints.append(
            Node(
                id=f"ep_{service['name']}_{i}",
                type="endpoint",
                attrs=MappingProxyType(
                    {
                        "path": path,
                        "method": "GET",
                        "auth_required": False,
                        "behavior_ref": f"{service['kind']}.default",
                    },
                ),
            ),
        )
    return endpoints


def _sample_accounts(
    rng: random.Random,
    priors: Mapping[str, object],
) -> tuple[list[Node], list[Node], list[Edge]]:
    # ``can_access`` edges are deferred — placement needs to know which
    # endpoints exist before wiring access. Today we only surface
    # accounts/credentials so the codegen can seed login data.
    count = sample_int(rng, priors, "account_count")
    accounts: list[Node] = []
    credentials: list[Node] = []
    edges: list[Edge] = []
    for i in range(count):
        is_admin = i == 0
        account = Node(
            id=f"acct_{i}",
            type="account",
            attrs=MappingProxyType(
                {
                    "username": "admin" if is_admin else f"user{i}",
                    "role": "admin" if is_admin else "user",
                    "active": True,
                },
            ),
        )
        accounts.append(account)
        credential = Node(
            id=f"cred_{i}",
            type="credential",
            attrs=MappingProxyType(
                {"kind": "password", "value_ref": f"hunter{i}!"},
            ),
        )
        credentials.append(credential)
        edges.append(
            Edge(
                source=account.id,
                relation="has_credential",
                target=credential.id,
            ),
        )
    return accounts, credentials, edges


def _sample_vulnerabilities(
    rng: random.Random,
    priors: Mapping[str, object],
    nodes: list[Node],
    edges: list[Edge],
    *,
    oracle_service_id: str | None = None,
) -> tuple[list[Node], list[Edge]]:
    """Place vulnerabilities so the oracle path is satisfiable.

    The first placed vuln is anchored to ``oracle_service_id`` (or one
    of its endpoints when the catalog entry targets endpoints). This
    guarantees the ``OraclePathExistsConstraint`` can be satisfied.
    Subsequent vulns are placed on randomly shuffled endpoints / services.
    """
    count = sample_int(rng, priors, "vuln_count")
    pool = weighted_pool(priors, "vuln_kinds")
    if not pool:
        return [], []
    endpoints = [n for n in nodes if n.type == "endpoint"]
    services = [n for n in nodes if n.type == "service"]
    if not endpoints:
        return [], []

    oracle_endpoints: list[Node] = []
    for edge in edges:
        if edge.relation == "exposes" and edge.source == oracle_service_id:
            for endpoint in endpoints:
                if endpoint.id == edge.target:
                    oracle_endpoints.append(endpoint)
    oracle_service: Node | None = None
    for service in services:
        if service.id == oracle_service_id:
            oracle_service = service
            break

    placed_vulns: list[Node] = []
    placed_edges: list[Edge] = []

    rng.shuffle(endpoints)
    for i in range(count):
        kind = rng.choice(pool)
        if kind not in VULN_CATALOG:
            continue
        catalog_entry = VULN_CATALOG[kind]
        target_kinds = catalog_entry.target_kinds
        target_node: Node | None = None
        if i == 0 and oracle_service_id is not None:
            if "endpoint" in target_kinds and oracle_endpoints:
                target_node = oracle_endpoints[0]
            elif "service" in target_kinds and oracle_service is not None:
                target_node = oracle_service
        if target_node is None:
            if "endpoint" in target_kinds:
                target_node = endpoints[i % len(endpoints)]
            elif "service" in target_kinds and services:
                target_node = services[i % len(services)]
            else:
                continue
        vuln_id = f"vuln_{kind}_{i}"
        vuln_node = Node(
            id=vuln_id,
            type="vulnerability",
            attrs=MappingProxyType(
                {
                    "kind": kind,
                    "family": catalog_entry.family,
                    "params": default_vuln_params(kind, target_node),
                },
            ),
        )
        placed_vulns.append(vuln_node)
        placed_edges.append(
            Edge(
                source=vuln_id,
                relation="affects",
                target=target_node.id,
                attrs=MappingProxyType(
                    {"injection_site": str(target_node.attrs.get("path", "service"))},
                ),
            ),
        )

    by_kind: dict[str, str] = {}
    for vuln in placed_vulns:
        kind = str(vuln.attrs["kind"])
        by_kind.setdefault(kind, vuln.id)
    for vuln in placed_vulns:
        kind = str(vuln.attrs["kind"])
        catalog_entry = VULN_CATALOG[kind]
        for next_kind in catalog_entry.enables:
            target_vuln = by_kind.get(next_kind)
            if target_vuln is not None and target_vuln != vuln.id:
                placed_edges.append(
                    Edge(source=vuln.id, relation="enables", target=target_vuln),
                )
    return placed_vulns, placed_edges


def default_vuln_params(kind: str, target: Node) -> dict[str, object]:
    """Default params per vuln kind. Used by both sampling and mutation.

    Kept terse on purpose — params differ by catalog entry, but per-target
    customization isn't necessary in v1; the realizer binds them at
    codegen time.
    """
    del target
    if kind == "sql_injection":
        return {
            "target_param": "q",
            "table": "records",
            "leak_column": "value",
        }
    if kind == "ssrf":
        return {
            "target_param": "url",
            "allowlist_pattern": r"^https?://internal\.",
        }
    if kind == "broken_authz":
        return {
            "trust_header": "X-User-Role",
            "expected_value": "admin",
            "leak_field": "value",
        }
    return {}


# ---------------------------------------------------------------------------
# Helpers (also reused by mutation.py)
# ---------------------------------------------------------------------------


def sample_int(
    rng: random.Random,
    priors: Mapping[str, object],
    key: str,
) -> int:
    spec = priors.get(key, {})
    if not isinstance(spec, Mapping):
        raise PackError(f"prior {key!r} must be a mapping")
    minimum_raw = spec.get("min", 1)
    maximum_raw = spec.get("max", 1)
    if not isinstance(minimum_raw, int) or not isinstance(maximum_raw, int):
        raise PackError(f"prior {key!r} bounds must be integers")
    if maximum_raw < minimum_raw:
        return minimum_raw
    return rng.randint(minimum_raw, maximum_raw)


def weighted_pool(
    priors: Mapping[str, object],
    key: str,
    *,
    exclude: tuple[str, ...] = (),
) -> list[str]:
    weights = priors.get(key, {})
    if not isinstance(weights, Mapping):
        raise PackError(f"prior {key!r} must be a mapping")
    pool: list[str] = []
    for name, weight in weights.items():
        if name in exclude:
            continue
        if not isinstance(weight, int):
            continue
        pool.extend([str(name)] * max(0, weight))
    return pool


def _unique_name(kind: str, used: set[str]) -> str:
    base = kind
    if base not in used:
        return base
    i = 1
    while f"{base}{i}" in used:
        i += 1
    return f"{base}{i}"


def _pick_deepest_service(
    services: Sequence[Mapping[str, str]],
) -> Mapping[str, str]:
    """Pick the service most likely to hold the flag.

    Preference: ``db`` > ``auth`` > ``api`` > ``web`` (so the flag is
    pulled out via a chain rather than sitting on the public service).
    """
    priority = {"db": 4, "auth": 3, "api": 2, "web": 1}
    return max(services, key=lambda svc: priority.get(svc["kind"], 0))
