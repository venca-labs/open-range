"""Graph-native path solvability checks."""

from __future__ import annotations

from collections import defaultdict, deque

from open_range.protocols import CheckResult, ContainerSet, SnapshotSpec
from open_range.validator.graphs import CompiledGraphs, compile_snapshot_graphs


class PathSolvabilityCheck:
    """Verify that vuln and flag hosts are reachable in the compiled host graph."""

    async def check(self, snapshot: SnapshotSpec, containers: ContainerSet) -> CheckResult:
        compiled = compile_snapshot_graphs(snapshot)
        issues: list[str] = []

        if not compiled.hosts:
            return CheckResult(
                name="path_solvability",
                passed=False,
                error="snapshot has no compiled hosts",
            )

        start_hosts = _start_hosts(compiled)
        vuln_hosts = {v.host for v in snapshot.truth_graph.vulns if v.host}
        flag_hosts = {flag.host for flag in snapshot.flags if flag.host}
        target_hosts = sorted(vuln_hosts.union(flag_hosts))
        if not target_hosts:
            return CheckResult(
                name="path_solvability",
                passed=False,
                error="snapshot has no vuln or flag hosts to solve toward",
            )

        adjacency = build_host_adjacency(snapshot, compiled)
        unreachable = [
            host
            for host in target_hosts
            if not _reachable_from_any(host, start_hosts, adjacency)
        ]
        if unreachable:
            issues.append(f"unreachable target hosts from start set {sorted(start_hosts)}: {unreachable}")

        for flag_host in sorted(flag_hosts):
            if not (
                flag_host in vuln_hosts
                or _reachable_from_any(flag_host, vuln_hosts or start_hosts, adjacency)
            ):
                issues.append(
                    f"flag host '{flag_host}' is not grounded by any vuln host or start host"
                )

        passed = len(issues) == 0
        return CheckResult(
            name="path_solvability",
            passed=passed,
            details={
                "start_hosts": sorted(start_hosts),
                "target_hosts": target_hosts,
                "issues": issues,
            },
            error="" if passed else "; ".join(issues),
        )


def _start_hosts(compiled: CompiledGraphs) -> set[str]:
    starts = {
        host
        for host in compiled.hosts
        if host in {"attacker", "internet"}
        or compiled.zones_by_host.get(host) == "external"
    }
    if starts:
        return starts
    if compiled.hosts:
        return {sorted(compiled.hosts)[0]}
    return set()


def build_host_adjacency(
    snapshot: SnapshotSpec,
    compiled: CompiledGraphs,
) -> dict[str, set[str]]:
    adjacency: dict[str, set[str]] = defaultdict(set)
    for source, target in compiled.dependency_edges:
        adjacency[source].add(target)

    principal_hosts = _principal_hosts(snapshot)
    for source_principal, target_principal, _edge_type in compiled.trust_edges:
        source_hosts = principal_hosts.get(source_principal, set())
        target_hosts = principal_hosts.get(target_principal, set())
        for source_host in source_hosts:
            for target_host in target_hosts:
                if source_host and target_host:
                    adjacency[source_host].add(target_host)
    return adjacency


def has_host_path(
    start: str,
    target: str,
    adjacency: dict[str, set[str]],
) -> bool:
    return _has_path(start, target, adjacency)


def _principal_hosts(snapshot: SnapshotSpec) -> dict[str, set[str]]:
    topology = snapshot.topology or {}
    mapping: dict[str, set[str]] = defaultdict(set)

    raw_users = topology.get("users", [])
    if isinstance(raw_users, list):
        for raw in raw_users:
            if not isinstance(raw, dict):
                continue
            username = str(raw.get("username", "")).strip()
            if not username:
                continue
            for raw_host in raw.get("hosts", []):
                host = str(raw_host).strip()
                if host:
                    mapping[username].add(host)

    raw_catalog = topology.get("principal_catalog", {})
    if isinstance(raw_catalog, dict):
        for raw_name, raw_principal in raw_catalog.items():
            name = str(raw_name).strip()
            if not name or not isinstance(raw_principal, dict):
                continue
            for raw_host in raw_principal.get("hosts", []):
                host = str(raw_host).strip()
                if host:
                    mapping[name].add(host)

    return mapping


def _reachable_from_any(
    target: str,
    starts: set[str],
    adjacency: dict[str, set[str]],
) -> bool:
    for start in starts:
        if start == target:
            return True
        if _has_path(start, target, adjacency):
            return True
    return False


def _has_path(start: str, target: str, adjacency: dict[str, set[str]]) -> bool:
    queue: deque[str] = deque([start])
    seen = {start}
    while queue:
        current = queue.popleft()
        for neighbor in adjacency.get(current, set()):
            if neighbor == target:
                return True
            if neighbor in seen:
                continue
            seen.add(neighbor)
            queue.append(neighbor)
    return False
