"""Graph-native reward grounding checks."""

from __future__ import annotations

from open_range.protocols import CheckResult, ContainerSet, SnapshotSpec
from open_range.validator.graphs import compile_snapshot_graphs
from open_range.validator.path_solvability import build_host_adjacency, has_host_path


class GraphRewardGroundingCheck:
    """Verify rewards are grounded by graph facts before live checks run."""

    async def check(self, snapshot: SnapshotSpec, containers: ContainerSet) -> CheckResult:
        compiled = compile_snapshot_graphs(snapshot)
        issues: list[str] = []

        if not snapshot.flags:
            return CheckResult(
                name="graph_reward_grounding",
                passed=False,
                error="snapshot has no flags to ground",
            )

        adjacency = build_host_adjacency(snapshot, compiled)
        vuln_hosts = {v.host for v in snapshot.truth_graph.vulns if v.host}
        for flag in snapshot.flags:
            if flag.host not in compiled.hosts:
                issues.append(f"flag '{flag.id}' references unknown host '{flag.host}'")
                continue

            if flag.host in vuln_hosts:
                continue

            if vuln_hosts and not any(
                has_host_path(source, flag.host, adjacency) for source in vuln_hosts
            ):
                issues.append(
                    f"flag '{flag.id}' on '{flag.host}' is not reachable from any vuln host"
                )

        passed = len(issues) == 0
        return CheckResult(
            name="graph_reward_grounding",
            passed=passed,
            details={"issues": issues},
            error="" if passed else "; ".join(issues),
        )
