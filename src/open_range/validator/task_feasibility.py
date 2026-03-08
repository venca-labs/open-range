"""Check 7: Task feasibility — golden path references real hosts, evidence targets exist."""

from __future__ import annotations

from open_range.protocols import CheckResult, ContainerSet, SnapshotSpec


class TaskFeasibilityCheck:
    """Verify:
    1. Every golden-path step references a host that exists in the topology.
    2. Every evidence_spec item references a container that exists.
    3. Red's exploit chain references vulns that exist in truth_graph.
    """

    async def check(self, snapshot: SnapshotSpec, containers: ContainerSet) -> CheckResult:
        issues: list[str] = []

        # Collect known host names from topology.
        topo_hosts: set[str] = set()
        raw_hosts = snapshot.topology.get("hosts", [])
        for h in raw_hosts:
            if isinstance(h, dict):
                topo_hosts.add(h.get("name", ""))
            else:
                topo_hosts.add(str(h))
        topo_hosts.discard("")

        # 1. Golden-path hosts exist in topology.
        for step in snapshot.golden_path:
            host = getattr(step, "host", None) or "attacker"
            if host not in topo_hosts and topo_hosts:
                issues.append(f"golden path step {step.step}: host '{host}' not in topology")

        # 2. Evidence targets reference existing containers.
        for item in snapshot.evidence_spec:
            loc = item.location
            if ":" in loc:
                host = loc.split(":")[0]
            else:
                host = "siem"
            if host not in topo_hosts and topo_hosts:
                issues.append(f"evidence item '{item.type}' references unknown host '{host}'")

        # 3. Exploit chain vuln IDs exist in truth_graph.
        vuln_ids = {v.id for v in snapshot.truth_graph.vulns}
        for step in snapshot.truth_graph.exploit_chain:
            if step.vuln_id and step.vuln_id not in vuln_ids:
                issues.append(f"exploit chain references unknown vuln '{step.vuln_id}'")

        # 4. Flag hosts exist in topology.
        for flag in snapshot.flags:
            if flag.host not in topo_hosts and topo_hosts:
                issues.append(f"flag '{flag.id}' references unknown host '{flag.host}'")

        passed = len(issues) == 0
        return CheckResult(
            name="task_feasibility",
            passed=passed,
            details={"issues": issues},
            error="" if passed else f"{len(issues)} feasibility issue(s)",
        )
