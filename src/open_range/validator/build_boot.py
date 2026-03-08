"""Check 1: Build + boot — verify all containers are healthy."""

from __future__ import annotations

from open_range.protocols import CheckResult, ContainerSet, SnapshotSpec


class BuildBootCheck:
    """Verify every host declared in the topology is running and healthy."""

    async def check(self, snapshot: SnapshotSpec, containers: ContainerSet) -> CheckResult:
        topology = snapshot.topology
        hosts: list[str] = topology.get("hosts", [])
        # hosts may be a list of dicts with "name" keys or plain strings.
        host_names: list[str] = []
        for h in hosts:
            if isinstance(h, dict):
                host_names.append(h.get("name", ""))
            else:
                host_names.append(str(h))

        if not host_names:
            return CheckResult(
                name="build_boot",
                passed=False,
                error="no hosts defined in topology",
            )

        unhealthy: list[str] = []
        for name in host_names:
            try:
                ok = await containers.is_healthy(name)
                if not ok:
                    unhealthy.append(name)
            except Exception as exc:  # noqa: BLE001
                unhealthy.append(f"{name} ({exc})")

        passed = len(unhealthy) == 0
        return CheckResult(
            name="build_boot",
            passed=passed,
            details={"unhealthy": unhealthy, "checked": host_names},
            error="" if passed else f"unhealthy containers: {', '.join(unhealthy)}",
        )
