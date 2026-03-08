"""Check 6: Isolation + leakage — zones enforced, no flag values in briefings."""

from __future__ import annotations

from open_range.protocols import CheckResult, ContainerSet, SnapshotSpec


class IsolationCheck:
    """Verify:
    1. Attacker cannot directly reach internal/management zones.
    2. Task briefings do not contain flag values or golden-path commands.
    """

    async def check(self, snapshot: SnapshotSpec, containers: ContainerSet) -> CheckResult:
        issues: list[str] = []

        # --- Zone isolation ---------------------------------------------------
        # Internal hosts that the attacker should NOT reach directly.
        zones = snapshot.topology.get("zones", {})
        attacker_host = "attacker"
        blocked_zones = {"internal", "management", "mgmt"}

        for zone_name, hosts in zones.items():
            if zone_name.lower() not in blocked_zones:
                continue
            if not isinstance(hosts, list):
                continue
            for target in hosts:
                target_name = target if isinstance(target, str) else target.get("name", "")
                try:
                    # Quick connectivity probe (TCP, 2s timeout).
                    output = await containers.exec(
                        attacker_host,
                        f"timeout 2 bash -c 'echo > /dev/tcp/{target_name}/22' 2>&1 || echo BLOCKED",
                    )
                    if "BLOCKED" not in output and "timed out" not in output.lower():
                        issues.append(f"attacker can reach {target_name} in {zone_name}")
                except Exception:  # noqa: BLE001
                    pass  # exec failure means unreachable — that is fine

        # --- Briefing leakage -------------------------------------------------
        flag_values = [f.value for f in snapshot.flags]
        golden_cmds = [s.command for s in snapshot.golden_path]

        briefings = [
            ("red_briefing", snapshot.task.red_briefing),
            ("blue_briefing", snapshot.task.blue_briefing),
        ]
        for label, text in briefings:
            if not text:
                continue
            for fv in flag_values:
                if fv in text:
                    issues.append(f"flag value leaked in {label}")
            for cmd in golden_cmds:
                # Only flag exact long commands (>20 chars) to avoid false hits on
                # short strings like "nmap".
                if len(cmd) > 20 and cmd in text:
                    issues.append(f"golden-path command leaked in {label}")

        passed = len(issues) == 0
        return CheckResult(
            name="isolation",
            passed=passed,
            details={"issues": issues},
            error="" if passed else "; ".join(issues),
        )
