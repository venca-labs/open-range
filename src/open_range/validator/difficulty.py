"""Check 8: Difficulty calibration — golden path steps within tier target."""

from __future__ import annotations

from open_range.protocols import CheckResult, ContainerSet, SnapshotSpec

# Tier -> target golden-path step count.
TIER_TARGETS: dict[int, int] = {
    1: 8,
    2: 15,
    3: 25,
    4: 35,
    5: 50,
}

TOLERANCE = 0.20  # +/- 20%


class DifficultyCheck:
    """Verify golden-path step count is within +-20% of the tier target.

    Also rejects:
    - Single-step golden paths (trivial).
    - Duplicate consecutive commands (likely builder hallucination).
    - Vuln count outside manifest ``difficulty.min_vulns / max_vulns``.
    """

    async def check(self, snapshot: SnapshotSpec, containers: ContainerSet) -> CheckResult:
        issues: list[str] = []
        n_steps = len(snapshot.golden_path)

        # --- Step count vs tier target ----------------------------------------
        # Tier can come from topology metadata or default to 1.
        tier: int = snapshot.topology.get("tier", 1)
        target = TIER_TARGETS.get(tier, TIER_TARGETS[1])
        lo = int(target * (1 - TOLERANCE))
        hi = int(target * (1 + TOLERANCE))

        if n_steps < lo or n_steps > hi:
            issues.append(
                f"golden path has {n_steps} steps; tier {tier} target "
                f"is {target} (allowed {lo}-{hi})"
            )

        # --- Trivial path -----------------------------------------------------
        if n_steps <= 1:
            issues.append("golden path has <= 1 step (trivial)")

        # --- Duplicate consecutive commands -----------------------------------
        cmds = [s.command for s in snapshot.golden_path]
        for i in range(1, len(cmds)):
            if cmds[i] == cmds[i - 1]:
                issues.append(f"duplicate consecutive command at steps {i} and {i + 1}")

        # --- Vuln count bounds ------------------------------------------------
        difficulty = snapshot.topology.get("difficulty", {})
        min_v = difficulty.get("min_vulns")
        max_v = difficulty.get("max_vulns")
        n_vulns = len(snapshot.truth_graph.vulns)

        if min_v is not None and n_vulns < min_v:
            issues.append(f"only {n_vulns} vuln(s); minimum is {min_v}")
        if max_v is not None and n_vulns > max_v:
            issues.append(f"{n_vulns} vuln(s); maximum is {max_v}")

        passed = len(issues) == 0
        return CheckResult(
            name="difficulty",
            passed=passed,
            details={"steps": n_steps, "tier": tier, "target": target, "issues": issues},
            error="" if passed else "; ".join(issues),
        )
