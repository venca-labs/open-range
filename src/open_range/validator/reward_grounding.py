"""Check 5: Reward grounding — verify flag values exist at expected paths."""

from __future__ import annotations

from open_range.protocols import CheckResult, ContainerSet, SnapshotSpec


class RewardGroundingCheck:
    """For every declared flag, ``docker exec cat <path>`` must return the
    expected value.  This ensures reward computation is grounded in real
    container state.
    """

    async def check(self, snapshot: SnapshotSpec, containers: ContainerSet) -> CheckResult:
        flags = snapshot.flags
        if not flags:
            return CheckResult(
                name="reward_grounding",
                passed=False,
                error="no flags defined in snapshot",
            )

        bad: list[dict] = []
        for flag in flags:
            host = flag.host
            path = flag.path

            # path might be a DB reference like "db:flags.secrets.flag" — only
            # check filesystem flags here (contain "/").
            if "/" not in path:
                # Non-filesystem flag (e.g. DB row). We cannot cat it directly.
                # Record it but don't fail — a deeper check would query the DB.
                bad.append({
                    "flag": flag.id,
                    "skipped": "non-filesystem path",
                    "path": path,
                })
                continue

            try:
                output = await containers.exec(host, f"cat {path}")
                output = output.strip()
            except Exception as exc:  # noqa: BLE001
                bad.append({"flag": flag.id, "error": str(exc)})
                continue

            if flag.value not in output:
                bad.append({
                    "flag": flag.id,
                    "expected": flag.value,
                    "got_snippet": output[:200],
                })

        # Filter actual failures (skip "skipped" entries)
        failures = [b for b in bad if "skipped" not in b]
        passed = len(failures) == 0
        return CheckResult(
            name="reward_grounding",
            passed=passed,
            details={"results": bad, "total_flags": len(flags)},
            error="" if passed else f"{len(failures)} flag(s) not found at expected path",
        )
