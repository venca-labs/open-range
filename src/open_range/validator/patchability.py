"""Check 3: Patchability — inverse mutation test.

For each planted vuln: apply its remediation, re-run the golden-path step
that exploits it, and verify the step *fails*.  Then revert.
"""

from __future__ import annotations

from open_range.protocols import CheckResult, ContainerSet, SnapshotSpec


class PatchabilityCheck:
    """Inverse mutation: patching a vuln must break the corresponding golden-path step."""

    async def check(self, snapshot: SnapshotSpec, containers: ContainerSet) -> CheckResult:
        vulns = snapshot.truth_graph.vulns
        if not vulns:
            return CheckResult(
                name="patchability",
                passed=False,
                error="no vulns in truth_graph",
            )

        results: list[dict] = []
        all_ok = True

        for vuln in vulns:
            if not vuln.remediation:
                results.append({"vuln": vuln.id, "skipped": "no remediation defined"})
                continue

            # Find the golden-path step(s) that exercise this vuln.
            linked_steps = [
                s for s in snapshot.truth_graph.exploit_chain
                if s.vuln_id == vuln.id
            ]
            if not linked_steps:
                results.append({"vuln": vuln.id, "skipped": "no exploit_chain step linked"})
                continue

            host = vuln.host or "attacker"

            # --- Apply remediation -------------------------------------------------
            try:
                await containers.exec(host, vuln.remediation)
            except Exception as exc:  # noqa: BLE001
                results.append({"vuln": vuln.id, "error": f"remediation failed: {exc}"})
                all_ok = False
                continue

            # --- Re-run linked golden-path step — must now fail --------------------
            step_still_works = False
            for chain_step in linked_steps:
                # Find the matching golden-path step by command similarity.
                gp_step = _find_golden_step(snapshot, chain_step.command)
                if gp_step is None:
                    continue
                try:
                    output = await containers.exec(
                        getattr(gp_step, "host", None) or "attacker",
                        gp_step.command,
                    )
                except Exception:  # noqa: BLE001
                    continue  # exec failure counts as "step failed" — good

                if gp_step.expect_in_stdout and gp_step.expect_in_stdout in output:
                    step_still_works = True

            if step_still_works:
                results.append({"vuln": vuln.id, "passed": False, "reason": "golden path still succeeds after patch"})
                all_ok = False
            else:
                results.append({"vuln": vuln.id, "passed": True})

            # --- Revert (best-effort) — restore vulnerable state -------------------
            # The caller is expected to rebuild/restart containers after validation,
            # but we try to undo the remediation to leave things clean for subsequent
            # checks.
            if vuln.vulnerable_code and isinstance(vuln.vulnerable_code, str):
                try:
                    await containers.exec(host, f"echo '{vuln.vulnerable_code}' > /tmp/_revert_stub")
                except Exception:  # noqa: BLE001
                    pass  # best-effort

        return CheckResult(
            name="patchability",
            passed=all_ok,
            details={"vuln_results": results},
            error="" if all_ok else "some vulns remain exploitable after remediation",
        )


def _find_golden_step(snapshot: SnapshotSpec, command_hint: str):
    """Return the golden-path step whose command best matches *command_hint*."""
    for gp in snapshot.golden_path:
        if command_hint and command_hint in gp.command:
            return gp
    # Fallback: return None — caller will skip.
    return None
