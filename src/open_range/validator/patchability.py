"""Check 3: Patchability — inverse mutation test.

For each planted vuln: apply its remediation, re-run the golden-path step
that exploits it, and verify the step *fails*.  Then revert via container
restart.
"""

from __future__ import annotations

import logging
import re

from open_range.protocols import CheckResult, ContainerSet, ExploitStep, SnapshotSpec
from open_range.validator._golden_path import execute_step

logger = logging.getLogger(__name__)

# Prefixes / patterns that indicate an executable shell command.
_CMD_PREFIXES = (
    "/", "sed", "chmod", "rm", "mv", "cp", "echo", "apt", "pip",
    "patch", "iptables", "mysql", "docker",
)
_CMD_OPERATORS_RE = re.compile(r"[|>&]|&&")


def _looks_executable(remediation: str) -> bool:
    """Heuristic: return True if *remediation* looks like a shell command."""
    stripped = remediation.strip()
    if not stripped:
        return False
    for prefix in _CMD_PREFIXES:
        if stripped.startswith(prefix):
            return True
    if _CMD_OPERATORS_RE.search(stripped):
        return True
    return False


def _find_golden_step(snapshot: SnapshotSpec, chain_step: ExploitStep):
    """Return the golden-path step matching *chain_step*.

    Strategy:
    1. Match via exploit_chain vuln_id → golden_path step whose command
       contains the exploit_chain command (exact vuln_id linkage).
    2. Fall back to substring match requiring >= 10 char overlap.
    3. Return None if no match.
    """
    command_hint = chain_step.command

    # Strategy 1: find golden-path step that contains the exploit command
    if command_hint:
        for gp in snapshot.golden_path:
            if command_hint in gp.command or gp.command in command_hint:
                return gp

    # Strategy 2: substring overlap >= 10 chars
    if command_hint and len(command_hint) >= 10:
        for gp in snapshot.golden_path:
            # Check if any 10-char substring of command_hint appears in gp.command
            overlap = _longest_common_substring(command_hint, gp.command)
            if overlap >= 10:
                return gp

    return None


def _longest_common_substring(a: str, b: str) -> int:
    """Return the length of the longest common substring between *a* and *b*."""
    if not a or not b:
        return 0
    # Use a simple O(n*m) approach, bounded since these are short command strings.
    max_len = 0
    for i in range(len(a)):
        for j in range(len(b)):
            k = 0
            while i + k < len(a) and j + k < len(b) and a[i + k] == b[j + k]:
                k += 1
            if k > max_len:
                max_len = k
    return max_len


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
        tested_count = 0

        for vuln in vulns:
            # --- Fail if no remediation defined ---
            if not vuln.remediation or not vuln.remediation.strip():
                msg = "no remediation defined"
                logger.warning("patchability: vuln %s has %s — counting as failure", vuln.id, msg)
                results.append({"vuln": vuln.id, "passed": False, "reason": msg})
                all_ok = False
                continue

            # --- Fail non-executable remediation (prose) ---
            if not _looks_executable(vuln.remediation):
                msg = f"remediation is not executable: {vuln.remediation!r}"
                logger.warning("patchability: vuln %s — %s — counting as failure", vuln.id, msg)
                results.append({"vuln": vuln.id, "passed": False, "reason": msg})
                all_ok = False
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
                # Revert via restart even on remediation failure
                try:
                    await containers.restart(host)
                except Exception:  # noqa: BLE001
                    pass
                continue

            # --- Re-run linked golden-path step — must now fail --------------------
            step_still_works = False
            matched_any = False
            for chain_step in linked_steps:
                gp_step = _find_golden_step(snapshot, chain_step)
                if gp_step is None:
                    continue
                matched_any = True
                try:
                    output = await execute_step(
                        snapshot,
                        containers,
                        gp_step.command,
                        host=getattr(gp_step, "host", None) or "attacker",
                    )
                except Exception:  # noqa: BLE001
                    continue  # exec failure counts as "step failed" — good

                if gp_step.expect_in_stdout and gp_step.expect_in_stdout in output:
                    step_still_works = True

            if not matched_any:
                results.append({
                    "vuln": vuln.id,
                    "skipped": "no matching golden-path step found for exploit_chain commands",
                })
                # Revert via restart
                try:
                    await containers.restart(host)
                except Exception:  # noqa: BLE001
                    pass
                continue

            tested_count += 1

            if step_still_works:
                results.append({
                    "vuln": vuln.id,
                    "passed": False,
                    "reason": "golden path still succeeds after patch",
                })
                all_ok = False
            else:
                results.append({"vuln": vuln.id, "passed": True})

            # --- Revert via container restart ---
            try:
                await containers.restart(host)
            except Exception:  # noqa: BLE001
                pass  # best-effort

        # --- Don't pass vacuously ---
        if tested_count == 0:
            return CheckResult(
                name="patchability",
                passed=False,
                details={"vuln_results": results},
                error="no vulns had testable remediation",
            )

        return CheckResult(
            name="patchability",
            passed=all_ok,
            details={"vuln_results": results},
            error="" if all_ok else "some vulns remain exploitable after remediation",
        )
