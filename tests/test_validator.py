"""Tests for validator checks — all run without Docker via mock_containers."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from open_range.protocols import (
    CheckResult,
    EvidenceItem,
    ExecResult,
    ExploitStep,
    FlagSpec,
    GoldenPathStep,
    MutationOp,
    MutationPlan,
    NPCPersona,
    SnapshotSpec,
    TaskSpec,
    TruthGraph,
    Vulnerability,
)
from open_range.validator.validator import ValidatorGate, ValidationResult


@pytest.mark.asyncio
async def test_manifest_compliance_rejects_illegal_mutation_plan(
    tier1_manifest,
    sample_snapshot_spec,
    mock_containers,
):
    from open_range.validator.manifest_compliance import ManifestComplianceCheck

    spec = sample_snapshot_spec.model_copy(deep=True)
    spec.mutation_plan = MutationPlan(
        parent_snapshot_id="root_snap",
        ops=[
            MutationOp(
                mutation_id="illegal1",
                op_type="seed_vuln",
                target_selector={"host": "web"},
                params={"vuln_type": "totally_fake_bug"},
            )
        ],
    )
    spec.lineage.parent_snapshot_id = "root_snap"
    spec.lineage.generation_depth = 1

    result = await ManifestComplianceCheck(tier1_manifest).check(spec, mock_containers)
    assert result.passed is False
    assert "illegal family" in result.error


@pytest.mark.asyncio
async def test_manifest_compliance_rejects_incompatible_seed_vuln_host(
    tier1_manifest,
    sample_snapshot_spec,
    mock_containers,
):
    from open_range.validator.manifest_compliance import ManifestComplianceCheck

    spec = sample_snapshot_spec.model_copy(deep=True)
    spec.mutation_plan = MutationPlan(
        parent_snapshot_id="root_snap",
        ops=[
            MutationOp(
                mutation_id="illegal_host",
                op_type="seed_vuln",
                target_selector={"host": "firewall"},
                params={
                    "vuln_type": "path_traversal",
                    "template_id": "vuln_path_traversal",
                    "required_services": ["nginx", "php-fpm"],
                },
            )
        ],
    )
    spec.lineage.parent_snapshot_id = "root_snap"
    spec.lineage.generation_depth = 1

    result = await ManifestComplianceCheck(tier1_manifest).check(spec, mock_containers)
    assert result.passed is False
    assert "incompatible with required services" in result.error


@pytest.mark.asyncio
async def test_graph_consistency_rejects_missing_parent_lineage(sample_snapshot_spec, mock_containers):
    from open_range.validator.graph_consistency import GraphConsistencyCheck

    spec = sample_snapshot_spec.model_copy(deep=True)
    spec.mutation_plan = MutationPlan(
        parent_snapshot_id="root_snap",
        ops=[
            MutationOp(
                mutation_id="mut1",
                op_type="add_benign_noise",
                target_selector={"location": "siem:noise.log"},
                params={"location": "siem:noise.log"},
            )
        ],
    )
    spec.lineage.generation_depth = 1
    spec.lineage.parent_snapshot_id = None

    result = await GraphConsistencyCheck().check(spec, mock_containers)
    assert result.passed is False
    assert "missing parent_snapshot_id" in result.error


@pytest.mark.asyncio
async def test_path_solvability_passes_for_reachable_flag_host(mock_containers):
    from open_range.protocols import EvidenceItem, TruthGraph, Vulnerability
    from open_range.validator.path_solvability import PathSolvabilityCheck

    spec = SnapshotSpec(
        topology={
            "hosts": ["attacker", "web", "db"],
            "zones": {"external": ["attacker"], "dmz": ["web"], "internal": ["db"]},
            "dependency_edges": [
                {"source": "attacker", "target": "web"},
                {"source": "web", "target": "db"},
            ],
            "host_details": {
                "attacker": {"services": ["nmap"]},
                "web": {"services": ["nginx"]},
                "db": {"services": ["mysql"]},
            },
        },
        truth_graph=TruthGraph(
            vulns=[Vulnerability(id="v1", type="sqli", host="web", service="nginx")],
        ),
        flags=[FlagSpec(id="f1", value="FLAG{ok}", path="/var/flags/flag1.txt", host="db")],
        evidence_spec=[EvidenceItem(type="log_entry", location="siem:/var/log/siem/all.log")],
        golden_path=[GoldenPathStep(step=1, command="nmap web", expect_in_stdout="80/tcp")],
        task=TaskSpec(red_briefing="go", blue_briefing="watch"),
    )

    result = await PathSolvabilityCheck().check(spec, mock_containers)
    assert result.passed is True


@pytest.mark.asyncio
async def test_graph_evidence_sufficiency_fails_without_supporting_hosts(mock_containers):
    from open_range.protocols import TruthGraph, Vulnerability
    from open_range.validator.graph_evidence import GraphEvidenceSufficiencyCheck

    spec = SnapshotSpec(
        topology={
            "hosts": ["attacker", "web", "db"],
            "zones": {"external": ["attacker"], "dmz": ["web"], "internal": ["db"]},
            "dependency_edges": [{"source": "attacker", "target": "web"}],
            "host_details": {
                "attacker": {"services": ["nmap"]},
                "web": {"services": ["nginx"]},
                "db": {"services": ["mysql"]},
            },
        },
        truth_graph=TruthGraph(
            vulns=[Vulnerability(id="v1", type="sqli", host="db", service="mysql")],
        ),
        flags=[FlagSpec(id="f1", value="FLAG{db}", path="/var/flags/flag1.txt", host="db")],
        evidence_spec=[EvidenceItem(type="log_entry", location="web:/var/log/access.log")],
        golden_path=[GoldenPathStep(step=1, command="scan", expect_in_stdout="ok")],
        task=TaskSpec(red_briefing="go", blue_briefing="watch"),
    )

    result = await GraphEvidenceSufficiencyCheck().check(spec, mock_containers)
    assert result.passed is False
    assert "no supporting evidence host" in result.error


@pytest.mark.asyncio
async def test_graph_reward_grounding_fails_when_flag_host_unreachable(mock_containers):
    from open_range.protocols import TruthGraph, Vulnerability
    from open_range.validator.graph_reward_grounding import GraphRewardGroundingCheck

    spec = SnapshotSpec(
        topology={
            "hosts": ["attacker", "web", "db"],
            "zones": {"external": ["attacker"], "dmz": ["web"], "internal": ["db"]},
            "dependency_edges": [{"source": "attacker", "target": "web"}],
            "host_details": {
                "attacker": {"services": ["nmap"]},
                "web": {"services": ["nginx"]},
                "db": {"services": ["mysql"]},
            },
        },
        truth_graph=TruthGraph(
            vulns=[Vulnerability(id="v1", type="sqli", host="web", service="nginx")],
        ),
        flags=[FlagSpec(id="f1", value="FLAG{db}", path="/var/flags/flag1.txt", host="db")],
        evidence_spec=[EvidenceItem(type="log_entry", location="siem:/var/log/siem/all.log")],
        golden_path=[GoldenPathStep(step=1, command="scan", expect_in_stdout="ok")],
        task=TaskSpec(red_briefing="go", blue_briefing="watch"),
    )

    result = await GraphRewardGroundingCheck().check(spec, mock_containers)
    assert result.passed is False
    assert "not reachable from any vuln host" in result.error


@pytest.mark.asyncio
async def test_graph_checks_allow_trust_based_host_pivots(mock_containers):
    from open_range.validator.graph_reward_grounding import GraphRewardGroundingCheck
    from open_range.validator.path_solvability import PathSolvabilityCheck

    spec = SnapshotSpec(
        topology={
            "hosts": ["attacker", "web", "db"],
            "zones": {"external": ["attacker"], "dmz": ["web"], "internal": ["db"]},
            "dependency_edges": [{"source": "attacker", "target": "web"}],
            "trust_edges": [{"source": "websvc", "target": "dbsvc", "type": "credential_reuse"}],
            "host_details": {
                "attacker": {"services": ["nmap"]},
                "web": {"services": ["nginx"]},
                "db": {"services": ["mysql"]},
            },
            "principal_catalog": {
                "websvc": {"username": "websvc", "hosts": ["web"], "is_login_account": False},
                "dbsvc": {"username": "dbsvc", "hosts": ["db"], "is_login_account": False},
            },
        },
        truth_graph=TruthGraph(
            vulns=[Vulnerability(id="v1", type="credential_reuse", host="web", service="nginx")],
        ),
        flags=[FlagSpec(id="f1", value="FLAG{db}", path="/var/flags/flag1.txt", host="db")],
        evidence_spec=[EvidenceItem(type="log_entry", location="db:/var/log/mysql.log")],
        golden_path=[GoldenPathStep(step=1, command="scan", expect_in_stdout="ok")],
        task=TaskSpec(red_briefing="go", blue_briefing="watch"),
    )

    path_result = await PathSolvabilityCheck().check(spec, mock_containers)
    reward_result = await GraphRewardGroundingCheck().check(spec, mock_containers)
    assert path_result.passed is True
    assert reward_result.passed is True


# ---------------------------------------------------------------------------
# Check 1: BuildBoot
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_build_boot_passes_when_all_healthy(sample_snapshot_spec, mock_containers):
    from open_range.validator.build_boot import BuildBootCheck

    for h in sample_snapshot_spec.topology["hosts"]:
        mock_containers.healthy.add(h)

    result = await BuildBootCheck().check(sample_snapshot_spec, mock_containers)
    assert result.passed is True
    assert result.name == "build_boot"


@pytest.mark.asyncio
async def test_build_boot_fails_when_host_unhealthy(sample_snapshot_spec, mock_containers):
    from open_range.validator.build_boot import BuildBootCheck

    # Mark all except 'web' as healthy
    for h in sample_snapshot_spec.topology["hosts"]:
        if h != "web":
            mock_containers.healthy.add(h)

    result = await BuildBootCheck().check(sample_snapshot_spec, mock_containers)
    assert result.passed is False
    assert "web" in result.error


# ---------------------------------------------------------------------------
# Check 2: Exploitability
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_exploitability_passes_when_golden_path_succeeds(mock_containers):
    from open_range.validator.exploitability import ExploitabilityCheck

    # Use a minimal spec with distinct commands to avoid substring collisions.
    spec = SnapshotSpec(
        golden_path=[
            GoldenPathStep(step=1, command="nmap -sV 10.0.1.0/24", expect_in_stdout="80/tcp"),
            GoldenPathStep(step=2, command="curl http://target/page", expect_in_stdout="OK"),
        ],
    )
    for step in spec.golden_path:
        mock_containers.exec_results[("attacker", step.command)] = step.expect_in_stdout

    result = await ExploitabilityCheck().check(spec, mock_containers)
    assert result.passed is True


@pytest.mark.asyncio
async def test_exploitability_normalizes_whitespace_for_tool_output(mock_containers):
    from open_range.validator.exploitability import ExploitabilityCheck

    spec = SnapshotSpec(
        golden_path=[
            GoldenPathStep(
                step=1,
                command="nmap -sV 10.0.1.0/24",
                expect_in_stdout="80/tcp open http",
            ),
        ],
    )
    mock_containers.exec_results[("attacker", "nmap -sV 10.0.1.0/24")] = (
        "80/tcp   open  http   nginx"
    )

    result = await ExploitabilityCheck().check(spec, mock_containers)
    assert result.passed is True


@pytest.mark.asyncio
async def test_exploitability_fails_when_step_output_missing(
    sample_snapshot_spec, mock_containers
):
    from open_range.validator.exploitability import ExploitabilityCheck

    # Register all steps but make one return wrong output
    for step in sample_snapshot_spec.golden_path:
        host = getattr(step, "host", None) or "attacker"
        mock_containers.exec_results[(host, step.command)] = step.expect_in_stdout

    # Override one step to return wrong output
    first_step = sample_snapshot_spec.golden_path[0]
    host = getattr(first_step, "host", None) or "attacker"
    mock_containers.exec_results[(host, first_step.command)] = "totally wrong output"

    result = await ExploitabilityCheck().check(sample_snapshot_spec, mock_containers)
    assert result.passed is False
    assert "failed" in result.error


@pytest.mark.asyncio
async def test_exploitability_fails_on_empty_golden_path(mock_containers):
    from open_range.validator.exploitability import ExploitabilityCheck

    spec = SnapshotSpec(golden_path=[])
    result = await ExploitabilityCheck().check(spec, mock_containers)
    assert result.passed is False
    assert "empty" in result.error


@pytest.mark.asyncio
async def test_exploitability_skips_meta_commands(mock_containers):
    from open_range.validator.exploitability import ExploitabilityCheck

    spec = SnapshotSpec(
        golden_path=[
            GoldenPathStep(step=1, command="curl http://web/", expect_in_stdout="Welcome"),
            GoldenPathStep(step=2, command="submit_flag FLAG{abc}", expect_in_stdout="correct"),
        ],
    )
    mock_containers.exec_results[("attacker", "curl http://web/")] = "Welcome"

    result = await ExploitabilityCheck().check(spec, mock_containers)
    assert result.passed is True
    assert result.details["skipped_steps"] == [2]


@pytest.mark.asyncio
async def test_exploitability_fails_when_expectation_missing_in_strict_mode(mock_containers):
    from open_range.validator.exploitability import ExploitabilityCheck

    spec = SnapshotSpec(
        golden_path=[
            GoldenPathStep(step=1, command="curl http://web/", expect_in_stdout=""),
        ],
    )
    mock_containers.exec_results[("attacker", "curl http://web/")] = "Welcome"

    result = await ExploitabilityCheck().check(spec, mock_containers)
    assert result.passed is False
    assert result.details["require_expectation"] is True
    assert result.details["failed_steps"][0]["error"] == (
        "golden path step 1 has no expect_in_stdout"
    )


@pytest.mark.asyncio
async def test_exploitability_allows_missing_expectation_in_lenient_mode(mock_containers):
    from open_range.validator.exploitability import ExploitabilityCheck

    spec = SnapshotSpec(
        golden_path=[
            GoldenPathStep(step=1, command="curl http://web/", expect_in_stdout=""),
        ],
    )
    mock_containers.exec_results[("attacker", "curl http://web/")] = "Welcome"

    result = await ExploitabilityCheck(require_expectation=False).check(spec, mock_containers)
    assert result.passed is True
    assert result.details["require_expectation"] is False
    assert result.details["unvalidated_steps"] == [1]


@pytest.mark.asyncio
async def test_exploitability_fails_on_nonzero_exit_even_with_expected_output(mock_containers):
    from open_range.validator.exploitability import ExploitabilityCheck

    spec = SnapshotSpec(
        golden_path=[
            GoldenPathStep(step=1, command="curl http://web/", expect_in_stdout="Welcome"),
        ],
    )
    mock_containers.exec_results[("attacker", "curl http://web/")] = "Welcome"
    mock_containers.exec_status[("attacker", "curl http://web/")] = 7

    result = await ExploitabilityCheck().check(spec, mock_containers)
    assert result.passed is False
    assert result.details["failed_steps"][0]["error"] == "command failed with exit_code=7"


# ---------------------------------------------------------------------------
# Check 3: Patchability
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_patchability_fails_when_no_vulns(mock_containers):
    from open_range.validator.patchability import PatchabilityCheck

    spec = SnapshotSpec(truth_graph=TruthGraph(vulns=[]))
    result = await PatchabilityCheck().check(spec, mock_containers)
    assert result.passed is False


@pytest.mark.asyncio
async def test_patchability_passes_when_patch_breaks_exploit(mock_containers):
    """Patch applied -> golden path step no longer produces expected output -> PASS."""
    from open_range.protocols import ExploitStep
    from open_range.validator.patchability import PatchabilityCheck

    spec = SnapshotSpec(
        truth_graph=TruthGraph(
            vulns=[
                Vulnerability(
                    id="v1",
                    type="sqli",
                    host="web",
                    remediation="sed -i 's/unsafe/safe/' /var/www/app.php",
                ),
            ],
            exploit_chain=[
                ExploitStep(vuln_id="v1", command="curl http://web/search?q=exploit"),
            ],
        ),
        golden_path=[
            GoldenPathStep(
                step=1,
                command="curl http://web/search?q=exploit",
                expect_in_stdout="SECRET_DATA",
            ),
        ],
    )

    # Remediation exec succeeds (exit 0 by default)
    mock_containers.exec_results[("web", "sed")] = ""
    # After patch, golden path step returns DIFFERENT output (no SECRET_DATA)
    mock_containers.exec_results[("attacker", "curl http://web/search?q=exploit")] = "no results"

    result = await PatchabilityCheck().check(spec, mock_containers)
    assert result.passed is True
    assert result.name == "patchability"


@pytest.mark.asyncio
async def test_patchability_fails_when_exploit_still_works(mock_containers):
    """Patch applied but golden path step still succeeds -> FAIL."""
    from open_range.protocols import ExploitStep
    from open_range.validator.patchability import PatchabilityCheck

    spec = SnapshotSpec(
        truth_graph=TruthGraph(
            vulns=[
                Vulnerability(
                    id="v1",
                    type="sqli",
                    host="web",
                    remediation="sed -i 's/unsafe/safe/' /var/www/app.php",
                ),
            ],
            exploit_chain=[
                ExploitStep(vuln_id="v1", command="curl http://web/search?q=exploit"),
            ],
        ),
        golden_path=[
            GoldenPathStep(
                step=1,
                command="curl http://web/search?q=exploit",
                expect_in_stdout="SECRET_DATA",
            ),
        ],
    )

    # Remediation exec succeeds
    mock_containers.exec_results[("web", "sed")] = ""
    # After patch, golden path step STILL returns the expected output (patch didn't work)
    mock_containers.exec_results[("attacker", "curl http://web/search?q=exploit")] = "SECRET_DATA"

    result = await PatchabilityCheck().check(spec, mock_containers)
    assert result.passed is False
    assert "exploitable after remediation" in result.error


@pytest.mark.asyncio
async def test_patchability_fails_when_remediation_command_exits_nonzero(mock_containers):
    from open_range.protocols import ExploitStep
    from open_range.validator.patchability import PatchabilityCheck

    spec = SnapshotSpec(
        truth_graph=TruthGraph(
            vulns=[
                Vulnerability(
                    id="v1",
                    type="sqli",
                    host="web",
                    remediation="sed -i 's/unsafe/safe/' /var/www/app.php",
                ),
            ],
            exploit_chain=[
                ExploitStep(vuln_id="v1", command="curl http://web/search?q=exploit"),
            ],
        ),
        golden_path=[
            GoldenPathStep(
                step=1,
                command="curl http://web/search?q=exploit",
                expect_in_stdout="SECRET_DATA",
            ),
        ],
    )
    mock_containers.exec_results[("web", "sed")] = "sed: cannot read /var/www/app.php"
    mock_containers.exec_status[("web", "sed")] = 2

    result = await PatchabilityCheck().check(spec, mock_containers)
    assert result.passed is False
    first = result.details["vuln_results"][0]
    assert first["passed"] is False
    assert "remediation command failed" in first["reason"]
    assert mock_containers.restarted == ["web"]


@pytest.mark.asyncio
async def test_patchability_fails_when_retest_command_is_inconclusive(mock_containers):
    from open_range.protocols import ExploitStep
    from open_range.validator.patchability import PatchabilityCheck

    spec = SnapshotSpec(
        truth_graph=TruthGraph(
            vulns=[
                Vulnerability(
                    id="v1",
                    type="sqli",
                    host="web",
                    remediation="sed -i 's/unsafe/safe/' /var/www/app.php",
                ),
            ],
            exploit_chain=[
                ExploitStep(vuln_id="v1", command="curl http://web/search?q=exploit"),
            ],
        ),
        golden_path=[
            GoldenPathStep(
                step=1,
                command="curl http://web/search?q=exploit",
                expect_in_stdout="SECRET_DATA",
            ),
        ],
    )

    mock_containers.exec_results[("web", "sed")] = ""
    mock_containers.exec_results[("attacker", "curl http://web/search?q=exploit")] = "curl: (7) failed to connect"
    mock_containers.exec_status[("attacker", "curl http://web/search?q=exploit")] = 7

    result = await PatchabilityCheck().check(spec, mock_containers)
    assert result.passed is False
    vuln_result = result.details["vuln_results"][0]
    assert vuln_result["passed"] is False
    assert vuln_result["reason"] == "retest inconclusive after remediation"
    assert "retest command failed (exit_code=7)" in vuln_result["details"][0]["reason"]
    assert mock_containers.restarted == ["web"]


@pytest.mark.asyncio
async def test_patchability_fails_when_retest_execution_is_inconclusive(mock_containers):
    from open_range.protocols import ExecResult, ExploitStep
    from open_range.validator.patchability import PatchabilityCheck

    spec = SnapshotSpec(
        truth_graph=TruthGraph(
            vulns=[
                Vulnerability(
                    id="v1",
                    type="sqli",
                    host="web",
                    remediation="sed -i 's/unsafe/safe/' /var/www/app.php",
                ),
            ],
            exploit_chain=[
                ExploitStep(vuln_id="v1", command="curl http://web/search?q=exploit"),
            ],
        ),
        golden_path=[
            GoldenPathStep(
                step=1,
                command="curl http://web/search?q=exploit",
                expect_in_stdout="SECRET_DATA",
            ),
        ],
    )

    async def exec_run_side_effect(container: str, cmd: str, **kwargs):
        if container == "web" and "sed -i 's/unsafe/safe/' /var/www/app.php" in cmd:
            return ExecResult(stdout="", exit_code=0)
        if container == "attacker" and "curl http://web/search?q=exploit" in cmd:
            raise RuntimeError("timeout")
        return ExecResult(stdout="", exit_code=0)

    mock_containers.exec_run = exec_run_side_effect
    result = await PatchabilityCheck().check(spec, mock_containers)
    assert result.passed is False
    vuln_result = result.details["vuln_results"][0]
    assert vuln_result["passed"] is False
    assert vuln_result["reason"] == "retest inconclusive after remediation"
    assert vuln_result["details"][0]["reason"] == "retest execution raised: timeout"
    assert mock_containers.restarted == ["web"]


@pytest.mark.asyncio
async def test_patchability_skips_prose_remediation(mock_containers):
    """Non-executable remediation (prose) is skipped with warning, fails if all skipped."""
    from open_range.protocols import ExploitStep
    from open_range.validator.patchability import PatchabilityCheck

    spec = SnapshotSpec(
        truth_graph=TruthGraph(
            vulns=[
                Vulnerability(
                    id="v1",
                    type="sqli",
                    host="web",
                    remediation="Use parameterized queries instead of string concatenation",
                ),
            ],
            exploit_chain=[
                ExploitStep(vuln_id="v1", command="curl http://web/search?q=exploit"),
            ],
        ),
        golden_path=[
            GoldenPathStep(
                step=1,
                command="curl http://web/search?q=exploit",
                expect_in_stdout="SECRET_DATA",
            ),
        ],
    )

    result = await PatchabilityCheck().check(spec, mock_containers)
    assert result.passed is False
    # Verify it was recorded as a failure (not silently skipped)
    vuln_results = result.details["vuln_results"]
    assert len(vuln_results) == 1
    assert vuln_results[0]["passed"] is False
    assert "not executable" in vuln_results[0]["reason"]


@pytest.mark.asyncio
async def test_patchability_fails_when_all_skipped(mock_containers):
    """If all vulns are skipped (no testable remediation), check FAILS."""
    from open_range.protocols import ExploitStep
    from open_range.validator.patchability import PatchabilityCheck

    spec = SnapshotSpec(
        truth_graph=TruthGraph(
            vulns=[
                Vulnerability(
                    id="v1",
                    type="sqli",
                    host="web",
                    remediation="",  # empty remediation
                ),
                Vulnerability(
                    id="v2",
                    type="xss",
                    host="web",
                    remediation="Sanitize all user input before rendering",  # prose
                ),
            ],
            exploit_chain=[
                ExploitStep(vuln_id="v1", command="cmd1"),
                ExploitStep(vuln_id="v2", command="cmd2"),
            ],
        ),
        golden_path=[
            GoldenPathStep(step=1, command="cmd1", expect_in_stdout="found"),
            GoldenPathStep(step=2, command="cmd2", expect_in_stdout="xss"),
        ],
    )

    result = await PatchabilityCheck().check(spec, mock_containers)
    assert result.passed is False
    assert "no vulns had testable remediation" in result.error


@pytest.mark.asyncio
async def test_patchability_restarts_container_after_patch(mock_containers):
    """Container is restarted after each vuln's test to restore pre-patched state."""
    from open_range.protocols import ExploitStep
    from open_range.validator.patchability import PatchabilityCheck

    spec = SnapshotSpec(
        truth_graph=TruthGraph(
            vulns=[
                Vulnerability(
                    id="v1",
                    type="sqli",
                    host="web",
                    remediation="sed -i 's/bad/good/' /app.php",
                ),
                Vulnerability(
                    id="v2",
                    type="lfi",
                    host="web",
                    remediation="rm /etc/sensitive_file",
                ),
            ],
            exploit_chain=[
                ExploitStep(vuln_id="v1", command="curl http://web/search?q=inject"),
                ExploitStep(vuln_id="v2", command="curl http://web/read?file=../../etc/passwd"),
            ],
        ),
        golden_path=[
            GoldenPathStep(
                step=1,
                command="curl http://web/search?q=inject",
                expect_in_stdout="SQLI_RESULT",
            ),
            GoldenPathStep(
                step=2,
                command="curl http://web/read?file=../../etc/passwd",
                expect_in_stdout="root:x:0",
            ),
        ],
    )

    # Remediation succeeds for both
    mock_containers.exec_results[("web", "sed")] = ""
    mock_containers.exec_results[("web", "rm")] = ""
    # After patch, exploits fail (return empty)
    mock_containers.exec_results[("attacker", "curl http://web/search")] = "blocked"
    mock_containers.exec_results[("attacker", "curl http://web/read")] = "forbidden"

    result = await PatchabilityCheck().check(spec, mock_containers)
    assert result.passed is True
    # Container should have been restarted once per tested vuln
    assert mock_containers.restarted == ["web", "web"]


# ---------------------------------------------------------------------------
# Check 4: Evidence
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evidence_passes_vacuously_when_no_spec(mock_containers):
    from open_range.validator.evidence import EvidenceCheck

    spec = SnapshotSpec(evidence_spec=[])
    result = await EvidenceCheck().check(spec, mock_containers)
    assert result.passed is True


@pytest.mark.asyncio
async def test_evidence_fails_when_pattern_missing(mock_containers):
    from open_range.validator.evidence import EvidenceCheck

    spec = SnapshotSpec(
        evidence_spec=[
            EvidenceItem(type="log_entry", location="siem:/var/log/test.log", pattern="ATTACK"),
        ]
    )
    # Return "0" matches from grep
    mock_containers.exec_results[("siem", "grep")] = "0"
    result = await EvidenceCheck().check(spec, mock_containers)
    assert result.passed is False


@pytest.mark.asyncio
async def test_evidence_fails_when_grep_returns_error_text(mock_containers):
    from open_range.validator.evidence import EvidenceCheck

    spec = SnapshotSpec(
        evidence_spec=[
            EvidenceItem(type="log_entry", location="siem:/var/log/missing.log", pattern="ATTACK"),
        ]
    )
    mock_containers.exec_results[("siem", "grep")] = "grep: /var/log/missing.log: No such file or directory"
    mock_containers.exec_status[("siem", "grep")] = 2
    result = await EvidenceCheck().check(spec, mock_containers)
    assert result.passed is False
    assert "No such file or directory" in result.details["missing"][0]["error"]


@pytest.mark.asyncio
async def test_evidence_fails_on_nonzero_exit_even_when_output_present(mock_containers):
    from open_range.validator.evidence import EvidenceCheck

    spec = SnapshotSpec(
        evidence_spec=[
            EvidenceItem(type="artifact", location="siem:/var/log/test.log"),
        ]
    )
    mock_containers.exec_status[("siem", "test -f")] = 1
    result = await EvidenceCheck().check(spec, mock_containers)
    assert result.passed is False
    assert result.details["missing"][0]["location"] == "siem:/var/log/test.log"


@pytest.mark.asyncio
async def test_evidence_quotes_pattern_and_location_path():
    """Evidence grep command must quote pattern and path from snapshot content."""
    import shlex

    from open_range.validator.evidence import EvidenceCheck

    class RecordingContainers:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        async def exec_run(self, container: str, cmd: str, **kwargs) -> ExecResult:
            self.calls.append((container, cmd))
            return ExecResult(stdout="1", exit_code=0)

    containers = RecordingContainers()
    pattern = "ERR'; touch /tmp/pwn #"
    path = "/var/log/app; echo PWNED"
    spec = SnapshotSpec(
        evidence_spec=[
            EvidenceItem(type="log_entry", location=f"siem:{path}", pattern=pattern),
        ],
    )

    result = await EvidenceCheck().check(spec, containers)  # type: ignore[arg-type]
    assert result.passed is True
    assert containers.calls
    assert containers.calls[0][1] == f"grep -c {shlex.quote(pattern)} {shlex.quote(path)}"


# ---------------------------------------------------------------------------
# Check 5: Reward grounding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reward_grounding_passes_when_flag_found(mock_containers):
    from open_range.validator.reward_grounding import RewardGroundingCheck

    spec = SnapshotSpec(
        flags=[FlagSpec(id="f1", value="FLAG{abc}", path="/var/flags/f.txt", host="web")]
    )
    mock_containers.exec_results[("web", "cat")] = "FLAG{abc}"
    result = await RewardGroundingCheck().check(spec, mock_containers)
    assert result.passed is True


@pytest.mark.asyncio
async def test_reward_grounding_fails_when_flag_wrong(mock_containers):
    from open_range.validator.reward_grounding import RewardGroundingCheck

    spec = SnapshotSpec(
        flags=[FlagSpec(id="f1", value="FLAG{abc}", path="/var/flags/f.txt", host="web")]
    )
    mock_containers.exec_results[("web", "cat")] = "FLAG{wrong}"
    result = await RewardGroundingCheck().check(spec, mock_containers)
    assert result.passed is False


@pytest.mark.asyncio
async def test_reward_grounding_no_flags(mock_containers):
    from open_range.validator.reward_grounding import RewardGroundingCheck

    spec = SnapshotSpec(flags=[])
    result = await RewardGroundingCheck().check(spec, mock_containers)
    assert result.passed is False


@pytest.mark.asyncio
async def test_reward_grounding_verifies_db_flag(mock_containers):
    """DB-stored flag verified via MySQL query — value found."""
    from open_range.validator.reward_grounding import RewardGroundingCheck

    spec = SnapshotSpec(
        flags=[FlagSpec(id="f1", value="FLAG{db_flag}", path="db:flags.secrets.flag", host="db")]
    )
    mock_containers.exec_results[("db", "mysql")] = "FLAG{db_flag}"
    result = await RewardGroundingCheck().check(spec, mock_containers)
    assert result.passed is True


@pytest.mark.asyncio
async def test_reward_grounding_fails_db_flag_not_found(mock_containers):
    """DB-stored flag verified via MySQL query — wrong value returned."""
    from open_range.validator.reward_grounding import RewardGroundingCheck

    spec = SnapshotSpec(
        flags=[FlagSpec(id="f1", value="FLAG{db_flag}", path="db:flags.secrets.flag", host="db")]
    )
    mock_containers.exec_results[("db", "mysql")] = "FLAG{wrong_value}"
    result = await RewardGroundingCheck().check(spec, mock_containers)
    assert result.passed is False
    assert "1 flag(s)" in result.error


@pytest.mark.asyncio
async def test_reward_grounding_skips_db_sql_path(mock_containers):
    """db:sql deployment artifacts are skipped, not treated as flag locations."""
    from open_range.validator.reward_grounding import RewardGroundingCheck

    spec = SnapshotSpec(
        flags=[
            FlagSpec(id="f1", value="FLAG{abc}", path="/var/flags/f.txt", host="web"),
            FlagSpec(id="f2", value="FLAG{deploy}", path="db:sql", host="db"),
        ]
    )
    mock_containers.exec_results[("web", "cat")] = "FLAG{abc}"
    result = await RewardGroundingCheck().check(spec, mock_containers)
    assert result.passed is True


@pytest.mark.asyncio
async def test_reward_grounding_quotes_filesystem_path():
    """Filesystem flag paths with shell metacharacters must be quoted."""
    from open_range.validator.reward_grounding import RewardGroundingCheck

    class RecordingContainers:
        def __init__(self):
            self.calls: list[tuple[str, str]] = []

        async def exec_run(self, container: str, cmd: str, **kwargs):
            from open_range.protocols import ExecResult

            self.calls.append((container, cmd))
            return ExecResult(stdout="FLAG{abc}", exit_code=0)

        async def exec(self, container: str, cmd: str, **kwargs) -> str:
            return (await self.exec_run(container, cmd, **kwargs)).combined_output

    containers = RecordingContainers()
    spec = SnapshotSpec(
        flags=[FlagSpec(id="f1", value="FLAG{abc}", path="/tmp/f; echo PWNED", host="web")]
    )
    result = await RewardGroundingCheck().check(spec, containers)  # type: ignore[arg-type]
    assert result.passed is True
    assert containers.calls
    assert containers.calls[0][1] == "cat -- '/tmp/f; echo PWNED'"


@pytest.mark.asyncio
async def test_reward_grounding_rejects_invalid_db_identifier_path():
    """Malformed DB paths must fail rather than altering SQL semantics."""
    from open_range.validator.reward_grounding import RewardGroundingCheck

    class RecordingContainers:
        def __init__(self):
            self.calls: list[tuple[str, str]] = []

        async def exec_run(self, container: str, cmd: str, **kwargs):
            from open_range.protocols import ExecResult

            self.calls.append((container, cmd))
            return ExecResult(stdout="FLAG{abc}", exit_code=0)

        async def exec(self, container: str, cmd: str, **kwargs) -> str:
            return (await self.exec_run(container, cmd, **kwargs)).combined_output

    containers = RecordingContainers()
    spec = SnapshotSpec(
        flags=[
            FlagSpec(
                id="f1",
                value="FLAG{abc}",
                path="db:flags.secrets.flag FROM secrets; SELECT 'x' --",
                host="db",
            )
        ]
    )
    result = await RewardGroundingCheck().check(spec, containers)  # type: ignore[arg-type]
    assert result.passed is False
    assert "invalid db flag path format" in result.details["results"][0]["error"]
    assert containers.calls == []


@pytest.mark.asyncio
async def test_reward_grounding_quotes_mysql_password_from_snapshot():
    """DB checks must not rely on unquoted shell expansion for credentials."""
    import shlex

    from open_range.validator.reward_grounding import RewardGroundingCheck

    class RecordingContainers:
        def __init__(self):
            self.calls: list[tuple[str, str]] = []

        async def exec_run(self, container: str, cmd: str, **kwargs):
            from open_range.protocols import ExecResult

            self.calls.append((container, cmd))
            return ExecResult(stdout="FLAG{abc}", exit_code=0)

        async def exec(self, container: str, cmd: str, **kwargs) -> str:
            return (await self.exec_run(container, cmd, **kwargs)).combined_output

    containers = RecordingContainers()
    password = "pa ss;$(id)"
    spec = SnapshotSpec(
        topology={"mysql_root_password": password},
        flags=[FlagSpec(id="f1", value="FLAG{abc}", path="db:flags.secrets.flag", host="db")],
    )
    result = await RewardGroundingCheck().check(spec, containers)  # type: ignore[arg-type]
    assert result.passed is True
    assert containers.calls
    cmd = containers.calls[0][1]
    assert cmd.startswith(
        f"MYSQL_PWD={shlex.quote(password)} mysql -u root -N -e "
    )
    assert "-p$MYSQL_ROOT_PASSWORD" not in cmd


# ---------------------------------------------------------------------------
# Check 6: Isolation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_isolation_passes_clean_briefing(mock_containers):
    from open_range.validator.isolation import IsolationCheck

    spec = SnapshotSpec(
        topology={"hosts": ["web"], "zones": {}},
        flags=[FlagSpec(id="f1", value="FLAG{secret}", path="/f.txt", host="web")],
        golden_path=[],
        task=TaskSpec(
            red_briefing="Investigate the network.",
            blue_briefing="Monitor for threats.",
        ),
    )
    result = await IsolationCheck().check(spec, mock_containers)
    assert result.passed is True


@pytest.mark.asyncio
async def test_isolation_fails_when_flag_in_briefing(mock_containers):
    from open_range.validator.isolation import IsolationCheck

    spec = SnapshotSpec(
        topology={"hosts": ["web"], "zones": {}},
        flags=[FlagSpec(id="f1", value="FLAG{secret}", path="/f.txt", host="web")],
        golden_path=[],
        task=TaskSpec(
            red_briefing="The flag is FLAG{secret}, go find it.",
            blue_briefing="Monitor for threats.",
        ),
    )
    result = await IsolationCheck().check(spec, mock_containers)
    assert result.passed is False
    assert "flag value leaked" in result.error


@pytest.mark.asyncio
async def test_isolation_checks_multiple_ports(mock_containers):
    """Zone isolation probes multiple ports — all CLOSED means pass."""
    from open_range.validator.isolation import IsolationCheck

    spec = SnapshotSpec(
        topology={
            "hosts": ["attacker", "db"],
            "zones": {"internal": ["db"]},
        },
        flags=[],
        golden_path=[],
        task=TaskSpec(red_briefing="Go.", blue_briefing="Watch."),
    )
    # All probes return CLOSED
    mock_containers.exec_results[("attacker", "/dev/tcp/")] = "CLOSED"
    result = await IsolationCheck().check(spec, mock_containers)
    assert result.passed is True


@pytest.mark.asyncio
async def test_isolation_fails_on_non_ssh_port(mock_containers):
    """Zone isolation detects reachability on a non-SSH port (e.g. 3306)."""
    from open_range.validator.isolation import IsolationCheck

    spec = SnapshotSpec(
        topology={
            "hosts": ["attacker", "db"],
            "zones": {"internal": ["db"]},
        },
        flags=[],
        golden_path=[],
        task=TaskSpec(red_briefing="Go.", blue_briefing="Watch."),
    )

    # Only port 3306 is OPEN; everything else CLOSED.
    async def exec_side_effect(container, cmd, **kwargs):
        if container == "attacker" and "/dev/tcp/" in cmd:
            if " 3306 " in cmd:
                return "OPEN"
            return "CLOSED"
        return ""

    mock_containers.exec = exec_side_effect
    result = await IsolationCheck().check(spec, mock_containers)
    assert result.passed is False
    assert "3306" in result.error
    assert "db" in result.error


@pytest.mark.asyncio
async def test_isolation_uses_argument_safe_tcp_probe_for_target_name():
    """Target names are passed as positional args, not interpolated into script."""
    from open_range.validator.isolation import IsolationCheck

    class RecordingContainers:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        async def exec(self, container: str, cmd: str, **kwargs) -> str:
            self.calls.append((container, cmd))
            return "CLOSED"

    containers = RecordingContainers()
    target = "db'; touch /tmp/pwn #"
    spec = SnapshotSpec(
        topology={"hosts": ["attacker", "db"], "zones": {"internal": [target]}},
        flags=[],
        golden_path=[],
        task=TaskSpec(red_briefing="Go.", blue_briefing="Watch."),
    )

    result = await IsolationCheck().check(spec, containers)  # type: ignore[arg-type]
    assert result.passed is True
    assert containers.calls
    first_cmd = containers.calls[0][1]
    script_part, _, arg_part = first_cmd.partition(" _ ")
    assert "bash -lc 'echo > /dev/tcp/\"$1\"/\"$2\"'" in script_part
    assert "touch /tmp/pwn" not in script_part
    assert "touch /tmp/pwn" in arg_part


# ---------------------------------------------------------------------------
# Check 7: Task feasibility
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_task_feasibility_passes_valid_spec(sample_snapshot_spec, mock_containers):
    from open_range.validator.task_feasibility import TaskFeasibilityCheck

    result = await TaskFeasibilityCheck().check(sample_snapshot_spec, mock_containers)
    assert result.passed is True


@pytest.mark.asyncio
async def test_task_feasibility_fails_unknown_flag_host(mock_containers):
    from open_range.validator.task_feasibility import TaskFeasibilityCheck

    spec = SnapshotSpec(
        topology={"hosts": ["web", "attacker"], "zones": {}},
        flags=[FlagSpec(id="f1", value="FLAG{x}", path="/f.txt", host="nonexistent")],
        golden_path=[],
    )
    result = await TaskFeasibilityCheck().check(spec, mock_containers)
    assert result.passed is False


@pytest.mark.asyncio
async def test_task_feasibility_rejects_seed_vuln_without_task_path(mock_containers):
    from open_range.validator.task_feasibility import TaskFeasibilityCheck

    spec = SnapshotSpec(
        topology={
            "hosts": ["attacker", "web", "db"],
            "zones": {"external": ["attacker"], "dmz": ["web"], "internal": ["db"]},
            "dependency_edges": [{"source": "attacker", "target": "web"}],
            "host_details": {
                "attacker": {"services": ["nmap"]},
                "web": {"services": ["nginx", "php-fpm"]},
                "db": {"services": ["mysql"]},
            },
        },
        truth_graph=TruthGraph(
            vulns=[Vulnerability(id="path_traversal_1", type="path_traversal", host="web")],
            exploit_chain=[
                ExploitStep(
                    vuln_id="path_traversal_1",
                    command="curl 'http://web/download?file=../../../var/flags/path_traversal_mut1.txt'",
                    description="download planted flag",
                )
            ],
        ),
        flags=[FlagSpec(id="flag1", value="FLAG{path_mut1}", path="/var/flags/path_traversal_mut1.txt", host="web")],
        evidence_spec=[EvidenceItem(type="log_entry", location="web:/var/log/app/access.log")],
        golden_path=[
            GoldenPathStep(
                step=1,
                command="curl http://web/",
                expect_in_stdout="Welcome",
                host="attacker",
            )
        ],
        task=TaskSpec(red_briefing="go", blue_briefing="watch"),
        mutation_plan=MutationPlan(
            parent_snapshot_id="root_snap",
            ops=[
                MutationOp(
                    mutation_id="seed_path",
                    op_type="seed_vuln",
                    target_selector={"host": "web"},
                    params={
                        "vuln_type": "path_traversal",
                        "instantiated_vuln_id": "path_traversal_1",
                        "instantiated_flag_id": "flag1",
                        "instantiated_flag_value": "FLAG{path_mut1}",
                        "instantiated_flag_host": "web",
                        "instantiated_exploit_command": "curl 'http://web/download?file=../../../var/flags/path_traversal_mut1.txt'",
                    },
                )
            ],
        ),
    )
    spec.lineage.parent_snapshot_id = "root_snap"
    spec.lineage.generation_depth = 1

    result = await TaskFeasibilityCheck().check(spec, mock_containers)
    assert result.passed is False
    assert any(
        "missing submit_flag step" in issue for issue in result.details["issues"]
    )


# ---------------------------------------------------------------------------
# Check 8: Difficulty
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_difficulty_passes_tier1_with_8_steps(mock_containers):
    from open_range.validator.difficulty import DifficultyCheck

    steps = [GoldenPathStep(step=i, command=f"cmd_{i}") for i in range(1, 9)]
    spec = SnapshotSpec(
        topology={"tier": 1},
        golden_path=steps,
        truth_graph=TruthGraph(vulns=[
            Vulnerability(id="v1", type="sqli", host="web"),
        ]),
    )
    result = await DifficultyCheck().check(spec, mock_containers)
    assert result.passed is True


@pytest.mark.asyncio
async def test_difficulty_fails_tier1_with_3_steps(mock_containers):
    from open_range.validator.difficulty import DifficultyCheck

    steps = [GoldenPathStep(step=i, command=f"cmd_{i}") for i in range(1, 4)]
    spec = SnapshotSpec(
        topology={"tier": 1},
        golden_path=steps,
        truth_graph=TruthGraph(vulns=[
            Vulnerability(id="v1", type="sqli", host="web"),
        ]),
    )
    result = await DifficultyCheck().check(spec, mock_containers)
    assert result.passed is False
    assert "steps" in result.error


@pytest.mark.asyncio
async def test_difficulty_fails_single_step(mock_containers):
    from open_range.validator.difficulty import DifficultyCheck

    spec = SnapshotSpec(
        topology={"tier": 1},
        golden_path=[GoldenPathStep(step=1, command="cmd1")],
        truth_graph=TruthGraph(vulns=[
            Vulnerability(id="v1", type="sqli", host="web"),
        ]),
    )
    result = await DifficultyCheck().check(spec, mock_containers)
    assert result.passed is False
    assert "trivial" in result.error or "steps" in result.error


@pytest.mark.asyncio
async def test_difficulty_fails_duplicate_consecutive(mock_containers):
    from open_range.validator.difficulty import DifficultyCheck

    steps = [GoldenPathStep(step=i, command="same_cmd") for i in range(1, 9)]
    spec = SnapshotSpec(
        topology={"tier": 1},
        golden_path=steps,
        truth_graph=TruthGraph(vulns=[
            Vulnerability(id="v1", type="sqli", host="web"),
        ]),
    )
    result = await DifficultyCheck().check(spec, mock_containers)
    assert result.passed is False
    assert "duplicate" in result.error


# ---------------------------------------------------------------------------
# Check 9: NPC consistency — mechanical card validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_npc_consistency_passes_no_personas(mock_containers):
    from open_range.validator.npc_consistency import NPCConsistencyCheck

    spec = SnapshotSpec(npc_personas=[])
    result = await NPCConsistencyCheck().check(spec, mock_containers)
    assert result.passed is True
    assert result.advisory is True


@pytest.mark.asyncio
async def test_npc_consistency_fails_high_awareness_high_susceptibility(mock_containers):
    from open_range.validator.npc_consistency import NPCConsistencyCheck

    spec = SnapshotSpec(
        npc_personas=[
            NPCPersona(
                name="Alice",
                security_awareness=0.9,
                susceptibility={"phishing_email": 0.8},
            )
        ]
    )
    result = await NPCConsistencyCheck().check(spec, mock_containers)
    assert result.passed is False
    assert result.advisory is True


@pytest.mark.asyncio
async def test_npc_consistency_fails_out_of_range_awareness(mock_containers):
    from open_range.validator.npc_consistency import NPCConsistencyCheck

    spec = SnapshotSpec(
        npc_personas=[
            NPCPersona(name="BadAwareness", security_awareness=1.5)
        ]
    )
    result = await NPCConsistencyCheck().check(spec, mock_containers)
    assert result.passed is False
    assert "out of [0, 1]" in result.details["issues"][0]


@pytest.mark.asyncio
async def test_npc_consistency_fails_low_awareness_low_susceptibility(mock_containers):
    from open_range.validator.npc_consistency import NPCConsistencyCheck

    spec = SnapshotSpec(
        npc_personas=[
            NPCPersona(
                name="Bob",
                security_awareness=0.2,
                susceptibility={"phishing_email": 0.1, "vishing": 0.1},
            )
        ]
    )
    result = await NPCConsistencyCheck().check(spec, mock_containers)
    assert result.passed is False
    assert "all susceptibility scores < 0.3" in result.details["issues"][0]


@pytest.mark.asyncio
async def test_npc_consistency_passes_valid_personas(mock_containers):
    """Valid personas with consistent awareness and susceptibility pass.

    David (high awareness) passes the LLM test by correctly rejecting phishing.
    Janet (mid-range awareness) is not tested by LLM — only mid-range skips.
    """
    from open_range.validator.npc_consistency import NPCConsistencyCheck

    spec = SnapshotSpec(
        npc_personas=[
            NPCPersona(
                name="David Chen",
                role="CISO",
                department="Security",
                security_awareness=0.95,
                susceptibility={
                    "phishing_email": 0.05,
                    "credential_sharing": 0.01,
                    "attachment_opening": 0.1,
                    "vishing": 0.05,
                },
                accounts={"ldap": "dchen"},
            ),
            NPCPersona(
                name="Janet Smith",
                role="Marketing Coordinator",
                department="Marketing",
                security_awareness=0.5,
                susceptibility={
                    "phishing_email": 0.5,
                    "credential_sharing": 0.3,
                },
            ),
        ]
    )

    # David (high awareness) should report phishing to IT.
    mock_acompletion = AsyncMock(
        return_value=_make_llm_response(
            "report_to_IT",
            "This is clearly a phishing attempt.",
            ["urgency", "suspicious link"],
        )
    )

    with patch("litellm.acompletion", mock_acompletion):
        result = await NPCConsistencyCheck().check(spec, mock_containers)

    assert result.passed is True
    # Only David should be tested (high awareness) — Janet is mid-range.
    assert mock_acompletion.call_count == 1


# ---------------------------------------------------------------------------
# Check 9: NPC consistency — LLM behavioral tests
# ---------------------------------------------------------------------------


def _make_llm_response(action: str, reasoning: str = "", suspicious: list | None = None):
    """Helper to create a mock litellm response."""
    content = json.dumps({
        "action": action,
        "reasoning": reasoning,
        "suspicious_elements_noticed": suspicious or [],
    })
    message = MagicMock()
    message.content = content
    choice = MagicMock()
    choice.message = message
    response = MagicMock()
    response.choices = [choice]
    return response


@pytest.mark.asyncio
async def test_npc_consistency_llm_high_awareness_rejects_phishing(mock_containers):
    """High-awareness NPC correctly rejects phishing — check passes."""
    from open_range.validator.npc_consistency import NPCConsistencyCheck

    spec = SnapshotSpec(
        npc_personas=[
            NPCPersona(
                name="David Chen",
                role="CISO",
                department="Security",
                security_awareness=0.95,
                susceptibility={
                    "phishing_email": 0.05,
                    "credential_sharing": 0.01,
                },
                accounts={"ldap": "dchen"},
            ),
        ]
    )

    mock_acompletion = AsyncMock(
        return_value=_make_llm_response(
            "report_to_IT",
            "This looks like a phishing attempt.",
            ["suspicious link", "urgency"],
        )
    )

    with patch("litellm.acompletion", mock_acompletion):
        result = await NPCConsistencyCheck().check(spec, mock_containers)

    assert result.passed is True
    assert result.advisory is True


@pytest.mark.asyncio
async def test_npc_consistency_llm_high_awareness_falls_for_phishing(mock_containers):
    """High-awareness NPC falls for phishing — check fails."""
    from open_range.validator.npc_consistency import NPCConsistencyCheck

    spec = SnapshotSpec(
        npc_personas=[
            NPCPersona(
                name="David Chen",
                role="CISO",
                department="Security",
                security_awareness=0.95,
                susceptibility={
                    "phishing_email": 0.05,
                },
                accounts={"ldap": "dchen"},
            ),
        ]
    )

    mock_acompletion = AsyncMock(
        return_value=_make_llm_response(
            "click_link",
            "I should reset my password as requested.",
        )
    )

    with patch("litellm.acompletion", mock_acompletion):
        result = await NPCConsistencyCheck().check(spec, mock_containers)

    assert result.passed is False
    assert result.advisory is True
    assert "fell for test phishing" in result.details["issues"][0]


@pytest.mark.asyncio
async def test_npc_consistency_llm_low_awareness_falls_for_phishing(mock_containers):
    """Low-awareness NPC falls for phishing — check passes (expected behavior)."""
    from open_range.validator.npc_consistency import NPCConsistencyCheck

    spec = SnapshotSpec(
        npc_personas=[
            NPCPersona(
                name="Janet Smith",
                role="Marketing Coordinator",
                department="Marketing",
                security_awareness=0.2,
                susceptibility={
                    "phishing_email": 0.7,
                    "attachment_opening": 0.8,
                },
                accounts={"ldap": "jsmith"},
            ),
        ]
    )

    mock_acompletion = AsyncMock(
        return_value=_make_llm_response(
            "click_link",
            "I need to reset my password right away!",
        )
    )

    with patch("litellm.acompletion", mock_acompletion):
        result = await NPCConsistencyCheck().check(spec, mock_containers)

    assert result.passed is True
    assert result.advisory is True


@pytest.mark.asyncio
async def test_npc_consistency_llm_low_awareness_rejects_phishing(mock_containers):
    """Low-awareness NPC rejects phishing — check fails (miscalibrated persona)."""
    from open_range.validator.npc_consistency import NPCConsistencyCheck

    spec = SnapshotSpec(
        npc_personas=[
            NPCPersona(
                name="Janet Smith",
                role="Marketing Coordinator",
                department="Marketing",
                security_awareness=0.2,
                susceptibility={
                    "phishing_email": 0.7,
                },
                accounts={"ldap": "jsmith"},
            ),
        ]
    )

    mock_acompletion = AsyncMock(
        return_value=_make_llm_response(
            "report_to_IT",
            "This seems suspicious, I'll forward it to IT.",
            ["suspicious URL"],
        )
    )

    with patch("litellm.acompletion", mock_acompletion):
        result = await NPCConsistencyCheck().check(spec, mock_containers)

    assert result.passed is False
    assert result.advisory is True
    assert "rejected test phishing" in result.details["issues"][0]
    assert "miscalibrated" in result.details["issues"][0]


@pytest.mark.asyncio
async def test_npc_consistency_llm_failure_degrades_gracefully(mock_containers):
    """LLM failure does not cause the check to fail — degrades gracefully."""
    from open_range.validator.npc_consistency import NPCConsistencyCheck

    spec = SnapshotSpec(
        npc_personas=[
            NPCPersona(
                name="David Chen",
                role="CISO",
                security_awareness=0.95,
                susceptibility={"phishing_email": 0.05},
                accounts={"ldap": "dchen"},
            ),
        ]
    )

    mock_acompletion = AsyncMock(side_effect=Exception("API rate limit exceeded"))

    with patch("litellm.acompletion", mock_acompletion):
        result = await NPCConsistencyCheck().check(spec, mock_containers)

    # LLM failure should not cause the check to fail — mechanical checks passed.
    assert result.passed is True
    assert result.advisory is True


@pytest.mark.asyncio
async def test_npc_consistency_skips_mid_awareness_llm_test(mock_containers):
    """Mid-range awareness personas (0.3-0.8) skip LLM behavioral test."""
    from open_range.validator.npc_consistency import NPCConsistencyCheck

    spec = SnapshotSpec(
        npc_personas=[
            NPCPersona(
                name="Bob Neutral",
                role="Accountant",
                security_awareness=0.5,
                susceptibility={"phishing_email": 0.5},
            ),
        ]
    )

    # The LLM should NOT be called for mid-range personas.
    mock_acompletion = AsyncMock(
        side_effect=AssertionError("LLM should not be called for mid-range awareness")
    )

    with patch("litellm.acompletion", mock_acompletion):
        result = await NPCConsistencyCheck().check(spec, mock_containers)

    assert result.passed is True
    mock_acompletion.assert_not_called()


# ---------------------------------------------------------------------------
# Check 10: Realism review (LLM advisory)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_realism_review_advisory_flag(mock_containers):
    from open_range.validator.realism_review import RealismReviewCheck

    spec = SnapshotSpec(topology={"hosts": ["web"], "tier": 1})
    with patch("litellm.acompletion", AsyncMock(side_effect=Exception("no provider configured"))):
        result = await RealismReviewCheck().check(spec, mock_containers)
    # Should pass (advisory) when the LLM path is unavailable or misconfigured.
    assert result.advisory is True
    assert result.passed is True


@pytest.mark.asyncio
async def test_realism_review_passes_with_llm(mock_containers):
    """Realism review passes when LLM finds no issues."""
    from open_range.validator.realism_review import RealismReviewCheck

    spec = SnapshotSpec(
        topology={"hosts": ["web", "db"], "tier": 1},
        truth_graph=TruthGraph(vulns=[
            Vulnerability(id="v1", type="sqli", host="web"),
        ]),
        golden_path=[GoldenPathStep(step=i, command=f"cmd_{i}") for i in range(1, 9)],
        task=TaskSpec(
            red_briefing="Investigate the corporate network.",
            blue_briefing="Monitor for threats.",
        ),
    )

    llm_response_content = json.dumps({"pass": True, "issues": []})
    message = MagicMock()
    message.content = llm_response_content
    choice = MagicMock()
    choice.message = message
    mock_response = MagicMock()
    mock_response.choices = [choice]

    mock_acompletion = AsyncMock(return_value=mock_response)

    with patch("litellm.acompletion", mock_acompletion):
        result = await RealismReviewCheck().check(spec, mock_containers)

    assert result.passed is True
    assert result.advisory is True
    assert result.details["issues"] == []


@pytest.mark.asyncio
async def test_realism_review_fails_with_issues(mock_containers):
    """Realism review fails when LLM finds issues (but still advisory)."""
    from open_range.validator.realism_review import RealismReviewCheck

    spec = SnapshotSpec(
        topology={"hosts": ["web"], "tier": 1},
        truth_graph=TruthGraph(vulns=[
            Vulnerability(id="v1", type="sqli", host="web"),
        ]),
        golden_path=[GoldenPathStep(step=1, command="cmd_1")],
        task=TaskSpec(
            red_briefing="Find the SQL injection vulnerability.",
            blue_briefing="Monitor for threats.",
        ),
    )

    issues = ["Red briefing leaks vulnerability type (SQL injection)"]
    llm_response_content = json.dumps({"pass": False, "issues": issues})
    message = MagicMock()
    message.content = llm_response_content
    choice = MagicMock()
    choice.message = message
    mock_response = MagicMock()
    mock_response.choices = [choice]

    mock_acompletion = AsyncMock(return_value=mock_response)

    with patch("litellm.acompletion", mock_acompletion):
        result = await RealismReviewCheck().check(spec, mock_containers)

    assert result.passed is False
    assert result.advisory is True
    assert "SQL injection" in result.error
    assert result.details["issues"] == issues


@pytest.mark.asyncio
async def test_realism_review_never_sends_flags_to_llm(mock_containers):
    """Verify the redacted summary sent to LLM never contains flag values."""
    from open_range.validator.realism_review import RealismReviewCheck

    flag_value = "FLAG{super_secret_123}"
    spec = SnapshotSpec(
        topology={"hosts": ["web", "db"], "tier": 1},
        truth_graph=TruthGraph(vulns=[
            Vulnerability(id="v1", type="sqli", host="web"),
        ]),
        flags=[FlagSpec(id="f1", value=flag_value, path="/f.txt", host="db")],
        golden_path=[
            GoldenPathStep(
                step=1,
                command=f"cat /f.txt  # reveals {flag_value}",
                expect_in_stdout=flag_value,
            ),
        ],
        task=TaskSpec(
            red_briefing="Investigate the network.",
            blue_briefing="Monitor for threats.",
        ),
    )

    captured_messages = []

    async def capturing_acompletion(**kwargs):
        captured_messages.append(kwargs.get("messages", []))
        content = json.dumps({"pass": True, "issues": []})
        message = MagicMock()
        message.content = content
        choice = MagicMock()
        choice.message = message
        response = MagicMock()
        response.choices = [choice]
        return response

    with patch("litellm.acompletion", capturing_acompletion):
        result = await RealismReviewCheck().check(spec, mock_containers)

    assert result.passed is True
    # Verify the flag value was NOT in the messages sent to LLM
    for msg_list in captured_messages:
        for msg in msg_list:
            assert flag_value not in msg.get("content", ""), \
                "Flag value was leaked to the LLM reviewer!"
            # Also verify golden path commands are not leaked
            assert "cat /f.txt" not in msg.get("content", ""), \
                "Golden path command was leaked to the LLM reviewer!"


@pytest.mark.asyncio
async def test_realism_review_llm_failure_degrades_gracefully(mock_containers):
    """LLM failure should not block validation — passes with advisory note."""
    from open_range.validator.realism_review import RealismReviewCheck

    spec = SnapshotSpec(
        topology={"hosts": ["web"], "tier": 1},
        truth_graph=TruthGraph(vulns=[
            Vulnerability(id="v1", type="sqli", host="web"),
        ]),
        golden_path=[GoldenPathStep(step=i, command=f"cmd_{i}") for i in range(1, 9)],
        task=TaskSpec(red_briefing="Investigate.", blue_briefing="Monitor."),
    )

    mock_acompletion = AsyncMock(side_effect=Exception("API key invalid"))

    with patch("litellm.acompletion", mock_acompletion):
        result = await RealismReviewCheck().check(spec, mock_containers)

    # Should pass even though LLM failed — advisory check degrades gracefully.
    assert result.passed is True
    assert result.advisory is True
    assert "LLM review failed" in result.details["note"]


@pytest.mark.asyncio
async def test_realism_review_malformed_llm_response(mock_containers):
    """Malformed LLM JSON response degrades gracefully."""
    from open_range.validator.realism_review import RealismReviewCheck

    spec = SnapshotSpec(
        topology={"hosts": ["web"], "tier": 1},
        truth_graph=TruthGraph(vulns=[
            Vulnerability(id="v1", type="sqli", host="web"),
        ]),
        golden_path=[GoldenPathStep(step=i, command=f"cmd_{i}") for i in range(1, 9)],
        task=TaskSpec(red_briefing="Investigate.", blue_briefing="Monitor."),
    )

    # Return invalid JSON
    message = MagicMock()
    message.content = "not valid json at all"
    choice = MagicMock()
    choice.message = message
    mock_response = MagicMock()
    mock_response.choices = [choice]

    mock_acompletion = AsyncMock(return_value=mock_response)

    with patch("litellm.acompletion", mock_acompletion):
        result = await RealismReviewCheck().check(spec, mock_containers)

    # Should pass gracefully — bad JSON is handled like an LLM failure.
    assert result.passed is True
    assert result.advisory is True


# ---------------------------------------------------------------------------
# ValidatorGate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_validator_gate_all_pass(sample_snapshot_spec, mock_containers):
    """Gate with passing checks returns passed=True."""

    class AlwaysPass:
        async def check(self, snapshot, containers):
            return CheckResult(name="pass_check", passed=True)

    gate = ValidatorGate([AlwaysPass(), AlwaysPass()])
    result = await gate.validate(sample_snapshot_spec, mock_containers)
    assert result.passed is True
    assert len(result.checks) == 2
    assert result.total_time_s >= 0


@pytest.mark.asyncio
async def test_validator_gate_fail_fast_on_mechanical(sample_snapshot_spec, mock_containers):
    """Mechanical failure stops the pipeline."""

    class Fail:
        async def check(self, snapshot, containers):
            return CheckResult(name="fail_check", passed=False, error="broken")

    class NeverReached:
        async def check(self, snapshot, containers):
            raise AssertionError("should not be reached")

    gate = ValidatorGate([Fail(), NeverReached()])
    result = await gate.validate(sample_snapshot_spec, mock_containers)
    assert result.passed is False
    assert len(result.checks) == 1  # second check was never run


@pytest.mark.asyncio
async def test_validator_gate_advisory_does_not_block(sample_snapshot_spec, mock_containers):
    """Advisory check failure does not prevent overall pass."""

    class Pass:
        async def check(self, snapshot, containers):
            return CheckResult(name="ok", passed=True)

    class AdvisoryFail:
        async def check(self, snapshot, containers):
            return CheckResult(name="adv", passed=False, advisory=True, error="meh")

    gate = ValidatorGate([Pass(), AdvisoryFail()])
    result = await gate.validate(sample_snapshot_spec, mock_containers)
    assert result.passed is True
    assert len(result.checks) == 2


@pytest.mark.asyncio
async def test_validator_gate_catches_exception(sample_snapshot_spec, mock_containers):
    """Unhandled exception in a check is caught and recorded as failure."""

    class Boom:
        async def check(self, snapshot, containers):
            raise RuntimeError("kaboom")

    gate = ValidatorGate([Boom()])
    result = await gate.validate(sample_snapshot_spec, mock_containers)
    assert result.passed is False
    assert "kaboom" in result.checks[0].error


@pytest.mark.asyncio
async def test_validator_gate_advisory_failure_does_not_stop_pipeline(
    sample_snapshot_spec, mock_containers
):
    """Advisory failures do not stop the pipeline — subsequent checks still run."""

    class MechanicalPass:
        async def check(self, snapshot, containers):
            return CheckResult(name="mechanical_ok", passed=True)

    class AdvisoryFail:
        async def check(self, snapshot, containers):
            return CheckResult(name="advisory_fail", passed=False, advisory=True, error="soft fail")

    class SecondMechanicalPass:
        async def check(self, snapshot, containers):
            return CheckResult(name="mechanical_ok_2", passed=True)

    gate = ValidatorGate([MechanicalPass(), AdvisoryFail(), SecondMechanicalPass()])
    result = await gate.validate(sample_snapshot_spec, mock_containers)
    assert result.passed is True
    assert len(result.checks) == 3  # All three checks ran


@pytest.mark.asyncio
async def test_validator_gate_mixed_mechanical_advisory(sample_snapshot_spec, mock_containers):
    """Mechanical pass + advisory fail = overall pass."""

    checks_run = []

    class Mechanical:
        async def check(self, snapshot, containers):
            checks_run.append("mechanical")
            return CheckResult(name="mechanical", passed=True)

    class Advisory:
        async def check(self, snapshot, containers):
            checks_run.append("advisory")
            return CheckResult(name="advisory", passed=False, advisory=True, error="issue")

    gate = ValidatorGate([Mechanical(), Advisory()])
    result = await gate.validate(sample_snapshot_spec, mock_containers)
    assert result.passed is True
    assert checks_run == ["mechanical", "advisory"]
    # Advisory failure should be recorded
    assert result.checks[1].passed is False
    assert result.checks[1].advisory is True


@pytest.mark.asyncio
async def test_validator_gate_mechanical_fail_before_advisory(
    sample_snapshot_spec, mock_containers
):
    """Mechanical failure before advisory checks prevents advisory from running."""

    class MechanicalFail:
        async def check(self, snapshot, containers):
            return CheckResult(name="mech_fail", passed=False, error="hard fail")

    class AdvisoryNeverReached:
        async def check(self, snapshot, containers):
            raise AssertionError("should not reach advisory check")

    gate = ValidatorGate([MechanicalFail(), AdvisoryNeverReached()])
    result = await gate.validate(sample_snapshot_spec, mock_containers)
    assert result.passed is False
    assert len(result.checks) == 1


# ---------------------------------------------------------------------------
# Full 10-check pipeline simulation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_full_pipeline_all_mechanical_pass_advisory_pass(
    sample_snapshot_spec, mock_containers
):
    """Simulate all 10 checks passing."""

    class MechanicalPass:
        async def check(self, snapshot, containers):
            return CheckResult(name="mechanical", passed=True)

    class NPCConsistencyCheck:
        async def check(self, snapshot, containers):
            return CheckResult(name="npc_consistency", passed=True, advisory=True)

    class RealismReviewCheck:
        async def check(self, snapshot, containers):
            return CheckResult(name="realism_review", passed=True, advisory=True)

    checks = [MechanicalPass() for _ in range(8)]
    checks.append(NPCConsistencyCheck())
    checks.append(RealismReviewCheck())

    gate = ValidatorGate(checks)
    result = await gate.validate(sample_snapshot_spec, mock_containers)
    assert result.passed is True
    assert len(result.checks) == 10


@pytest.mark.asyncio
async def test_full_pipeline_mechanical_pass_advisory_fail(
    sample_snapshot_spec, mock_containers
):
    """All mechanical pass, advisory checks fail — overall still passes."""

    class MechanicalPass:
        async def check(self, snapshot, containers):
            return CheckResult(name="mechanical", passed=True)

    class NPCConsistencyCheck:
        async def check(self, snapshot, containers):
            return CheckResult(
                name="npc_consistency", passed=False, advisory=True,
                error="NPC miscalibrated"
            )

    class RealismReviewCheck:
        async def check(self, snapshot, containers):
            return CheckResult(
                name="realism_review", passed=False, advisory=True,
                error="briefing leakage"
            )

    checks = [MechanicalPass() for _ in range(8)]
    checks.append(NPCConsistencyCheck())
    checks.append(RealismReviewCheck())

    gate = ValidatorGate(checks)
    result = await gate.validate(sample_snapshot_spec, mock_containers)
    assert result.passed is True
    assert len(result.checks) == 10
    # Advisory failures are recorded
    assert result.checks[8].passed is False
    assert result.checks[8].advisory is True
    assert result.checks[9].passed is False
    assert result.checks[9].advisory is True


@pytest.mark.asyncio
async def test_full_pipeline_mechanical_fail_skips_rest(
    sample_snapshot_spec, mock_containers
):
    """Mechanical failure at check 3 stops pipeline — checks 4-10 never run."""
    run_order = []

    class TrackedPass:
        def __init__(self, n):
            self.n = n

        async def check(self, snapshot, containers):
            run_order.append(self.n)
            return CheckResult(name=f"check_{self.n}", passed=True)

    class TrackedFail:
        def __init__(self, n):
            self.n = n

        async def check(self, snapshot, containers):
            run_order.append(self.n)
            return CheckResult(name=f"check_{self.n}", passed=False, error="fail")

    checks = [TrackedPass(1), TrackedPass(2), TrackedFail(3)]
    checks.extend([TrackedPass(i) for i in range(4, 9)])
    # Checks 9 and 10 are advisory but never reached
    checks.append(TrackedPass(9))
    checks.append(TrackedPass(10))

    gate = ValidatorGate(checks)
    result = await gate.validate(sample_snapshot_spec, mock_containers)
    assert result.passed is False
    assert run_order == [1, 2, 3]  # Only first 3 ran
    assert len(result.checks) == 3
