"""Admission checks and private runtime helpers."""

from __future__ import annotations

import json
from pathlib import Path

from open_range.admission.encryption import check_encryption_enforcement
from open_range.admission.identity import check_identity_enforcement
from open_range.admission.models import (
    ReferenceBundle,
    ValidatorCheckReport,
)
from open_range.admission.mtls import check_mtls_enforcement
from open_range.admission.references import (
    build_reference_bundle,
    ephemeral_runtime_snapshot,
    reference_weakness_id,
)
from open_range.admission.registry import admission_check
from open_range.build_config import BuildConfig
from open_range.catalog.services import service_kind_names
from open_range.objectives.engine import PredicateEngine
from open_range.runtime.replay import run_blue_reference, run_red_reference
from open_range.snapshot import KindArtifacts, world_hash
from open_range.weaknesses import remediation_command_for_weakness
from open_range.world_ir import WorldIR


@admission_check("manifest_compliance")
def _check_manifest_compliance(
    world: WorldIR, _artifacts: KindArtifacts, _wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    allowed = set(service_kind_names())
    invalid = sorted(
        service.kind for service in world.services if service.kind not in allowed
    )
    passed = world.world_family == "enterprise_saas_v1" and not invalid
    return ValidatorCheckReport(
        name="manifest_compliance",
        passed=passed,
        details={"invalid_service_kinds": invalid},
        error="" if passed else "world violates the fixed service palette",
    )


@admission_check("graph_consistency")
def _check_graph_consistency(
    world: WorldIR, _artifacts: KindArtifacts, _wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    host_ids = {host.id for host in world.hosts}
    service_ids = {service.id for service in world.services}
    asset_ids = {asset.id for asset in world.assets}
    issues = []

    if len(host_ids) != len(world.hosts):
        issues.append("duplicate host ids")
    if len(service_ids) != len(world.services):
        issues.append("duplicate service ids")

    for service in world.services:
        if service.host not in host_ids:
            issues.append(
                f"service {service.id} references missing host {service.host}"
            )
        for dep in service.dependencies:
            if dep not in service_ids:
                issues.append(
                    f"service {service.id} references missing dependency {dep}"
                )

    for asset in world.assets:
        if asset.owner_service not in service_ids:
            issues.append(
                f"asset {asset.id} references missing owner service {asset.owner_service}"
            )

    valid_nodes = (
        host_ids
        | service_ids
        | asset_ids
        | {group.id for group in world.groups}
        | {user.id for user in world.users}
        | {user.role for user in world.users}
        | {workflow.id for workflow in world.workflows}
    )
    for edge in world.edges:
        if edge.source not in valid_nodes:
            issues.append(f"edge {edge.id} missing source {edge.source}")
        if edge.target not in valid_nodes:
            issues.append(f"edge {edge.id} missing target {edge.target}")

    return ValidatorCheckReport(
        name="graph_consistency",
        passed=not issues,
        details={"issues": issues},
        error="; ".join(issues),
    )


@admission_check("path_solvability")
def _check_path_solvability(
    world: WorldIR, _artifacts: KindArtifacts, _wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    predicates = PredicateEngine(world)
    starts = {
        service.id
        for service in world.services
        if predicates.is_public_service(service)
    }
    unreachable = []
    for objective in world.red_objectives:
        target_service = predicates.objective_target_service(objective.predicate)
        if target_service and not predicates.reachable_from_any(starts, target_service):
            unreachable.append(target_service)
    return ValidatorCheckReport(
        name="path_solvability",
        passed=not unreachable,
        details={"starts": sorted(starts), "unreachable_targets": unreachable},
        error=""
        if not unreachable
        else f"unreachable objective targets: {sorted(set(unreachable))}",
    )


@admission_check("objective_grounding")
def _check_objective_grounding(
    world: WorldIR, _artifacts: KindArtifacts, _wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    predicates = PredicateEngine(world)
    issues = []
    graders = {}
    for objective in world.red_objectives + world.blue_objectives:
        if not predicates.is_groundable(objective.predicate):
            issues.append(objective.predicate)
            continue
        grader = predicates.objective_grader(objective.predicate)
        if objective.owner == "red" and grader is None:
            issues.append(f"missing service-native grader for {objective.predicate}")
            continue
        if grader is not None:
            graders[objective.predicate] = grader.model_dump(mode="json")
    if not predicates.active_weaknesses():
        issues.append("no weaknesses seeded")
    return ValidatorCheckReport(
        name="objective_grounding",
        passed=not issues,
        details={"issues": issues, "graders": graders},
        error="; ".join(issues),
    )


@admission_check("topology_workflow_consistency")
def _check_workflow_consistency(
    world: WorldIR, _artifacts: KindArtifacts, _wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    service_ids = {service.id for service in world.services}
    asset_ids = {asset.id for asset in world.assets}
    issues = []
    for workflow in world.workflows:
        for step in workflow.steps:
            if step.service and step.service not in service_ids:
                issues.append(
                    f"workflow {workflow.id} references missing service {step.service}"
                )
            if step.asset and step.asset not in asset_ids:
                issues.append(
                    f"workflow {workflow.id} references missing asset {step.asset}"
                )
    return ValidatorCheckReport(
        name="topology_workflow_consistency",
        passed=not issues,
        details={"issues": issues},
        error="; ".join(issues),
    )


@admission_check("render_outputs")
def _check_render_outputs(
    _world: WorldIR, artifacts: KindArtifacts, _wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    missing = [path for path in artifacts.rendered_files if not Path(path).exists()]
    return ValidatorCheckReport(
        name="render_outputs",
        passed=not missing,
        details={"missing": missing},
        error="" if not missing else f"missing rendered files: {missing}",
    )


@admission_check("identity_enforcement")
def _check_identity_enforcement(
    world: WorldIR, artifacts: KindArtifacts, wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    return check_identity_enforcement(world, artifacts, wb)


@admission_check("encryption_enforcement")
def _check_encryption_enforcement(
    world: WorldIR, artifacts: KindArtifacts, wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    return check_encryption_enforcement(world, artifacts, wb)


@admission_check("mtls_enforcement")
def _check_mtls_enforcement(
    world: WorldIR, artifacts: KindArtifacts, wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    return check_mtls_enforcement(world, artifacts, wb)


@admission_check("service_health")
def _check_service_health_contract(
    world: WorldIR, artifacts: KindArtifacts, _wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    rendered = artifacts.chart_values.get("services", {})
    missing = [service.id for service in world.services if service.id not in rendered]
    passed = not missing and len(rendered) == len(world.services)
    return ValidatorCheckReport(
        name="service_health",
        passed=passed,
        details={"missing_services": missing, "rendered_service_count": len(rendered)},
        error=""
        if passed
        else f"services missing from rendered chart values: {missing}",
    )


@admission_check("siem_ingest")
def _check_siem_ingest(
    world: WorldIR, _artifacts: KindArtifacts, _wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    telemetry_targets = {edge.target for edge in world.telemetry_edges}
    actual_sources = {edge.source for edge in world.telemetry_edges}
    expected_sources = {
        service.id for service in world.services if service.id != "svc-siem"
    }
    passed = "svc-siem" in telemetry_targets and expected_sources <= actual_sources
    return ValidatorCheckReport(
        name="siem_ingest",
        passed=passed,
        details={
            "expected_sources": sorted(expected_sources),
            "actual_sources": sorted(actual_sources),
        },
        error="" if passed else "not all services ship telemetry to svc-siem",
    )


@admission_check("isolation")
def _check_isolation(
    world: WorldIR, _artifacts: KindArtifacts, _wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    issues = []
    host_by_id = {host.id: host for host in world.hosts}
    for service in world.services:
        host = host_by_id[service.host]
        if host.zone in {"data", "management"} and host.exposure == "public":
            issues.append(f"{service.id} is public in restricted zone {host.zone}")
    return ValidatorCheckReport(
        name="isolation",
        passed=not issues,
        details={"issues": issues},
        error="; ".join(issues),
    )


@admission_check("difficulty_envelope")
def _check_difficulty_envelope(
    world: WorldIR, _artifacts: KindArtifacts, _wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    predicates = PredicateEngine(world)
    red_depth = predicates.red_path_depth()
    lower = max(1, world.target_red_path_depth - 2)
    upper = world.target_red_path_depth + 2
    blue_signal_points = len({edge.source for edge in world.telemetry_edges})
    passed = lower <= red_depth <= upper and blue_signal_points >= min(
        world.target_blue_signal_points, len(world.services)
    )
    return ValidatorCheckReport(
        name="difficulty_envelope",
        passed=passed,
        details={
            "computed_red_path_depth": red_depth,
            "target_red_path_depth": world.target_red_path_depth,
            "blue_signal_points": blue_signal_points,
            "target_blue_signal_points": world.target_blue_signal_points,
        },
        error=""
        if passed
        else "world falls outside the configured difficulty envelope",
    )


@admission_check("red_reference")
def _check_red_reference(
    world: WorldIR, artifacts: KindArtifacts, wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    if wb is None or not wb.reference_attack_traces:
        return ValidatorCheckReport(
            name="red_reference",
            passed=False,
            details={"trace_id": "", "step_count": 0},
            error="no valid red reference",
        )
    snapshot = ephemeral_runtime_snapshot(world, artifacts, wb)
    predicates = PredicateEngine(world)
    per_trace = []
    passed = True
    satisfied_all: set[str] = set()
    for trace_index, trace in enumerate(wb.reference_attack_traces):
        score, events, health, outputs = run_red_reference(
            snapshot,
            None,
            episode_seed=world.seed,
            trace_index=trace_index,
        )
        satisfied = predicates.evaluate_red_objectives(
            snapshot=snapshot,
            events=events,
            service_health=dict(health),
        )
        trace_passed = (
            score.winner == "red"
            and score.done
            and predicates.red_terminal_satisfied(satisfied)
        )
        passed = passed and trace_passed
        satisfied_all.update(satisfied)
        per_trace.append(
            {
                "trace_id": trace.id,
                "step_count": len(trace.steps),
                "winner": score.winner,
                "event_count": len(events),
                "satisfied_predicates": sorted(satisfied),
                "outputs": outputs,
                "passed": trace_passed,
            }
        )
    return ValidatorCheckReport(
        name="red_reference",
        passed=passed,
        details={
            "trace_count": len(per_trace),
            "satisfied_predicates": sorted(satisfied_all),
            "traces": per_trace,
        },
        error=""
        if passed
        else "offline red reference did not satisfy terminal objectives",
    )


@admission_check("blue_reference")
def _check_blue_reference(
    world: WorldIR, artifacts: KindArtifacts, wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    if wb is None or not wb.reference_defense_traces:
        return ValidatorCheckReport(
            name="blue_reference",
            passed=False,
            details={"trace_id": "", "step_count": 0},
            error="no valid blue reference",
        )
    snapshot = ephemeral_runtime_snapshot(world, artifacts, wb)
    per_trace = []
    passed = True
    for trace_index, trace in enumerate(wb.reference_defense_traces):
        score, outputs = run_blue_reference(snapshot, None, trace_index=trace_index)
        trace_passed = (
            score.winner == "blue"
            and score.done
            and len(trace.objective_ids) <= len(world.blue_objectives)
        )
        passed = passed and trace_passed
        per_trace.append(
            {
                "trace_id": trace.id,
                "step_count": len(trace.steps),
                "winner": score.winner,
                "outputs": outputs,
                "passed": trace_passed,
            }
        )
    return ValidatorCheckReport(
        name="blue_reference",
        passed=passed,
        details={"trace_count": len(per_trace), "traces": per_trace},
        error=""
        if passed
        else "offline blue reference did not validate detect-and-contain path",
    )


@admission_check("necessity")
def _check_necessity(
    world: WorldIR, artifacts: KindArtifacts, wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    weaknesses = PredicateEngine(world).active_weaknesses()
    observability_sources = {edge.source for edge in world.telemetry_edges}
    executable_targets = {
        weak.target for weak in weaknesses if remediation_command_for_weakness(weak)
    }
    trace_bindings = []
    if wb is not None:
        for trace_index, red_trace in enumerate(wb.reference_attack_traces):
            weakness_id = reference_weakness_id(red_trace)
            weakness = next(
                (weak for weak in weaknesses if weak.id == weakness_id), None
            )
            if weakness is not None:
                trace_bindings.append((trace_index, red_trace, weakness))
    issues = []
    if not weaknesses:
        issues.append("no weakness targets")
    if not trace_bindings:
        issues.append("red reference does not reference an exact seeded weakness")
    if not observability_sources:
        issues.append("blue reference lacks observability substrate")
    if not all(weak.remediation for weak in weaknesses):
        issues.append("one or more weaknesses lack remediation metadata")
    if not executable_targets:
        issues.append("no executable remediation exists for live necessity checks")
    elif not any(
        weakness.target in executable_targets
        for _idx, _trace, weakness in trace_bindings
    ):
        issues.append("no reference-relevant weakness has executable remediation")
    if not issues and trace_bindings:
        trace_results = []
        for trace_index, _trace, weakness in trace_bindings:
            counterfactual_world = world.model_copy(
                update={
                    "weaknesses": tuple(
                        weak for weak in world.weaknesses if weak.id != weakness.id
                    )
                }
            )
            score, _events, _health, outputs = run_red_reference(
                ephemeral_runtime_snapshot(counterfactual_world, artifacts, wb),
                None,
                episode_seed=counterfactual_world.seed,
                trace_index=trace_index,
            )
            trace_passed = score.winner != "red"
            if not trace_passed:
                issues.append(
                    f"counterfactual red reference {trace_index} still succeeds after removing {weakness.id}"
                )
            trace_results.append(
                {
                    "trace_id": wb.reference_attack_traces[trace_index].id,
                    "weakness_id": weakness.id,
                    "counterfactual_winner": score.winner,
                    "outputs": outputs,
                    "passed": trace_passed,
                }
            )
        details = {"traces": trace_results}
    else:
        details = {"issues": issues}
    return ValidatorCheckReport(
        name="necessity",
        passed=not issues,
        details=details,
        error="; ".join(issues),
    )


@admission_check("shortcut_probes")
def _check_shortcut_probes(
    world: WorldIR, artifacts: KindArtifacts, wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    probes = wb.shortcut_probes if wb else ()
    predicates = PredicateEngine(world)
    public_services = {
        service.id
        for service in world.services
        if predicates.is_public_service(service)
    }
    critical_assets = {
        asset.owner_service
        for asset in world.assets
        if asset.confidentiality == "critical"
    }
    issues = []
    if public_services & critical_assets:
        issues.append("critical asset exposed directly via public service")
    if not probes:
        issues.append("no shortcut probes generated")
    issues.extend(_artifact_shortcut_findings(world, artifacts))
    issues.extend(_unlogged_critical_action_findings(world))
    return ValidatorCheckReport(
        name="shortcut_probes",
        passed=not issues,
        details={"issues": issues, "probe_count": len(probes)},
        error="; ".join(issues),
    )


@admission_check("determinism")
def _check_determinism(
    world: WorldIR, artifacts: KindArtifacts, wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    regenerated = build_reference_bundle(
        world,
        BuildConfig(
            red_reference_count=len(wb.reference_attack_traces) if wb else 1,
            blue_reference_count=len(wb.reference_defense_traces) if wb else 1,
        ),
    )
    snapshot = ephemeral_runtime_snapshot(world, artifacts, wb or regenerated)
    trace_results = []
    passed = wb is not None and regenerated.model_dump(mode="json") == wb.model_dump(
        mode="json"
    )
    for trace_index, trace in enumerate((wb or regenerated).reference_attack_traces):
        first_score, first_events, first_health, _first_outputs = run_red_reference(
            snapshot,
            None,
            episode_seed=world.seed,
            trace_index=trace_index,
        )
        second_score, second_events, second_health, _second_outputs = run_red_reference(
            snapshot,
            None,
            episode_seed=world.seed,
            trace_index=trace_index,
        )
        trace_passed = (
            first_events == second_events
            and first_health == second_health
            and first_score.winner == second_score.winner
            and first_score.terminal_reason == second_score.terminal_reason
        )
        passed = passed and trace_passed
        trace_results.append(
            {
                "trace_id": trace.id,
                "first_event_count": len(first_events),
                "second_event_count": len(second_events),
                "winner": first_score.winner,
                "passed": trace_passed,
            }
        )
    return ValidatorCheckReport(
        name="determinism",
        passed=passed,
        details={
            "world_hash": world_hash(world),
            "trace_count": len(trace_results),
            "traces": trace_results,
        },
        error="" if passed else "reference execution is not deterministic",
    )


def _artifact_shortcut_findings(world: WorldIR, artifacts: KindArtifacts) -> list[str]:
    findings: list[str] = []
    public_services = {
        service.id
        for service in world.services
        if PredicateEngine(world).is_public_service(service)
    }
    materials = _sensitive_materials(world)
    if not materials:
        return findings

    summary_payload: dict[str, object] | None = None
    summary_path = next(
        (
            Path(path)
            for path in artifacts.rendered_files
            if path.endswith("synth-summary.json")
        ),
        None,
    )
    if summary_path is not None and summary_path.exists():
        try:
            summary_payload = json.loads(summary_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            summary_payload = None

    if isinstance(summary_payload, dict):
        mailboxes = summary_payload.get("mailboxes", {})
        if isinstance(mailboxes, dict):
            for mailbox, messages in mailboxes.items():
                joined = (
                    "\n".join(str(message) for message in messages)
                    if isinstance(messages, list)
                    else str(messages)
                )
                for ref, material in materials.items():
                    if material in joined and not _mailbox_leak_allowed(world, ref):
                        findings.append(f"mailbox_secret_leak:{mailbox}:{ref}")

    for file_path in artifacts.rendered_files:
        path = Path(file_path)
        if not path.exists() or path.name == "synth-summary.json":
            continue
        service_id = _artifact_service_id(path, public_services)
        if service_id is None:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for ref, material in materials.items():
            if material in text and not _public_leak_allowed(world, service_id, ref):
                findings.append(f"public_surface_secret_leak:{service_id}:{ref}")
    return sorted(dict.fromkeys(findings))


def _unlogged_critical_action_findings(world: WorldIR) -> list[str]:
    service_by_id = {service.id: service for service in world.services}
    telemetry_sources = {
        edge.source for edge in world.telemetry_edges if edge.target == "svc-siem"
    }
    findings: list[str] = []
    for weakness in PredicateEngine(world).active_weaknesses():
        if weakness.family == "telemetry_blindspot":
            continue
        service = service_by_id.get(weakness.target)
        if service is None:
            continue
        if weakness.target not in telemetry_sources:
            findings.append(f"unlogged_critical_action:no_siem_edge:{weakness.id}")
            continue
        expected_surfaces = set(weakness.blue_observability_surfaces) - {"svc-siem"}
        if expected_surfaces and not (
            set(service.telemetry_surfaces) & expected_surfaces
        ):
            findings.append(
                f"unlogged_critical_action:no_surface_overlap:{weakness.id}"
            )
    return findings


def _sensitive_materials(world: WorldIR) -> dict[str, str]:
    materials: dict[str, str] = {}
    for asset in world.assets:
        if asset.confidentiality in {"high", "critical"}:
            materials[asset.id] = f"seeded-{asset.asset_class}-{asset.id}"
    for user in world.users:
        materials[f"user:{user.id}"] = f"{user.id}-pass"
    for credential in world.credentials:
        materials[credential.id] = f"seeded-secret-{credential.id}"
    return materials


def _artifact_service_id(path: Path, public_services: set[str]) -> str | None:
    parts = path.parts
    for service_id in public_services:
        if service_id in parts:
            return service_id
    return None


def _public_leak_allowed(world: WorldIR, service_id: str, ref: str) -> bool:
    asset = next((asset for asset in world.assets if asset.id == ref), None)
    if asset is not None and asset.owner_service == service_id:
        return True
    return any(
        weakness.family == "secret_exposure"
        and weakness.target == service_id
        and weakness.target_ref == ref
        for weakness in world.weaknesses
    )


def _mailbox_leak_allowed(world: WorldIR, ref: str) -> bool:
    return any(
        weakness.kind == "token_in_email" and weakness.target_ref == ref
        for weakness in world.weaknesses
    )
