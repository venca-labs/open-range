"""Admission checks and private runtime helpers."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from open_range.admission.encryption import check_encryption_enforcement
from open_range.admission.identity import check_identity_enforcement
from open_range.admission.models import (
    ReferenceBundle,
    ValidatorCheckReport,
)
from open_range.admission.mtls import check_mtls_enforcement
from open_range.admission.reference_checks import (
    check_blue_reference,
    check_determinism,
    check_red_reference,
    reference_trace_bindings,
    run_red_reference,
)
from open_range.admission.references import (
    build_reference_bundle,
    ephemeral_runtime_snapshot,
)
from open_range.catalog.services import service_kind_names
from open_range.config import BuildConfig
from open_range.contracts.snapshot import KindArtifacts, world_hash
from open_range.contracts.world import WorldIR
from open_range.objectives.engine import PredicateEngine
from open_range.weaknesses import remediation_command_for_weakness

CheckFunc = Callable[
    [WorldIR, KindArtifacts, ReferenceBundle | None], ValidatorCheckReport
]


@dataclass(frozen=True, slots=True)
class BuiltinAdmissionCheckSpec:
    name: str
    fn: CheckFunc
    stage: str
    requires_references: bool = False


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


def _check_identity_enforcement(
    world: WorldIR, artifacts: KindArtifacts, wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    return check_identity_enforcement(world, artifacts, wb)


def _check_encryption_enforcement(
    world: WorldIR, artifacts: KindArtifacts, wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    return check_encryption_enforcement(world, artifacts, wb)


def _check_mtls_enforcement(
    world: WorldIR, artifacts: KindArtifacts, wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    return check_mtls_enforcement(world, artifacts, wb)


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
    return check_red_reference(ephemeral_runtime_snapshot(world, artifacts, wb))


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
    return check_blue_reference(ephemeral_runtime_snapshot(world, artifacts, wb))


def _check_necessity(
    world: WorldIR, artifacts: KindArtifacts, wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    weaknesses = PredicateEngine(world).active_weaknesses()
    observability_sources = {edge.source for edge in world.telemetry_edges}
    executable_targets = {
        weak.target for weak in weaknesses if remediation_command_for_weakness(weak)
    }
    trace_bindings = reference_trace_bindings(
        () if wb is None else wb.reference_attack_traces,
        weaknesses,
    )
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
    report = check_determinism(
        ephemeral_runtime_snapshot(world, artifacts, wb or regenerated),
        reference_bundle_stable=(
            wb is not None
            and regenerated.model_dump(mode="json") == wb.model_dump(mode="json")
        ),
    )
    return report.model_copy(
        update={"details": {**report.details, "world_hash": world_hash(world)}}
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


BUILTIN_ADMISSION_CHECKS: tuple[BuiltinAdmissionCheckSpec, ...] = (
    BuiltinAdmissionCheckSpec(
        "manifest_compliance", _check_manifest_compliance, stage="static"
    ),
    BuiltinAdmissionCheckSpec("graph_consistency", _check_graph_consistency, "static"),
    BuiltinAdmissionCheckSpec("path_solvability", _check_path_solvability, "static"),
    BuiltinAdmissionCheckSpec(
        "objective_grounding", _check_objective_grounding, "static"
    ),
    BuiltinAdmissionCheckSpec(
        "topology_workflow_consistency", _check_workflow_consistency, "static"
    ),
    BuiltinAdmissionCheckSpec(
        "identity_enforcement", _check_identity_enforcement, stage="security"
    ),
    BuiltinAdmissionCheckSpec(
        "encryption_enforcement", _check_encryption_enforcement, stage="security"
    ),
    BuiltinAdmissionCheckSpec(
        "mtls_enforcement", _check_mtls_enforcement, stage="security"
    ),
    BuiltinAdmissionCheckSpec("render_outputs", _check_render_outputs, stage="live"),
    BuiltinAdmissionCheckSpec(
        "service_health", _check_service_health_contract, stage="live"
    ),
    BuiltinAdmissionCheckSpec("siem_ingest", _check_siem_ingest, stage="live"),
    BuiltinAdmissionCheckSpec("isolation", _check_isolation, stage="live"),
    BuiltinAdmissionCheckSpec(
        "difficulty_envelope", _check_difficulty_envelope, stage="live"
    ),
    BuiltinAdmissionCheckSpec(
        "red_reference",
        _check_red_reference,
        stage="red_reference",
        requires_references=True,
    ),
    BuiltinAdmissionCheckSpec(
        "blue_reference",
        _check_blue_reference,
        stage="blue_reference",
        requires_references=True,
    ),
    BuiltinAdmissionCheckSpec(
        "necessity",
        _check_necessity,
        stage="necessity",
        requires_references=True,
    ),
    BuiltinAdmissionCheckSpec(
        "shortcut_probes",
        _check_shortcut_probes,
        stage="shortcut",
        requires_references=True,
    ),
    BuiltinAdmissionCheckSpec(
        "determinism",
        _check_determinism,
        stage="determinism",
        requires_references=True,
    ),
)
