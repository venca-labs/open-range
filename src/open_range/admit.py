"""Deterministic admission controller."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Callable, Protocol
from urllib.parse import urlencode

from open_range.admission import (
    ReferenceBundle,
    ValidatorCheckReport,
    ValidatorReport,
    ValidatorStageReport,
)
from open_range.admission_plan import admission_stages, profile_requires_live
from open_range.admission_scoring import report_summary
from open_range.async_utils import run_async
from open_range.build_config import DEFAULT_BUILD_CONFIG, BuildConfig
from open_range.cluster import KindBackend, LiveBackend
from open_range.counterfactuals import clear_runtime_markers, remediation_command
from open_range.encryption_enforcement import check_encryption_enforcement
from open_range.execution import PodActionBackend
from open_range.identity_enforcement import check_identity_enforcement
from open_range.k3d_runner import K3dBackend
from open_range.live_checks import check_live_db_mtls, check_live_service_smoke
from open_range.mtls_enforcement import check_mtls_enforcement
from open_range.objectives import evaluate_objective_grader_live
from open_range.predicates import PredicateEngine
from open_range.probe_planner import build_reference_bundle
from open_range.probe_runner import run_blue_reference, run_red_reference
from open_range.snapshot import KindArtifacts, RuntimeSnapshot, world_hash
from open_range.world_ir import ServiceSpec, WorldIR


class AdmissionController(Protocol):
    def admit(
        self,
        world: WorldIR,
        artifacts: KindArtifacts,
        build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
    ) -> tuple[ReferenceBundle, ValidatorReport]: ...


CheckFunc = Callable[
    [WorldIR, KindArtifacts, ReferenceBundle | None], ValidatorCheckReport
]


class LocalAdmissionController:
    """Run deterministic admission in fail-fast or analysis mode."""

    def __init__(
        self,
        mode: str = "fail_fast",
        *,
        live_backend: LiveBackend | None = None,
        auto_live: bool = True,
    ) -> None:
        if mode not in {"fail_fast", "analysis"}:
            raise ValueError("mode must be 'fail_fast' or 'analysis'")
        self.mode = mode
        self.live_backend = live_backend
        self.auto_live = auto_live

    def admit(
        self,
        world: WorldIR,
        artifacts: KindArtifacts,
        build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
    ) -> tuple[ReferenceBundle, ValidatorReport]:
        reference_bundle: ReferenceBundle | None = None
        stages: list[ValidatorStageReport] = []
        continue_running = True
        health_info: dict[str, object] = {"render_dir": artifacts.render_dir}
        live_backend = self.live_backend or self._auto_live_backend(build_config)
        health_info["live_backend_mode"] = (
            "explicit"
            if self.live_backend is not None
            else ("auto" if live_backend is not None else "unavailable")
        )

        check_map = self._check_map()
        for stage in admission_stages(build_config):
            checks: list[ValidatorCheckReport] = []
            for check_name in stage.check_names:
                if not continue_running:
                    break
                if reference_bundle is None and stage.requires_references:
                    reference_bundle = build_reference_bundle(world, build_config)
                result = check_map[check_name](world, artifacts, reference_bundle)
                checks.append(result)
                if (
                    self.mode == "fail_fast"
                    and not result.passed
                    and not result.advisory
                ):
                    continue_running = False
            stage_passed = all(result.passed or result.advisory for result in checks)
            stages.append(
                ValidatorStageReport(
                    name=stage.name,
                    passed=stage_passed,
                    checks=tuple(checks),
                )
            )
            if self.mode == "fail_fast" and not stage_passed:
                break

        final_bundle = reference_bundle or build_reference_bundle(world, build_config)

        if continue_running and live_backend is not None:
            live_stage, live_info = self._run_live_backend_checks(
                world, artifacts, final_bundle, live_backend
            )
            stages.append(live_stage)
            health_info.update(live_info)
            if self.mode == "fail_fast" and not live_stage.passed:
                continue_running = False
        elif profile_requires_live(build_config):
            stages.append(
                ValidatorStageReport(
                    name="kind_live",
                    passed=False,
                    checks=(
                        ValidatorCheckReport(
                            name="live_backend_required",
                            passed=False,
                            details={
                                "validation_profile": build_config.validation_profile,
                                "live_backend_mode": health_info["live_backend_mode"],
                            },
                            error="live Kind validation is required for this admission profile",
                        ),
                    ),
                )
            )
            continue_running = False

        admitted = all(stage.passed for stage in stages)
        summary_fields = report_summary(
            world=world,
            stages=tuple(stages),
            reference_bundle=final_bundle,
            health_info=health_info,
        )
        report = ValidatorReport(
            admitted=admitted,
            **summary_fields,
            mode=self.mode,
            world_id=world.world_id,
            world_hash=world_hash(world),
            summary="admitted" if admitted else "rejected",
            build_logs=tuple(artifacts.rendered_files),
            health_info=health_info,
            stages=tuple(stages),
        )
        return final_bundle, report

    @staticmethod
    def _check_map() -> dict[str, CheckFunc]:
        return {
            "manifest_compliance": _check_manifest_compliance,
            "graph_consistency": _check_graph_consistency,
            "path_solvability": _check_path_solvability,
            "objective_grounding": _check_objective_grounding,
            "topology_workflow_consistency": _check_workflow_consistency,
            "identity_enforcement": check_identity_enforcement,
            "encryption_enforcement": check_encryption_enforcement,
            "mtls_enforcement": check_mtls_enforcement,
            "render_outputs": _check_render_outputs,
            "service_health": _check_service_health_contract,
            "siem_ingest": _check_siem_ingest,
            "isolation": _check_isolation,
            "difficulty_envelope": _check_difficulty_envelope,
            "red_reference": _check_red_reference,
            "blue_reference": _check_blue_reference,
            "necessity": _check_necessity,
            "shortcut_probes": _check_shortcut_probes,
            "determinism": _check_determinism,
        }

    def _run_live_backend_checks(
        self,
        world: WorldIR,
        artifacts: KindArtifacts,
        reference_bundle: ReferenceBundle,
        live_backend: LiveBackend,
    ) -> tuple[ValidatorStageReport, dict[str, object]]:
        checks: list[ValidatorCheckReport] = []
        expected_services = {service.id for service in world.services}
        live_info: dict[str, object] = {}
        try:
            release = live_backend.boot(
                snapshot_id=world.world_id,
                artifacts_dir=Path(artifacts.render_dir),
            )
            discovered = set(release.pods.pod_ids)
            checks.append(
                ValidatorCheckReport(
                    name="kind_boot",
                    passed=expected_services <= discovered,
                    details={
                        "release_name": release.release_name,
                        "expected_services": sorted(expected_services),
                        "discovered_services": sorted(discovered),
                    },
                    error=""
                    if expected_services <= discovered
                    else "live release missing expected services",
                )
            )

            unhealthy = [
                service_id
                for service_id in sorted(expected_services & discovered)
                if not run_async(release.pods.is_healthy(service_id))
            ]
            checks.append(
                ValidatorCheckReport(
                    name="kind_health",
                    passed=not unhealthy,
                    details={
                        "release_name": release.release_name,
                        "unhealthy_services": unhealthy,
                    },
                    error=""
                    if not unhealthy
                    else "one or more live services failed readiness",
                )
            )
            snapshot = _ephemeral_snapshot(world, artifacts, reference_bundle)
            backend = PodActionBackend()
            backend.bind(snapshot, release)
            checks.append(check_live_service_smoke(world, release))
            checks.append(check_live_db_mtls(world, release))
            clear_runtime_markers(release, world)
            checks.append(_live_red_reference_check(snapshot, release, backend))
            checks.append(_live_siem_ingest_check(release))
            clear_runtime_markers(release, world)
            checks.append(_live_blue_reference_check(snapshot, backend))
            clear_runtime_markers(release, world)
            checks.append(_live_determinism_check(snapshot, backend))
            clear_runtime_markers(release, world)
            checks.append(_live_necessity_check(snapshot, release, backend))
            clear_runtime_markers(release, world)
            checks.append(_live_shortcut_probe_check(snapshot, release))
            live_info = {
                "live_release": release.release_name,
                "live_service_count": len(discovered),
            }
        except Exception as exc:  # noqa: BLE001
            checks.append(
                ValidatorCheckReport(
                    name="kind_boot",
                    passed=False,
                    details={"artifacts_dir": artifacts.render_dir},
                    error=str(exc),
                )
            )
        finally:
            if "release" in locals():
                try:
                    live_backend.teardown(release)
                except Exception:
                    pass

        stage = ValidatorStageReport(
            name="kind_live",
            passed=all(check.passed or check.advisory for check in checks),
            checks=tuple(checks),
        )
        return stage, live_info

    def _auto_live_backend(self, build_config: BuildConfig) -> LiveBackend | None:
        if not self.auto_live:
            return None
        if not profile_requires_live(build_config):
            return None
        if not shutil.which("helm"):
            return None
        if build_config.cluster_backend == "k3d":
            if not (shutil.which("k3d") and shutil.which("docker")):
                return None
            clusters = subprocess.run(
                ["k3d", "cluster", "list", "-o", "json"],
                capture_output=True,
                text=True,
                check=False,
            )
            if clusters.returncode != 0 or '"name":"openrange"' not in clusters.stdout:
                return None
            return K3dBackend(
                kind_cluster="openrange",
                k3d_agents=build_config.k3d_agents,
                k3d_subnet=build_config.k3d_subnet,
            )
        if not (shutil.which("kind") and shutil.which("docker")):
            return None
        clusters = subprocess.run(
            ["kind", "get", "clusters"],
            capture_output=True,
            text=True,
            check=False,
        )
        if clusters.returncode != 0:
            return None
        if "openrange" not in {
            line.strip() for line in clusters.stdout.splitlines() if line.strip()
        }:
            return None
        return KindBackend()


def _check_manifest_compliance(
    world: WorldIR, _artifacts: KindArtifacts, _wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    allowed = {"web_app", "email", "idp", "fileshare", "db", "siem"}
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
    _world: WorldIR, _artifacts: KindArtifacts, wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    if wb is None or not wb.reference_attack_traces:
        return ValidatorCheckReport(
            name="red_reference",
            passed=False,
            details={"trace_id": "", "step_count": 0},
            error="no valid red reference",
        )
    snapshot = _ephemeral_snapshot(_world, _artifacts, wb)
    predicates = PredicateEngine(_world)
    per_trace = []
    passed = True
    satisfied_all: set[str] = set()
    for trace_index, trace in enumerate(wb.reference_attack_traces):
        score, events, health, outputs = run_red_reference(
            snapshot,
            None,
            episode_seed=_world.seed,
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


def _check_blue_reference(
    world: WorldIR, _artifacts: KindArtifacts, wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    if wb is None or not wb.reference_defense_traces:
        return ValidatorCheckReport(
            name="blue_reference",
            passed=False,
            details={"trace_id": "", "step_count": 0},
            error="no valid blue reference",
        )
    snapshot = _ephemeral_snapshot(world, _artifacts, wb)
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


def _check_necessity(
    world: WorldIR, _artifacts: KindArtifacts, wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    weaknesses = PredicateEngine(world).active_weaknesses()
    observability_sources = {edge.source for edge in world.telemetry_edges}
    executable_targets = {
        weak.target for weak in weaknesses if remediation_command(weak)
    }
    trace_bindings = []
    if wb is not None:
        for trace_index, red_trace in enumerate(wb.reference_attack_traces):
            weakness_id = _reference_weakness_id(red_trace)
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
                _ephemeral_snapshot(counterfactual_world, _artifacts, wb),
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


def _check_shortcut_probes(
    world: WorldIR, _artifacts: KindArtifacts, wb: ReferenceBundle | None
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
    issues.extend(_artifact_shortcut_findings(world, _artifacts))
    issues.extend(_unlogged_critical_action_findings(world))
    return ValidatorCheckReport(
        name="shortcut_probes",
        passed=not issues,
        details={"issues": issues, "probe_count": len(probes)},
        error="; ".join(issues),
    )


def _check_determinism(
    world: WorldIR, _artifacts: KindArtifacts, wb: ReferenceBundle | None
) -> ValidatorCheckReport:
    regenerated = build_reference_bundle(
        world,
        BuildConfig(
            red_reference_count=len(wb.reference_attack_traces) if wb else 1,
            blue_reference_count=len(wb.reference_defense_traces) if wb else 1,
        ),
    )
    snapshot = _ephemeral_snapshot(world, _artifacts, wb or regenerated)
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


def _reference_weakness_id(trace) -> str:
    if trace is None:
        return ""
    for step in trace.steps:
        weakness_id = step.payload.get("weakness_id", step.payload.get("weakness", ""))
        if isinstance(weakness_id, str) and weakness_id:
            return weakness_id
    return ""


def _ephemeral_snapshot(
    world: WorldIR, artifacts: KindArtifacts, reference_bundle: ReferenceBundle
) -> RuntimeSnapshot:
    predicates = PredicateEngine(world)
    db_seed_state = {
        "services": [service.id for service in world.services if service.kind == "db"]
    }
    mail_state = {
        "mailboxes": [
            persona.mailbox for persona in world.green_personas if persona.mailbox
        ]
    }
    file_assets = {asset.id: asset.location for asset in world.assets}
    identity_seed = {"users": [user.id for user in world.users]}
    report = ValidatorReport(
        admitted=True,
        graph_ok=True,
        boot_ok=True,
        workflow_ok=True,
        telemetry_ok=True,
        reference_attack_ok=True,
        reference_defense_ok=True,
        necessity_ok=True,
        shortcut_risk="low",
        determinism_score=1.0,
        flakiness=0.0,
        red_path_depth=predicates.red_path_depth(),
        red_alt_path_count=predicates.red_alt_path_count(),
        blue_signal_points=len({edge.source for edge in world.telemetry_edges}),
        business_continuity_score=1.0,
        benchmark_tags_covered=predicates.benchmark_tags_covered(),
        world_id=world.world_id,
        world_hash=world_hash(world),
        summary="admission-live-check",
    )
    return RuntimeSnapshot(
        snapshot_id=f"{world.world_id}-admission",
        world_id=world.world_id,
        seed=world.seed,
        artifacts_dir=artifacts.render_dir,
        image_digests=artifacts.pinned_image_digests,
        state_seed_dir=artifacts.render_dir,
        validator_report_path=f"{artifacts.render_dir}/validator_report.json",
        world=world,
        artifacts=artifacts,
        db_seed_state=db_seed_state,
        mail_state=mail_state,
        file_assets=file_assets,
        identity_seed=identity_seed,
        validator_report=report,
        reference_bundle=reference_bundle,
        world_hash=world_hash(world),
    )


def _live_red_reference_check(
    snapshot: RuntimeSnapshot, release, backend: PodActionBackend
) -> ValidatorCheckReport:
    predicates = PredicateEngine(snapshot.world)
    per_trace = []
    passed = True
    for trace_index, trace in enumerate(
        snapshot.reference_bundle.reference_attack_traces
    ):
        score, events, health, outputs = run_red_reference(
            snapshot,
            backend,
            episode_seed=snapshot.world.seed,
            trace_index=trace_index,
        )
        satisfied: set[str] = set()
        for objective in snapshot.world.red_objectives:
            grader = predicates.objective_grader(objective.predicate)
            if grader is None:
                continue
            if evaluate_objective_grader_live(
                objective.predicate,
                grader,
                snapshot=snapshot,
                pods=release.pods,
                events=events,
                service_health=dict(health),
                outputs=outputs,
            ):
                satisfied.add(objective.predicate)
        trace_passed = (
            score.winner == "red"
            and score.done
            and predicates.red_terminal_satisfied(satisfied)
        )
        passed = passed and trace_passed
        per_trace.append(
            {
                "trace_id": trace.id,
                "winner": score.winner,
                "terminal_reason": score.terminal_reason,
                "satisfied_predicates": sorted(satisfied),
                "outputs": outputs,
                "passed": trace_passed,
            }
        )
    return ValidatorCheckReport(
        name="live_red_reference",
        passed=passed,
        details={"trace_count": len(per_trace), "traces": per_trace},
        error=""
        if passed
        else "live red reference did not satisfy terminal objectives",
    )


def _live_blue_reference_check(
    snapshot: RuntimeSnapshot, backend: PodActionBackend
) -> ValidatorCheckReport:
    per_trace = []
    passed = True
    for trace_index, trace in enumerate(
        snapshot.reference_bundle.reference_defense_traces
    ):
        score, outputs = run_blue_reference(snapshot, backend, trace_index=trace_index)
        trace_passed = score.winner == "blue" and score.done
        passed = passed and trace_passed
        per_trace.append(
            {
                "trace_id": trace.id,
                "winner": score.winner,
                "terminal_reason": score.terminal_reason,
                "outputs": outputs,
                "passed": trace_passed,
            }
        )
    return ValidatorCheckReport(
        name="live_blue_reference",
        passed=passed,
        details={"trace_count": len(per_trace), "traces": per_trace},
        error=""
        if passed
        else "live blue reference did not validate detect-and-contain path",
    )


def _live_siem_ingest_check(release) -> ValidatorCheckReport:
    result = run_async(
        release.pods.exec(
            "svc-siem", "grep -q 'InitialAccess' /srv/http/siem/all.log", timeout=10.0
        )
    )
    return ValidatorCheckReport(
        name="live_siem_ingest",
        passed=result.ok,
        details={"stdout": result.stdout.strip(), "stderr": result.stderr.strip()},
        error="" if result.ok else "siem log sink did not record reference events",
    )


def _live_determinism_check(
    snapshot: RuntimeSnapshot, backend: PodActionBackend
) -> ValidatorCheckReport:
    trace_results = []
    passed = True
    for trace_index, trace in enumerate(
        snapshot.reference_bundle.reference_attack_traces
    ):
        first_score, first_events, first_health, _first_outputs = run_red_reference(
            snapshot,
            backend,
            episode_seed=snapshot.world.seed,
            trace_index=trace_index,
        )
        second_score, second_events, second_health, _second_outputs = run_red_reference(
            snapshot,
            backend,
            episode_seed=snapshot.world.seed,
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
        name="live_determinism",
        passed=passed,
        details={"trace_count": len(trace_results), "traces": trace_results},
        error="" if passed else "live reference replay is not deterministic",
    )


def _live_necessity_check(
    snapshot: RuntimeSnapshot, release, backend: PodActionBackend
) -> ValidatorCheckReport:
    trace_bindings = []
    for trace_index, trace in enumerate(
        snapshot.reference_bundle.reference_attack_traces
    ):
        weakness_id = _reference_weakness_id(trace)
        if not weakness_id:
            continue
        weakness = next(
            (
                weak
                for weak in PredicateEngine(snapshot.world).active_weaknesses()
                if weak.id == weakness_id
            ),
            None,
        )
        if weakness is not None:
            trace_bindings.append((trace_index, trace, weakness))
    red_targets = {
        step.target for _idx, trace, _weak in trace_bindings for step in trace.steps
    }
    candidate_weaknesses = sorted(
        (
            weak
            for weak in PredicateEngine(snapshot.world).active_weaknesses()
            if weak.target in red_targets
        ),
        key=lambda weak: (
            0 if weak.instantiation_mode == "exact_code" else 1,
            0
            if trace_bindings and weak.target == trace_bindings[0][1].steps[0].target
            else 1,
            weak.id,
        ),
    )
    target_weakness = candidate_weaknesses[0] if candidate_weaknesses else None
    if target_weakness is None:
        return ValidatorCheckReport(
            name="live_necessity",
            passed=False,
            details={"reason": "no reference-relevant weakness"},
            error="no reference-relevant weakness available for live necessity check",
        )
    command = remediation_command(target_weakness)
    if not command:
        return ValidatorCheckReport(
            name="live_necessity",
            passed=False,
            details={
                "weakness_id": target_weakness.id,
                "remediation": target_weakness.remediation,
                "remediation_kind": target_weakness.remediation_kind,
            },
            error="weakness remediation is not executable",
        )
    apply_result = run_async(
        release.pods.exec(target_weakness.target, command, timeout=10.0)
    )
    trace_index = next(
        (idx for idx, _trace, weak in trace_bindings if weak.id == target_weakness.id),
        0,
    )
    score, _events, _health, outputs = run_red_reference(
        snapshot,
        backend,
        episode_seed=snapshot.world.seed,
        trace_index=trace_index,
    )
    run_async(
        release.pods.exec(
            target_weakness.target,
            "rm -f /tmp/openrange-contained /tmp/openrange-patched",
            timeout=10.0,
        )
    )
    passed = apply_result.ok and score.winner != "red"
    return ValidatorCheckReport(
        name="live_necessity",
        passed=passed,
        details={
            "weakness_id": target_weakness.id,
            "target": target_weakness.target,
            "winner_after_remediation": score.winner,
            "outputs": outputs,
        },
        error="" if passed else "live remediation did not break the reference path",
    )


def _live_shortcut_probe_check(
    snapshot: RuntimeSnapshot, release
) -> ValidatorCheckReport:
    host_by_id = {host.id: host for host in snapshot.world.hosts}
    service_by_id = {service.id: service for service in snapshot.world.services}
    public_services = [
        service
        for service in snapshot.world.services
        if host_by_id[service.host].exposure == "public"
    ]
    protected_targets = sorted(
        {
            asset.owner_service
            for asset in snapshot.world.assets
            if asset.confidentiality == "critical"
            and asset.owner_service in service_by_id
            and host_by_id[service_by_id[asset.owner_service].host].exposure != "public"
        }
    )
    unexpected: list[str] = []
    for service_id in protected_targets:
        service = service_by_id[service_id]
        result = run_async(
            release.pods.exec(
                "sandbox-red", _service_probe_command(service), timeout=10.0
            )
        )
        if result.ok:
            unexpected.append(f"direct_external_access:{service_id}")
    if "svc-idp" in service_by_id:
        admin_probe = run_async(
            release.pods.exec(
                "sandbox-red",
                _service_probe_command(service_by_id["svc-idp"]),
                timeout=10.0,
            )
        )
        if admin_probe.ok:
            unexpected.append("direct_admin_access:svc-idp")
    unexpected.extend(_web_shortcut_findings(snapshot, release, public_services))
    return ValidatorCheckReport(
        name="live_shortcuts",
        passed=not unexpected,
        details={"unexpected_reachability": unexpected},
        error="; ".join(unexpected),
    )


def _service_probe_command(service: ServiceSpec) -> str:
    port = service.ports[0] if service.ports else 80
    if service.kind == "web_app":
        return f"wget -qO- http://{service.id}:{port}/ >/dev/null"
    return f"nc -z -w 3 {service.id} {port}"


def _web_shortcut_findings(
    snapshot: RuntimeSnapshot, release, public_services: list[ServiceSpec]
) -> list[str]:
    findings: list[str] = []
    for service in public_services:
        if service.kind != "web_app":
            continue
        seeded_kinds = {
            weakness.kind
            for weakness in snapshot.world.weaknesses
            if weakness.family == "code_web" and weakness.target == service.id
        }
        for kind, path, query in _shortcut_web_route_probes():
            if kind in seeded_kinds:
                continue
            result = run_async(
                release.pods.exec(
                    "sandbox-red",
                    _http_probe_command(service, path, query),
                    timeout=10.0,
                )
            )
            if _looks_like_shortcut_payload(result.stdout):
                findings.append(f"unguarded_web_route:{service.id}:{kind}")
        for asset in snapshot.world.assets:
            if asset.confidentiality not in {"high", "critical"}:
                continue
            result = run_async(
                release.pods.exec(
                    "sandbox-red",
                    _http_probe_command(service, f"/content/{asset.id}.txt"),
                    timeout=10.0,
                )
            )
            expected = f"seeded-{asset.asset_class}-{asset.id}"
            if expected in result.stdout:
                findings.append(f"public_asset_route:{service.id}:{asset.id}")
    return findings


def _http_probe_command(
    service: ServiceSpec, path: str, query: dict[str, str] | None = None
) -> str:
    port = service.ports[0] if service.ports else 80
    suffix = ""
    if query:
        suffix = "?" + urlencode(query)
    return f"wget -qO- {_quote_http_url(service.id, port, path, suffix)} | head -c 2048"


def _quote_http_url(host: str, port: int, path: str, suffix: str) -> str:
    return f"'http://{host}:{port}{path}{suffix}'"


def _shortcut_web_route_probes() -> tuple[tuple[str, str, dict[str, str]], ...]:
    return (
        (
            "sql_injection",
            "/search.php",
            {"q": "' UNION SELECT 'shortcut' -- ", "asset": "finance_docs"},
        ),
        (
            "broken_authorization",
            "/records.php",
            {"record": "admin-console", "viewer": "sales-01"},
        ),
        (
            "auth_bypass",
            "/admin.php",
            {"debug": "1", "as": "admin"},
        ),
    )


def _looks_like_shortcut_payload(stdout: str) -> bool:
    text = stdout.strip()
    if not text:
        return False
    return (
        "OPENRANGE-FOOTHOLD:" in text
        or "OPENRANGE-EFFECT:" in text
        or "admin_console=enabled" in text
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
