"""Deterministic admission controller."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol
from urllib.parse import urlencode

from open_range.admission_scoring import report_summary
from open_range.admission import (
    ValidatorCheckReport,
    ValidatorReport,
    ValidatorStageReport,
    WitnessBundle,
)
from open_range.build_config import BuildConfig, DEFAULT_BUILD_CONFIG
from open_range.cluster import LiveBackend
from open_range.counterfactuals import clear_runtime_markers, remediation_command
from open_range.execution import PodActionBackend
from open_range.predicates import PredicateEngine
from open_range.probe_planner import build_witness_bundle
from open_range.probe_runner import run_blue_witness, run_red_witness
from open_range.snapshot import KindArtifacts, Snapshot, world_hash
from open_range.world_ir import ServiceSpec, WorldIR


class AdmissionController(Protocol):
    def admit(
        self,
        world: WorldIR,
        artifacts: KindArtifacts,
        build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
    ) -> tuple[WitnessBundle, ValidatorReport]: ...


CheckFunc = Callable[[WorldIR, KindArtifacts, WitnessBundle | None], ValidatorCheckReport]


@dataclass(frozen=True)
class _Stage:
    name: str
    checks: tuple[CheckFunc, ...]


class LocalAdmissionController:
    """Run deterministic admission in fail-fast or analysis mode."""

    def __init__(self, mode: str = "fail_fast", *, live_backend: LiveBackend | None = None) -> None:
        if mode not in {"fail_fast", "analysis"}:
            raise ValueError("mode must be 'fail_fast' or 'analysis'")
        self.mode = mode
        self.live_backend = live_backend

    def admit(
        self,
        world: WorldIR,
        artifacts: KindArtifacts,
        build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
    ) -> tuple[WitnessBundle, ValidatorReport]:
        witness_bundle: WitnessBundle | None = None
        stages: list[ValidatorStageReport] = []
        continue_running = True
        health_info: dict[str, object] = {"render_dir": artifacts.render_dir}

        for stage in self._stages(build_config):
            checks: list[ValidatorCheckReport] = []
            for check in stage.checks:
                if not continue_running:
                    break
                if witness_bundle is None and stage.name in {"red_witness", "blue_witness", "necessity", "shortcut", "determinism"}:
                    witness_bundle = build_witness_bundle(world, build_config)
                result = check(world, artifacts, witness_bundle)
                checks.append(result)
                if self.mode == "fail_fast" and not result.passed and not result.advisory:
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

        final_bundle = witness_bundle or build_witness_bundle(world, build_config)

        if continue_running and self.live_backend is not None:
            live_stage, live_info = self._run_live_backend_checks(world, artifacts, final_bundle)
            stages.append(live_stage)
            health_info.update(live_info)
            if self.mode == "fail_fast" and not live_stage.passed:
                continue_running = False

        admitted = all(stage.passed for stage in stages)
        summary_fields = report_summary(
            world=world,
            stages=tuple(stages),
            witness_bundle=final_bundle,
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
    def _stages(build_config: BuildConfig) -> tuple[_Stage, ...]:
        static_stage = _Stage(
            "static",
            (
                _check_manifest_compliance,
                _check_graph_consistency,
                _check_path_solvability,
                _check_objective_grounding,
                _check_workflow_consistency,
            ),
        )
        live_stage = _Stage(
            "live",
            (
                _check_render_outputs,
                _check_service_health_contract,
                _check_siem_ingest,
                _check_isolation,
                _check_difficulty_envelope,
            ),
        )
        witness_stages = (
            _Stage("red_witness", (_check_red_witness,)),
            _Stage("blue_witness", (_check_blue_witness,)),
        )
        advanced_stages = (
            _Stage("necessity", (_check_necessity,)),
            _Stage("shortcut", (_check_shortcut_probes,)),
            _Stage("determinism", (_check_determinism,)),
        )

        if build_config.validation_profile == "graph_only":
            return (static_stage,)
        if build_config.validation_profile == "graph_plus_live":
            return (static_stage, live_stage) + witness_stages
        if build_config.validation_profile == "no_necessity":
            return (static_stage, live_stage) + witness_stages + (
                _Stage("shortcut", (_check_shortcut_probes,)),
                _Stage("determinism", (_check_determinism,)),
            )
        return (
            _Stage(
                static_stage.name,
                static_stage.checks,
            ),
            _Stage(
                live_stage.name,
                live_stage.checks,
            ),
        ) + witness_stages + advanced_stages

    def _run_live_backend_checks(
        self,
        world: WorldIR,
        artifacts: KindArtifacts,
        witness_bundle: WitnessBundle,
    ) -> tuple[ValidatorStageReport, dict[str, object]]:
        assert self.live_backend is not None
        checks: list[ValidatorCheckReport] = []
        expected_services = {service.id for service in world.services}
        live_info: dict[str, object] = {}
        try:
            release = self.live_backend.boot(
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
                    error="" if expected_services <= discovered else "live release missing expected services",
                )
            )

            unhealthy = [
                service_id
                for service_id in sorted(expected_services & discovered)
                if not asyncio.run(release.pods.is_healthy(service_id))
            ]
            checks.append(
                ValidatorCheckReport(
                    name="kind_health",
                    passed=not unhealthy,
                    details={
                        "release_name": release.release_name,
                        "unhealthy_services": unhealthy,
                    },
                    error="" if not unhealthy else "one or more live services failed readiness",
                )
            )
            snapshot = _ephemeral_snapshot(world, artifacts, witness_bundle)
            backend = PodActionBackend()
            backend.bind(snapshot, release)
            checks.append(_live_service_smoke_check(world, release))
            clear_runtime_markers(release, world)
            checks.append(_live_red_witness_check(snapshot, backend))
            checks.append(_live_siem_ingest_check(release))
            clear_runtime_markers(release, world)
            checks.append(_live_blue_witness_check(snapshot, backend))
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
                    self.live_backend.teardown(release)
                except Exception:
                    pass

        stage = ValidatorStageReport(
            name="kind_live",
            passed=all(check.passed or check.advisory for check in checks),
            checks=tuple(checks),
        )
        return stage, live_info


def _check_manifest_compliance(world: WorldIR, _artifacts: KindArtifacts, _wb: WitnessBundle | None) -> ValidatorCheckReport:
    allowed = {"web_app", "email", "idp", "fileshare", "db", "siem"}
    invalid = sorted(service.kind for service in world.services if service.kind not in allowed)
    passed = world.world_family == "enterprise_saas_v1" and not invalid
    return ValidatorCheckReport(
        name="manifest_compliance",
        passed=passed,
        details={"invalid_service_kinds": invalid},
        error="" if passed else "world violates the fixed service palette",
    )


def _check_graph_consistency(world: WorldIR, _artifacts: KindArtifacts, _wb: WitnessBundle | None) -> ValidatorCheckReport:
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
            issues.append(f"service {service.id} references missing host {service.host}")
        for dep in service.dependencies:
            if dep not in service_ids:
                issues.append(f"service {service.id} references missing dependency {dep}")

    for asset in world.assets:
        if asset.owner_service not in service_ids:
            issues.append(f"asset {asset.id} references missing owner service {asset.owner_service}")

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


def _check_path_solvability(world: WorldIR, _artifacts: KindArtifacts, _wb: WitnessBundle | None) -> ValidatorCheckReport:
    predicates = PredicateEngine(world)
    starts = {service.id for service in world.services if predicates.is_public_service(service)}
    unreachable = []
    for objective in world.red_objectives:
        target_service = predicates.objective_target_service(objective.predicate)
        if target_service and not predicates.reachable_from_any(starts, target_service):
            unreachable.append(target_service)
    return ValidatorCheckReport(
        name="path_solvability",
        passed=not unreachable,
        details={"starts": sorted(starts), "unreachable_targets": unreachable},
        error="" if not unreachable else f"unreachable objective targets: {sorted(set(unreachable))}",
    )


def _check_objective_grounding(world: WorldIR, _artifacts: KindArtifacts, _wb: WitnessBundle | None) -> ValidatorCheckReport:
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


def _check_workflow_consistency(world: WorldIR, _artifacts: KindArtifacts, _wb: WitnessBundle | None) -> ValidatorCheckReport:
    service_ids = {service.id for service in world.services}
    asset_ids = {asset.id for asset in world.assets}
    issues = []
    for workflow in world.workflows:
        for step in workflow.steps:
            if step.service and step.service not in service_ids:
                issues.append(f"workflow {workflow.id} references missing service {step.service}")
            if step.asset and step.asset not in asset_ids:
                issues.append(f"workflow {workflow.id} references missing asset {step.asset}")
    return ValidatorCheckReport(
        name="topology_workflow_consistency",
        passed=not issues,
        details={"issues": issues},
        error="; ".join(issues),
    )


def _check_render_outputs(_world: WorldIR, artifacts: KindArtifacts, _wb: WitnessBundle | None) -> ValidatorCheckReport:
    missing = [path for path in artifacts.rendered_files if not Path(path).exists()]
    return ValidatorCheckReport(
        name="render_outputs",
        passed=not missing,
        details={"missing": missing},
        error="" if not missing else f"missing rendered files: {missing}",
    )


def _check_service_health_contract(world: WorldIR, artifacts: KindArtifacts, _wb: WitnessBundle | None) -> ValidatorCheckReport:
    rendered = artifacts.chart_values.get("services", {})
    missing = [service.id for service in world.services if service.id not in rendered]
    passed = not missing and len(rendered) == len(world.services)
    return ValidatorCheckReport(
        name="service_health",
        passed=passed,
        details={"missing_services": missing, "rendered_service_count": len(rendered)},
        error="" if passed else f"services missing from rendered chart values: {missing}",
    )


def _check_siem_ingest(world: WorldIR, _artifacts: KindArtifacts, _wb: WitnessBundle | None) -> ValidatorCheckReport:
    telemetry_targets = {edge.target for edge in world.telemetry_edges}
    actual_sources = {edge.source for edge in world.telemetry_edges}
    expected_sources = {service.id for service in world.services if service.id != "svc-siem"}
    passed = "svc-siem" in telemetry_targets and expected_sources <= actual_sources
    return ValidatorCheckReport(
        name="siem_ingest",
        passed=passed,
        details={"expected_sources": sorted(expected_sources), "actual_sources": sorted(actual_sources)},
        error="" if passed else "not all services ship telemetry to svc-siem",
    )


def _check_isolation(world: WorldIR, _artifacts: KindArtifacts, _wb: WitnessBundle | None) -> ValidatorCheckReport:
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


def _check_difficulty_envelope(world: WorldIR, _artifacts: KindArtifacts, _wb: WitnessBundle | None) -> ValidatorCheckReport:
    predicates = PredicateEngine(world)
    red_depth = predicates.red_path_depth()
    lower = max(1, world.target_red_path_depth - 2)
    upper = world.target_red_path_depth + 2
    blue_signal_points = len({edge.source for edge in world.telemetry_edges})
    passed = lower <= red_depth <= upper and blue_signal_points >= min(world.target_blue_signal_points, len(world.services))
    return ValidatorCheckReport(
        name="difficulty_envelope",
        passed=passed,
        details={
            "computed_red_path_depth": red_depth,
            "target_red_path_depth": world.target_red_path_depth,
            "blue_signal_points": blue_signal_points,
            "target_blue_signal_points": world.target_blue_signal_points,
        },
        error="" if passed else "world falls outside the configured difficulty envelope",
    )


def _check_red_witness(_world: WorldIR, _artifacts: KindArtifacts, wb: WitnessBundle | None) -> ValidatorCheckReport:
    if wb is None or not wb.red_witnesses:
        return ValidatorCheckReport(
            name="red_witness",
            passed=False,
            details={"trace_id": "", "step_count": 0},
            error="no valid red witness",
        )
    snapshot = _ephemeral_snapshot(_world, _artifacts, wb)
    score, events, health, outputs = run_red_witness(snapshot, None, episode_seed=_world.seed)
    trace = wb.red_witnesses[0]
    predicates = PredicateEngine(_world)
    satisfied = predicates.evaluate_red_objectives(
        snapshot=snapshot,
        events=events,
        service_health=dict(health),
    )
    passed = score.winner == "red" and score.done and predicates.red_terminal_satisfied(satisfied)
    return ValidatorCheckReport(
        name="red_witness",
        passed=passed,
        details={
            "trace_id": trace.id,
            "step_count": len(trace.steps),
            "winner": score.winner,
            "event_count": len(events),
            "satisfied_predicates": sorted(satisfied),
            "outputs": outputs,
        },
        error="" if passed else "offline red witness did not satisfy terminal objectives",
    )


def _check_blue_witness(world: WorldIR, _artifacts: KindArtifacts, wb: WitnessBundle | None) -> ValidatorCheckReport:
    if wb is None or not wb.blue_witnesses:
        return ValidatorCheckReport(
            name="blue_witness",
            passed=False,
            details={"trace_id": "", "step_count": 0},
            error="no valid blue witness",
        )
    snapshot = _ephemeral_snapshot(world, _artifacts, wb)
    score, outputs = run_blue_witness(snapshot, None)
    trace = wb.blue_witnesses[0]
    passed = score.winner == "blue" and score.done and len(trace.objective_ids) <= len(world.blue_objectives)
    return ValidatorCheckReport(
        name="blue_witness",
        passed=passed,
        details={
            "trace_id": trace.id,
            "step_count": len(trace.steps),
            "winner": score.winner,
            "outputs": outputs,
        },
        error="" if passed else "offline blue witness did not validate detect-and-contain path",
    )


def _check_necessity(world: WorldIR, _artifacts: KindArtifacts, wb: WitnessBundle | None) -> ValidatorCheckReport:
    red_trace = wb.red_witnesses[0] if wb and wb.red_witnesses else None
    weaknesses = PredicateEngine(world).active_weaknesses()
    observability_sources = {edge.source for edge in world.telemetry_edges}
    executable_targets = {weak.target for weak in weaknesses if remediation_command(weak)}
    witness_weakness_id = _witness_weakness_id(red_trace)
    witness_weakness = next((weak for weak in weaknesses if weak.id == witness_weakness_id), None)
    issues = []
    if not weaknesses:
        issues.append("no weakness targets")
    if witness_weakness is None:
        issues.append("red witness does not reference an exact seeded weakness")
    if not observability_sources:
        issues.append("blue witness lacks observability substrate")
    if not all(weak.remediation for weak in weaknesses):
        issues.append("one or more weaknesses lack remediation metadata")
    if not executable_targets:
        issues.append("no executable remediation exists for live necessity checks")
    elif witness_weakness is not None and witness_weakness.target not in executable_targets:
        issues.append("no witness-relevant weakness has executable remediation")
    if not issues and witness_weakness is not None and red_trace is not None:
        counterfactual_world = world.model_copy(
            update={"weaknesses": tuple(weak for weak in world.weaknesses if weak.id != witness_weakness.id)}
        )
        score, _events, _health, outputs = run_red_witness(
            _ephemeral_snapshot(counterfactual_world, _artifacts, wb),
            None,
            episode_seed=counterfactual_world.seed,
        )
        if score.winner == "red":
            issues.append("counterfactual red witness still succeeds after removing the referenced weakness")
        details = {
            "witness_weakness_id": witness_weakness.id,
            "counterfactual_winner": score.winner,
            "outputs": outputs,
        }
    else:
        details = {"issues": issues}
    return ValidatorCheckReport(
        name="necessity",
        passed=not issues,
        details=details,
        error="; ".join(issues),
    )


def _check_shortcut_probes(world: WorldIR, _artifacts: KindArtifacts, wb: WitnessBundle | None) -> ValidatorCheckReport:
    probes = wb.shortcut_probes if wb else ()
    predicates = PredicateEngine(world)
    public_services = {service.id for service in world.services if predicates.is_public_service(service)}
    critical_assets = {asset.owner_service for asset in world.assets if asset.confidentiality == "critical"}
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


def _check_determinism(world: WorldIR, _artifacts: KindArtifacts, wb: WitnessBundle | None) -> ValidatorCheckReport:
    regenerated = build_witness_bundle(
        world,
        BuildConfig(
            red_witness_count=len(wb.red_witnesses) if wb else 1,
            blue_witness_count=len(wb.blue_witnesses) if wb else 1,
        ),
    )
    snapshot = _ephemeral_snapshot(world, _artifacts, wb or regenerated)
    first_score, first_events, first_health, _first_outputs = run_red_witness(snapshot, None, episode_seed=world.seed)
    second_score, second_events, second_health, _second_outputs = run_red_witness(snapshot, None, episode_seed=world.seed)
    passed = (
        wb is not None
        and regenerated.model_dump(mode="json") == wb.model_dump(mode="json")
        and first_events == second_events
        and first_health == second_health
        and first_score.winner == second_score.winner
        and first_score.terminal_reason == second_score.terminal_reason
    )
    return ValidatorCheckReport(
        name="determinism",
        passed=passed,
        details={
            "world_hash": world_hash(world),
            "first_event_count": len(first_events),
            "second_event_count": len(second_events),
        },
        error="" if passed else "witness execution is not deterministic",
    )


def _witness_weakness_id(trace) -> str:
    if trace is None:
        return ""
    for step in trace.steps:
        weakness_id = step.payload.get("weakness_id", step.payload.get("weakness", ""))
        if isinstance(weakness_id, str) and weakness_id:
            return weakness_id
    return ""


def _ephemeral_snapshot(world: WorldIR, artifacts: KindArtifacts, witness_bundle: WitnessBundle) -> Snapshot:
    predicates = PredicateEngine(world)
    db_seed_state = {"services": [service.id for service in world.services if service.kind == "db"]}
    mail_state = {"mailboxes": [persona.mailbox for persona in world.green_personas if persona.mailbox]}
    file_assets = {asset.id: asset.location for asset in world.assets}
    identity_seed = {"users": [user.id for user in world.users]}
    report = ValidatorReport(
        admitted=True,
        graph_ok=True,
        boot_ok=True,
        workflow_ok=True,
        telemetry_ok=True,
        red_witness_ok=True,
        blue_witness_ok=True,
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
    return Snapshot(
        snapshot_id=f"{world.world_id}-admission",
        world_id=world.world_id,
        seed=world.seed,
        artifacts_dir=artifacts.render_dir,
        image_digests=artifacts.pinned_image_digests,
        state_seed_dir=artifacts.render_dir,
        witness_bundle_path=f"{artifacts.render_dir}/witness_bundle.json",
        validator_report_path=f"{artifacts.render_dir}/validator_report.json",
        world=world,
        artifacts=artifacts,
        db_seed_state=db_seed_state,
        mail_state=mail_state,
        file_assets=file_assets,
        identity_seed=identity_seed,
        validator_report=report,
        witness_bundle=witness_bundle,
        world_hash=world_hash(world),
    )


def _live_service_smoke_check(world: WorldIR, release) -> ValidatorCheckReport:
    commands = {
        "svc-web": ("sandbox-red", "wget -qO- http://svc-web:80/ | grep -q OpenRange"),
        "svc-email": ("sandbox-red", "nc -z -w 3 svc-email 25"),
        "svc-idp": ("sandbox-blue", "nc -z -w 3 svc-idp 389"),
        "svc-fileshare": ("sandbox-blue", "nc -z -w 3 svc-fileshare 445"),
        "svc-db": ("sandbox-blue", "nc -z -w 3 svc-db 3306"),
        "svc-siem": ("sandbox-blue", "wget -qO- http://svc-siem:9200/all.log >/dev/null"),
    }
    failures: list[str] = []
    for service in world.services:
        runner, cmd = commands.get(service.id, ("sandbox-blue", "true"))
        result = asyncio.run(release.pods.exec(runner, cmd, timeout=10.0))
        if not result.ok:
            failures.append(f"{service.id}:{result.stderr or result.stdout or 'smoke failed'}")
    return ValidatorCheckReport(
        name="live_service_smoke",
        passed=not failures,
        details={"failures": failures},
        error="; ".join(failures),
    )


def _live_red_witness_check(snapshot: Snapshot, backend: PodActionBackend) -> ValidatorCheckReport:
    score, events, health, outputs = run_red_witness(snapshot, backend, episode_seed=snapshot.world.seed)
    predicates = PredicateEngine(snapshot.world)
    satisfied = predicates.evaluate_red_objectives(
        snapshot=snapshot,
        events=events,
        service_health=dict(health),
    )
    passed = score.winner == "red" and score.done and predicates.red_terminal_satisfied(satisfied)
    return ValidatorCheckReport(
        name="live_red_witness",
        passed=passed,
        details={
            "winner": score.winner,
            "terminal_reason": score.terminal_reason,
            "satisfied_predicates": sorted(satisfied),
            "outputs": outputs,
        },
        error="" if passed else "live red witness did not satisfy terminal objectives",
    )


def _live_blue_witness_check(snapshot: Snapshot, backend: PodActionBackend) -> ValidatorCheckReport:
    score, outputs = run_blue_witness(snapshot, backend)
    passed = score.winner == "blue" and score.done
    return ValidatorCheckReport(
        name="live_blue_witness",
        passed=passed,
        details={"winner": score.winner, "terminal_reason": score.terminal_reason, "outputs": outputs},
        error="" if passed else "live blue witness did not validate detect-and-contain path",
    )


def _live_siem_ingest_check(release) -> ValidatorCheckReport:
    result = asyncio.run(
        release.pods.exec("svc-siem", "grep -q 'InitialAccess' /srv/http/siem/all.log", timeout=10.0)
    )
    return ValidatorCheckReport(
        name="live_siem_ingest",
        passed=result.ok,
        details={"stdout": result.stdout.strip(), "stderr": result.stderr.strip()},
        error="" if result.ok else "siem log sink did not record witness events",
    )


def _live_determinism_check(snapshot: Snapshot, backend: PodActionBackend) -> ValidatorCheckReport:
    first_score, first_events, first_health, _first_outputs = run_red_witness(
        snapshot,
        backend,
        episode_seed=snapshot.world.seed,
    )
    second_score, second_events, second_health, _second_outputs = run_red_witness(
        snapshot,
        backend,
        episode_seed=snapshot.world.seed,
    )
    passed = (
        first_events == second_events
        and first_health == second_health
        and first_score.winner == second_score.winner
        and first_score.terminal_reason == second_score.terminal_reason
    )
    return ValidatorCheckReport(
        name="live_determinism",
        passed=passed,
        details={
            "first_event_count": len(first_events),
            "second_event_count": len(second_events),
            "winner": first_score.winner,
        },
        error="" if passed else "live witness replay is not deterministic",
    )


def _live_necessity_check(snapshot: Snapshot, release, backend: PodActionBackend) -> ValidatorCheckReport:
    red_targets = {step.target for step in snapshot.witness_bundle.red_witnesses[0].steps}
    candidate_weaknesses = sorted(
        (
            weak
            for weak in PredicateEngine(snapshot.world).active_weaknesses()
            if weak.target in red_targets
        ),
        key=lambda weak: (
            0 if weak.instantiation_mode == "exact_code" else 1,
            0 if weak.target == snapshot.witness_bundle.red_witnesses[0].steps[0].target else 1,
            weak.id,
        ),
    )
    target_weakness = candidate_weaknesses[0] if candidate_weaknesses else None
    if target_weakness is None:
        return ValidatorCheckReport(
            name="live_necessity",
            passed=False,
            details={"reason": "no witness-relevant weakness"},
            error="no witness-relevant weakness available for live necessity check",
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
    apply_result = asyncio.run(release.pods.exec(target_weakness.target, command, timeout=10.0))
    score, _events, _health, outputs = run_red_witness(
        snapshot,
        backend,
        episode_seed=snapshot.world.seed,
    )
    asyncio.run(
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
        error="" if passed else "live remediation did not break the witness path",
    )


def _live_shortcut_probe_check(snapshot: Snapshot, release) -> ValidatorCheckReport:
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
        result = asyncio.run(release.pods.exec("sandbox-red", _service_probe_command(service), timeout=10.0))
        if result.ok:
            unexpected.append(f"direct_external_access:{service_id}")
    if "svc-idp" in service_by_id:
        admin_probe = asyncio.run(release.pods.exec("sandbox-red", _service_probe_command(service_by_id["svc-idp"]), timeout=10.0))
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


def _web_shortcut_findings(snapshot: Snapshot, release, public_services: list[ServiceSpec]) -> list[str]:
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
            result = asyncio.run(
                release.pods.exec("sandbox-red", _http_probe_command(service, path, query), timeout=10.0)
            )
            if _looks_like_shortcut_payload(result.stdout):
                findings.append(f"unguarded_web_route:{service.id}:{kind}")
        for asset in snapshot.world.assets:
            if asset.confidentiality not in {"high", "critical"}:
                continue
            result = asyncio.run(
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


def _http_probe_command(service: ServiceSpec, path: str, query: dict[str, str] | None = None) -> str:
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
    return "OPENRANGE-FOOTHOLD:" in text or "admin_console=enabled" in text


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
    summary_path = next((Path(path) for path in artifacts.rendered_files if path.endswith("synth-summary.json")), None)
    if summary_path is not None and summary_path.exists():
        try:
            summary_payload = json.loads(summary_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            summary_payload = None

    if isinstance(summary_payload, dict):
        mailboxes = summary_payload.get("mailboxes", {})
        if isinstance(mailboxes, dict):
            for mailbox, messages in mailboxes.items():
                joined = "\n".join(str(message) for message in messages) if isinstance(messages, list) else str(messages)
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
    telemetry_sources = {edge.source for edge in world.telemetry_edges if edge.target == "svc-siem"}
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
        if expected_surfaces and not (set(service.telemetry_surfaces) & expected_surfaces):
            findings.append(f"unlogged_critical_action:no_surface_overlap:{weakness.id}")
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
