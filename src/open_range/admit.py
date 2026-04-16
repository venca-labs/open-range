"""Deterministic admission controller."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Protocol
from urllib.parse import urlencode

from open_range._admission_checks import _ephemeral_snapshot, _reference_weakness_id
from open_range._admission_registry import get_admission_check
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
from open_range.execution import PodActionBackend
from open_range.k3d_runner import K3dBackend
from open_range.live_checks import check_live_db_mtls, check_live_service_smoke
from open_range.objectives import evaluate_objective_grader_live
from open_range.predicates import PredicateEngine
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

        for stage in admission_stages(build_config):
            checks: list[ValidatorCheckReport] = []
            for check_name in stage.check_names:
                if not continue_running:
                    break
                if reference_bundle is None and stage.requires_references:
                    from open_range.probe_planner import build_reference_bundle

                    reference_bundle = build_reference_bundle(world, build_config)
                result = get_admission_check(check_name)(
                    world,
                    artifacts,
                    reference_bundle,
                )
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

        if reference_bundle is None:
            from open_range.probe_planner import build_reference_bundle

            reference_bundle = build_reference_bundle(world, build_config)

        if continue_running and live_backend is not None:
            live_stage, live_info = self._run_live_backend_checks(
                world,
                artifacts,
                reference_bundle,
                live_backend,
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
            reference_bundle=reference_bundle,
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
        return reference_bundle, report

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
            "svc-siem",
            "grep -q 'InitialAccess' /srv/http/siem/all.log",
            timeout=10.0,
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
                "sandbox-red",
                _service_probe_command(service),
                timeout=10.0,
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
    service: ServiceSpec,
    path: str,
    query: dict[str, str] | None = None,
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
