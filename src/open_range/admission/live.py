"""Kind-backed live admission checks and reference replay."""

from __future__ import annotations

import shlex
import time
from pathlib import Path
from urllib.parse import urlencode

from open_range.admission.models import (
    ReferenceBundle,
    ValidatorCheckReport,
    ValidatorStageReport,
)
from open_range.admission.references import (
    ephemeral_runtime_snapshot,
    reference_weakness_id,
)
from open_range.async_utils import run_async
from open_range.catalog.probes import SHORTCUT_WEB_ROUTE_PROBE_SPECS
from open_range.objectives import evaluate_objective_grader_live
from open_range.objectives.engine import PredicateEngine
from open_range.runtime.execution import clear_runtime_markers, live_action_backend
from open_range.runtime.replay import run_blue_reference, run_red_reference
from open_range.snapshot import KindArtifacts, RuntimeSnapshot
from open_range.weaknesses import remediation_command_for_weakness
from open_range.world_ir import ServiceSpec, WorldIR

_DB_MTLS_CLIENT_CONTAINER = "db-client-mtls"
_DB_MTLS_CLIENT_CONFIG = "/etc/mysql/conf.d/openrange-client-mtls.cnf"
_DB_MTLS_FAILURE_MARKERS = (
    "access denied",
    "require x509",
    "x509",
    "certificate",
    "ssl",
    "tls",
    "1045",
)


def run_live_backend_checks(
    world: WorldIR,
    artifacts: KindArtifacts,
    reference_bundle: ReferenceBundle,
    live_backend,
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

        snapshot = ephemeral_runtime_snapshot(world, artifacts, reference_bundle)
        backend = live_action_backend(snapshot, release)

        checks.append(check_live_service_smoke(world, release))
        checks.append(check_live_db_mtls(world, release))

        clear_runtime_markers(release, world)
        checks.append(_live_red_reference_check(snapshot, release, backend))
        checks.append(_live_siem_ingest_check(release))

        for check in (
            lambda: _live_blue_reference_check(snapshot, backend),
            lambda: _live_determinism_check(snapshot, backend),
            lambda: _live_necessity_check(snapshot, release, backend),
            lambda: _live_shortcut_probe_check(snapshot, release),
        ):
            clear_runtime_markers(release, world)
            checks.append(check())

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


def check_live_service_smoke(world: WorldIR, release) -> ValidatorCheckReport:
    failures: list[str] = []
    for service in world.services:
        runner = smoke_runner_for_service(world, service.id)
        cmd = _smoke_probe_command(service)
        last_error = "smoke failed"
        ok = False
        attempts = 10 if service.kind == "db" else 3
        retry_delay_s = 2.0 if service.kind == "db" else 1.0
        for attempt in range(attempts):
            result = run_async(release.pods.exec(runner, cmd, timeout=10.0))
            if result.ok:
                ok = True
                break
            last_error = result.stderr or result.stdout or "smoke failed"
            if attempt + 1 < attempts:
                time.sleep(retry_delay_s)
        if not ok:
            failures.append(f"{service.id}:{last_error}")
    return ValidatorCheckReport(
        name="live_service_smoke",
        passed=not failures,
        details={"failures": failures},
        error="; ".join(failures),
    )


def check_live_db_mtls(world: WorldIR, release) -> ValidatorCheckReport:
    mtls = world.security_runtime.mtls
    if not mtls or not mtls.get("enabled"):
        return ValidatorCheckReport(
            name="live_db_mtls",
            passed=True,
            details={"note": "mTLS not enabled"},
        )

    web_client = _db_mtls_web_client(world)
    if web_client is None:
        return ValidatorCheckReport(
            name="live_db_mtls",
            passed=True,
            details={"note": "no built-in web client depends on svc-db"},
        )

    positive_cmd = _db_mtls_positive_cmd()
    positive_result = run_async(
        release.pods.exec(
            web_client.id,
            positive_cmd,
            timeout=15.0,
            container=_DB_MTLS_CLIENT_CONTAINER,
        )
    )

    negative_cmd = _db_mtls_negative_cmd()
    negative_result = run_async(
        release.pods.exec("sandbox-red", negative_cmd, timeout=15.0)
    )

    failures = _db_mtls_failures(positive_result, negative_result)
    return ValidatorCheckReport(
        name="live_db_mtls",
        passed=not failures,
        details={
            "web_client": web_client.id,
            "positive_runner": web_client.id,
            "positive_container": _DB_MTLS_CLIENT_CONTAINER,
            "positive_cmd": positive_cmd,
            "positive_stdout": positive_result.stdout.strip(),
            "positive_stderr": positive_result.stderr.strip(),
            "negative_runner": "sandbox-red",
            "negative_cmd": negative_cmd,
            "negative_stdout": negative_result.stdout.strip(),
            "negative_stderr": negative_result.stderr.strip(),
        },
        error="; ".join(failures),
    )


def smoke_runner_for_service(world: WorldIR, service_id: str) -> str:
    service_by_id = {service.id: service for service in world.services}
    host_zone_by_id = {host.id: host.zone for host in world.hosts}
    service = service_by_id[service_id]
    zone = host_zone_by_id.get(service.host, "")
    if zone in {"dmz", "external"}:
        return "sandbox-red"
    if zone == "management":
        return "sandbox-blue"
    if zone in {"corp", "data"}:
        runner = _first_green_sandbox_in_zones(world, ("dmz", "corp", zone))
        if runner:
            return runner
    runner = _first_green_sandbox_in_zones(world, (zone,))
    if runner:
        return runner
    return "sandbox-blue" if zone == "management" else "sandbox-red"


def _live_red_reference_check(
    snapshot: RuntimeSnapshot, release, backend
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
    snapshot: RuntimeSnapshot, backend
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


def _live_determinism_check(snapshot: RuntimeSnapshot, backend) -> ValidatorCheckReport:
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
    snapshot: RuntimeSnapshot, release, backend
) -> ValidatorCheckReport:
    engine = PredicateEngine(snapshot.world)
    trace_bindings = []
    for trace_index, trace in enumerate(
        snapshot.reference_bundle.reference_attack_traces
    ):
        weakness_id = reference_weakness_id(trace)
        if not weakness_id:
            continue
        weakness = next(
            (weak for weak in engine.active_weaknesses() if weak.id == weakness_id),
            None,
        )
        if weakness is not None:
            trace_bindings.append((trace_index, trace, weakness))
    red_targets = {
        step.target for _idx, trace, _weak in trace_bindings for step in trace.steps
    }
    candidate_weaknesses = sorted(
        (weak for weak in engine.active_weaknesses() if weak.target in red_targets),
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
    command = remediation_command_for_weakness(target_weakness)
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


def _db_mtls_web_client(world: WorldIR) -> ServiceSpec | None:
    for service in world.services:
        if service.kind == "web_app" and "svc-db" in service.dependencies:
            return service
    return None


def _db_mtls_positive_cmd() -> str:
    return f'mysql --defaults-extra-file={_DB_MTLS_CLIENT_CONFIG} -Nse "SELECT 1;"'


def _db_mtls_negative_cmd() -> str:
    return shlex.join(
        [
            "mysql",
            "--protocol=TCP",
            "--connect-timeout=5",
            "-h",
            "svc-db",
            "-uapp",
            "-papp-pass",
            "app",
            "-Nse",
            "SELECT 'openrange-db-mtls-ok';",
        ]
    )


def _db_mtls_failures(positive_result, negative_result) -> list[str]:
    failures: list[str] = []
    if not positive_result.ok:
        failures.append(
            f"positive_path:{positive_result.stderr or positive_result.stdout or 'failed'}"
        )
    if negative_result.ok:
        failures.append("no_cert_path:unexpected_success")
    elif not _negative_result_reflects_mtls_enforcement(negative_result):
        failures.append(
            f"no_cert_path:unexpected_failure_mode:{negative_result.stderr or negative_result.stdout or 'failed'}"
        )
    return failures


def _negative_result_reflects_mtls_enforcement(result) -> bool:
    output = (
        "\n".join(part for part in (result.stdout, result.stderr) if part)
        .strip()
        .lower()
    )
    return any(marker in output for marker in _DB_MTLS_FAILURE_MARKERS)


def _first_green_sandbox_in_zones(world: WorldIR, zones: tuple[str, ...]) -> str:
    host_zone_by_id = {host.id: host.zone for host in world.hosts}
    allowed = set(zones)
    for persona in world.green_personas:
        zone = host_zone_by_id.get(persona.home_host, "")
        if zone in allowed:
            safe = "".join(ch.lower() if ch.isalnum() else "-" for ch in persona.id)
            return f"sandbox-green-{safe.strip('-')}"
    return ""


def _smoke_probe_command(service: ServiceSpec) -> str:
    port = service.ports[0] if service.ports else 80
    if service.id == "svc-web":
        return f"wget -qO- http://{service.id}:{port}/ | grep -q OpenRange"
    if service.id == "svc-siem":
        return "wget -qO- http://svc-siem:9200/all.log >/dev/null"
    return f"nc -z -w 3 {service.id} {port}"


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
        for probe in SHORTCUT_WEB_ROUTE_PROBE_SPECS:
            if probe.weakness_kind in seeded_kinds:
                continue
            result = run_async(
                release.pods.exec(
                    "sandbox-red",
                    _http_probe_command(service, probe.path, dict(probe.query)),
                    timeout=10.0,
                )
            )
            if _looks_like_shortcut_payload(result.stdout):
                findings.append(
                    f"unguarded_web_route:{service.id}:{probe.weakness_kind}"
                )
        for asset in snapshot.world.assets:
            if asset.confidentiality not in {"high", "critical"}:
                continue
            if asset.owner_service != service.id:
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


def _looks_like_shortcut_payload(stdout: str) -> bool:
    text = stdout.strip()
    if not text:
        return False
    return (
        "OPENRANGE-FOOTHOLD:" in text
        or "OPENRANGE-EFFECT:" in text
        or "admin_console=enabled" in text
    )
