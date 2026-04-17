"""Kind-backed live admission checks and reference replay."""

from __future__ import annotations

import time
from pathlib import Path
from urllib.parse import urlencode

from open_range.admission.live_security import check_live_db_mtls
from open_range.admission.models import (
    ReferenceBundle,
    ValidatorCheckReport,
    ValidatorStageReport,
)
from open_range.admission.reference_checks import run_live_reference_checks
from open_range.admission.references import ephemeral_runtime_snapshot
from open_range.catalog.probes import SHORTCUT_WEB_ROUTE_PROBE_SPECS
from open_range.contracts.snapshot import KindArtifacts, RuntimeSnapshot, world_hash
from open_range.contracts.world import ServiceSpec, WorldIR
from open_range.support.async_utils import run_async


def run_live_backend_checks(
    world: WorldIR,
    artifacts: KindArtifacts,
    reference_bundle: ReferenceBundle,
    live_backend,
    *,
    build_config,
) -> tuple[ValidatorStageReport, dict[str, object]]:
    checks: list[ValidatorCheckReport] = []
    expected_services = {service.id for service in world.services}
    live_info: dict[str, object] = {}
    try:
        release = live_backend.boot(
            snapshot_id=f"{world.world_id}-{world_hash(world)[:8]}",
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
        checks.append(check_live_service_smoke(world, release))
        checks.append(check_live_db_mtls(world, release))
        checks.extend(
            run_live_reference_checks(
                snapshot,
                release,
                validation_profile=build_config.validation_profile,
            )
        )
        if build_config.validation_profile in {"full", "no_necessity"}:
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


def check_live_service_smoke(world: WorldIR, release) -> ValidatorCheckReport:
    failures: list[str] = []
    for service in world.services:
        runner = smoke_runner_for_service(world, service.id)
        cmd = _smoke_probe_command(service)
        last_error = "smoke failed"
        ok = False
        slow_start_service = service.kind == "db" or service.id == "svc-email"
        attempts = 10 if slow_start_service else 3
        retry_delay_s = 2.0 if slow_start_service else 1.0
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
