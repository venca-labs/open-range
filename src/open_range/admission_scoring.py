"""Admission summary scoring and report aggregation."""

from __future__ import annotations

from open_range.admission import (
    ValidatorCheckReport,
    ValidatorStageReport,
    ReferenceBundle,
)
from open_range.predicates import PredicateEngine
from open_range.world_ir import WorldIR


def report_summary(
    *,
    world: WorldIR,
    stages: tuple[ValidatorStageReport, ...],
    reference_bundle: ReferenceBundle,
    health_info: dict[str, object],
) -> dict[str, object]:
    del reference_bundle
    engine = PredicateEngine(world)
    checks = {check.name: check for stage in stages for check in stage.checks}
    rejection_reasons = tuple(
        check.error
        for stage in stages
        for check in stage.checks
        if not check.passed and not check.advisory and check.error
    )
    determinism_checks = [
        check.passed
        for name, check in checks.items()
        if name in {"determinism", "live_determinism"}
    ]
    determinism_score = (
        sum(1.0 for passed in determinism_checks if passed) / len(determinism_checks)
        if determinism_checks
        else 0.0
    )
    flakiness = 1.0 - determinism_score if determinism_checks else 1.0
    shortcut_failures = [
        name
        for name in ("shortcut_probes", "live_shortcuts")
        if name in checks and not checks[name].passed
    ]
    if not shortcut_failures:
        shortcut_risk = "low"
    elif len(shortcut_failures) == 1:
        shortcut_risk = "medium"
    else:
        shortcut_risk = "high"
    live_service_count = float(
        health_info.get("live_service_count", len(world.services))
        or len(world.services)
    )
    continuity = min(1.0, live_service_count / max(1.0, float(len(world.services))))
    return {
        "graph_ok": all(
            checks.get(name, ValidatorCheckReport(name=name, passed=False)).passed
            for name in (
                "manifest_compliance",
                "graph_consistency",
                "path_solvability",
                "objective_grounding",
            )
        ),
        "boot_ok": all(
            checks.get(name, ValidatorCheckReport(name=name, passed=False)).passed
            for name in ("render_outputs", "service_health")
        )
        and all(
            checks.get(name, ValidatorCheckReport(name=name, passed=True)).passed
            for name in ("kind_boot", "kind_health")
        ),
        "workflow_ok": all(
            checks.get(name, ValidatorCheckReport(name=name, passed=False)).passed
            for name in ("topology_workflow_consistency", "live_service_smoke")
            if name in checks
        ),
        "telemetry_ok": all(
            checks.get(name, ValidatorCheckReport(name=name, passed=False)).passed
            for name in ("siem_ingest", "live_siem_ingest")
            if name in checks
        ),
        "reference_attack_ok": all(
            checks.get(name, ValidatorCheckReport(name=name, passed=False)).passed
            for name in ("red_reference", "live_red_reference")
            if name in checks
        ),
        "reference_defense_ok": all(
            checks.get(name, ValidatorCheckReport(name=name, passed=False)).passed
            for name in ("blue_reference", "live_blue_reference")
            if name in checks
        ),
        "necessity_ok": all(
            checks.get(name, ValidatorCheckReport(name=name, passed=False)).passed
            for name in ("necessity", "live_necessity")
            if name in checks
        ),
        "shortcut_risk": shortcut_risk,
        "determinism_score": round(determinism_score, 4),
        "flakiness": round(flakiness, 4),
        "red_path_depth": engine.red_path_depth(),
        "red_alt_path_count": engine.red_alt_path_count(),
        "blue_signal_points": len({edge.source for edge in world.telemetry_edges}),
        "business_continuity_score": round(continuity, 4),
        "benchmark_tags_covered": engine.benchmark_tags_covered(),
        "rejection_reasons": rejection_reasons,
    }
