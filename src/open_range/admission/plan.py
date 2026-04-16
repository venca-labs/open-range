"""Shared admission stage planning helpers."""

from __future__ import annotations

from dataclasses import dataclass

from open_range.build_config import BuildConfig


@dataclass(frozen=True, slots=True)
class AdmissionStagePlan:
    name: str
    check_names: tuple[str, ...]
    requires_references: bool = False


def admission_stages(build_config: BuildConfig) -> tuple[AdmissionStagePlan, ...]:
    static_stage = AdmissionStagePlan(
        "static",
        (
            "manifest_compliance",
            "graph_consistency",
            "path_solvability",
            "objective_grounding",
            "topology_workflow_consistency",
        ),
    )
    security_stage = AdmissionStagePlan(
        "security",
        (
            "identity_enforcement",
            "encryption_enforcement",
            "mtls_enforcement",
        ),
    )
    live_stage = AdmissionStagePlan(
        "live",
        (
            "render_outputs",
            "service_health",
            "siem_ingest",
            "isolation",
            "difficulty_envelope",
        ),
    )
    reference_stages = (
        AdmissionStagePlan(
            "red_reference", ("red_reference",), requires_references=True
        ),
        AdmissionStagePlan(
            "blue_reference", ("blue_reference",), requires_references=True
        ),
    )
    advanced_stages = (
        AdmissionStagePlan("necessity", ("necessity",), requires_references=True),
        AdmissionStagePlan("shortcut", ("shortcut_probes",), requires_references=True),
        AdmissionStagePlan("determinism", ("determinism",), requires_references=True),
    )
    security_stages = (security_stage,) if build_config.security_enabled else ()

    if build_config.validation_profile == "graph_only":
        return (static_stage, *security_stages)
    if build_config.validation_profile == "graph_plus_live":
        return (static_stage, *security_stages, live_stage) + reference_stages
    if build_config.validation_profile == "no_necessity":
        return (
            static_stage,
            *security_stages,
            live_stage,
            *reference_stages,
            AdmissionStagePlan(
                "shortcut", ("shortcut_probes",), requires_references=True
            ),
            AdmissionStagePlan(
                "determinism", ("determinism",), requires_references=True
            ),
        )
    return (
        static_stage,
        *security_stages,
        live_stage,
        *reference_stages,
        *advanced_stages,
    )


def profile_requires_live(build_config: BuildConfig) -> bool:
    return build_config.validation_profile in {"full", "graph_plus_live"}
