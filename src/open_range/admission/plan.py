"""Shared admission stage planning helpers."""

from __future__ import annotations

from dataclasses import dataclass

from open_range.admission.checks import builtin_admission_check_specs
from open_range.config import BuildConfig


@dataclass(frozen=True, slots=True)
class AdmissionStagePlan:
    name: str
    check_names: tuple[str, ...]
    requires_references: bool = False


_PROFILE_STAGE_NAMES: dict[str, tuple[str, ...]] = {
    "graph_only": ("static", "security"),
    "graph_plus_live": (
        "static",
        "security",
        "live",
        "red_reference",
        "blue_reference",
    ),
    "no_necessity": (
        "static",
        "security",
        "live",
        "red_reference",
        "blue_reference",
        "shortcut",
        "determinism",
    ),
    "full": (
        "static",
        "security",
        "live",
        "red_reference",
        "blue_reference",
        "necessity",
        "shortcut",
        "determinism",
    ),
}


def admission_stages(build_config: BuildConfig) -> tuple[AdmissionStagePlan, ...]:
    stage_names = _PROFILE_STAGE_NAMES[build_config.validation_profile]
    if not build_config.security_enabled:
        stage_names = tuple(name for name in stage_names if name != "security")

    stage_checks: dict[str, list[str]] = {}
    stage_requires_references: dict[str, bool] = {}
    for spec in builtin_admission_check_specs():
        stage_checks.setdefault(spec.stage, []).append(spec.name)
        stage_requires_references[spec.stage] = (
            stage_requires_references.get(spec.stage, False) or spec.requires_references
        )

    return tuple(
        AdmissionStagePlan(
            name=stage_name,
            check_names=tuple(stage_checks[stage_name]),
            requires_references=stage_requires_references.get(stage_name, False),
        )
        for stage_name in stage_names
    )


def profile_requires_live(build_config: BuildConfig) -> bool:
    return build_config.validation_profile in {"full", "graph_plus_live"}
