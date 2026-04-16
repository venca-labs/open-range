from __future__ import annotations

from open_range.admission.plan import admission_stages
from open_range.admission.registry import registered_admission_checks
from open_range.build_config import BuildConfig


def test_admission_stage_plan_only_references_registered_checks() -> None:
    planned: set[str] = set()
    for build_config in (
        BuildConfig(validation_profile="full"),
        BuildConfig(validation_profile="graph_only"),
        BuildConfig(validation_profile="graph_plus_live"),
        BuildConfig(validation_profile="no_necessity"),
        BuildConfig(
            validation_profile="graph_only",
            security_integration_enabled=True,
            security_tier=3,
        ),
    ):
        for stage in admission_stages(build_config):
            planned.update(stage.check_names)

    assert planned == set(registered_admission_checks())
