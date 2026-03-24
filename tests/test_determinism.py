from __future__ import annotations

from pathlib import Path

from open_range.admit import LocalAdmissionController
from open_range.pipeline import BuildPipeline
from tests.support import OFFLINE_BUILD_CONFIG, manifest_payload


def _manifest_payload() -> dict:
    return manifest_payload()


def test_build_pipeline_is_repeatable_for_same_manifest(tmp_path: Path):
    pipeline = BuildPipeline()

    candidate_a = pipeline.build(_manifest_payload(), tmp_path / "render-a")
    candidate_b = pipeline.build(_manifest_payload(), tmp_path / "render-b")

    assert candidate_a.world == candidate_b.world
    assert candidate_a.artifacts.chart_values == candidate_b.artifacts.chart_values
    assert (
        candidate_a.artifacts.pinned_image_digests
        == candidate_b.artifacts.pinned_image_digests
    )


def test_admission_is_repeatable_for_same_world(tmp_path: Path):
    pipeline = BuildPipeline()
    candidate = pipeline.build(
        _manifest_payload(), tmp_path / "render", OFFLINE_BUILD_CONFIG
    )
    admission = LocalAdmissionController(mode="fail_fast")

    bundle_a, report_a = admission.admit(
        candidate.world, candidate.artifacts, OFFLINE_BUILD_CONFIG
    )
    bundle_b, report_b = admission.admit(
        candidate.world, candidate.artifacts, OFFLINE_BUILD_CONFIG
    )

    assert bundle_a == bundle_b
    assert report_a.model_dump(
        exclude={"build_logs", "health_info"}
    ) == report_b.model_dump(exclude={"build_logs", "health_info"})
