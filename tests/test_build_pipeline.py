from __future__ import annotations

from pathlib import Path

from open_range.pipeline import BuildPipeline
from tests.support import OFFLINE_BUILD_CONFIG, manifest_payload


def _manifest_payload() -> dict:
    return manifest_payload()


def test_pipeline_builds_and_admits_snapshot(tmp_path: Path):
    pipeline = BuildPipeline()
    candidate = pipeline.build(
        _manifest_payload(), tmp_path / "rendered", OFFLINE_BUILD_CONFIG
    )
    snapshot = pipeline.admit(candidate)

    assert candidate.world.weaknesses
    assert candidate.synth.generated_files
    assert snapshot.validator_report.admitted is True
    assert snapshot.snapshot_id.startswith(candidate.world.world_id)
    assert snapshot.world_id == candidate.world.world_id
    assert snapshot.artifacts_dir == candidate.artifacts.render_dir
    assert "world" not in snapshot.model_dump()
    assert "world_path" not in snapshot.model_dump()
    assert "reference_bundle_path" not in snapshot.model_dump()
    assert "mailboxes" in snapshot.identity_seed
    assert not hasattr(pipeline.store, "load_world")
    assert not hasattr(pipeline.store, "hydrate")
    assert not hasattr(pipeline.store, "load_runtime")
    assert not hasattr(pipeline.store, "_load_world")
    assert not hasattr(pipeline.store, "_hydrate")
    assert not hasattr(pipeline.store, "_load_runtime")
    assert not hasattr(pipeline.store, "_sample_runtime")
