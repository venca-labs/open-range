from __future__ import annotations

import shutil
from pathlib import Path

from open_range.store import BuildPipeline, FileSnapshotStore
from open_range.store.build import CandidateWorld
from tests.support import OFFLINE_BUILD_CONFIG, manifest_payload


def _manifest_payload() -> dict:
    return manifest_payload()


def test_pipeline_builds_and_admits_snapshot(tmp_path: Path):
    pipeline = BuildPipeline(store=FileSnapshotStore(tmp_path / "snapshots"))
    candidate = pipeline.build(
        _manifest_payload(), tmp_path / "rendered", OFFLINE_BUILD_CONFIG
    )
    snapshot = pipeline.admit(candidate)

    assert candidate.world.weaknesses
    assert candidate.synth.generated_files
    assert snapshot.validator_report.admitted is True
    assert snapshot.snapshot_id.startswith(candidate.world.world_id)
    assert snapshot.world_id == candidate.world.world_id
    assert snapshot.artifacts_dir != candidate.artifacts.render_dir
    assert Path(snapshot.artifacts_dir).exists()
    assert Path(snapshot.state_seed_dir).exists()
    assert f"-train-{snapshot.world_hash[:8]}-" in snapshot.snapshot_id
    assert all(
        not check.details
        for stage in snapshot.validator_report.stages
        for check in stage.checks
    )
    assert "world" not in snapshot.model_dump()
    assert "world_path" not in snapshot.model_dump()
    assert "reference_bundle_path" not in snapshot.model_dump()


def test_pipeline_snapshot_remains_loadable_after_build_dir_is_deleted(tmp_path: Path):
    pipeline = BuildPipeline(store=FileSnapshotStore(tmp_path / "snapshots"))
    candidate = pipeline.build(
        _manifest_payload(), tmp_path / "rendered", OFFLINE_BUILD_CONFIG
    )
    snapshot = pipeline.admit(candidate)

    shutil.rmtree(candidate.artifacts.render_dir)

    assert Path(snapshot.artifacts_dir).exists()
    assert Path(snapshot.state_seed_dir).exists()


def test_pipeline_uses_distinct_snapshot_ids_per_split(tmp_path: Path):
    pipeline = BuildPipeline(store=FileSnapshotStore(tmp_path / "snapshots"))
    candidate = pipeline.build(
        _manifest_payload(), tmp_path / "rendered", OFFLINE_BUILD_CONFIG
    )

    train_snapshot = pipeline.admit(candidate, split="train")
    eval_snapshot = pipeline.admit(candidate, split="eval")

    assert train_snapshot.snapshot_id != eval_snapshot.snapshot_id
    assert "train" in train_snapshot.snapshot_id
    assert "eval" in eval_snapshot.snapshot_id


def test_pipeline_reuses_existing_snapshot_for_same_world_and_split(tmp_path: Path):
    pipeline = BuildPipeline(store=FileSnapshotStore(tmp_path / "snapshots"))
    candidate = pipeline.build(
        _manifest_payload(), tmp_path / "rendered", OFFLINE_BUILD_CONFIG
    )

    first = pipeline.admit(candidate, split="train")
    second = pipeline.admit(candidate, split="train")
    third = pipeline.admit(
        CandidateWorld(
            world=candidate.world,
            synth=candidate.synth,
            artifacts=candidate.artifacts,
            build_config=candidate.build_config.model_copy(
                update={"blue_reference_count": 2}
            ),
        ),
        split="train",
    )

    assert second.snapshot_id == first.snapshot_id
    assert third.snapshot_id != first.snapshot_id
