from __future__ import annotations

import shutil
from pathlib import Path

from open_range.config import BuildConfig
from open_range.store import BuildPipeline, FileSnapshotStore, load_runtime_snapshot
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
    runtime_snapshot = load_runtime_snapshot(pipeline.store, snapshot.snapshot_id)

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
    assert all(
        "content" not in payload
        for service in snapshot.artifacts.chart_values["services"].values()
        for payload in service.get("payloads", ())
    )
    assert all(
        "content" not in payload
        for service in snapshot.artifacts.chart_values["services"].values()
        for sidecar in service.get("sidecars", ())
        for payload in sidecar.get("payloads", ())
    )
    assert all(
        Path(path).exists() and Path(snapshot.artifacts_dir) in Path(path).parents
        for path in snapshot.artifacts.rendered_files
    )
    assert snapshot.db_seed_state == {}
    assert snapshot.file_assets == {}
    assert not any(Path(snapshot.state_seed_dir).iterdir())
    assert not (Path(snapshot.artifacts_dir) / "security").exists()
    assert not (Path(snapshot.artifacts_dir) / "synth").exists()
    assert runtime_snapshot.artifacts_dir != snapshot.artifacts_dir
    assert runtime_snapshot.state_seed_dir != snapshot.state_seed_dir
    assert runtime_snapshot.db_seed_state
    assert runtime_snapshot.file_assets
    assert any(
        "content" in payload
        for service in runtime_snapshot.artifacts.chart_values["services"].values()
        for payload in service.get("payloads", ())
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


def test_pipeline_snapshot_id_changes_when_artifacts_change(tmp_path: Path):
    pipeline = BuildPipeline(store=FileSnapshotStore(tmp_path / "snapshots"))

    base_candidate = pipeline.build(
        _manifest_payload(), tmp_path / "rendered-base", OFFLINE_BUILD_CONFIG
    )
    cilium_candidate = pipeline.build(
        _manifest_payload(),
        tmp_path / "rendered-cilium",
        BuildConfig(
            validation_profile="graph_only",
            network_policy_backend="cilium",
        ),
    )

    base_snapshot = pipeline.admit(base_candidate, split="train")
    cilium_snapshot = pipeline.admit(cilium_candidate, split="train")

    assert base_candidate.world.model_dump(
        mode="json"
    ) == cilium_candidate.world.model_dump(mode="json")
    assert base_snapshot.snapshot_id != cilium_snapshot.snapshot_id
