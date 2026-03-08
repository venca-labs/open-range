"""Tests for the managed snapshot runtime."""

from __future__ import annotations

import pytest

from open_range.server.environment import RangeEnvironment
from open_range.server.runtime import ManagedSnapshotRuntime


class TestManagedSnapshotRuntime:
    def test_offline_validator_profile_includes_static_checks(self, tier1_manifest, tmp_path):
        runtime = ManagedSnapshotRuntime(
            manifest=tier1_manifest,
            store_dir=tmp_path / "snapshots",
            validator_profile="offline",
            refill_enabled=False,
        )
        names = [type(check).__name__ for check in runtime.validator.checks]
        assert names == [
            "StructuralSnapshotCheck",
            "TaskFeasibilityCheck",
        ]

    def test_training_validator_profile_includes_live_checks(self, tier1_manifest, tmp_path):
        runtime = ManagedSnapshotRuntime(
            manifest=tier1_manifest,
            store_dir=tmp_path / "snapshots",
            validator_profile="training",
            refill_enabled=False,
        )
        names = [type(check).__name__ for check in runtime.validator.checks]
        assert "BuildBootCheck" in names
        assert "ExploitabilityCheck" in names
        assert "PatchabilityCheck" in names
        assert "EvidenceCheck" in names
        assert "RewardGroundingCheck" in names
        assert "DifficultyCheck" in names

    def test_start_preloads_snapshot_pool(self, tier1_manifest, tmp_path):
        runtime = ManagedSnapshotRuntime(
            manifest=tier1_manifest,
            store_dir=tmp_path / "snapshots",
            pool_size=2,
            refill_enabled=False,
        )

        runtime.start()
        try:
            listing = runtime.list_snapshots()
            assert len(listing) == 2
            assert all(item["snapshot_id"] for item in listing)
        finally:
            runtime.stop()

    def test_start_materializes_rendered_artifacts(self, tier1_manifest, tmp_path):
        runtime = ManagedSnapshotRuntime(
            manifest=tier1_manifest,
            store_dir=tmp_path / "snapshots",
            pool_size=1,
            refill_enabled=False,
        )

        runtime.start()
        try:
            admitted = runtime.acquire_snapshot()
            artifacts_dir = tmp_path / "snapshots" / admitted.snapshot_id / "artifacts"
            assert (artifacts_dir / "docker-compose.yml").exists()
            assert (artifacts_dir / "Dockerfile.web").exists()
            assert admitted.snapshot.compose
            assert "services" in admitted.snapshot.compose
        finally:
            runtime.stop()

    def test_acquire_snapshot_returns_admitted_snapshot(self, tier1_manifest, tmp_path):
        runtime = ManagedSnapshotRuntime(
            manifest=tier1_manifest,
            store_dir=tmp_path / "snapshots",
            pool_size=1,
            selection_strategy="latest",
            refill_enabled=False,
        )

        runtime.start()
        try:
            admitted = runtime.acquire_snapshot()
            assert admitted.snapshot_id
            assert admitted.snapshot.truth_graph.vulns
            assert admitted.snapshot.flags
        finally:
            runtime.stop()

    def test_get_snapshot_by_id_returns_exact_snapshot(self, tier1_manifest, tmp_path):
        runtime = ManagedSnapshotRuntime(
            manifest=tier1_manifest,
            store_dir=tmp_path / "snapshots",
            pool_size=1,
            refill_enabled=False,
        )

        runtime.start()
        try:
            first = runtime.acquire_snapshot()
            loaded = runtime.get_snapshot(first.snapshot_id)
            assert loaded.snapshot_id == first.snapshot_id
            assert loaded.snapshot.flags[0].value == first.snapshot.flags[0].value
            assert loaded.snapshot.compose == first.snapshot.compose
        finally:
            runtime.stop()

    def test_start_records_root_and_child_lineage(self, tier1_manifest, tmp_path):
        runtime = ManagedSnapshotRuntime(
            manifest=tier1_manifest,
            store_dir=tmp_path / "snapshots",
            pool_size=2,
            selection_strategy="latest",
            refill_enabled=False,
        )

        runtime.start()
        try:
            listing = runtime.list_snapshots()
            assert len(listing) == 2
            depths = {item["generation_depth"] for item in listing}
            assert 0 in depths
            assert 1 in depths
            assert any(item["parent_snapshot_id"] for item in listing)
        finally:
            runtime.stop()

    def test_acquire_snapshot_exposes_lineage_metadata(self, tier1_manifest, tmp_path):
        runtime = ManagedSnapshotRuntime(
            manifest=tier1_manifest,
            store_dir=tmp_path / "snapshots",
            pool_size=2,
            refill_enabled=False,
        )

        runtime.start()
        try:
            admitted = runtime.acquire_snapshot()
            assert admitted.snapshot.lineage.snapshot_id == admitted.snapshot_id
            assert admitted.snapshot.lineage.root_snapshot_id
        finally:
            runtime.stop()


class TestEnvironmentRuntimeIntegration:
    def test_reset_uses_managed_runtime_snapshot(self, tier1_manifest, tmp_path):
        runtime = ManagedSnapshotRuntime(
            manifest=tier1_manifest,
            store_dir=tmp_path / "snapshots",
            pool_size=1,
            refill_enabled=False,
        )
        runtime.start()

        env = RangeEnvironment(runtime=runtime, docker_available=False)
        try:
            obs = env.reset()
            assert "Range ready" in obs.stdout
            assert env.snapshot is not None
            assert env.snapshot.truth_graph.vulns
        finally:
            env.close()
            runtime.stop()

    def test_reset_snapshot_id_uses_runtime_store(self, tier1_manifest, tmp_path):
        runtime = ManagedSnapshotRuntime(
            manifest=tier1_manifest,
            store_dir=tmp_path / "snapshots",
            pool_size=1,
            refill_enabled=False,
        )
        runtime.start()

        env = RangeEnvironment(runtime=runtime, docker_available=False)
        try:
            admitted = runtime.acquire_snapshot()
            env.reset(snapshot_id=admitted.snapshot_id)
            assert env.snapshot is not None
            assert env.snapshot.flags[0].value == admitted.snapshot.flags[0].value
        finally:
            env.close()
            runtime.stop()

    def test_missing_snapshot_id_raises(self, tier1_manifest, tmp_path):
        runtime = ManagedSnapshotRuntime(
            manifest=tier1_manifest,
            store_dir=tmp_path / "snapshots",
            pool_size=1,
            refill_enabled=False,
        )
        runtime.start()

        env = RangeEnvironment(runtime=runtime, docker_available=False)
        try:
            with pytest.raises(FileNotFoundError):
                env.reset(snapshot_id="missing_snapshot")
        finally:
            env.close()
            runtime.stop()
