"""Tests for the managed snapshot runtime."""

from __future__ import annotations

import pytest

from open_range.server.environment import RangeEnvironment
from open_range.server.runtime import ManagedSnapshotRuntime


class TestManagedSnapshotRuntime:
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
