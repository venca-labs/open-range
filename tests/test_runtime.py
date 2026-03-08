"""Tests for the managed snapshot runtime."""

from __future__ import annotations

from pathlib import Path

import pytest

from open_range.protocols import CheckResult, ContainerSet, SnapshotSpec
from open_range.server.compose_runner import BootedSnapshotProject
from open_range.server.environment import RangeEnvironment
from open_range.server.runtime import ManagedSnapshotRuntime
from open_range.validator.validator import ValidationResult


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
            "ManifestComplianceCheck",
            "GraphConsistencyCheck",
            "PathSolvabilityCheck",
            "GraphEvidenceSufficiencyCheck",
            "GraphRewardGroundingCheck",
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
        assert names[:5] == [
            "ManifestComplianceCheck",
            "GraphConsistencyCheck",
            "PathSolvabilityCheck",
            "GraphEvidenceSufficiencyCheck",
            "GraphRewardGroundingCheck",
        ]
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
            parent_selection_strategy="policy",
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

    def test_status_reports_parent_selection_strategy(self, tier1_manifest, tmp_path):
        runtime = ManagedSnapshotRuntime(
            manifest=tier1_manifest,
            store_dir=tmp_path / "snapshots",
            pool_size=1,
            parent_selection_strategy="policy",
            refill_enabled=False,
        )
        status = runtime.status()
        assert status["parent_selection_strategy"] == "policy"

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

    def test_live_admission_boots_bundle_and_marks_snapshot(
        self,
        tier1_manifest,
        tmp_path,
    ):
        class FakeContainers:
            def __init__(self) -> None:
                self.exec_calls: list[tuple[str, str]] = []
                self.cp_calls: list[tuple[str, str, str]] = []

            async def exec(self, container: str, cmd: str, **kwargs) -> str:
                self.exec_calls.append((container, cmd))
                if "mysql -u root" in cmd:
                    return "ok"
                return "ok"

            async def cp(self, container: str, src: str, dest: str) -> None:
                self.cp_calls.append((container, src, dest))

            async def is_healthy(self, container: str) -> bool:
                return True

        class FakeComposeRunner:
            def __init__(self) -> None:
                self.boot_calls: list[tuple[str, str]] = []
                self.teardown_calls: list[str] = []
                self.containers = FakeContainers()

            def boot(self, *, snapshot_id, artifacts_dir, compose):
                self.boot_calls.append((snapshot_id, str(artifacts_dir)))
                return BootedSnapshotProject(
                    project_name=f"openrange-{snapshot_id}",
                    compose_file=artifacts_dir / "docker-compose.yml",
                    artifacts_dir=artifacts_dir,
                    containers=self.containers,  # type: ignore[arg-type]
                )

            def teardown(self, project):
                self.teardown_calls.append(project.project_name)

        class FakeLiveValidator:
            async def validate(self, snapshot, containers):
                return ValidationResult(
                    passed=True,
                    checks=[CheckResult(name="live_checks", passed=True)],
                    total_time_s=0.0,
                )

        compose_runner = FakeComposeRunner()
        runtime = ManagedSnapshotRuntime(
            manifest=tier1_manifest,
            store_dir=tmp_path / "snapshots",
            pool_size=1,
            refill_enabled=False,
            live_admission_enabled=True,
            compose_runner=compose_runner,  # type: ignore[arg-type]
            live_validator=FakeLiveValidator(),  # type: ignore[arg-type]
        )

        runtime.start()
        try:
            admitted = runtime.acquire_snapshot()
            assert compose_runner.boot_calls
            assert compose_runner.teardown_calls == [f"openrange-{admitted.snapshot_id}"]
            assert admitted.snapshot.topology["live_validated"] is True
            assert admitted.snapshot.compose["x-project-name"] == f"openrange-{admitted.snapshot_id}"
            assert any(dest.endswith("/var/www/portal/index.php") for _, _, dest in compose_runner.containers.cp_calls)
            listing = runtime.list_snapshots()
            assert listing[0]["live_validated"] is True
        finally:
            runtime.stop()

    def test_activate_snapshot_project_uses_unique_episode_project_name(
        self,
        tier1_manifest,
        tmp_path,
    ):
        class FakeContainers:
            def __init__(self) -> None:
                self.exec_calls: list[tuple[str, str]] = []
                self.cp_calls: list[tuple[str, str, str]] = []

            async def exec(self, container: str, cmd: str, **kwargs) -> str:
                self.exec_calls.append((container, cmd))
                return "ok"

            async def cp(self, container: str, src: str, dest: str) -> None:
                self.cp_calls.append((container, src, dest))

            async def is_healthy(self, container: str) -> bool:
                return True

        class FakeComposeRunner:
            def __init__(self) -> None:
                self.boot_calls: list[tuple[str, str, str | None]] = []
                self.teardown_calls: list[str] = []
                self.containers = FakeContainers()

            def project_name_for(self, snapshot_id: str) -> str:
                return f"openrange-{snapshot_id}"[:63]

            def boot(self, *, snapshot_id, artifacts_dir, compose, project_name=None):
                self.boot_calls.append((snapshot_id, str(artifacts_dir), project_name))
                return BootedSnapshotProject(
                    project_name=project_name or f"openrange-{snapshot_id}",
                    compose_file=artifacts_dir / "docker-compose.yml",
                    artifacts_dir=artifacts_dir,
                    containers=self.containers,  # type: ignore[arg-type]
                )

            def teardown(self, project):
                self.teardown_calls.append(project.project_name)

        compose_runner = FakeComposeRunner()
        runtime = ManagedSnapshotRuntime(
            manifest=tier1_manifest,
            store_dir=tmp_path / "snapshots",
            pool_size=1,
            refill_enabled=False,
            compose_runner=compose_runner,  # type: ignore[arg-type]
        )

        runtime.start()
        try:
            admitted = runtime.acquire_snapshot()
            project = runtime.activate_snapshot_project(
                snapshot_id=admitted.snapshot_id,
                snapshot=admitted.snapshot,
                episode_id="episode-123",
            )
            assert compose_runner.boot_calls
            _, artifacts_dir, project_name = compose_runner.boot_calls[0]
            assert artifacts_dir.endswith(f"{admitted.snapshot_id}/artifacts")
            assert project_name == f"openrange-{admitted.snapshot_id}-episode-123"
            runtime.teardown_snapshot_project(project)
            assert compose_runner.teardown_calls == [project.project_name]
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

    def test_reset_activates_clean_runtime_project_and_tears_down_previous(self):
        class FakeRuntime:
            def __init__(self, snapshot: SnapshotSpec) -> None:
                self.snapshot = snapshot
                self.activate_calls: list[tuple[str, str | None]] = []
                self.teardown_calls: list[str] = []
                self.recorded: list[bool] = []

            def acquire_snapshot(self):
                return type(
                    "Admitted",
                    (),
                    {"snapshot_id": "snap-001", "snapshot": self.snapshot},
                )()

            def get_snapshot(self, snapshot_id: str):
                assert snapshot_id == "snap-001"
                return self.acquire_snapshot()

            def activate_snapshot_project(self, *, snapshot_id, snapshot, episode_id=None):
                self.activate_calls.append((snapshot_id, episode_id))
                return BootedSnapshotProject(
                    project_name=f"project-{episode_id}",
                    compose_file=Path("/tmp/docker-compose.yml"),
                    artifacts_dir=Path("/tmp"),
                    containers=ContainerSet(
                        project_name=f"project-{episode_id}",
                        container_ids={"web": "cid-web", "attacker": "cid-attacker", "siem": "cid-siem"},
                    ),
                )

            def teardown_snapshot_project(self, project):
                self.teardown_calls.append(project.project_name)

            def record_episode_result(self, **kwargs):
                self.recorded.append(bool(kwargs.get("completed", False)))

        snapshot = SnapshotSpec(
            topology={"hosts": ["attacker", "siem", "web"]},
            compose={"services": {"attacker": {}, "siem": {}, "web": {}}},
            task={"red_briefing": "Go.", "blue_briefing": "Watch."},
        )
        runtime = FakeRuntime(snapshot)
        env = RangeEnvironment(
            runtime=runtime,  # type: ignore[arg-type]
            docker_available=True,
            execution_mode="docker",
        )

        env._get_docker = lambda: object()  # type: ignore[method-assign]
        apply_calls: list[str] = []
        env._apply_snapshot = lambda snapshot: apply_calls.append("overlay")  # type: ignore[method-assign]
        env._start_npcs = lambda snapshot: None  # type: ignore[method-assign]

        try:
            env.reset(episode_id="ep-1")
            assert runtime.activate_calls == [("snap-001", "ep-1")]
            assert apply_calls == []
            assert env.snapshot is not None
            assert env.snapshot.compose["x-project-name"] == "project-ep-1"
            assert env._container_name("web") == "cid-web"

            env.reset(episode_id="ep-2")
            assert runtime.activate_calls == [("snap-001", "ep-1"), ("snap-001", "ep-2")]
            assert runtime.teardown_calls == ["project-ep-1"]
            assert env.snapshot is not None
            assert env.snapshot.compose["x-project-name"] == "project-ep-2"
        finally:
            env.close()

        assert runtime.teardown_calls == ["project-ep-1", "project-ep-2"]
