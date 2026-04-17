from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace

from open_range.config import EpisodeConfig
from open_range.contracts.runtime import Action
from open_range.render.live import ExecResult
from open_range.sdk import OpenRange
from open_range.store import BuildPipeline, FileSnapshotStore, hydrate_runtime_snapshot
from tests.support import OFFLINE_BUILD_CONFIG, manifest_payload


def _manifest_payload() -> dict:
    return manifest_payload()


def _service_and_snapshots(tmp_path: Path):
    store = FileSnapshotStore(tmp_path / "snapshots")
    pipeline = BuildPipeline(store=store)
    train_snapshot = hydrate_runtime_snapshot(
        store,
        pipeline.admit(
            pipeline.build(
                _manifest_payload(), tmp_path / "train-render", OFFLINE_BUILD_CONFIG
            ),
            split="train",
        ),
    )

    eval_payload = _manifest_payload()
    eval_payload["seed"] = 2048
    eval_snapshot = hydrate_runtime_snapshot(
        store,
        pipeline.admit(
            pipeline.build(
                eval_payload, tmp_path / "eval-render", OFFLINE_BUILD_CONFIG
            ),
            split="eval",
        ),
    )
    return OpenRange(store=store), train_snapshot, eval_snapshot


def test_service_reset_loads_snapshot_and_primes_first_decision(tmp_path: Path):
    service, train_snapshot, _eval_snapshot = _service_and_snapshots(tmp_path)

    state = service.reset(
        train_snapshot.snapshot_id,
        EpisodeConfig(mode="joint_pool", green_enabled=False),
    )

    assert state.snapshot_id == train_snapshot.snapshot_id
    assert service.active_snapshot_id == train_snapshot.snapshot_id
    assert state.next_actor == "red"
    assert state.controls_red is True
    assert state.controls_blue is True
    assert state.execution_mode == "offline"
    assert service.execution_mode == "offline"


def test_service_can_sample_held_out_eval_pool(tmp_path: Path):
    service, _train_snapshot, eval_snapshot = _service_and_snapshots(tmp_path)

    state = service.reset(
        None,
        EpisodeConfig(mode="joint_pool", green_enabled=False),
        split="eval",
        strategy="latest",
        sample_seed=11,
    )

    assert state.snapshot_id == eval_snapshot.snapshot_id
    assert service.active_snapshot_id == eval_snapshot.snapshot_id


def test_service_latest_snapshot_uses_store_timestamp_not_name(tmp_path: Path):
    store = FileSnapshotStore(tmp_path / "snapshots")
    pipeline = BuildPipeline(store=store)

    first_payload = _manifest_payload()
    first_payload["seed"] = 4096
    first_snapshot = pipeline.admit(
        pipeline.build(first_payload, tmp_path / "eval-render-a", OFFLINE_BUILD_CONFIG),
        split="eval",
    )
    time.sleep(0.01)
    second_payload = _manifest_payload()
    second_payload["seed"] = 1024
    second_snapshot = pipeline.admit(
        pipeline.build(
            second_payload, tmp_path / "eval-render-b", OFFLINE_BUILD_CONFIG
        ),
        split="eval",
    )

    service = OpenRange(store=store)
    state = service.reset(
        None,
        EpisodeConfig(mode="joint_pool", green_enabled=False),
        split="eval",
        strategy="latest",
    )

    assert first_snapshot.snapshot_id > second_snapshot.snapshot_id
    assert state.snapshot_id == second_snapshot.snapshot_id


def test_service_proxies_runtime_decisions_and_actions(tmp_path: Path):
    service, train_snapshot, _eval_snapshot = _service_and_snapshots(tmp_path)
    service.reset(
        train_snapshot.snapshot_id,
        EpisodeConfig(mode="joint_pool", green_enabled=False),
    )

    decision = service.next_decision()
    red_step = train_snapshot.reference_bundle.reference_attack_traces[0].steps[0]
    result = service.act(
        "red",
        Action(
            actor_id="red",
            role="red",
            kind=red_step.kind,
            payload={"target": red_step.target, **red_step.payload},
        ),
    )

    assert decision.actor == "red"
    assert decision.obs.actor_id == "red"
    assert result.sim_time == 0.0
    assert service.state().next_actor == ""


def test_service_boots_and_tears_down_live_release(tmp_path: Path):
    store = FileSnapshotStore(tmp_path / "snapshots")
    pipeline = BuildPipeline(store=store)
    snapshot = hydrate_runtime_snapshot(
        store,
        pipeline.admit(
            pipeline.build(
                _manifest_payload(), tmp_path / "rendered", OFFLINE_BUILD_CONFIG
            ),
            split="train",
        ),
    )
    calls: list[str] = []

    class FakePods:
        def __init__(self, pod_ids):
            self.pod_ids = pod_ids

        async def is_healthy(self, service: str) -> bool:
            return service in self.pod_ids

        async def exec(
            self, service: str, cmd: str, timeout: float = 30.0
        ) -> ExecResult:
            del timeout
            return ExecResult(stdout=f"{service}:{cmd}", stderr="", exit_code=0)

    class FakeBackend:
        def boot(self, *, snapshot_id: str, artifacts_dir: Path):
            calls.append(f"boot:{snapshot_id}:{artifacts_dir.name}")
            pod_ids = {
                service.id: f"ns/{service.id}-pod"
                for service in snapshot.world.services
            }
            pod_ids["sandbox-red"] = "ns/sandbox-red-pod"
            pod_ids["sandbox-blue"] = "ns/sandbox-blue-pod"
            for persona in snapshot.world.green_personas:
                pod_ids[f"sandbox-green-{persona.id.replace('_', '-').lower()}"] = (
                    f"ns/{persona.id}-pod"
                )
            return SimpleNamespace(
                release_name=f"or-{snapshot_id}", pods=FakePods(pod_ids)
            )

        def teardown(self, release) -> None:
            calls.append(f"down:{release.release_name}")

    service = OpenRange(store=store, live_backend=FakeBackend())
    service.reset(
        snapshot.snapshot_id, EpisodeConfig(mode="joint_pool", green_enabled=False)
    )
    assert service.live_release is not None
    assert service.execution_mode == "live"
    assert service.state().execution_mode == "live"
    service.close()

    assert calls[0].startswith("boot:")
    assert calls[-1].startswith("down:")


def test_service_reset_can_require_live_runtime(tmp_path: Path):
    service, train_snapshot, _eval_snapshot = _service_and_snapshots(tmp_path)

    try:
        service.reset(
            train_snapshot.snapshot_id,
            EpisodeConfig(mode="joint_pool", green_enabled=False),
            require_live=True,
        )
    except RuntimeError as exc:
        assert "live runtime required" in str(exc)
    else:
        raise AssertionError(
            "expected reset(require_live=True) to fail without live backend"
        )
