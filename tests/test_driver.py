from __future__ import annotations

from pathlib import Path

from open_range._runtime_store import hydrate_runtime_snapshot
from open_range.admit import LocalAdmissionController
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.driver import ScriptedRuntimeAgent, TandemEpisodeDriver
from open_range.episode_config import EpisodeConfig
from open_range.render import EnterpriseSaaSKindRenderer
from open_range.runtime import ReferenceDrivenRuntime
from open_range.runtime_types import Action
from open_range.store import FileSnapshotStore
from open_range.synth import EnterpriseSaaSWorldSynthesizer
from open_range.weaknesses import CatalogWeaknessSeeder
from tests.support import OFFLINE_BUILD_CONFIG, manifest_payload


def _manifest_payload() -> dict:
    return manifest_payload()


def _snapshot(tmp_path: Path):
    world = CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(_manifest_payload())
    )
    synth = EnterpriseSaaSWorldSynthesizer().synthesize(world, tmp_path / "synth")
    artifacts = EnterpriseSaaSKindRenderer().render(world, synth, tmp_path / "rendered")
    reference_bundle, report = LocalAdmissionController(mode="fail_fast").admit(
        world, artifacts, OFFLINE_BUILD_CONFIG
    )
    store = FileSnapshotStore(tmp_path / "snapshots")
    return hydrate_runtime_snapshot(
        store, store.create(world, artifacts, reference_bundle, report, synth=synth)
    )


def test_tandem_driver_runs_joint_pool_episode(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    runtime = ReferenceDrivenRuntime()
    driver = TandemEpisodeDriver(runtime)

    red_trace = snapshot.reference_bundle.reference_attack_traces[0].steps
    blue_target = red_trace[1].target
    red_agent = ScriptedRuntimeAgent(
        [
            Action(
                actor_id="red",
                role="red",
                kind=red_trace[0].kind,
                payload={"target": red_trace[0].target, **red_trace[0].payload},
            ),
            Action(actor_id="red", role="red", kind="sleep", payload={}),
        ]
    )
    blue_agent = ScriptedRuntimeAgent(
        [
            Action(
                actor_id="blue",
                role="blue",
                kind="submit_finding",
                payload={"event_type": "InitialAccess", "target": red_trace[0].target},
            ),
            Action(
                actor_id="blue",
                role="blue",
                kind="control",
                payload={"target": blue_target, "action": "contain"},
            ),
        ]
    )

    episode = driver.run_episode(
        snapshot,
        red_agent=red_agent,
        blue_agent=blue_agent,
        episode_config=EpisodeConfig(mode="joint_pool", green_enabled=False),
    )

    assert episode.done is True
    assert episode.winner == "blue"
    assert [turn.role for turn in episode.turns] == ["red", "blue", "red", "blue"]
    assert all(turn.observation.actor_id == turn.role for turn in episode.turns)


def test_driver_can_run_blue_only_prefix_episode(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    runtime = ReferenceDrivenRuntime()
    driver = TandemEpisodeDriver(runtime)

    red_trace = snapshot.reference_bundle.reference_attack_traces[0].steps
    red_agent = ScriptedRuntimeAgent(
        [Action(actor_id="red", role="red", kind="sleep", payload={})]
    )
    blue_agent = ScriptedRuntimeAgent(
        [
            Action(
                actor_id="blue",
                role="blue",
                kind="submit_finding",
                payload={"event_type": "InitialAccess", "target": red_trace[0].target},
            ),
            Action(
                actor_id="blue",
                role="blue",
                kind="control",
                payload={
                    "target": snapshot.reference_bundle.reference_defense_traces[0]
                    .steps[2]
                    .target,
                    "action": "contain",
                },
            ),
        ]
    )

    episode = driver.run_episode(
        snapshot,
        red_agent=red_agent,
        blue_agent=blue_agent,
        episode_config=EpisodeConfig(
            mode="blue_only_from_prefix",
            start_state="prefix_foothold",
            green_enabled=False,
        ),
    )

    assert episode.done is True
    assert all(turn.role == "blue" for turn in episode.turns)
