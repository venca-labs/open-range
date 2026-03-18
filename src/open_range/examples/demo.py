"""Run a small deterministic OpenRange episode from a bundled manifest."""

from __future__ import annotations

import argparse
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from open_range._runtime_store import hydrate_runtime_snapshot
from open_range.build_config import OFFLINE_BUILD_CONFIG
from open_range.decision_surface import trace_actions
from open_range.driver import ScriptedRuntimeAgent, TandemEpisodeDriver
from open_range.episode_config import EpisodeConfig
from open_range.pipeline import BuildPipeline
from open_range.resources import load_bundled_manifest
from open_range.service import OpenRange
from open_range.store import FileSnapshotStore


def _default_manifest_name() -> str:
    return "tier1_basic.yaml"


def _load_manifest(source: str | Path | None) -> dict[str, Any]:
    if source is None:
        return load_bundled_manifest(_default_manifest_name())
    path = Path(source)
    if path.exists():
        import yaml

        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"expected a YAML mapping in {path}")
        return payload
    return load_bundled_manifest(str(source))


def run_demo(
    *,
    manifest: str | Path | None = None,
    seed: int = 7,
    quiet: bool = False,
) -> dict[str, Any]:
    payload = _load_manifest(manifest)

    with TemporaryDirectory(prefix="openrange-demo-") as tmp:
        root = Path(tmp)
        store = FileSnapshotStore(root / "snapshots")
        pipeline = BuildPipeline(store=store)
        candidate = pipeline.build(payload, root / "rendered", OFFLINE_BUILD_CONFIG)
        snapshot = hydrate_runtime_snapshot(
            store, pipeline.admit(candidate, split="train")
        )

        attack_idx = seed % max(
            1, len(snapshot.reference_bundle.reference_attack_traces)
        )
        defense_idx = seed % max(
            1, len(snapshot.reference_bundle.reference_defense_traces)
        )
        red_agent = ScriptedRuntimeAgent(
            trace_actions(snapshot, "red", trace_index=attack_idx)[:2]
        )
        blue_agent = ScriptedRuntimeAgent(
            trace_actions(snapshot, "blue", trace_index=defense_idx)[1:3]
        )

        service = OpenRange(store=store)
        driver = TandemEpisodeDriver(service.runtime)
        episode = driver.run_episode(
            snapshot,
            red_agent=red_agent,
            blue_agent=blue_agent,
            episode_config=EpisodeConfig(
                mode="joint_pool", scheduler_mode="strict_turns"
            ),
        )
        score = service.score()
        events = service.runtime.export_events()
        service.close()

        result = {
            "world_id": candidate.world.world_id,
            "snapshot_id": snapshot.snapshot_id,
            "winner": episode.winner,
            "done": episode.done,
            "turn_count": len(episode.turns),
            "green_events": sum(1 for event in events if event.actor == "green"),
            "red_reward": score.red_reward,
            "blue_reward": score.blue_reward,
        }
        if not quiet:
            print(f"world={result['world_id']}")
            print(f"snapshot={result['snapshot_id']}")
            print(
                f"winner={result['winner']} done={result['done']} turns={result['turn_count']}"
            )
            print(
                f"red_reward={result['red_reward']} blue_reward={result['blue_reward']}"
            )
        return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a deterministic OpenRange demo episode."
    )
    parser.add_argument(
        "--manifest",
        default=None,
        help="Bundled manifest name or path to a strict manifest YAML.",
    )
    parser.add_argument("--seed", type=int, default=7, help="Episode seed.")
    args = parser.parse_args()
    run_demo(manifest=args.manifest, seed=args.seed, quiet=False)


if __name__ == "__main__":
    main()
