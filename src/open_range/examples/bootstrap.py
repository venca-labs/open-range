"""Run a small bootstrap-trace example against an admitted snapshot.

This example preserves the old "warmup trace" idea, but keeps it outside the
core environment contract. It uses the optional sim plane to generate a cheap
deterministic bootstrap trace, then optionally compares that to a real runtime
episode over the same admitted snapshot.
"""

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
from open_range.runtime import ReferenceDrivenRuntime
from open_range.sim import ReferenceSimPlane
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


def _scripted_agents(snapshot):
    attack_idx = snapshot.seed % max(
        1, len(snapshot.reference_bundle.reference_attack_traces)
    )
    defense_idx = snapshot.seed % max(
        1, len(snapshot.reference_bundle.reference_defense_traces)
    )
    red_agent = ScriptedRuntimeAgent(
        trace_actions(snapshot, "red", trace_index=attack_idx)[:2]
    )
    blue_agent = ScriptedRuntimeAgent(
        trace_actions(snapshot, "blue", trace_index=defense_idx)[1:3]
    )
    return red_agent, blue_agent


def run_bootstrap_demo(
    *,
    manifest: str | Path | None = None,
    seed: int = 7,
    quiet: bool = False,
) -> dict[str, Any]:
    payload = _load_manifest(manifest)

    with TemporaryDirectory(prefix="openrange-bootstrap-") as tmp:
        root = Path(tmp)
        store = FileSnapshotStore(root / "snapshots")
        pipeline = BuildPipeline(store=store)
        candidate = pipeline.build(payload, root / "rendered", OFFLINE_BUILD_CONFIG)
        snapshot = hydrate_runtime_snapshot(
            store, pipeline.admit(candidate, split="train")
        )

        sim_plane = ReferenceSimPlane()
        bootstrap_trace = sim_plane.generate_bootstrap_trace(
            snapshot, episode_seed=seed
        )

        runtime = ReferenceDrivenRuntime()
        driver = TandemEpisodeDriver(runtime)
        red_agent, blue_agent = _scripted_agents(snapshot)
        episode = driver.run_episode(
            snapshot,
            red_agent=red_agent,
            blue_agent=blue_agent,
            episode_config=EpisodeConfig(
                mode="joint_pool", scheduler_mode="strict_turns"
            ),
        )
        score = runtime.score()

        result = {
            "world_id": snapshot.world.world_id,
            "snapshot_id": snapshot.snapshot_id,
            "bootstrap_turn_count": len(bootstrap_trace.turns),
            "bootstrap_winner": bootstrap_trace.winner,
            "bootstrap_roles": sorted({turn.role for turn in bootstrap_trace.turns}),
            "runtime_turn_count": len(episode.turns),
            "runtime_winner": episode.winner,
            "runtime_done": episode.done,
            "runtime_red_reward": score.red_reward,
            "runtime_blue_reward": score.blue_reward,
        }
        if not quiet:
            print(f"world={result['world_id']}")
            print(f"snapshot={result['snapshot_id']}")
            print(
                "bootstrap="
                f"winner={result['bootstrap_winner']} turns={result['bootstrap_turn_count']} "
                f"roles={','.join(result['bootstrap_roles'])}"
            )
            print(
                "runtime="
                f"winner={result['runtime_winner']} done={result['runtime_done']} "
                f"turns={result['runtime_turn_count']}"
            )
            print(
                f"red_reward={result['runtime_red_reward']} "
                f"blue_reward={result['runtime_blue_reward']}"
            )
        return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a deterministic OpenRange bootstrap-trace example.",
    )
    parser.add_argument(
        "--manifest",
        default=None,
        help="Bundled manifest name or path to a strict manifest YAML.",
    )
    parser.add_argument("--seed", type=int, default=7, help="Bootstrap trace seed.")
    args = parser.parse_args()
    run_bootstrap_demo(manifest=args.manifest, seed=args.seed, quiet=False)


if __name__ == "__main__":
    main()
