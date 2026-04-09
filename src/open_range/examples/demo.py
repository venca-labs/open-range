"""Run a small deterministic OpenRange episode from a bundled manifest."""

from __future__ import annotations

import argparse
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from open_range.build_config import OFFLINE_BUILD_CONFIG
from open_range.driver import TandemEpisodeDriver
from open_range.episode_config import EpisodeConfig
from open_range.pipeline import BuildPipeline
from open_range.resources import load_bundled_manifest
from open_range.service import OpenRange


from open_range.runtime_types import Action

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
        pipeline = BuildPipeline()
        
        if not quiet:
            print(f"\n[Phase 1] Building Enterprise Candidate from '{manifest or _default_manifest_name()}'...")
        
        # Build candidate world
        candidate = pipeline.build(payload, root / "rendered", OFFLINE_BUILD_CONFIG)
        
        if not quiet:
            print(f"         ✅ Built World: {candidate.world.world_id}")
            print(f"[Phase 2] Admitting Candidate into Immutable Snapshot pool...")
        
        # Admit candidate -> public snapshot
        snapshot = pipeline.admit(candidate, split="train")

        if not quiet:
            print(f"         ✅ Snapshot frozen: {snapshot.snapshot_id}")
            print(f"[Phase 3] Initializing the OpenRange Engine (Live Episode Engine)...")
            
        service = OpenRange()
        
        # Reset runtime onto target state
        state = service.reset(snapshot.snapshot_id, EpisodeConfig(
            mode="joint_pool", 
            scheduler_mode="strict_turns"
        ))

        if not quiet:
            print(f"\n[Phase 4] Executing Red vs Blue Bounds:")
            
        loop_runs = 0
        while not service.state().done and loop_runs < 4:
            decision = service.next_decision()
            # Actor from next_decision is lowercase role string ('red', 'blue', 'green')
            actor = decision.actor
            
            # Formulate automatic demo response payload
            action_kind = "api" if actor == "blue" else "shell"
            action_msg = "Isolate host" if actor == "blue" else "Execute exploratory payload"
            
            if not quiet:
                print(f"  > [{actor.upper()}] executes `{action_kind}` at time {decision.obs.sim_time}: {action_msg}")
            
            # Formally route action via OpenRange Service API constraint
            action_obj = Action(actor_id=actor, role=actor, kind=action_kind, payload={"raw": action_msg})
            service.act(actor, action_obj)
            loop_runs += 1

        score = service.score()
        events = service.runtime.export_events()
        service.close()

        result = {
            "world_id": candidate.world.world_id,
            "snapshot_id": snapshot.snapshot_id,
            "winner": "blue" if score.blue_reward > score.red_reward else "red",
            "done": True,
            "turn_count": loop_runs,
            "green_events": sum(1 for event in events if event.actor == "green"),
            "red_reward": score.red_reward,
            "blue_reward": score.blue_reward,
        }
        
        if not quiet:
            print(f"\n[Phase 5] Episode Terminated.")
            print(f"  -> Winner: {result['winner'].upper()}")
            print(f"  -> Red Reward: {result['red_reward']}")
            print(f"  -> Blue Reward: {result['blue_reward']}")
            print(f"  -> Green Noise Events Tracked: {result['green_events']}\n")
            print("To run deeper experiments, read `docs/how-an-episode-works.md`!\n")
            
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
