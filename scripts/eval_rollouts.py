#!/usr/bin/env python3
"""Evaluate deterministic runtime rollouts over admitted snapshots and mutations."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from open_range import (
    BuildPipeline,
    EpisodeConfig,
    FileSnapshotStore,
    FrontierMutationPolicy,
    PopulationStats,
    ScriptedRuntimeAgent,
    WitnessSimPlane,
    WitnessDrivenRuntime,
    load_bundled_manifest,
)
from open_range.probe_planner import runtime_action
from open_range.runtime_types import Action, EpisodeScore
from open_range.snapshot import Snapshot


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


def _actions_for(snapshot: Snapshot, actor: str) -> list[Action]:
    trace = snapshot.witness_bundle.red_witnesses[0] if actor == "red" else snapshot.witness_bundle.blue_witnesses[0]
    actions = [runtime_action(actor, step) for step in trace.steps]
    if actions:
        return actions
    return [Action(actor_id=actor, role=actor, kind="sleep", payload={})]


def _scripted_agent(snapshot: Snapshot, actor: str) -> ScriptedRuntimeAgent:
    return ScriptedRuntimeAgent(_actions_for(snapshot, actor))


def _run_mode(snapshot: Snapshot, episode_config: EpisodeConfig) -> dict[str, Any]:
    runtime = WitnessDrivenRuntime()
    red_agent = _scripted_agent(snapshot, "red")
    blue_agent = _scripted_agent(snapshot, "blue")
    state = runtime.reset(snapshot, episode_config)
    if state.controls_red:
        red_agent.reset(f"snapshot={snapshot.snapshot_id}", "red")
    if state.controls_blue:
        blue_agent.reset(f"snapshot={snapshot.snapshot_id}", "blue")

    turns = 0
    while not runtime.state().done:
        try:
            decision = runtime.next_decision()
        except RuntimeError:
            if runtime.state().done:
                break
            raise
        agent = red_agent if decision.actor == "red" else blue_agent
        runtime.act(decision.actor, agent.act(decision.obs))
        turns += 1

    score = runtime.score()
    return _score_payload(score, turns=turns, mode=episode_config.mode)


def _score_payload(score: EpisodeScore, *, turns: int, mode: str) -> dict[str, Any]:
    return {
        "mode": mode,
        "winner": score.winner,
        "done": score.done,
        "terminal_reason": score.terminal_reason,
        "sim_time": score.sim_time,
        "turns": turns,
        "continuity": score.continuity,
        "red_reward": score.red_reward,
        "blue_reward": score.blue_reward,
        "red_objectives": list(score.red_objectives_satisfied),
        "blue_objectives": list(score.blue_objectives_satisfied),
        "event_count": score.event_count,
    }


def _population_stats(snapshot: Snapshot, episodes: list[dict[str, Any]], *, split: str, novelty: float) -> PopulationStats:
    total = len(episodes)
    red_wins = sum(1 for episode in episodes if episode["winner"] == "red")
    blue_wins = sum(1 for episode in episodes if episode["winner"] == "blue")
    flake = 0.0 if len({episode["winner"] for episode in episodes}) <= 1 else 0.5
    avg_turns = sum(episode["turns"] for episode in episodes) / total if total else 0.0
    return PopulationStats(
        snapshot_id=snapshot.snapshot_id,
        world_id=snapshot.world.world_id,
        split=split,
        episodes=total,
        red_win_rate=red_wins / total if total else 0.0,
        blue_win_rate=blue_wins / total if total else 0.0,
        avg_ticks=avg_turns,
        flake_rate=flake,
        novelty=novelty,
        blue_signal_points=snapshot.validator_report.blue_signal_points,
    )


def evaluate_rollouts(
    *,
    manifest: str | Path | None = None,
    mutations: int = 3,
    quiet: bool = False,
) -> dict[str, Any]:
    payload = _load_manifest(manifest)
    sim_plane = WitnessSimPlane()
    mutation_policy = FrontierMutationPolicy()

    mode_plan = (
        EpisodeConfig(mode="joint_pool", scheduler_mode="strict_turns"),
        EpisodeConfig(mode="red_only", scheduler_mode="strict_turns", opponent_blue="witness"),
        EpisodeConfig(mode="blue_only_live", scheduler_mode="strict_turns", opponent_red="witness"),
        EpisodeConfig(
            mode="blue_only_from_prefix",
            scheduler_mode="strict_turns",
            opponent_red="none",
            start_state="prefix_foothold",
        ),
    )

    with TemporaryDirectory(prefix="openrange-rollout-eval-") as tmp:
        root = Path(tmp)
        store = FileSnapshotStore(root / "snapshots")
        pipeline = BuildPipeline(store=store)
        snapshots: list[Snapshot] = []

        base = pipeline.admit(pipeline.build(payload, root / "rendered-base"), split="train")
        snapshots.append(base)

        current = base
        for idx in range(1, mutations + 1):
            parent_stats = PopulationStats(
                snapshot_id=current.snapshot_id,
                world_id=current.world.world_id,
                split="train",
                episodes=4,
                red_win_rate=0.25 if idx % 2 else 0.65,
                blue_win_rate=0.75 if idx % 2 else 0.35,
                avg_ticks=6.0 + idx,
                flake_rate=0.0,
                novelty=min(0.5 + idx * 0.1, 1.0),
                blue_signal_points=current.validator_report.blue_signal_points,
            )
            child_world = mutation_policy.mutate(current.world, parent_stats=parent_stats)
            current = pipeline.admit_child(child_world, root / f"rendered-child-{idx}", split="eval")
            snapshots.append(current)

        snapshot_reports: list[dict[str, Any]] = []
        population: list[PopulationStats] = []
        for idx, snapshot in enumerate(snapshots):
            bootstrap = sim_plane.generate_bootstrap_trace(snapshot, episode_seed=idx + 7)
            episodes = [_run_mode(snapshot, config) for config in mode_plan]
            split = "train" if idx == 0 else "eval"
            report = {
                "snapshot_id": snapshot.snapshot_id,
                "world_id": snapshot.world.world_id,
                "split": split,
                "seed": snapshot.seed,
                "parent_world_id": snapshot.parent_world_id,
                "weaknesses": [
                    {
                        "id": weakness.id,
                        "family": weakness.family,
                        "kind": weakness.kind,
                        "target": weakness.target,
                        "benchmark_tags": list(weakness.benchmark_tags),
                    }
                    for weakness in snapshot.world.weaknesses
                ],
                "validator": {
                    "admitted": snapshot.validator_report.admitted,
                    "red_path_depth": snapshot.validator_report.red_path_depth,
                    "blue_signal_points": snapshot.validator_report.blue_signal_points,
                    "determinism_score": snapshot.validator_report.determinism_score,
                    "shortcut_risk": snapshot.validator_report.shortcut_risk,
                },
                "bootstrap": {
                    "winner": bootstrap.winner,
                    "turns": len(bootstrap.turns),
                    "roles": sorted({turn.role for turn in bootstrap.turns}),
                },
                "episodes": episodes,
            }
            snapshot_reports.append(report)
            population.append(_population_stats(snapshot, episodes, split=split, novelty=min(0.5 + idx * 0.1, 1.0)))

        aggregate: dict[str, dict[str, Any]] = {}
        for mode in {episode["mode"] for report in snapshot_reports for episode in report["episodes"]}:
            matching = [episode for report in snapshot_reports for episode in report["episodes"] if episode["mode"] == mode]
            total = len(matching)
            aggregate[mode] = {
                "episodes": total,
                "red_win_rate": sum(1 for episode in matching if episode["winner"] == "red") / total if total else 0.0,
                "blue_win_rate": sum(1 for episode in matching if episode["winner"] == "blue") / total if total else 0.0,
                "avg_red_reward": sum(episode["red_reward"] for episode in matching) / total if total else 0.0,
                "avg_blue_reward": sum(episode["blue_reward"] for episode in matching) / total if total else 0.0,
                "avg_continuity": sum(episode["continuity"] for episode in matching) / total if total else 0.0,
                "avg_turns": sum(episode["turns"] for episode in matching) / total if total else 0.0,
            }

        result = {
            "manifest_source": str(manifest) if manifest is not None else _default_manifest_name(),
            "snapshot_count": len(snapshot_reports),
            "population": [entry.model_dump(mode="json") for entry in population],
            "snapshots": snapshot_reports,
            "aggregate": aggregate,
        }
        if not quiet:
            print(f"manifest={result['manifest_source']}")
            print(f"snapshots={result['snapshot_count']}")
            for mode, metrics in sorted(aggregate.items()):
                print(
                    f"{mode}: blue_win_rate={metrics['blue_win_rate']:.3f} "
                    f"red_win_rate={metrics['red_win_rate']:.3f} "
                    f"avg_turns={metrics['avg_turns']:.2f}"
                )
        return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run held-out OpenRange rollout evaluation.")
    parser.add_argument("--manifest", default=None, help="Bundled manifest name or path to strict manifest YAML.")
    parser.add_argument("--mutations", type=int, default=3, help="How many sequential admitted mutations to evaluate.")
    parser.add_argument("--out", default="/tmp/openrange-rollout-eval.json", help="Where to write the JSON report.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = evaluate_rollouts(manifest=args.manifest, mutations=args.mutations, quiet=False)
    out_path = Path(args.out)
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"report={out_path}")


if __name__ == "__main__":
    main()
