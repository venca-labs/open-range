#!/usr/bin/env python3
"""Run a bounded red-only model rollout probe against admitted snapshots.

This is intentionally scoped:
- red only
- reference-conditioned candidate action set
- model scores candidate continuations instead of free-form action generation

It is a bridge from tiny SFT adapters to runtime evaluation, not the final
policy-learning stack.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from open_range._runtime_store import hydrate_runtime_snapshot
from open_range.build_config import OFFLINE_BUILD_CONFIG
from open_range.curriculum import FrontierMutationPolicy, PopulationStats
from open_range.decision_surface import candidate_actions, teacher_action
from open_range.episode_config import EpisodeConfig
from open_range.pipeline import BuildPipeline
from open_range.resources import load_bundled_manifest
from open_range.runtime import ReferenceDrivenRuntime
from open_range.snapshot import RuntimeSnapshot
from open_range.store import FileSnapshotStore
from open_range.training_data import (
    TraceCandidate,
    TraceLineage,
    build_decision_prompt,
    render_candidate_completion,
)

DEFAULT_BASE_MODEL = "HuggingFaceTB/SmolLM2-360M-Instruct"
DEFAULT_ADAPTER = "/tmp/openrange-sft-tiny-split/adapter"


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


def teacher_pick_rate(picks: list[dict[str, Any]]) -> float:
    if not picks:
        return 0.0
    return sum(1 for pick in picks if pick.get("chosen_label") == "teacher") / len(
        picks
    )


def build_prompt(
    snapshot: RuntimeSnapshot, observation, candidates, decision_index: int
) -> str:
    return (
        "<system>\n"
        "You are the red operator in OpenRange. "
        "Choose exactly one candidate action that best advances the validated attack path.\n"
        "</system>\n\n"
        "<user>\n"
        + build_decision_prompt(
            snapshot_id=snapshot.snapshot_id,
            world_id=snapshot.world.world_id,
            world_hash=snapshot.world_hash,
            lineage=TraceLineage(
                root_world_id=snapshot.parent_world_id or snapshot.world.world_id,
                generation=snapshot.world.lineage.generation,
                parent_world_id=snapshot.parent_world_id,
                mutation_ops=tuple(snapshot.world.lineage.mutation_ops),
            ),
            mode="red_only",
            start_state="clean",
            role="red",
            decision_index=decision_index,
            observation=observation,
            candidate_actions=candidates,
            weaknesses=(),
            benchmark_tags=(),
            trace_source="runtime",
            teacher_source="reference_runtime",
            split="test",
            prompt_mode="zero_day",
        )
        + "\n</user>\n\n<assistant>\n"
    )


def red_candidates(
    runtime: ReferenceDrivenRuntime, snapshot: RuntimeSnapshot, observation
):
    expected = runtime.reference_step("red")
    return candidate_actions(
        snapshot,
        actor="red",
        observation=observation,
        expected_action=teacher_action(snapshot, "red", expected),
        remaining_targets=runtime.remaining_red_targets(),
    )


def score_candidates(
    model: Any, tokenizer: Any, prompt: str, candidates
) -> list[tuple[TraceCandidate, float]]:
    import torch

    prompt_ids = tokenizer(prompt, return_tensors="pt").input_ids.to(model.device)
    scored: list[tuple[TraceCandidate, float]] = []
    for candidate in candidates:
        completion = render_candidate_completion(candidate)
        full_ids = tokenizer(prompt + completion, return_tensors="pt").input_ids.to(
            model.device
        )
        labels = full_ids.clone()
        labels[:, : prompt_ids.shape[1]] = -100
        with torch.no_grad():
            loss = model(input_ids=full_ids, labels=labels).loss
        scored.append((candidate, float(loss.item())))
    scored.sort(key=lambda item: item[1])
    return scored


def evaluate_model_rollouts(
    *,
    adapter: str | Path = DEFAULT_ADAPTER,
    base_model: str = DEFAULT_BASE_MODEL,
    manifest: str | Path | None = None,
    mutations: int = 3,
    max_turns: int = 8,
    quiet: bool = False,
) -> dict[str, Any]:
    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    payload = _load_manifest(manifest)
    tokenizer = AutoTokenizer.from_pretrained(str(adapter), use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    dtype = (
        torch.bfloat16
        if torch.cuda.is_available() and torch.cuda.is_bf16_supported()
        else (torch.float16 if torch.cuda.is_available() else torch.float32)
    )
    base = AutoModelForCausalLM.from_pretrained(
        base_model,
        dtype=dtype,
        device_map="auto" if torch.cuda.is_available() else None,
    )
    model = PeftModel.from_pretrained(base, str(adapter))
    model.eval()

    mutation_policy = FrontierMutationPolicy()
    with TemporaryDirectory(prefix="openrange-model-rollout-") as tmp:
        root = Path(tmp)
        store = FileSnapshotStore(root / "snapshots")
        pipeline = BuildPipeline(store=store)

        snapshots: list[RuntimeSnapshot] = []
        current = hydrate_runtime_snapshot(
            store,
            pipeline.admit(
                pipeline.build(payload, root / "rendered-base", OFFLINE_BUILD_CONFIG),
                split="train",
            ),
        )
        snapshots.append(current)
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
            child_world = mutation_policy.mutate(
                current.world, parent_stats=parent_stats
            )
            current = hydrate_runtime_snapshot(
                store,
                pipeline.admit_child(
                    child_world,
                    root / f"rendered-child-{idx}",
                    split="eval",
                    build_config=OFFLINE_BUILD_CONFIG,
                ),
            )
            snapshots.append(current)

        reports: list[dict[str, Any]] = []
        exact_picks = 0
        total_picks = 0
        red_wins = 0
        total_pairs = 0

        for snapshot in snapshots:
            pair_reports: list[dict[str, Any]] = []
            for attack_trace_index in range(
                max(1, len(snapshot.reference_bundle.reference_attack_traces))
            ):
                total_pairs += 1
                runtime = ReferenceDrivenRuntime()
                runtime.reset(
                    snapshot,
                    EpisodeConfig(
                        mode="red_only",
                        scheduler_mode="strict_turns",
                        opponent_blue="scripted",
                    ),
                    reference_attack_index=attack_trace_index,
                )
                picks: list[dict[str, Any]] = []
                turns = 0
                while not runtime.state().done and turns < max_turns:
                    try:
                        decision = runtime.next_decision()
                    except RuntimeError:
                        if runtime.state().done:
                            break
                        raise
                    expected = runtime.reference_step("red")
                    candidates = candidate_actions(
                        snapshot,
                        actor="red",
                        observation=decision.obs,
                        expected_action=teacher_action(snapshot, "red", expected),
                        remaining_targets=runtime.remaining_red_targets(),
                    )
                    prompt = build_prompt(snapshot, decision.obs, candidates, turns)
                    ranked = score_candidates(model, tokenizer, prompt, candidates)
                    chosen, loss = ranked[0]
                    runtime.act("red", chosen.action)
                    turns += 1
                    total_picks += 1
                    if chosen.label == "teacher":
                        exact_picks += 1
                    picks.append(
                        {
                            "chosen_label": chosen.label,
                            "chosen_text": chosen.text,
                            "chosen_loss": loss,
                            "candidates": [
                                {"label": cand.label, "loss": cand_loss}
                                for cand, cand_loss in ranked
                            ],
                        }
                    )

                score = runtime.score()
                if score.winner == "red":
                    red_wins += 1
                truncated = not runtime.state().done
                pair_reports.append(
                    {
                        "attack_trace_index": attack_trace_index,
                        "done": score.done,
                        "truncated": truncated,
                        "winner": score.winner,
                        "terminal_reason": score.terminal_reason
                        or ("max_turns_reached" if truncated else ""),
                        "red_reward": score.red_reward,
                        "blue_reward": score.blue_reward,
                        "turns": turns,
                        "exact_pick_rate": teacher_pick_rate(picks),
                        "picks": picks,
                    }
                )
            reports.append(
                {
                    "snapshot_id": snapshot.snapshot_id,
                    "world_id": snapshot.world.world_id,
                    "red_win_rate": sum(
                        1 for report in pair_reports if report["winner"] == "red"
                    )
                    / len(pair_reports)
                    if pair_reports
                    else 0.0,
                    "exact_pick_rate": sum(
                        report["exact_pick_rate"] for report in pair_reports
                    )
                    / len(pair_reports)
                    if pair_reports
                    else 0.0,
                    "pairs": pair_reports,
                    "weaknesses": [
                        f"{weak.family}:{weak.kind}@{weak.target}"
                        for weak in snapshot.world.weaknesses
                    ],
                }
            )

        result = {
            "manifest_source": str(manifest)
            if manifest is not None
            else _default_manifest_name(),
            "adapter": str(adapter),
            "base_model": base_model,
            "snapshot_count": len(reports),
            "red_win_rate": red_wins / total_pairs if total_pairs else 0.0,
            "exact_pick_rate": exact_picks / total_picks if total_picks else 0.0,
            "reports": reports,
        }
        if not quiet:
            print(f"manifest={result['manifest_source']}")
            print(f"snapshots={result['snapshot_count']}")
            print(f"red_win_rate={result['red_win_rate']:.3f}")
            print(f"exact_pick_rate={result['exact_pick_rate']:.3f}")
        return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a bounded model-in-the-loop OpenRange rollout probe."
    )
    parser.add_argument(
        "--adapter", default=DEFAULT_ADAPTER, help="Path to a saved LoRA adapter."
    )
    parser.add_argument(
        "--base-model", default=DEFAULT_BASE_MODEL, help="Base model id or local path."
    )
    parser.add_argument(
        "--manifest",
        default=None,
        help="Bundled manifest name or path to strict manifest YAML.",
    )
    parser.add_argument("--mutations", type=int, default=3)
    parser.add_argument("--max-turns", type=int, default=8)
    parser.add_argument("--out", default="/tmp/openrange-model-rollout.json")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = evaluate_model_rollouts(
        adapter=args.adapter,
        base_model=args.base_model,
        manifest=args.manifest,
        mutations=args.mutations,
        max_turns=args.max_turns,
        quiet=False,
    )
    out_path = Path(args.out)
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"report={out_path}")


if __name__ == "__main__":
    main()
