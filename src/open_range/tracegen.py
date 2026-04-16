"""First-class branch-native trace generation for training and evaluation."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from open_range._decision_sft import row_to_sft_record
from open_range._reference_replay import (
    action_for_reference_step,
    reference_trace_pairs,
)
from open_range._runtime_store import hydrate_runtime_snapshot
from open_range.build_config import OFFLINE_BUILD_CONFIG, BuildConfig
from open_range.curriculum import FrontierMutationPolicy, PopulationStats
from open_range.episode_config import EpisodeConfig
from open_range.pipeline import BuildPipeline
from open_range.runtime import OpenRangeRuntime
from open_range.snapshot import RuntimeSnapshot
from open_range.store import FileSnapshotStore
from open_range.training_data import (
    ActionSource,
    TraceDatasetReport,
    TraceDecisionRow,
    TraceLineage,
    TraceSource,
    TraceSplit,
    grounded_effects_for_result,
    mitigation_effects_for_result,
    public_trace_action,
    render_action_text,
    trace_benchmark_tags,
    trace_weaknesses,
)

DEFAULT_RUNTIME_MODES = ("red_only", "blue_only_live", "blue_only_from_prefix")
MAX_MUTATION_ATTEMPTS = 4
DEFAULT_TRACE_BUILD_CONFIG = OFFLINE_BUILD_CONFIG


class TraceDatasetGenerator:
    """Generate branch-native runtime and sim traces tied to admitted snapshots."""

    def __init__(
        self,
        *,
        build_config: BuildConfig = DEFAULT_TRACE_BUILD_CONFIG,
        mutation_policy: FrontierMutationPolicy | None = None,
        pipeline: BuildPipeline | None = None,
    ) -> None:
        self.build_config = build_config
        self.mutation_policy = mutation_policy or FrontierMutationPolicy()
        self.pipeline = pipeline

    def generate(
        self,
        manifest: dict[str, Any],
        outdir: str | Path,
        *,
        manifest_source: str = "inline",
        roots: int = 1,
        mutations_per_root: int = 3,
        include_sim: bool = True,
        include_joint_pool: bool = False,
    ) -> TraceDatasetReport:
        if roots < 1:
            raise ValueError("roots must be >= 1")
        if mutations_per_root < 0:
            raise ValueError("mutations_per_root must be >= 0")

        root_dir = Path(outdir)
        root_dir.mkdir(parents=True, exist_ok=True)
        store = FileSnapshotStore(root_dir / "snapshots")
        pipeline = self.pipeline or BuildPipeline(store=store)

        raw_rows: list[TraceDecisionRow] = []
        lineage_roots: list[str] = []
        for root_idx in range(roots):
            payload = _seed_manifest_copy(manifest, root_idx)
            lineage_dir = root_dir / f"root-{root_idx:02d}"
            lineage_dir.mkdir(parents=True, exist_ok=True)
            store_split = "train" if root_idx == 0 else "eval"
            base_public = pipeline.admit(
                pipeline.build(
                    payload, lineage_dir / "rendered-base", self.build_config
                ),
                split=store_split,
            )
            base = hydrate_runtime_snapshot(store, base_public)
            lineage_root = base.world.world_id
            lineage_roots.append(lineage_root)
            dataset_split = _dataset_split(root_idx, roots)
            snapshots = [base]
            current = base
            for mutation_idx in range(1, mutations_per_root + 1):
                admitted_child: RuntimeSnapshot | None = None
                for attempt_idx in range(1, MAX_MUTATION_ATTEMPTS + 1):
                    child_world = self.mutation_policy.mutate(
                        current.world,
                        parent_stats=_parent_stats(
                            current,
                            root_idx=root_idx,
                            mutation_idx=mutation_idx,
                            attempt_idx=attempt_idx,
                        ),
                    )
                    try:
                        child_public = pipeline.admit_child(
                            child_world,
                            lineage_dir
                            / f"rendered-child-{mutation_idx}-attempt-{attempt_idx}",
                            split=store_split,
                            build_config=self.build_config,
                        )
                        admitted_child = hydrate_runtime_snapshot(store, child_public)
                    except ValueError:
                        continue
                    break
                if admitted_child is None:
                    break
                current = admitted_child
                snapshots.append(current)

            for snapshot_idx, snapshot in enumerate(snapshots):
                if include_sim:
                    for attack_idx, defense_idx in reference_trace_pairs(
                        snapshot, "joint_pool"
                    ):
                        raw_rows.extend(
                            self._episode_rows(
                                snapshot,
                                EpisodeConfig(
                                    mode="joint_pool", scheduler_mode="strict_turns"
                                ),
                                trace_source="sim",
                                action_source="reference_sim",
                                split=dataset_split,
                                lineage_root=lineage_root,
                                attack_trace_index=attack_idx,
                                defense_trace_index=defense_idx,
                            )
                        )
                for mode in DEFAULT_RUNTIME_MODES:
                    for attack_idx, defense_idx in reference_trace_pairs(
                        snapshot, mode
                    ):
                        raw_rows.extend(
                            self._episode_rows(
                                snapshot,
                                _episode_config_for(mode),
                                trace_source="runtime",
                                action_source="reference_runtime",
                                split=dataset_split,
                                lineage_root=lineage_root,
                                attack_trace_index=attack_idx,
                                defense_trace_index=defense_idx,
                            )
                        )
                if include_joint_pool:
                    for attack_idx, defense_idx in reference_trace_pairs(
                        snapshot, "joint_pool"
                    ):
                        raw_rows.extend(
                            self._episode_rows(
                                snapshot,
                                EpisodeConfig(
                                    mode="joint_pool", scheduler_mode="strict_turns"
                                ),
                                trace_source="runtime",
                                action_source="reference_runtime",
                                split=dataset_split,
                                lineage_root=lineage_root,
                                attack_trace_index=attack_idx,
                                defense_trace_index=defense_idx,
                            )
                        )

        raw_path = root_dir / "trace_rows.jsonl"
        decision_sft_path = root_dir / "decision_sft.jsonl"
        raw_payloads = [row.model_dump(mode="json") for row in raw_rows]
        decision_payloads = [row_to_sft_record(row) for row in raw_rows]
        _write_jsonl(raw_path, raw_payloads)
        _write_jsonl(decision_sft_path, decision_payloads)
        shard_paths = _write_role_source_shards(root_dir, raw_rows)

        return TraceDatasetReport(
            manifest_source=manifest_source,
            raw_path=str(raw_path),
            decision_sft_path=str(decision_sft_path),
            shard_paths=shard_paths,
            roots=roots,
            mutations_per_root=mutations_per_root,
            rows=len(raw_rows),
            counts_by_source=_counts(raw_rows, key=lambda row: row.trace_source),
            counts_by_role=_counts(raw_rows, key=lambda row: row.role),
            counts_by_mode=_counts(raw_rows, key=lambda row: row.mode),
            counts_by_split=_counts(raw_rows, key=lambda row: row.split),
            lineage_roots=tuple(lineage_roots),
        )

    def _episode_rows(
        self,
        snapshot: RuntimeSnapshot,
        episode_config: EpisodeConfig,
        *,
        trace_source: TraceSource,
        action_source: ActionSource,
        split: TraceSplit,
        lineage_root: str,
        attack_trace_index: int = 0,
        defense_trace_index: int = 0,
    ) -> list[TraceDecisionRow]:
        runtime = OpenRangeRuntime()
        runtime.reset(
            snapshot,
            episode_config,
            reference_attack_index=attack_trace_index,
            reference_defense_index=defense_trace_index,
        )
        rows: list[TraceDecisionRow] = []
        decision_index = 0

        while not runtime.state().done:
            try:
                decision = runtime.next_decision()
            except RuntimeError:
                if runtime.state().done:
                    break
                raise
            actor = decision.actor
            expected = runtime.reference_step(actor)
            chosen_action = action_for_reference_step(snapshot, actor, expected)
            result = runtime.act(actor, chosen_action)
            public_action = public_trace_action(chosen_action)
            rows.append(
                TraceDecisionRow(
                    trace_source=trace_source,
                    action_source=action_source,
                    split=split,
                    snapshot_id=snapshot.snapshot_id,
                    world_id=snapshot.world.world_id,
                    world_hash=snapshot.world_hash,
                    lineage=TraceLineage(
                        root_world_id=lineage_root,
                        generation=snapshot.world.lineage.generation,
                        parent_world_id=snapshot.parent_world_id,
                        mutation_ops=tuple(snapshot.world.lineage.mutation_ops),
                    ),
                    episode_id=runtime.state().episode_id,
                    mode=episode_config.mode,
                    start_state=episode_config.start_state,
                    role=actor,
                    decision_index=decision_index,
                    observation=decision.obs,
                    chosen_action=public_action,
                    chosen_action_text=render_action_text(public_action),
                    result_stdout=result.stdout,
                    result_stderr=result.stderr,
                    emitted_events=result.emitted_events,
                    grounded_effects=grounded_effects_for_result(
                        stdout=result.stdout,
                        emitted_events=result.emitted_events,
                    ),
                    mitigation_effects=mitigation_effects_for_result(
                        action=public_action,
                        stdout=result.stdout,
                        emitted_events=result.emitted_events,
                    ),
                    reward_delta=result.reward_delta,
                    winner="",
                    terminal_reason="",
                    done=False,
                    build_config=self.build_config,
                    episode_config=episode_config,
                    weaknesses=trace_weaknesses(snapshot),
                    benchmark_tags=trace_benchmark_tags(snapshot),
                )
            )
            decision_index += 1

        score = runtime.score()
        return [
            row.model_copy(
                update={
                    "winner": score.winner,
                    "terminal_reason": score.terminal_reason,
                    "done": score.done,
                }
            )
            for row in rows
        ]


def generate_trace_dataset(
    manifest: dict[str, Any],
    outdir: str | Path,
    *,
    manifest_source: str = "inline",
    build_config: BuildConfig = DEFAULT_TRACE_BUILD_CONFIG,
    roots: int = 1,
    mutations_per_root: int = 3,
    include_sim: bool = True,
    include_joint_pool: bool = False,
) -> TraceDatasetReport:
    return TraceDatasetGenerator(build_config=build_config).generate(
        manifest,
        outdir,
        manifest_source=manifest_source,
        roots=roots,
        mutations_per_root=mutations_per_root,
        include_sim=include_sim,
        include_joint_pool=include_joint_pool,
    )


def _dataset_split(root_idx: int, roots: int) -> str:
    if roots <= 1:
        return "train"
    if roots == 2:
        return "train" if root_idx == 0 else "test"
    train_cut = max(1, int(round(roots * 0.7)))
    val_cut = max(train_cut + 1, int(round(roots * 0.85)))
    if root_idx < train_cut:
        return "train"
    if root_idx < val_cut:
        return "val"
    return "test"


def _episode_config_for(mode: str) -> EpisodeConfig:
    if mode == "red_only":
        return EpisodeConfig(
            mode="red_only", scheduler_mode="strict_turns", opponent_blue="reference"
        )
    if mode == "blue_only_live":
        return EpisodeConfig(
            mode="blue_only_live",
            scheduler_mode="strict_turns",
            opponent_red="reference",
        )
    if mode == "blue_only_from_prefix":
        return EpisodeConfig(
            mode="blue_only_from_prefix",
            scheduler_mode="strict_turns",
            opponent_red="none",
            start_state="prefix_foothold",
        )
    return EpisodeConfig(mode=mode, scheduler_mode="strict_turns")


def _seed_manifest_copy(manifest: dict[str, Any], root_idx: int) -> dict[str, Any]:
    payload = deepcopy(manifest)
    seed = int(payload.get("seed", 0))
    payload["seed"] = seed + root_idx
    return payload


def _parent_stats(
    snapshot: RuntimeSnapshot, *, root_idx: int, mutation_idx: int, attempt_idx: int = 1
) -> PopulationStats:
    offset = mutation_idx + attempt_idx - 1
    parity = (root_idx + offset) % 2
    return PopulationStats(
        snapshot_id=snapshot.snapshot_id,
        world_id=snapshot.world.world_id,
        split="train",
        episodes=4 + offset,
        red_win_rate=0.25 if parity else 0.65,
        blue_win_rate=0.75 if parity else 0.35,
        avg_ticks=6.0 + offset,
        flake_rate=0.0,
        novelty=min(0.5 + 0.1 * (offset + root_idx), 1.0),
        blue_signal_points=snapshot.validator_report.blue_signal_points,
    )


def _counts(rows: list[TraceDecisionRow], *, key) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        token = str(key(row))
        counts[token] = counts.get(token, 0) + 1
    return counts


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def _write_role_source_shards(
    root_dir: Path, rows: list[TraceDecisionRow]
) -> dict[str, str]:
    shards: dict[str, str] = {}
    shard_rows: dict[str, list[TraceDecisionRow]] = {}

    def add(name: str, selected: list[TraceDecisionRow]) -> None:
        if selected:
            shard_rows[name] = selected

    for role in ("red", "blue"):
        role_rows = [row for row in rows if row.role == role]
        add(f"raw.{role}.all", role_rows)
        for source in ("runtime", "sim"):
            add(
                f"raw.{role}.{source}",
                [row for row in role_rows if row.trace_source == source],
            )
        for action_source in ("reference_runtime", "reference_sim"):
            add(
                f"raw.{role}.source.{action_source}",
                [row for row in role_rows if row.action_source == action_source],
            )

    for name, selected in shard_rows.items():
        payloads = [row.model_dump(mode="json") for row in selected]
        path = root_dir / f"{name.replace('.', '_')}.jsonl"
        _write_jsonl(path, payloads)
        shards[name] = str(path)

    sft_rows: dict[str, list[dict[str, Any]]] = {}
    for role in ("red", "blue"):
        role_rows = [row for row in rows if row.role == role]
        if role_rows:
            sft_rows[f"sft.{role}.all"] = [row_to_sft_record(row) for row in role_rows]
        for source in ("runtime", "sim"):
            selected = [row for row in role_rows if row.trace_source == source]
            if selected:
                sft_rows[f"sft.{role}.{source}"] = [
                    row_to_sft_record(row) for row in selected
                ]
        for action_source in ("reference_runtime", "reference_sim"):
            selected = [row for row in role_rows if row.action_source == action_source]
            if selected:
                sft_rows[f"sft.{role}.source.{action_source}"] = [
                    row_to_sft_record(row) for row in selected
                ]

    for name, payloads in sft_rows.items():
        path = root_dir / f"{name.replace('.', '_')}.jsonl"
        _write_jsonl(path, payloads)
        shards[name] = str(path)

    return dict(sorted(shards.items()))
