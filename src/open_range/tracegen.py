"""First-class branch-native trace generation for training and evaluation."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from open_range.build_config import BuildConfig, DEFAULT_BUILD_CONFIG
from open_range.curriculum import FrontierMutationPolicy, PopulationStats
from open_range.episode_config import EpisodeConfig
from open_range.pipeline import BuildPipeline
from open_range.probe_planner import runtime_action
from open_range.runtime import WitnessDrivenRuntime
from open_range.runtime_types import Action, Observation
from open_range.snapshot import Snapshot
from open_range.store import FileSnapshotStore
from open_range.training_data import (
    TraceCandidate,
    TraceDatasetReport,
    TraceDecisionRow,
    TraceLineage,
    normalize_trace_action,
    render_action_text,
    row_to_sft_record,
    trace_benchmark_tags,
    trace_weaknesses,
)


DEFAULT_RUNTIME_MODES = ("red_only", "blue_only_live", "blue_only_from_prefix")
MAX_MUTATION_ATTEMPTS = 4


class TraceDatasetGenerator:
    """Generate branch-native runtime and sim traces tied to admitted snapshots."""

    def __init__(
        self,
        *,
        build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
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
            base = pipeline.admit(
                pipeline.build(payload, lineage_dir / "rendered-base", self.build_config),
                split=store_split,
            )
            lineage_root = base.world.world_id
            lineage_roots.append(lineage_root)
            dataset_split = _dataset_split(root_idx, roots)
            snapshots = [base]
            current = base
            for mutation_idx in range(1, mutations_per_root + 1):
                admitted_child: Snapshot | None = None
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
                        admitted_child = pipeline.admit_child(
                            child_world,
                            lineage_dir / f"rendered-child-{mutation_idx}-attempt-{attempt_idx}",
                            split=store_split,
                            build_config=self.build_config,
                        )
                    except ValueError:
                        continue
                    break
                if admitted_child is None:
                    break
                current = admitted_child
                snapshots.append(current)

            for snapshot_idx, snapshot in enumerate(snapshots):
                if include_sim:
                    raw_rows.extend(
                        self._episode_rows(
                            snapshot,
                            EpisodeConfig(mode="joint_pool", scheduler_mode="strict_turns"),
                            trace_source="sim",
                            teacher_source="witness_sim",
                            split=dataset_split,
                            lineage_root=lineage_root,
                        )
                    )
                for mode in DEFAULT_RUNTIME_MODES:
                    raw_rows.extend(
                        self._episode_rows(
                            snapshot,
                            _episode_config_for(mode),
                            trace_source="runtime",
                            teacher_source="witness_runtime",
                            split=dataset_split,
                            lineage_root=lineage_root,
                        )
                    )
                if include_joint_pool:
                    raw_rows.extend(
                        self._episode_rows(
                            snapshot,
                            EpisodeConfig(mode="joint_pool", scheduler_mode="strict_turns"),
                            trace_source="runtime",
                            teacher_source="witness_runtime",
                            split=dataset_split,
                            lineage_root=lineage_root,
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
        snapshot: Snapshot,
        episode_config: EpisodeConfig,
        *,
        trace_source: str,
        teacher_source: str,
        split: str,
        lineage_root: str,
    ) -> list[TraceDecisionRow]:
        runtime = WitnessDrivenRuntime()
        runtime.reset(snapshot, episode_config)
        teacher_steps = {
            "red": list(snapshot.witness_bundle.red_witnesses[0].steps),
            "blue": list(snapshot.witness_bundle.blue_witnesses[0].steps),
        }
        teacher_progress = {"red": 0, "blue": 0}
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
            expected = _expected_step(teacher_steps[actor], teacher_progress[actor])
            chosen_action = _teacher_action(snapshot, actor, expected)
            candidates = _candidate_actions(
                snapshot,
                actor=actor,
                observation=decision.obs,
                expected_action=chosen_action,
                remaining_targets=runtime._remaining_red_targets(),
            )
            result = runtime.act(actor, chosen_action)
            if expected is not None and runtime._matches_step(chosen_action, expected, result.stdout):
                teacher_progress[actor] += 1
            rows.append(
                TraceDecisionRow(
                    trace_source=trace_source,  # type: ignore[arg-type]
                    teacher_source=teacher_source,  # type: ignore[arg-type]
                    split=split,  # type: ignore[arg-type]
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
                    candidate_actions=candidates,
                    chosen_action=chosen_action,
                    chosen_action_text=render_action_text(chosen_action),
                    emitted_events=result.emitted_events,
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
    build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
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


def _expected_step(steps, index: int):
    if not steps or index >= len(steps):
        return None
    return steps[index]


def _teacher_action(snapshot: Snapshot, actor: str, expected) -> Action:
    if expected is None:
        return Action(actor_id=actor, role=actor, kind="sleep", payload={})
    action = runtime_action(actor, expected)
    return normalize_trace_action(snapshot, action)


def _candidate_actions(
    snapshot: Snapshot,
    *,
    actor: str,
    observation: Observation,
    expected_action: Action,
    remaining_targets: set[str],
) -> tuple[TraceCandidate, ...]:
    candidates: list[TraceCandidate] = [
        TraceCandidate(
            label="teacher",
            action=expected_action,
            text=render_action_text(expected_action),
            selected=True,
            counterfactual_label="teacher",
        )
    ]
    if actor == "red":
        candidates.extend(_red_alternatives(expected_action))
    else:
        candidates.extend(_blue_alternatives(snapshot, observation, expected_action, remaining_targets))
    return _dedupe_candidates(candidates)


def _red_alternatives(expected_action: Action) -> list[TraceCandidate]:
    target = str(expected_action.payload.get("target", ""))
    alternatives: list[TraceCandidate] = []
    if expected_action.kind == "api":
        root_probe = Action(actor_id="red", role="red", kind="api", payload={"target": target, "path": "/"})
        alternatives.append(
            TraceCandidate(
                label="root_probe",
                action=root_probe,
                text=render_action_text(root_probe),
                counterfactual_label="probe",
            )
        )
        if target != "svc-web":
            web_probe = Action(actor_id="red", role="red", kind="api", payload={"target": "svc-web", "path": "/"})
            alternatives.append(
                TraceCandidate(
                    label="web_probe",
                    action=web_probe,
                    text=render_action_text(web_probe),
                    counterfactual_label="probe",
                )
            )
    else:
        recon_hosts = Action(actor_id="red", role="red", kind="shell", payload={"target": target, "command": "cat /etc/hosts"})
        recon_net = Action(actor_id="red", role="red", kind="shell", payload={"target": target, "command": "ip -br a"})
        alternatives.extend(
            [
                TraceCandidate(
                    label="recon_hosts",
                    action=recon_hosts,
                    text=render_action_text(recon_hosts),
                    counterfactual_label="probe",
                ),
                TraceCandidate(
                    label="recon_net",
                    action=recon_net,
                    text=render_action_text(recon_net),
                    counterfactual_label="probe",
                ),
            ]
        )
    sleep = Action(actor_id="red", role="red", kind="sleep", payload={})
    alternatives.append(
        TraceCandidate(
            label="sleep",
            action=sleep,
            text=render_action_text(sleep),
            counterfactual_label="sleep",
        )
    )
    return alternatives


def _blue_alternatives(
    snapshot: Snapshot,
    observation: Observation,
    expected_action: Action,
    remaining_targets: set[str],
) -> list[TraceCandidate]:
    target = str(expected_action.payload.get("target", ""))
    alternatives: list[TraceCandidate] = []
    wrong_target = _service_not_in(
        snapshot,
        excluded={target, *{event.target_entity for event in observation.visible_events if event.malicious}},
    )
    if expected_action.kind == "submit_finding":
        false_positive = Action(
            actor_id="blue",
            role="blue",
            kind="submit_finding",
            payload={
                "event_type": str(expected_action.payload.get("event_type", "InitialAccess")),
                "target": wrong_target or "svc-email",
            },
        )
        alternatives.append(
            TraceCandidate(
                label="false_positive",
                action=false_positive,
                text=render_action_text(false_positive),
                counterfactual_label="false_positive",
            )
        )
    if expected_action.kind == "control":
        disruptive_target = _service_not_in(snapshot, excluded={target, *remaining_targets}) or wrong_target or target
        disruptive = normalize_trace_action(
            snapshot,
            Action(
                actor_id="blue",
                role="blue",
                kind="control",
                payload={
                    "target": disruptive_target,
                    "action": str(expected_action.payload.get("action", "contain")),
                },
            ),
        )
        alternatives.append(
            TraceCandidate(
                label="over_disruptive",
                action=disruptive,
                text=render_action_text(disruptive),
                counterfactual_label="continuity_damaging",
            )
        )
    if expected_action.kind != "submit_finding" and observation.visible_events:
        visible = next((event for event in observation.visible_events if event.malicious), observation.visible_events[0])
        opportunistic = Action(
            actor_id="blue",
            role="blue",
            kind="submit_finding",
            payload={"event_type": visible.event_type, "target": visible.target_entity},
        )
        alternatives.append(
            TraceCandidate(
                label="detect_now",
                action=opportunistic,
                text=render_action_text(opportunistic),
                counterfactual_label="alternative",
            )
        )
    sleep = Action(actor_id="blue", role="blue", kind="sleep", payload={})
    alternatives.append(
        TraceCandidate(
            label="sleep",
            action=sleep,
            text=render_action_text(sleep),
            counterfactual_label="sleep",
        )
    )
    return alternatives


def _dedupe_candidates(candidates: list[TraceCandidate]) -> tuple[TraceCandidate, ...]:
    seen: set[tuple[str, str]] = set()
    deduped: list[TraceCandidate] = []
    selected_seen = False
    for candidate in candidates:
        token = (candidate.text, json.dumps(candidate.action.model_dump(mode="json"), sort_keys=True))
        if token in seen:
            continue
        seen.add(token)
        if candidate.selected:
            if selected_seen:
                candidate = candidate.model_copy(update={"selected": False})
            selected_seen = True
        deduped.append(candidate)
    return tuple(deduped)


def _service_not_in(snapshot: Snapshot, *, excluded: set[str]) -> str:
    for preferred in ("svc-email", "svc-web", "svc-idp", "svc-fileshare", "svc-db", "svc-siem"):
        if preferred not in excluded and any(service.id == preferred for service in snapshot.world.services):
            return preferred
    for service in snapshot.world.services:
        if service.id not in excluded:
            return service.id
    return ""


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
        return EpisodeConfig(mode="red_only", scheduler_mode="strict_turns", opponent_blue="witness")
    if mode == "blue_only_live":
        return EpisodeConfig(mode="blue_only_live", scheduler_mode="strict_turns", opponent_red="witness")
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


def _parent_stats(snapshot: Snapshot, *, root_idx: int, mutation_idx: int, attempt_idx: int = 1) -> PopulationStats:
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


def _write_role_source_shards(root_dir: Path, rows: list[TraceDecisionRow]) -> dict[str, str]:
    shards: dict[str, str] = {}
    shard_rows: dict[str, list[TraceDecisionRow]] = {}

    def add(name: str, selected: list[TraceDecisionRow]) -> None:
        if selected:
            shard_rows[name] = selected

    for role in ("red", "blue"):
        role_rows = [row for row in rows if row.role == role]
        add(f"raw.{role}.all", role_rows)
        for source in ("runtime", "sim"):
            add(f"raw.{role}.{source}", [row for row in role_rows if row.trace_source == source])

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
                sft_rows[f"sft.{role}.{source}"] = [row_to_sft_record(row) for row in selected]

    for name, payloads in sft_rows.items():
        path = root_dir / f"{name.replace('.', '_')}.jsonl"
        _write_jsonl(path, payloads)
        shards[name] = str(path)

    return dict(sorted(shards.items()))
