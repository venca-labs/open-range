"""Branch-native trace row schema."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from open_range.config import BuildConfig, EpisodeConfig
from open_range.objectives import StandardAttackObjective
from open_range.runtime_types import Action, Observation, RuntimeEvent

TraceSource = Literal["runtime", "sim"]
TraceSplit = Literal["train", "val", "test"]
ActionSource = Literal["reference_runtime", "reference_sim"]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TraceLineage(_StrictModel):
    root_world_id: str = Field(min_length=1)
    generation: int = Field(ge=0)
    parent_world_id: str | None = None
    mutation_ops: tuple[str, ...] = Field(default_factory=tuple)


class TraceWeakness(_StrictModel):
    weakness_id: str = Field(min_length=1)
    family: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    target: str = Field(min_length=1)
    benchmark_tags: tuple[str, ...] = Field(default_factory=tuple)
    objective_tags: tuple[StandardAttackObjective, ...] = Field(default_factory=tuple)


class TraceDecisionRow(_StrictModel):
    trace_source: TraceSource
    action_source: ActionSource
    split: TraceSplit
    snapshot_id: str = Field(min_length=1)
    world_id: str = Field(min_length=1)
    world_hash: str = Field(min_length=1)
    lineage: TraceLineage
    episode_id: str = Field(min_length=1)
    mode: str = Field(min_length=1)
    start_state: str = Field(min_length=1)
    role: Literal["red", "blue"]
    decision_index: int = Field(ge=0)
    observation: Observation
    chosen_action: Action
    chosen_action_text: str
    result_stdout: str = ""
    result_stderr: str = ""
    emitted_events: tuple[RuntimeEvent, ...] = Field(default_factory=tuple)
    grounded_effects: tuple[str, ...] = Field(default_factory=tuple)
    mitigation_effects: tuple[str, ...] = Field(default_factory=tuple)
    reward_delta: float = 0.0
    winner: str = ""
    terminal_reason: str = ""
    done: bool = False
    build_config: BuildConfig
    episode_config: EpisodeConfig
    weaknesses: tuple[TraceWeakness, ...] = Field(default_factory=tuple)
    benchmark_tags: tuple[str, ...] = Field(default_factory=tuple)


class TraceDatasetReport(_StrictModel):
    manifest_source: str = Field(min_length=1)
    raw_path: str = Field(min_length=1)
    decision_sft_path: str = Field(min_length=1)
    shard_paths: dict[str, str] = Field(default_factory=dict)
    roots: int = Field(ge=1)
    mutations_per_root: int = Field(ge=0)
    rows: int = Field(ge=0)
    counts_by_source: dict[str, int] = Field(default_factory=dict)
    counts_by_role: dict[str, int] = Field(default_factory=dict)
    counts_by_mode: dict[str, int] = Field(default_factory=dict)
    counts_by_split: dict[str, int] = Field(default_factory=dict)
    lineage_roots: tuple[str, ...] = Field(default_factory=tuple)
