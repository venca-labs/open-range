"""admission, witness, and validator reporting models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


WitnessRole = Literal["red", "blue"]
ProbeKind = Literal["smoke", "shortcut", "determinism", "necessity"]
ReportMode = Literal["fail_fast", "analysis"]


class WitnessAction(_StrictModel):
    actor: WitnessRole
    kind: str = Field(min_length=1)
    target: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)


class WitnessTrace(_StrictModel):
    id: str = Field(min_length=1)
    role: WitnessRole
    objective_ids: tuple[str, ...] = Field(default_factory=tuple)
    expected_events: tuple[str, ...] = Field(default_factory=tuple)
    steps: tuple[WitnessAction, ...] = Field(default_factory=tuple)


class ProbeSpec(_StrictModel):
    id: str = Field(min_length=1)
    kind: ProbeKind
    description: str = Field(min_length=1)
    command: str = ""
    expected: dict[str, Any] = Field(default_factory=dict)


class ValidatorCheckReport(_StrictModel):
    name: str = Field(min_length=1)
    passed: bool
    advisory: bool = False
    duration_s: float = Field(default=0.0, ge=0.0)
    details: dict[str, Any] = Field(default_factory=dict)
    error: str = ""


class ValidatorStageReport(_StrictModel):
    name: str = Field(min_length=1)
    passed: bool
    duration_s: float = Field(default=0.0, ge=0.0)
    checks: tuple[ValidatorCheckReport, ...] = Field(default_factory=tuple)


class ValidatorReport(_StrictModel):
    admitted: bool
    graph_ok: bool = False
    boot_ok: bool = False
    workflow_ok: bool = False
    telemetry_ok: bool = False
    red_witness_ok: bool = False
    blue_witness_ok: bool = False
    necessity_ok: bool = False
    shortcut_risk: Literal["low", "medium", "high"] = "high"
    determinism_score: float = Field(default=0.0, ge=0.0, le=1.0)
    flakiness: float = Field(default=1.0, ge=0.0, le=1.0)
    red_path_depth: int = Field(default=0, ge=0)
    red_alt_path_count: int = Field(default=0, ge=0)
    blue_signal_points: int = Field(default=0, ge=0)
    business_continuity_score: float = Field(default=0.0, ge=0.0, le=1.0)
    benchmark_tags_covered: tuple[str, ...] = Field(default_factory=tuple)
    rejection_reasons: tuple[str, ...] = Field(default_factory=tuple)
    mode: ReportMode = "fail_fast"
    world_id: str = Field(min_length=1)
    world_hash: str = Field(min_length=1)
    summary: str = ""
    build_logs: tuple[str, ...] = Field(default_factory=tuple)
    health_info: dict[str, Any] = Field(default_factory=dict)
    stages: tuple[ValidatorStageReport, ...] = Field(default_factory=tuple)


class WitnessBundle(_StrictModel):
    red_witnesses: tuple[WitnessTrace, ...] = Field(default_factory=tuple)
    blue_witnesses: tuple[WitnessTrace, ...] = Field(default_factory=tuple)
    smoke_tests: tuple[ProbeSpec, ...] = Field(default_factory=tuple)
    shortcut_probes: tuple[ProbeSpec, ...] = Field(default_factory=tuple)
    determinism_probes: tuple[ProbeSpec, ...] = Field(default_factory=tuple)
    necessity_probes: tuple[ProbeSpec, ...] = Field(default_factory=tuple)
