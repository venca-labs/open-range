"""Episode-time controls for runtime behavior."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from open_range.audit import AuditConfig


TrainingMode = Literal[
    "red_only", "blue_only_live", "blue_only_from_prefix", "joint_pool"
]
SchedulerMode = Literal["async", "strict_turns"]
GreenProfile = Literal["off", "low", "medium", "high"]
GreenBranchBackend = Literal["none", "scripted", "small_llm", "workflow_orchestrator"]
TelemetryDelayProfile = Literal["none", "low", "medium", "high"]
OpponentController = Literal[
    "none", "scripted", "reference", "frozen_policy", "checkpoint_pool", "replay"
]
PromptMode = Literal["zero_day", "one_day"]
StartState = Literal[
    "clean",
    "prefix_delivery",
    "prefix_click",
    "prefix_credential_theft",
    "prefix_foothold",
    "prefix_lateral_movement",
]
RewardProfile = Literal["terminal_only", "terminal_plus_shaping"]


class EpisodeConfig(BaseModel):
    """Empirical controls for one admitted episode runtime."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: TrainingMode = "joint_pool"
    scheduler_mode: SchedulerMode = "async"
    green_enabled: bool = True
    green_routine_enabled: bool = True
    green_branch_enabled: bool = True
    green_profile: GreenProfile = "medium"
    green_branch_backend: GreenBranchBackend = "scripted"
    prompt_mode: PromptMode = "zero_day"
    telemetry_delay_enabled: bool = True
    telemetry_delay_profile: TelemetryDelayProfile = "medium"
    continuity_enforced: bool = True
    reward_profile: RewardProfile = "terminal_plus_shaping"
    red_milestone_shaping_enabled: bool = True
    blue_detection_shaping_enabled: bool = True
    blue_containment_shaping_enabled: bool = True
    false_positive_penalty_enabled: bool = True
    hallucination_penalty_enabled: bool = True
    opponent_red: OpponentController = "scripted"
    opponent_blue: OpponentController = "scripted"
    audit: AuditConfig = Field(default_factory=AuditConfig)
    start_state: StartState = "clean"
    episode_horizon_minutes: float = Field(default=25.0, gt=0.0)
    continuity_threshold: float = Field(default=0.9, ge=0.0, le=1.0)

    @field_validator("opponent_red", "opponent_blue", mode="before")
    @classmethod
    def _normalize_reference_aliases(cls, value: Any) -> Any:
        return "reference" if value == "witness" else value

    @property
    def controls_red(self) -> bool:
        return self.mode in {"red_only", "joint_pool"}

    @property
    def controls_blue(self) -> bool:
        return self.mode in {"blue_only_live", "blue_only_from_prefix", "joint_pool"}

    @property
    def episode_horizon(self) -> float:
        return float(self.episode_horizon_minutes)

    @property
    def red_shaping_enabled(self) -> bool:
        return (
            self.reward_profile == "terminal_plus_shaping"
            and self.red_milestone_shaping_enabled
        )

    @property
    def blue_detection_shaping(self) -> bool:
        return (
            self.reward_profile == "terminal_plus_shaping"
            and self.blue_detection_shaping_enabled
        )

    @property
    def blue_containment_shaping(self) -> bool:
        return (
            self.reward_profile == "terminal_plus_shaping"
            and self.blue_containment_shaping_enabled
        )


DEFAULT_EPISODE_CONFIG = EpisodeConfig()
