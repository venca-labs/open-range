"""Shared runtime-facing types."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


ActorRole = Literal["red", "blue", "green"]
ExternalRole = Literal["red", "blue"]
ActionKind = Literal[
    "shell",
    "api",
    "mail",
    "chat",
    "document_share",
    "voice",
    "control",
    "submit_finding",
    "sleep",
]
EventType = Literal[
    "InitialAccess",
    "CredentialObtained",
    "UnauthorizedCredentialUse",
    "PrivilegeEscalation",
    "CrossZoneTraversal",
    "SensitiveAssetRead",
    "PersistenceEstablished",
    "DetectionAlertRaised",
    "ContainmentApplied",
    "PatchApplied",
    "RecoveryCompleted",
    "ServiceDegraded",
    "BenignUserAction",
    "SuspiciousActionObserved",
    "ChatReceived",
    "DocumentShared",
    "PhishingVoiceCall",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Action(_StrictModel):
    actor_id: str = Field(min_length=1)
    role: ActorRole
    kind: ActionKind
    payload: dict[str, Any] = Field(default_factory=dict)
    timeout_s: float = Field(default=30.0, ge=0.0)


class RuntimeEvent(_StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    event_type: EventType
    actor: ActorRole
    time: float = Field(ge=0.0)
    source_entity: str
    target_entity: str
    malicious: bool
    observability_surfaces: tuple[str, ...] = Field(default_factory=tuple)
    linked_objective_predicates: tuple[str, ...] = Field(default_factory=tuple)
    suspicious: bool = False
    suspicious_reasons: tuple[str, ...] = Field(default_factory=tuple)


class ServiceHealth(_StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    service_id: str
    health: float = Field(ge=0.0, le=1.0)


class Observation(_StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    actor_id: str
    sim_time: float = Field(ge=0.0)
    stdout: str = ""
    stderr: str = ""
    visible_events: tuple[RuntimeEvent, ...] = Field(default_factory=tuple)
    alerts_delta: tuple[RuntimeEvent, ...] = Field(default_factory=tuple)
    inbox_delta: tuple[str, ...] = Field(default_factory=tuple)
    service_health: tuple[ServiceHealth, ...] = Field(default_factory=tuple)
    reward_delta: float = 0.0
    done: bool = False


class Decision(_StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    decision_id: str
    actor: ExternalRole
    obs: Observation


class ActionResult(_StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Action
    sim_time: float = Field(ge=0.0)
    stdout: str = ""
    stderr: str = ""
    emitted_events: tuple[RuntimeEvent, ...] = Field(default_factory=tuple)
    reward_delta: float = 0.0
    done: bool = False


class ActorSessionState(_StrictModel):
    session_id: str
    actor_id: str
    role: ExternalRole
    action_count: int = 0
    observation_count: int = 0


class EpisodeState(_StrictModel):
    snapshot_id: str
    episode_id: str
    sim_time: float = 0.0
    done: bool = False
    winner: Literal["red", "blue", "timeout", "failure", ""] = ""
    terminal_reason: str = ""
    continuity: float = Field(default=1.0, ge=0.0, le=1.0)
    service_health: dict[str, float] = Field(default_factory=dict)
    red_objectives_satisfied: tuple[str, ...] = Field(default_factory=tuple)
    blue_objectives_satisfied: tuple[str, ...] = Field(default_factory=tuple)
    controls_red: bool = True
    controls_blue: bool = True
    next_actor: ExternalRole | Literal[""] = ""
    decision_count: int = 0
    red_session: ActorSessionState | None = None
    blue_session: ActorSessionState | None = None


class AuditActionRecord(_StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    actor: ExternalRole
    sim_time: float = Field(ge=0.0)
    action_kind: ActionKind
    target: str = ""
    command: str = ""
    fingerprint: str = Field(min_length=1)
    fingerprint_prefix: str = Field(min_length=1)
    matched_patterns: tuple[str, ...] = Field(default_factory=tuple)
    emitted_event_ids: tuple[str, ...] = Field(default_factory=tuple)


class ActionDiversitySummary(_StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    actor: ExternalRole
    total_actions: int = Field(ge=0)
    unique_fingerprints: int = Field(ge=0)
    diversity_score: float = Field(ge=0.0, le=1.0)
    dominant_fingerprint: str = ""
    dominant_fingerprint_prefix: str = ""
    dominant_share: float = Field(default=0.0, ge=0.0, le=1.0)
    collapse_warning: bool = False


class IntegritySample(_StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    service_id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    probe_ok: bool = True
    exists: bool
    digest: str = ""


class IntegrityDelta(_StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    service_id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    before_exists: bool
    after_exists: bool
    before_digest: str = ""
    after_digest: str = ""


class IntegrityServiceSummary(_StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    service_id: str = Field(min_length=1)
    available: bool = False
    checked_paths: int = Field(default=0, ge=0)
    changed_paths: tuple[IntegrityDelta, ...] = Field(default_factory=tuple)
    unchanged_paths: int = Field(default=0, ge=0)


class BinaryIntegritySummary(_StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = False
    available: bool = False
    checked_services: tuple[str, ...] = Field(default_factory=tuple)
    available_services: tuple[str, ...] = Field(default_factory=tuple)
    unavailable_services: tuple[str, ...] = Field(default_factory=tuple)
    checked_paths: int = Field(default=0, ge=0)
    changed_services: tuple[str, ...] = Field(default_factory=tuple)
    unchanged_services: tuple[str, ...] = Field(default_factory=tuple)
    changed_paths: tuple[IntegrityDelta, ...] = Field(default_factory=tuple)
    service_summaries: tuple[IntegrityServiceSummary, ...] = Field(
        default_factory=tuple
    )


class EpisodeAudit(_StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action_count: int = Field(default=0, ge=0)
    unique_fingerprints: int = Field(default=0, ge=0)
    action_diversity_score: float = Field(default=1.0, ge=0.0, le=1.0)
    collapse_warning: bool = False
    suspicious_actions: tuple[AuditActionRecord, ...] = Field(default_factory=tuple)
    suspicious_event_ids: tuple[str, ...] = Field(default_factory=tuple)
    role_diversity: tuple[ActionDiversitySummary, ...] = Field(default_factory=tuple)
    binary_integrity: BinaryIntegritySummary = Field(
        default_factory=BinaryIntegritySummary
    )


class EpisodeScore(_StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    snapshot_id: str
    episode_id: str
    done: bool
    winner: Literal["red", "blue", "timeout", "failure", ""]
    terminal_reason: str
    sim_time: float
    continuity: float
    red_reward: float
    blue_reward: float
    red_objectives_satisfied: tuple[str, ...]
    blue_objectives_satisfied: tuple[str, ...]
    event_count: int
    audit: EpisodeAudit | None = None


EpisodeHandle = EpisodeState
