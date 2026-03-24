"""Strict public manifest types.

The manifest defines the legal family of business worlds. It is intentionally
public and must not encode a golden path, literal exploit steps, or flag paths.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, PositiveInt, model_validator

from open_range.objectives import PUBLIC_OBJECTIVE_PREDICATE_NAMES
from open_range.predicate_expr import parse_predicate


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


WeaknessFamily = Literal[
    "code_web",
    "config_identity",
    "secret_exposure",
    "workflow_abuse",
    "telemetry_blindspot",
]

CodeFlawKind = Literal[
    "sql_injection",
    "broken_authorization",
    "auth_bypass",
    "path_traversal",
    "ssrf",
    "command_injection",
]
ConfigIdentityKind = Literal[
    "weak_password",
    "default_credential",
    "overbroad_service_account",
    "admin_surface_exposed",
    "trust_edge_misconfig",
]
SecretExposureKind = Literal[
    "env_file_leak",
    "credential_in_share",
    "backup_leak",
    "token_in_email",
    "hardcoded_app_secret",
]
WorkflowAbuseKind = Literal[
    "helpdesk_reset_bypass",
    "approval_chain_bypass",
    "document_share_abuse",
    "phishing_credential_capture",
    "internal_request_impersonation",
]
TelemetryBlindspotKind = Literal[
    "missing_web_logs",
    "missing_idp_logs",
    "delayed_siem_ingest",
    "unmonitored_admin_action",
    "silent_mail_rule",
]
SupportedWeaknessKind = Literal[
    "sql_injection",
    "broken_authorization",
    "auth_bypass",
    "path_traversal",
    "ssrf",
    "command_injection",
    "weak_password",
    "default_credential",
    "overbroad_service_account",
    "admin_surface_exposed",
    "trust_edge_misconfig",
    "env_file_leak",
    "credential_in_share",
    "backup_leak",
    "token_in_email",
    "hardcoded_app_secret",
    "helpdesk_reset_bypass",
    "approval_chain_bypass",
    "document_share_abuse",
    "phishing_credential_capture",
    "internal_request_impersonation",
    "missing_web_logs",
    "missing_idp_logs",
    "delayed_siem_ingest",
    "unmonitored_admin_action",
    "silent_mail_rule",
]

NoiseDensity = Literal["low", "medium", "high"]
AssetClass = Literal["crown_jewel", "sensitive", "operational"]
WeaknessTargetKind = Literal["service", "workflow", "asset", "credential", "telemetry"]
Probability = Annotated[float, Field(ge=0.0, le=1.0)]

WEAKNESS_KIND_CATALOG: dict[WeaknessFamily, tuple[str, ...]] = {
    "code_web": (
        "sql_injection",
        "broken_authorization",
        "auth_bypass",
        "path_traversal",
        "ssrf",
        "command_injection",
    ),
    "config_identity": (
        "weak_password",
        "default_credential",
        "overbroad_service_account",
        "admin_surface_exposed",
        "trust_edge_misconfig",
    ),
    "secret_exposure": (
        "env_file_leak",
        "credential_in_share",
        "backup_leak",
        "token_in_email",
        "hardcoded_app_secret",
    ),
    "workflow_abuse": (
        "helpdesk_reset_bypass",
        "approval_chain_bypass",
        "document_share_abuse",
        "phishing_credential_capture",
        "internal_request_impersonation",
    ),
    "telemetry_blindspot": (
        "missing_web_logs",
        "missing_idp_logs",
        "delayed_siem_ingest",
        "unmonitored_admin_action",
        "silent_mail_rule",
    ),
}


class BusinessSpec(_StrictModel):
    archetype: str = Field(min_length=1)
    workflows: tuple[str, ...] = Field(default_factory=tuple, min_length=1)


class TopologySpec(_StrictModel):
    zones: tuple[str, ...] = Field(default_factory=tuple, min_length=1)
    services: tuple[str, ...] = Field(default_factory=tuple, min_length=1)


class UserRoleSpec(_StrictModel):
    roles: dict[str, PositiveInt] = Field(default_factory=dict, min_length=1)


class NPCProfileSpec(_StrictModel):
    awareness: float | None = Field(default=None, ge=0.0, le=1.0)
    susceptibility: dict[str, Probability] = Field(default_factory=dict)
    routine: tuple[str, ...] | None = None


class ManifestAsset(_StrictModel):
    id: str = Field(min_length=1)
    asset_class: AssetClass = Field(alias="class")


class ObjectivePredicate(_StrictModel):
    predicate: str = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_predicate_name(self) -> "ObjectivePredicate":
        expr = parse_predicate(self.predicate)
        if expr.name not in PUBLIC_OBJECTIVE_PREDICATE_NAMES:
            raise ValueError(f"unsupported objective predicate {expr.name!r}")
        if "(" in self.predicate and not self.predicate.endswith(")"):
            raise ValueError(
                "objective predicate must end with ')' when using arguments"
            )
        return self


class ObjectiveSet(_StrictModel):
    red: tuple[ObjectivePredicate, ...] = Field(default_factory=tuple, min_length=1)
    blue: tuple[ObjectivePredicate, ...] = Field(default_factory=tuple, min_length=1)


class ObservabilityRequirements(_StrictModel):
    require_web_logs: bool = False
    require_idp_logs: bool = False
    require_email_logs: bool = False
    require_siem_ingest: bool = False


class PinnedWeaknessSpec(_StrictModel):
    family: WeaknessFamily
    kind: SupportedWeaknessKind
    target: str = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_family_kind_pair(self) -> "PinnedWeaknessSpec":
        if self.kind not in WEAKNESS_KIND_CATALOG[self.family]:
            raise ValueError(
                f"unsupported kind {self.kind!r} for family {self.family!r}"
            )
        return self


class SecuritySpec(_StrictModel):
    allowed_weakness_families: tuple[WeaknessFamily, ...] = Field(
        default_factory=tuple,
        min_length=1,
    )
    code_flaw_kinds: tuple[CodeFlawKind, ...] = Field(default_factory=tuple)
    pinned_weaknesses: tuple[PinnedWeaknessSpec, ...] = Field(default_factory=tuple)
    phishing_surface_enabled: bool = True
    observability: ObservabilityRequirements

    @model_validator(mode="after")
    def _validate_security_catalog(self) -> "SecuritySpec":
        allowed = set(self.allowed_weakness_families)
        if self.code_flaw_kinds and "code_web" not in allowed:
            raise ValueError(
                "code_flaw_kinds requires code_web in allowed_weakness_families"
            )
        for pinned in self.pinned_weaknesses:
            if pinned.family not in allowed:
                raise ValueError(
                    f"pinned weakness family {pinned.family!r} is not enabled in allowed_weakness_families"
                )
            if (
                pinned.family == "code_web"
                and self.code_flaw_kinds
                and pinned.kind not in self.code_flaw_kinds
            ):
                raise ValueError(
                    f"pinned code_web kind {pinned.kind!r} must be present in code_flaw_kinds when that list is set"
                )
        return self


class DifficultySpec(_StrictModel):
    target_red_path_depth: PositiveInt
    target_blue_signal_points: PositiveInt
    target_noise_density: NoiseDensity


class MutationBounds(_StrictModel):
    max_new_hosts: int = Field(ge=0, default=0)
    max_new_services: int = Field(ge=0, default=0)
    max_new_users: int = Field(ge=0, default=0)
    max_new_weaknesses: int = Field(ge=0, default=0)
    allow_patch_old_weaknesses: bool = True


class EnterpriseSaaSManifest(_StrictModel):
    version: Literal[1] = 1
    world_family: Literal["enterprise_saas_v1"] = "enterprise_saas_v1"
    seed: int
    business: BusinessSpec
    topology: TopologySpec
    users: UserRoleSpec
    npc_profiles: dict[str, NPCProfileSpec] = Field(default_factory=dict)
    assets: tuple[ManifestAsset, ...] = Field(default_factory=tuple, min_length=1)
    objectives: ObjectiveSet
    security: SecuritySpec
    difficulty: DifficultySpec
    mutation_bounds: MutationBounds


def validate_manifest(payload: dict) -> EnterpriseSaaSManifest:
    """Validate raw public manifest payload into the strict model."""
    return EnterpriseSaaSManifest.model_validate(payload)


def manifest_schema() -> dict:
    """Return the JSON schema for the strict public manifest."""
    return EnterpriseSaaSManifest.model_json_schema()
