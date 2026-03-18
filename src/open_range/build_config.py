"""Build-time feature controls for world construction and admission."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from open_range.manifest import CodeFlawKind, WeaknessFamily


class BuildConfig(BaseModel):
    """Empirical controls for world construction and admission strength."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    world_family: str = "enterprise_saas_v1"
    services_enabled: tuple[str, ...] = Field(default_factory=tuple)
    workflows_enabled: tuple[str, ...] = Field(default_factory=tuple)
    weakness_families_enabled: tuple[WeaknessFamily, ...] = Field(default_factory=tuple)
    code_flaw_kinds_enabled: tuple[CodeFlawKind, ...] = Field(default_factory=tuple)
    observability_surfaces_enabled: tuple[str, ...] = Field(default_factory=tuple)
    phishing_surface_enabled: bool = True
    green_artifacts_enabled: bool = True
    topology_scale: Literal["small", "medium", "large"] = "medium"
    validation_profile: Literal[
        "full", "no_necessity", "graph_plus_live", "graph_only"
    ] = "full"
    red_reference_count: int = Field(default=1, ge=1)
    blue_reference_count: int = Field(default=1, ge=1)


DEFAULT_BUILD_CONFIG = BuildConfig()
OFFLINE_BUILD_CONFIG = BuildConfig(validation_profile="graph_only")
OFFLINE_REFERENCE_BUILD_CONFIG = BuildConfig(validation_profile="no_necessity")
