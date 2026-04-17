"""Shared render-stage contracts."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class KindArtifacts(_StrictModel):
    render_dir: str
    chart_dir: str
    values_path: str
    kind_config_path: str
    manifest_summary_path: str
    rendered_files: tuple[str, ...] = Field(default_factory=tuple)
    chart_values: dict[str, Any] = Field(default_factory=dict)
    pinned_image_digests: dict[str, str] = Field(default_factory=dict)
