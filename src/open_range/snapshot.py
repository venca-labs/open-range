"""Rendered artifact, public snapshot, and runtime snapshot models."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from open_range.admission import ReferenceBundle, ValidatorReport
from open_range.world_ir import WorldIR


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


class Snapshot(_StrictModel):
    snapshot_id: str
    world_id: str
    seed: int
    artifacts_dir: str
    image_digests: dict[str, str] = Field(default_factory=dict)
    state_seed_dir: str
    validator_report_path: str
    artifacts: KindArtifacts
    db_seed_state: dict[str, Any] = Field(default_factory=dict)
    mail_state: dict[str, Any] = Field(default_factory=dict)
    file_assets: dict[str, str] = Field(default_factory=dict)
    identity_seed: dict[str, Any] = Field(default_factory=dict)
    validator_report: ValidatorReport
    world_hash: str
    parent_snapshot_id: str | None = None
    parent_world_id: str | None = None


class RuntimeSnapshot(Snapshot):
    """Internal runtime/admission snapshot hydrated with private references."""

    world: WorldIR
    reference_bundle: ReferenceBundle


def world_hash(world: WorldIR) -> str:
    payload = json.dumps(
        world.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
