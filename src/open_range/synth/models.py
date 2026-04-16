"""Synth package contracts and value models."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from open_range.world_ir import WorldIR


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SynthFile(_StrictModel):
    key: str = Field(min_length=1)
    mount_path: str = Field(min_length=1)
    content: str


class SynthArtifacts(_StrictModel):
    outdir: str
    summary_path: str
    service_payloads: dict[str, tuple[SynthFile, ...]] = Field(default_factory=dict)
    mailboxes: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    generated_files: tuple[str, ...] = Field(default_factory=tuple)


class WorldSynthesizer(Protocol):
    def synthesize(self, world: WorldIR, outdir: Path) -> SynthArtifacts: ...
