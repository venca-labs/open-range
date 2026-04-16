"""Store package value models."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from open_range.build_config import DEFAULT_BUILD_CONFIG, BuildConfig
from open_range.snapshot import KindArtifacts
from open_range.synth import SynthArtifacts
from open_range.world_ir import WorldIR


class CandidateWorld(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    world: WorldIR
    synth: SynthArtifacts
    artifacts: KindArtifacts
    build_config: BuildConfig = DEFAULT_BUILD_CONFIG
