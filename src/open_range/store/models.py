"""Store package value models."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from open_range.config import DEFAULT_BUILD_CONFIG, BuildConfig
from open_range.contracts.snapshot import KindArtifacts
from open_range.contracts.world import WorldIR
from open_range.synth import SynthArtifacts


class CandidateWorld(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    world: WorldIR
    synth: SynthArtifacts
    artifacts: KindArtifacts
    build_config: BuildConfig = DEFAULT_BUILD_CONFIG
