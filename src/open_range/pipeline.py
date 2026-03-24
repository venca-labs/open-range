"""Thin build/admit pipeline for the standalone core."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from open_range.admit import LocalAdmissionController
from open_range.build_config import BuildConfig, DEFAULT_BUILD_CONFIG
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.manifest import EnterpriseSaaSManifest, validate_manifest
from open_range.render import EnterpriseSaaSKindRenderer
from open_range.snapshot import KindArtifacts, Snapshot
from open_range.store import FileSnapshotStore, PoolSplit
from open_range.synth import EnterpriseSaaSWorldSynthesizer, SynthArtifacts
from open_range.weaknesses import CatalogWeaknessSeeder
from open_range.world_ir import WorldIR


class CandidateWorld(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    world: WorldIR
    synth: SynthArtifacts
    artifacts: KindArtifacts
    build_config: BuildConfig = DEFAULT_BUILD_CONFIG


class BuildPipeline:
    """Compose compile -> seed -> render -> admit -> store."""

    def __init__(
        self,
        *,
        compiler: EnterpriseSaaSManifestCompiler | None = None,
        seeder: CatalogWeaknessSeeder | None = None,
        synthesizer: EnterpriseSaaSWorldSynthesizer | None = None,
        renderer: EnterpriseSaaSKindRenderer | None = None,
        admission: LocalAdmissionController | None = None,
        store: FileSnapshotStore | None = None,
    ) -> None:
        self.compiler = compiler or EnterpriseSaaSManifestCompiler()
        self.seeder = seeder or CatalogWeaknessSeeder()
        self.synthesizer = synthesizer or EnterpriseSaaSWorldSynthesizer()
        self.renderer = renderer or EnterpriseSaaSKindRenderer()
        self.admission = admission or LocalAdmissionController(mode="fail_fast")
        self.store = store or FileSnapshotStore()

    def build(
        self,
        source: dict[str, Any] | EnterpriseSaaSManifest | WorldIR,
        outdir: str | Path,
        build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
    ) -> CandidateWorld:
        world = self._prepare_world(source, build_config)
        synth = self.synthesizer.synthesize(world, Path(outdir) / "synth")
        artifacts = self.renderer.render(world, synth, Path(outdir))
        return CandidateWorld(
            world=world, synth=synth, artifacts=artifacts, build_config=build_config
        )

    def admit(
        self, candidate: CandidateWorld, *, split: PoolSplit = "train"
    ) -> Snapshot:
        reference_bundle, report = self.admission.admit(
            candidate.world,
            candidate.artifacts,
            candidate.build_config,
        )
        if not report.admitted:
            raise ValueError(
                f"candidate world {candidate.world.world_id} was not admitted"
            )
        return self.store.create(
            candidate.world,
            candidate.artifacts,
            reference_bundle,
            report,
            split=split,
            synth=candidate.synth,
        )

    def admit_child(
        self,
        world: WorldIR,
        outdir: str | Path,
        *,
        split: PoolSplit = "train",
        build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
    ) -> Snapshot:
        return self.admit(self.build(world, outdir, build_config), split=split)

    def _prepare_world(
        self,
        source: dict[str, Any] | EnterpriseSaaSManifest | WorldIR,
        build_config: BuildConfig,
    ) -> WorldIR:
        if isinstance(source, WorldIR):
            return source if source.weaknesses else self.seeder.apply(source)
        parsed = (
            source
            if isinstance(source, EnterpriseSaaSManifest)
            else validate_manifest(source)
        )
        world = self.compiler.compile(parsed, build_config)
        return self.seeder.apply(world)


def build(
    source: dict[str, Any] | EnterpriseSaaSManifest | WorldIR,
    outdir: str | Path,
    build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
) -> CandidateWorld:
    """Build a candidate world from a public manifest or mutated WorldIR."""
    return BuildPipeline().build(source, outdir, build_config)


def admit(candidate: CandidateWorld, *, split: PoolSplit = "train") -> Snapshot:
    """Admit a built candidate and persist it as an immutable snapshot."""
    return BuildPipeline().admit(candidate, split=split)


def admit_child(
    world: WorldIR,
    outdir: str | Path,
    *,
    split: PoolSplit = "train",
    build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
) -> Snapshot:
    """Render, admit, and persist a mutated child world."""
    return BuildPipeline().admit_child(
        world, outdir, split=split, build_config=build_config
    )
