"""Thin build/admit pipeline for the standalone core."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from open_range.admission.controller import LocalAdmissionController
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.config import DEFAULT_BUILD_CONFIG, BuildConfig
from open_range.contracts.snapshot import KindArtifacts, Snapshot
from open_range.contracts.world import WorldIR
from open_range.manifest import EnterpriseSaaSManifest
from open_range.render import EnterpriseSaaSKindRenderer, SecurityIntegrator
from open_range.synth import EnterpriseSaaSWorldSynthesizer
from open_range.synth.models import SynthArtifacts
from open_range.weaknesses import CatalogWeaknessSeeder

from .core import FileSnapshotStore, PoolSplit
from .prepare import prepare_world, renderer_for
from .rendered import integrate_network_policies


@dataclass(frozen=True, slots=True)
class CandidateWorld:
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
        security_integrator: SecurityIntegrator | None = None,
        admission: LocalAdmissionController | None = None,
        store: FileSnapshotStore | None = None,
    ) -> None:
        self.compiler = compiler or EnterpriseSaaSManifestCompiler()
        self.seeder = seeder or CatalogWeaknessSeeder()
        self.synthesizer = synthesizer or EnterpriseSaaSWorldSynthesizer()
        self.renderer = renderer or EnterpriseSaaSKindRenderer()
        self.security_integrator = security_integrator
        self.admission = admission or LocalAdmissionController(mode="fail_fast")
        self.store = store or FileSnapshotStore()

    def build(
        self,
        source: dict[str, Any] | EnterpriseSaaSManifest | WorldIR,
        outdir: str | Path,
        build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
    ) -> CandidateWorld:
        world = prepare_world(
            source,
            build_config,
            compiler=self.compiler,
            seeder=self.seeder,
            security_integrator=self.security_integrator,
        )
        synth = self.synthesizer.synthesize(world, Path(outdir) / "synth")
        artifacts = renderer_for(build_config, self.renderer).render(
            world,
            synth,
            Path(outdir),
        )
        artifacts = integrate_network_policies(artifacts, build_config)
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
