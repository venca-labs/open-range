"""World preparation helpers for the build pipeline."""

from __future__ import annotations

from typing import Any

from open_range.build_config import BuildConfig
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.manifest import EnterpriseSaaSManifest, validate_manifest
from open_range.render import (
    EnterpriseSaaSKindRenderer,
    K3dRenderer,
    SecurityIntegrator,
    SecurityIntegratorConfig,
    SecurityRuntimeSpec,
)
from open_range.weaknesses import CatalogWeaknessSeeder
from open_range.world_ir import WorldIR


def prepare_world(
    source: dict[str, Any] | EnterpriseSaaSManifest | WorldIR,
    build_config: BuildConfig,
    *,
    compiler: EnterpriseSaaSManifestCompiler,
    seeder: CatalogWeaknessSeeder,
    security_integrator: SecurityIntegrator | None,
) -> WorldIR:
    if isinstance(source, WorldIR):
        world = source if source.weaknesses else seeder.apply(source)
        return attach_security_runtime(
            world,
            build_config,
            security_integrator=security_integrator,
        )

    parsed = (
        source
        if isinstance(source, EnterpriseSaaSManifest)
        else validate_manifest(source)
    )
    world = compiler.compile(parsed, build_config)
    return attach_security_runtime(
        seeder.apply(world),
        build_config,
        security_integrator=security_integrator,
    )


def renderer_for(
    build_config: BuildConfig,
    renderer: EnterpriseSaaSKindRenderer,
) -> EnterpriseSaaSKindRenderer:
    if not isinstance(renderer, EnterpriseSaaSKindRenderer):
        return renderer
    if build_config.cluster_backend == "k3d":
        return K3dRenderer(
            agents=build_config.k3d_agents,
            subnet=build_config.k3d_subnet,
        )
    return renderer


def attach_security_runtime(
    world: WorldIR,
    build_config: BuildConfig,
    *,
    security_integrator: SecurityIntegrator | None,
) -> WorldIR:
    if not build_config.security_enabled:
        return world.model_copy(update={"security_runtime": SecurityRuntimeSpec()})
    integrator = security_integrator or SecurityIntegrator(
        SecurityIntegratorConfig(enabled=True)
    )
    runtime = integrator.plan(world, tier=build_config.security_tier)
    return world.model_copy(update={"security_runtime": runtime})
