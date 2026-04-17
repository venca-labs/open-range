"""Deterministic manifest compiler for the fixed `enterprise_saas_v1` family."""

from __future__ import annotations

from open_range.config import DEFAULT_BUILD_CONFIG, BuildConfig
from open_range.contracts.world import (
    AssetSpec,
    GreenWorkloadSpec,
    LineageSpec,
    MutationBoundsSpec,
    ObjectiveSpec,
    WorldIR,
)
from open_range.manifest import EnterpriseSaaSManifest, validate_manifest
from open_range.objectives.expr import predicate_inner
from open_range.objectives.resolution import objective_tags_for_predicate

from .assets import place_assets
from .selection import (
    selected_code_flaw_kinds,
    selected_services,
    selected_weakness_families,
    selected_workflows,
    target_weakness_budget,
)
from .services import compile_service_topology
from .users import expand_users, validate_npc_profiles
from .workflows import compile_workflows


def _compile_objectives(
    *,
    owner: str,
    predicates: tuple[str, ...],
    assets: tuple[AssetSpec, ...],
) -> tuple[ObjectiveSpec, ...]:
    return tuple(
        _compile_objective(
            owner=owner,
            index=index,
            predicate=predicate,
            assets=assets,
        )
        for index, predicate in enumerate(predicates, start=1)
    )


def _compile_objective(
    *,
    owner: str,
    index: int,
    predicate: str,
    assets: tuple[AssetSpec, ...],
) -> ObjectiveSpec:
    target = predicate_inner(predicate)
    asset = next((item for item in assets if item.id == target), None)
    objective_tags = objective_tags_for_predicate(
        predicate,
        asset_location=asset.location if asset is not None else "",
        owner_service=asset.owner_service if asset is not None else "",
        target_id=target,
    )
    return ObjectiveSpec(
        id=f"{owner}-{index}",
        owner=owner,
        predicate=predicate,
        objective_tags=objective_tags,
    )


class EnterpriseSaaSManifestCompiler:
    """Compile the strict manifest into a hand-checkable WorldIR."""

    def compile(
        self,
        manifest: dict | EnterpriseSaaSManifest,
        build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
    ) -> WorldIR:
        parsed = (
            manifest
            if isinstance(manifest, EnterpriseSaaSManifest)
            else validate_manifest(manifest)
        )
        if build_config.world_family != parsed.world_family:
            raise ValueError(
                f"build_config.world_family={build_config.world_family!r} does not match manifest world_family={parsed.world_family!r}"
            )

        validate_npc_profiles(parsed)
        service_names = selected_services(parsed, build_config)
        workflow_names = selected_workflows(parsed, build_config)
        allowed_families = selected_weakness_families(parsed, build_config)
        allowed_code_flaw_kinds = selected_code_flaw_kinds(parsed, build_config)
        allowed_surfaces = set(build_config.observability_surfaces_enabled)

        hosts, services, edges = compile_service_topology(
            service_names=service_names,
            available_zones=parsed.topology.zones,
            allowed_surfaces=allowed_surfaces,
        )
        users, groups, credentials, personas = expand_users(parsed, build_config)
        service_ids = frozenset(service.id for service in services)
        workflows, workflow_edges = compile_workflows(
            workflow_names,
            available_service_ids=service_ids,
        )
        assets = place_assets(parsed.assets, available_service_ids=service_ids)
        red_objectives = _compile_objectives(
            owner="red",
            predicates=tuple(obj.predicate for obj in parsed.objectives.red),
            assets=assets,
        )
        blue_objectives = _compile_objectives(
            owner="blue",
            predicates=tuple(obj.predicate for obj in parsed.objectives.blue),
            assets=assets,
        )

        return WorldIR(
            world_id=f"{parsed.world_family}-{parsed.seed}",
            seed=parsed.seed,
            business_archetype=parsed.business.archetype,
            allowed_service_kinds=service_names,
            allowed_weakness_families=allowed_families,
            allowed_code_flaw_kinds=allowed_code_flaw_kinds,
            pinned_weaknesses=parsed.security.pinned_weaknesses,
            target_weakness_count=target_weakness_budget(parsed, build_config),
            phishing_surface_enabled=parsed.security.phishing_surface_enabled
            and build_config.phishing_surface_enabled,
            target_red_path_depth=parsed.difficulty.target_red_path_depth,
            target_blue_signal_points=parsed.difficulty.target_blue_signal_points,
            zones=parsed.topology.zones,
            hosts=hosts,
            services=services,
            users=users,
            groups=groups,
            credentials=credentials,
            assets=assets,
            workflows=workflows,
            edges=edges + workflow_edges,
            weaknesses=(),
            red_objectives=red_objectives,
            blue_objectives=blue_objectives,
            green_personas=personas if build_config.green_artifacts_enabled else (),
            green_workload=GreenWorkloadSpec(
                noise_density=parsed.difficulty.target_noise_density,
            ),
            mutation_bounds=MutationBoundsSpec(
                max_new_hosts=parsed.mutation_bounds.max_new_hosts,
                max_new_services=parsed.mutation_bounds.max_new_services,
                max_new_users=parsed.mutation_bounds.max_new_users,
                max_new_weaknesses=parsed.mutation_bounds.max_new_weaknesses,
                allow_patch_old_weaknesses=parsed.mutation_bounds.allow_patch_old_weaknesses,
            ),
            lineage=LineageSpec(seed=parsed.seed),
        )
