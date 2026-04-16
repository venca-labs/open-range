"""Build-config filtering and small compile policy helpers."""

from __future__ import annotations

from open_range.build_config import BuildConfig
from open_range.manifest import EnterpriseSaaSManifest


def selected_services(
    manifest: EnterpriseSaaSManifest,
    build_config: BuildConfig,
) -> tuple[str, ...]:
    services = tuple(manifest.topology.services)
    if build_config.services_enabled:
        enabled = set(build_config.services_enabled)
        services = tuple(service for service in services if service in enabled)
    if not services:
        raise ValueError("build_config removed all services from the world")
    return services


def selected_workflows(
    manifest: EnterpriseSaaSManifest,
    build_config: BuildConfig,
) -> tuple[str, ...]:
    workflows = tuple(manifest.business.workflows)
    if build_config.workflows_enabled:
        enabled = set(build_config.workflows_enabled)
        workflows = tuple(workflow for workflow in workflows if workflow in enabled)
    if not workflows:
        raise ValueError("build_config removed all workflows from the world")
    return workflows


def selected_weakness_families(
    manifest: EnterpriseSaaSManifest,
    build_config: BuildConfig,
) -> tuple[str, ...]:
    families = tuple(manifest.security.allowed_weakness_families)
    if build_config.weakness_families_enabled:
        enabled = set(build_config.weakness_families_enabled)
        families = tuple(family for family in families if family in enabled)
    if not families:
        raise ValueError("build_config removed all enabled weakness families")
    return families


def selected_code_flaw_kinds(
    manifest: EnterpriseSaaSManifest,
    build_config: BuildConfig,
) -> tuple[str, ...]:
    kinds = tuple(manifest.security.code_flaw_kinds)
    if build_config.code_flaw_kinds_enabled:
        enabled = set(build_config.code_flaw_kinds_enabled)
        kinds = tuple(kind for kind in kinds if kind in enabled)
    return kinds


def target_weakness_budget(
    manifest: EnterpriseSaaSManifest,
    build_config: BuildConfig,
) -> int:
    base = 2 if manifest.difficulty.target_red_path_depth <= 8 else 3
    if build_config.topology_scale == "small":
        return max(1, base - 1)
    if build_config.topology_scale == "large":
        return base + 1
    return base
