from __future__ import annotations

from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.weaknesses import (
    CatalogWeaknessSeeder,
    build_catalog_weakness,
    seed_catalog_weakness,
)
from tests.support import manifest_payload


def test_seeded_world_keeps_catalog_backed_family_metadata() -> None:
    payload = manifest_payload()
    world = CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(payload)
    )

    assert world.weaknesses
    assert all(weak.expected_event_signatures for weak in world.weaknesses)
    assert all(weak.benchmark_tags for weak in world.weaknesses)
    assert all(weak.instantiation_mode for weak in world.weaknesses)
    assert all(weak.blue_observability_surfaces for weak in world.weaknesses)


def test_family_registry_keeps_seed_defaults_for_small_family_handlers() -> None:
    payload = manifest_payload()
    world = EnterpriseSaaSManifestCompiler().compile(payload)

    config_identity = seed_catalog_weakness(world, "config_identity")
    telemetry = seed_catalog_weakness(world, "telemetry_blindspot")

    assert config_identity.target == "svc-idp"
    assert config_identity.target_ref == "svc-idp"
    assert telemetry.target == "svc-email"
    assert telemetry.target_ref == "svc-email"


def test_family_registry_keeps_current_target_normalization_and_build_outputs() -> None:
    payload = manifest_payload()
    world = EnterpriseSaaSManifestCompiler().compile(payload)

    code_web = build_catalog_weakness(
        world,
        "code_web",
        kind="sql_injection",
        target="svc-web",
        target_kind="service",
        target_ref="svc-web",
        weakness_id="test-code-web",
    )
    secret_exposure = build_catalog_weakness(
        world,
        "secret_exposure",
        kind="credential_in_share",
        target="svc-idp",
        target_kind="asset",
        target_ref=world.assets[0].id,
        weakness_id="test-secret-exposure",
    )
    workflow_abuse = build_catalog_weakness(
        world,
        "workflow_abuse",
        kind="phishing_credential_capture",
        target="svc-web",
        target_kind="workflow",
        target_ref=world.workflows[0].id,
        weakness_id="test-workflow-abuse",
    )
    config_identity = build_catalog_weakness(
        world,
        "config_identity",
        kind="admin_surface_exposed",
        target="svc-web",
        target_kind="service",
        target_ref="svc-web",
        weakness_id="test-config-identity",
    )
    telemetry = build_catalog_weakness(
        world,
        "telemetry_blindspot",
        kind="silent_mail_rule",
        target="svc-web",
        target_kind="service",
        target_ref="svc-web",
        weakness_id="test-telemetry",
    )

    assert any(realization.kind == "code" for realization in code_web.realization)
    assert secret_exposure.target == "svc-fileshare"
    assert any(
        realization.kind == "seed_data" for realization in secret_exposure.realization
    )
    assert workflow_abuse.target == "svc-email"
    assert any(
        realization.kind == "mailbox" for realization in workflow_abuse.realization
    )
    assert workflow_abuse.preconditions == (
        world.workflows[0].id,
        "approval_path_exists",
        "phishing_credential_capture",
    )
    assert config_identity.target == "svc-idp"
    assert config_identity.realization[0].path.endswith("admin-surface.json")
    assert config_identity.preconditions == (
        "interactive_login",
        "identity_surface_present",
        "admin_surface_exposed",
    )
    assert telemetry.target == "svc-email"
    assert telemetry.target_kind == "telemetry"
    assert telemetry.realization[0].path.endswith("silent_mail_rule.json")
    assert telemetry.preconditions == ("critical_action_exists", "silent_mail_rule")
