from __future__ import annotations

from typing import get_args

import pytest
from pydantic import ValidationError

from open_range.catalog.weaknesses import (
    all_supported_weakness_kinds,
    is_supported_weakness_kind,
    resolve_pinned_target,
    supported_weakness_kinds_for_family,
)
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.manifest import (
    CodeFlawKind,
    ConfigIdentityKind,
    PinnedWeaknessSpec,
    SecretExposureKind,
    SupportedWeaknessKind,
    TelemetryBlindspotKind,
    WorkflowAbuseKind,
)
from open_range.weaknesses import (
    CatalogWeaknessSeeder,
    build_catalog_weakness,
    seed_catalog_weakness,
    supported_weakness_kinds,
)
from tests.support import manifest_payload


def test_weakness_catalog_keeps_pinned_target_resolution_rules() -> None:
    payload = manifest_payload()
    world = EnterpriseSaaSManifestCompiler().compile(payload)
    workflow = world.workflows[0]
    workflow_target = next(
        (step.service for step in workflow.steps if step.service),
        "svc-web",
    )
    asset = world.assets[0]
    credential = world.credentials[0]
    telemetry_source = world.telemetry_edges[0].source

    assert resolve_pinned_target(world, "svc-web") == ("svc-web", "service", "svc-web")
    assert resolve_pinned_target(world, "web_app") == ("svc-web", "service", "svc-web")
    assert resolve_pinned_target(world, f"workflow:{workflow.name}") == (
        workflow_target,
        "workflow",
        workflow.id,
    )
    assert resolve_pinned_target(world, f"asset:{asset.id}") == (
        asset.owner_service,
        "asset",
        asset.id,
    )
    assert resolve_pinned_target(world, f"credential:{credential.subject}") == (
        credential.scope[0] if credential.scope else "svc-idp",
        "credential",
        credential.id,
    )
    assert resolve_pinned_target(world, f"telemetry:{telemetry_source}") == (
        telemetry_source,
        "telemetry",
        telemetry_source,
    )


def test_weakness_kind_catalog_stays_in_sync_with_public_manifest_types() -> None:
    assert supported_weakness_kinds_for_family("code_web") == get_args(CodeFlawKind)
    assert supported_weakness_kinds_for_family("config_identity") == get_args(
        ConfigIdentityKind
    )
    assert supported_weakness_kinds_for_family("secret_exposure") == get_args(
        SecretExposureKind
    )
    assert supported_weakness_kinds_for_family("workflow_abuse") == get_args(
        WorkflowAbuseKind
    )
    assert supported_weakness_kinds_for_family("telemetry_blindspot") == get_args(
        TelemetryBlindspotKind
    )
    assert supported_weakness_kinds("workflow_abuse") == get_args(WorkflowAbuseKind)
    assert all_supported_weakness_kinds() == get_args(SupportedWeaknessKind)
    assert is_supported_weakness_kind("workflow_abuse", "document_share_abuse")
    assert not is_supported_weakness_kind("workflow_abuse", "sql_injection")


def test_pinned_weakness_validation_reads_catalog_kind_inventory() -> None:
    pinned = PinnedWeaknessSpec(
        family="workflow_abuse",
        kind="document_share_abuse",
        target="svc-fileshare",
    )

    assert pinned.kind == "document_share_abuse"

    with pytest.raises(ValidationError):
        PinnedWeaknessSpec(
            family="workflow_abuse",
            kind="sql_injection",
            target="svc-web",
        )


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
