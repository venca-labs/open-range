from __future__ import annotations

import random
from typing import get_args

import pytest
from pydantic import ValidationError

from open_range.catalog.weaknesses import (
    all_supported_weakness_kinds,
    available_seed_families_for_world,
    available_weakness_families_for_service_kinds,
    benchmark_tags_for_family,
    default_target_kind_for_family,
    expected_events_for_weakness,
    instantiation_mode_for_family,
    is_supported_weakness_kind,
    observability_surfaces_for_weakness,
    preconditions_for_weakness,
    remediation_text_for_kind,
    resolve_pinned_target,
    seed_selection_for_family,
    select_seed_families,
    selected_seed_families_for_world,
    supported_weakness_kinds_for_family,
    weakness_build_defaults,
    weakness_family_contract,
    weakness_id_for,
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
from open_range.weakness_families import seed_catalog_weakness
from open_range.weaknesses import (
    CatalogWeaknessSeeder,
    build_catalog_weakness,
    supported_weakness_kinds,
)
from tests.support import manifest_payload


def test_weakness_family_catalog_keeps_current_family_defaults() -> None:
    assert default_target_kind_for_family("workflow_abuse") == "workflow"
    assert benchmark_tags_for_family("code_web") == ("cve_bench", "xbow", "cybench_web")
    assert instantiation_mode_for_family("telemetry_blindspot") == "exact_config"
    assert preconditions_for_weakness(
        "secret_exposure",
        kind="credential_in_share",
        target_ref="asset-finance-docs",
    ) == (
        "sensitive_material_present",
        "asset-finance-docs",
        "credential_in_share",
    )


def test_weakness_family_catalog_keeps_concrete_precondition_templates() -> None:
    assert preconditions_for_weakness(
        "code_web",
        kind="sql_injection",
        target_ref="svc-web",
    ) == ("public_reachability", "user_input_surface", "sql_injection")
    assert preconditions_for_weakness(
        "workflow_abuse",
        kind="phishing_credential_capture",
        target_ref="wf-helpdesk-ticketing",
    ) == (
        "wf-helpdesk-ticketing",
        "approval_path_exists",
        "phishing_credential_capture",
    )
    assert preconditions_for_weakness(
        "telemetry_blindspot",
        kind="silent_mail_rule",
        target_ref="svc-email",
    ) == ("critical_action_exists", "silent_mail_rule")


def test_weakness_family_catalog_keeps_context_defaults_in_one_place() -> None:
    defaults = weakness_build_defaults(
        "secret_exposure",
        kind="token_in_email",
        target="svc-email",
        target_ref="idp_admin_cred",
    )

    assert defaults.objective_tags == ("file_access",)
    assert defaults.expected_event_signatures == (
        "CredentialObtained",
        "SensitiveAssetRead",
    )
    assert defaults.blue_observability_surfaces == ("smtp", "imap", "audit", "ingest")
    assert defaults.instantiation_mode == "exact_config"
    assert defaults.remediation == "apply remediation for token in email"


def test_weakness_family_catalog_keeps_default_id_and_remediation_helpers() -> None:
    assert (
        weakness_id_for(
            "sql_injection",
            target="svc-web",
            target_ref="svc-web",
        )
        == "wk-sql-injection-svc-web"
    )
    assert remediation_text_for_kind("admin_surface_exposed") == (
        "apply remediation for admin surface exposed"
    )


def test_weakness_family_catalog_keeps_expected_event_rules() -> None:
    assert expected_events_for_weakness("code_web", "ssrf") == (
        "InitialAccess",
        "CrossZoneTraversal",
    )
    assert expected_events_for_weakness(
        "workflow_abuse",
        "phishing_credential_capture",
    ) == ("InitialAccess", "CredentialObtained", "UnauthorizedCredentialUse")
    assert expected_events_for_weakness(
        "telemetry_blindspot",
        "silent_mail_rule",
    ) == ("InitialAccess", "DetectionAlertRaised")


def test_weakness_family_catalog_keeps_observability_surface_rules() -> None:
    assert observability_surfaces_for_weakness("code_web", kind="ssrf") == (
        "web_access",
        "ingest",
    )
    assert observability_surfaces_for_weakness(
        "workflow_abuse",
        kind="document_share_abuse",
        target="svc-web",
    ) == ("share_access", "audit", "ingest")
    assert observability_surfaces_for_weakness(
        "secret_exposure",
        kind="hardcoded_app_secret",
        target="svc-fileshare",
    ) == ("share_access", "audit", "ingest")
    assert observability_surfaces_for_weakness(
        "config_identity",
        kind="admin_surface_exposed",
    ) == ("auth", "audit", "web_access")
    assert observability_surfaces_for_weakness(
        "telemetry_blindspot",
        kind="silent_mail_rule",
    ) == ("smtp", "imap", "ingest")


def test_weakness_family_catalog_drives_family_availability() -> None:
    assert available_weakness_families_for_service_kinds({"web_app"}) == {
        "code_web",
        "workflow_abuse",
    }
    assert available_weakness_families_for_service_kinds({"idp"}) >= {
        "config_identity",
        "secret_exposure",
    }
    assert weakness_family_contract("telemetry_blindspot") is not None


def test_weakness_family_catalog_keeps_seed_selection_policy() -> None:
    policy = seed_selection_for_family("code_web")

    assert policy.auto_include is True
    assert policy.priority == 0

    selected = select_seed_families(
        ("workflow_abuse", "secret_exposure", "code_web"),
        weakness_count=2,
        rng=random.Random(7),
    )

    assert selected[0] == "code_web"
    assert len(selected) == 2


def test_weakness_family_catalog_selects_seed_families_from_world_contracts() -> None:
    world = (
        EnterpriseSaaSManifestCompiler()
        .compile(manifest_payload())
        .model_copy(
            update={
                "allowed_weakness_families": ("code_web", "config_identity"),
                "target_weakness_count": 2,
            }
        )
    )

    assert available_seed_families_for_world(world) == ("code_web", "config_identity")
    assert selected_seed_families_for_world(world, rng=random.Random(7)) == (
        "code_web",
        "config_identity",
    )


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
