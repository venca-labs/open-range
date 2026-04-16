from __future__ import annotations

from open_range.catalog.weaknesses import (
    available_weakness_families_for_service_kinds,
    benchmark_tags_for_family,
    default_target_kind_for_family,
    expected_events_for_weakness,
    instantiation_mode_for_family,
    precondition_mode_for_family,
    weakness_family_contract,
)
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.weaknesses import CatalogWeaknessSeeder
from tests.support import manifest_payload


def test_weakness_family_catalog_keeps_current_family_defaults() -> None:
    assert default_target_kind_for_family("workflow_abuse") == "workflow"
    assert benchmark_tags_for_family("code_web") == ("cve_bench", "xbow", "cybench_web")
    assert instantiation_mode_for_family("telemetry_blindspot") == "exact_config"
    assert precondition_mode_for_family("secret_exposure") == "secret_exposure"


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


def test_seeded_world_keeps_catalog_backed_family_metadata() -> None:
    payload = manifest_payload()
    world = CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(payload)
    )

    assert world.weaknesses
    assert all(weak.expected_event_signatures for weak in world.weaknesses)
    assert all(weak.benchmark_tags for weak in world.weaknesses)
    assert all(weak.instantiation_mode for weak in world.weaknesses)
