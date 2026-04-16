from __future__ import annotations

from open_range.catalog.probes import (
    DEFAULT_DETERMINISM_PROBE_TEMPLATES,
    DEFAULT_SHORTCUT_PROBE_TEMPLATES,
    SHORTCUT_WEB_ROUTE_PROBE_SPECS,
    detection_for_reference_step_action,
    identity_effect_markers_for_kind,
    is_blue_detectable_action,
    necessity_probe_template,
    reference_action_for_weakness_family,
    smoke_probe_template,
    workflow_effect_markers_for_kind,
    workflow_kind_uses_email_delivery,
)
from open_range.code_web import code_web_template
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.probe_planner import ProbePlanner, build_reference_bundle
from open_range.weaknesses import CatalogWeaknessSeeder, build_catalog_weakness
from tests.support import manifest_payload


def _seeded_world():
    payload = manifest_payload()
    return CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(payload)
    )


def test_catalog_probe_templates_keep_current_static_defaults() -> None:
    assert tuple(
        (probe.id, probe.kind, probe.description, probe.command)
        for probe in DEFAULT_SHORTCUT_PROBE_TEMPLATES
    ) == (
        ("shortcut-direct-asset", "shortcut", "direct external crown-jewel access", ""),
        ("shortcut-admin", "shortcut", "direct admin access", ""),
        ("shortcut-cross-zone", "shortcut", "unintended cross-zone reachability", ""),
        ("shortcut-secret", "shortcut", "leaked secrets", ""),
        ("shortcut-unlogged", "shortcut", "unlogged critical actions", ""),
    )
    assert tuple(
        (probe.id, probe.kind, probe.description, probe.command)
        for probe in DEFAULT_DETERMINISM_PROBE_TEMPLATES
    ) == (("determinism-red", "determinism", "replay red reference", ""),)


def test_reference_bundle_uses_catalog_probe_templates() -> None:
    world = _seeded_world()
    bundle = build_reference_bundle(world)

    assert tuple(probe.id for probe in bundle.shortcut_probes) == tuple(
        template.id for template in DEFAULT_SHORTCUT_PROBE_TEMPLATES
    )
    assert tuple(probe.description for probe in bundle.shortcut_probes) == tuple(
        template.description for template in DEFAULT_SHORTCUT_PROBE_TEMPLATES
    )
    assert tuple(probe.id for probe in bundle.determinism_probes) == tuple(
        template.id for template in DEFAULT_DETERMINISM_PROBE_TEMPLATES
    )
    assert tuple(probe.id for probe in bundle.smoke_tests) == tuple(
        smoke_probe_template(service.id).id for service in world.services
    )
    assert tuple(probe.command for probe in bundle.smoke_tests) == tuple(
        smoke_probe_template(service.id).command for service in world.services
    )
    assert tuple(probe.id for probe in bundle.necessity_probes) == tuple(
        necessity_probe_template(weak.id).id for weak in world.weaknesses
    )


def test_catalog_probe_detection_policy_keeps_current_mappings() -> None:
    assert detection_for_reference_step_action("initial_access", target="svc-web") == (
        "InitialAccess",
        "svc-web",
    )
    assert detection_for_reference_step_action("traverse", target="svc-db") == (
        "CrossZoneTraversal",
        "svc-db",
    )
    assert detection_for_reference_step_action(
        "collect_secret",
        target="svc-db",
        asset="idp_admin_cred",
    ) == ("CredentialObtained", "idp_admin_cred")
    assert detection_for_reference_step_action(
        "abuse_workflow",
        target="svc-web",
        asset="finance_docs",
    ) == ("SensitiveAssetRead", "finance_docs")
    assert detection_for_reference_step_action(
        "satisfy_objective",
        target="svc-idp",
        asset="idp_admin_cred",
        objective="credential_obtained(idp_admin_cred)",
    ) == ("CredentialObtained", "idp_admin_cred")
    assert not is_blue_detectable_action(
        "deliver_phish",
        target="svc-email",
        blindspot_targets=frozenset(),
    )
    assert is_blue_detectable_action(
        "click_lure",
        target="svc-email",
        blindspot_targets=frozenset({"svc-web"}),
    )
    assert not is_blue_detectable_action(
        "traverse",
        target="svc-db",
        source_target="svc-web",
        blindspot_targets=frozenset({"svc-web"}),
    )


def test_catalog_probe_reference_presets_keep_current_static_rules() -> None:
    assert workflow_kind_uses_email_delivery("phishing_credential_capture")
    assert workflow_kind_uses_email_delivery("internal_request_impersonation")
    assert not workflow_kind_uses_email_delivery("document_share_abuse")
    assert reference_action_for_weakness_family("secret_exposure") == "collect_secret"
    assert reference_action_for_weakness_family("config_identity") == "abuse_identity"
    assert reference_action_for_weakness_family("workflow_abuse") == "abuse_workflow"
    assert identity_effect_markers_for_kind("weak_password") == (
        '"min_password_length": 6',
        '"password_reuse_allowed": true',
    )
    assert workflow_effect_markers_for_kind("helpdesk_reset_bypass") == (
        '"identity_verification": "none"',
        '"reset_without_ticket_owner": true',
    )


def test_shortcut_route_catalog_matches_code_web_templates() -> None:
    world = _seeded_world()
    route_specs = {
        probe.weakness_kind: probe for probe in SHORTCUT_WEB_ROUTE_PROBE_SPECS
    }

    for kind in ("sql_injection", "broken_authorization", "auth_bypass"):
        weakness = build_catalog_weakness(
            world,
            "code_web",
            kind=kind,
            target="svc-web",
            target_kind="service",
            target_ref="svc-web",
            weakness_id=f"test-{kind}",
        )
        template = code_web_template(world, weakness)
        probe = route_specs[kind]

        assert probe.path == template.route_path
        assert tuple(key for key, _ in probe.query) == tuple(
            key for key, _ in template.witness_query
        )
        if kind == "sql_injection":
            assert dict(probe.query)["asset"] == dict(template.witness_query)["asset"]
            assert dict(probe.query)["q"].startswith("' UNION SELECT '")
            assert dict(template.witness_query)["q"].startswith("' UNION SELECT '")
        else:
            assert probe.query == template.witness_query


def test_probe_planner_uses_catalog_reference_presets_for_phishing_workflow() -> None:
    world = _seeded_world()
    weakness = build_catalog_weakness(
        world,
        "workflow_abuse",
        kind="phishing_credential_capture",
        target="svc-email",
        target_kind="service",
        target_ref="svc-email",
        weakness_id="test-phish",
    )
    planned_world = world.model_copy(update={"weaknesses": (weakness,)})
    trace = ProbePlanner(planned_world).build_red_reference(
        start="svc-web",
        exploit=weakness,
        ordinal=1,
    )

    assert trace.steps[0].payload["action"] == "deliver_phish"
    assert any(step.payload.get("action") == "click_lure" for step in trace.steps)


def test_probe_planner_uses_catalog_reference_action_names_for_family_steps() -> None:
    world = _seeded_world()
    cases = (
        ("secret_exposure", "token_in_email", "svc-email", "collect_secret"),
        ("config_identity", "weak_password", "svc-idp", "abuse_identity"),
        ("workflow_abuse", "helpdesk_reset_bypass", "svc-web", "abuse_workflow"),
    )

    for family, kind, target, expected_action in cases:
        weakness = build_catalog_weakness(
            world,
            family,
            kind=kind,
            target=target,
            target_kind="service",
            target_ref=target,
            weakness_id=f"test-{kind}",
        )
        planned_world = world.model_copy(update={"weaknesses": (weakness,)})
        trace = ProbePlanner(planned_world).build_red_reference(
            start="svc-web",
            exploit=weakness,
            ordinal=1,
        )

        assert any(
            step.payload.get("action") == expected_action for step in trace.steps
        )
