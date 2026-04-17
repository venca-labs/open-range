from __future__ import annotations

from open_range.admission.references import ReferencePlanner, build_reference_bundle
from open_range.catalog.probes import (
    identity_effect_markers_for_kind,
    workflow_effect_markers_for_kind,
)
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.objectives.effects import effect_marker_path, effect_marker_token
from open_range.weaknesses import CatalogWeaknessSeeder, build_catalog_weakness
from tests.support import manifest_payload


def _seeded_world():
    payload = manifest_payload()
    return CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(payload)
    )


def test_reference_bundle_builds_smoke_shortcut_and_necessity_probes() -> None:
    world = _seeded_world()
    bundle = build_reference_bundle(world)

    assert bundle.reference_attack_traces
    assert bundle.reference_defense_traces
    assert len(bundle.smoke_tests) == len(world.services)
    assert {probe.kind for probe in bundle.smoke_tests} == {"smoke"}
    assert bundle.shortcut_probes
    assert {probe.kind for probe in bundle.shortcut_probes} == {"shortcut"}
    assert len(bundle.determinism_probes) == 1
    assert {probe.kind for probe in bundle.determinism_probes} == {"determinism"}
    assert len(bundle.necessity_probes) == len(world.weaknesses)
    assert {probe.kind for probe in bundle.necessity_probes} == {"necessity"}


def test_probe_planner_keeps_code_web_reference_payload_details() -> None:
    world = _seeded_world()
    weakness = build_catalog_weakness(
        world,
        "code_web",
        kind="sql_injection",
        target="svc-web",
        target_kind="service",
        target_ref="svc-web",
        weakness_id="test-sqli",
    )
    planned_world = world.model_copy(update={"weaknesses": (weakness,)})
    trace = ReferencePlanner(planned_world).build_red_reference(
        start="svc-email",
        exploit=weakness,
        ordinal=1,
    )

    step = trace.steps[0]

    assert step.kind == "api"
    assert step.target == "svc-web"
    assert step.payload["action"] == "initial_access"
    assert step.payload["weakness_id"] == weakness.id
    assert step.payload["path"] == "/search.php"
    assert step.payload["query"]["asset"] == "finance_docs"
    assert step.payload["exploit_kind"] == "sql_injection"
    assert "expect_contains" in step.payload


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
    trace = ReferencePlanner(planned_world).build_red_reference(
        start="svc-web",
        exploit=weakness,
        ordinal=1,
    )

    assert [step.payload["action"] for step in trace.steps[:3]] == [
        "deliver_phish",
        "click_lure",
        "abuse_workflow",
    ]


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
        trace = ReferencePlanner(planned_world).build_red_reference(
            start="svc-web",
            exploit=weakness,
            ordinal=1,
        )

        assert any(
            step.payload.get("action") == expected_action for step in trace.steps
        )


def test_probe_planner_keeps_secret_reference_payload_details() -> None:
    world = _seeded_world()
    cases = (
        (
            "backup_leak",
            "svc-fileshare",
            "asset",
            "finance_docs",
            "INSERT INTO leaked_credentials",
            "asset_read(finance_docs)",
        ),
        (
            "token_in_email",
            "svc-email",
            "asset",
            "idp_admin_cred",
            "seeded-sensitive-idp_admin_cred",
            "credential_obtained(idp_admin_cred)",
        ),
    )

    for (
        kind,
        target,
        target_kind,
        target_ref,
        expected_contains,
        expected_objective,
    ) in cases:
        weakness = build_catalog_weakness(
            world,
            "secret_exposure",
            kind=kind,
            target=target,
            target_kind=target_kind,
            target_ref=target_ref,
            weakness_id=f"test-{kind}",
        )
        planned_world = world.model_copy(update={"weaknesses": (weakness,)})
        trace = ReferencePlanner(planned_world).build_red_reference(
            start="svc-web",
            exploit=weakness,
            ordinal=1,
        )

        secret_step = next(step for step in trace.steps if step.kind == "shell")
        assert secret_step.payload["action"] == "collect_secret"
        assert secret_step.payload["expect_contains"] == expected_contains
        assert secret_step.payload["asset"] == target_ref
        assert secret_step.payload["objective"] == expected_objective


def test_probe_planner_keeps_effect_marker_commands_for_shell_families() -> None:
    world = _seeded_world()
    cases = (
        (
            "config_identity",
            "weak_password",
            "svc-idp",
            "credential",
            "cred-it_admin-01",
            identity_effect_markers_for_kind("weak_password"),
        ),
        (
            "workflow_abuse",
            "helpdesk_reset_bypass",
            "svc-web",
            "workflow",
            "wf-helpdesk_ticketing",
            workflow_effect_markers_for_kind("helpdesk_reset_bypass"),
        ),
    )

    for family, kind, target, target_kind, target_ref, markers in cases:
        weakness = build_catalog_weakness(
            world,
            family,
            kind=kind,
            target=target,
            target_kind=target_kind,
            target_ref=target_ref,
            weakness_id=f"test-{kind}",
        )
        planned_world = world.model_copy(update={"weaknesses": (weakness,)})
        trace = ReferencePlanner(planned_world).build_red_reference(
            start="svc-web",
            exploit=weakness,
            ordinal=1,
        )

        shell_step = next(step for step in trace.steps if step.kind == "shell")
        assert shell_step.payload["expect_contains"] == effect_marker_token(weakness)
        assert shell_step.payload["command"] == shell_step.payload["service_command"]
        assert effect_marker_path(weakness) in shell_step.payload["service_command"]
        assert all(
            marker in shell_step.payload["service_command"] for marker in markers
        )


def test_probe_planner_keeps_default_api_reference_for_telemetry_blindspots() -> None:
    world = _seeded_world()
    weakness = build_catalog_weakness(
        world,
        "telemetry_blindspot",
        kind="silent_mail_rule",
        target="svc-email",
        target_kind="telemetry",
        target_ref="svc-email",
        weakness_id="test-telemetry",
    )
    planned_world = world.model_copy(update={"weaknesses": (weakness,)})
    trace = ReferencePlanner(planned_world).build_red_reference(
        start="svc-web",
        exploit=weakness,
        ordinal=1,
    )

    weakness_step = next(
        step
        for step in trace.steps
        if step.target == "svc-email" and step.payload.get("weakness_id") == weakness.id
    )
    assert weakness_step.kind == "api"
    assert weakness_step.payload["action"] == "initial_access"


def test_probe_planner_prefers_code_web_when_public_start_bias_is_equal() -> None:
    world = _seeded_world()
    code_web = build_catalog_weakness(
        world,
        "code_web",
        kind="sql_injection",
        target="svc-web",
        target_kind="service",
        target_ref="svc-web",
        weakness_id="rank-code-web",
    )
    workflow = build_catalog_weakness(
        world,
        "workflow_abuse",
        kind="helpdesk_reset_bypass",
        target="svc-web",
        target_kind="workflow",
        target_ref="wf-helpdesk_ticketing",
        weakness_id="rank-workflow",
    )
    planned_world = world.model_copy(update={"weaknesses": (workflow, code_web)})
    traces = ReferencePlanner(planned_world).build_red_references()

    assert traces[0].steps[0].payload["weakness_id"] == code_web.id


def test_probe_planner_primary_selection_prefers_target_locality_over_family_bias() -> (
    None
):
    world = _seeded_world()
    code_web = build_catalog_weakness(
        world,
        "code_web",
        kind="sql_injection",
        target="svc-web",
        target_kind="service",
        target_ref="svc-web",
        weakness_id="local-code-web",
    )
    secret = build_catalog_weakness(
        world,
        "secret_exposure",
        kind="token_in_email",
        target="svc-email",
        target_kind="asset",
        target_ref="idp_admin_cred",
        weakness_id="local-secret",
    )
    planned_world = world.model_copy(update={"weaknesses": (code_web, secret)})
    trace = ReferencePlanner(planned_world).build_red_reference(
        start="svc-email",
        exploit=None,
        ordinal=1,
    )

    weakness_ids = {
        step.payload.get("weakness_id")
        for step in trace.steps
        if step.payload.get("weakness_id")
    }

    assert weakness_ids == {secret.id}


def test_probe_planner_primary_selection_falls_back_to_telemetry_only_worlds() -> None:
    world = _seeded_world()
    weakness = build_catalog_weakness(
        world,
        "telemetry_blindspot",
        kind="silent_mail_rule",
        target="svc-email",
        target_kind="telemetry",
        target_ref="svc-email",
        weakness_id="only-telemetry",
    )
    planned_world = world.model_copy(update={"weaknesses": (weakness,)})
    trace = ReferencePlanner(planned_world).build_red_reference(
        start="svc-email",
        exploit=None,
        ordinal=1,
    )

    weakness_ids = {
        step.payload.get("weakness_id")
        for step in trace.steps
        if step.payload.get("weakness_id")
    }

    assert weakness_ids == {weakness.id}


def test_probe_planner_blue_reference_builds_observe_find_contain_trace() -> None:
    world = _seeded_world()
    red_trace = ReferencePlanner(world).build_red_reference(ordinal=1)
    blue_trace = ReferencePlanner(world).build_blue_reference(red_trace, ordinal=1)

    observe_steps = [step for step in blue_trace.steps if step.kind == "shell"]
    finding_step = next(
        step for step in blue_trace.steps if step.kind == "submit_finding"
    )
    contain_step = next(step for step in blue_trace.steps if step.kind == "control")

    assert blue_trace.role == "blue"
    assert observe_steps
    assert blue_trace.steps.index(finding_step) == len(observe_steps)
    assert blue_trace.steps.index(contain_step) == len(observe_steps) + 1
    assert finding_step.payload["event"]
    assert contain_step.payload["action"] == "contain"
    assert tuple(blue_trace.expected_events) == (
        "DetectionAlertRaised",
        "ContainmentApplied",
    )


def test_probe_planner_uses_resolved_objective_events_for_red_trace() -> None:
    payload = manifest_payload()
    payload["objectives"]["red"] = [{"predicate": "outbound_service(svc-web)"}]
    world = CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(payload)
    )

    trace = ReferencePlanner(world).build_red_reference(ordinal=1)

    assert "PersistenceEstablished" in trace.expected_events
    assert trace.expected_events[-1] == "PersistenceEstablished"
