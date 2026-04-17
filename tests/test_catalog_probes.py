from __future__ import annotations

import pytest

from open_range.admission.references import ReferencePlanner, build_reference_bundle
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.weaknesses import CatalogWeaknessSeeder, build_catalog_weakness
from tests.support import manifest_payload


def _seeded_world():
    payload = manifest_payload()
    return CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(payload)
    )


def test_reference_bundle_builds_reference_and_validation_probe_sets() -> None:
    world = _seeded_world()
    bundle = build_reference_bundle(world)

    assert bundle.reference_attack_traces
    assert bundle.reference_defense_traces
    assert len(bundle.smoke_tests) == len(world.services)
    assert {probe.kind for probe in bundle.smoke_tests} == {"smoke"}
    assert {probe.kind for probe in bundle.shortcut_probes} == {"shortcut"}
    assert {probe.kind for probe in bundle.determinism_probes} == {"determinism"}
    assert len(bundle.necessity_probes) == len(world.weaknesses)
    assert {probe.kind for probe in bundle.necessity_probes} == {"necessity"}


@pytest.mark.parametrize(
    ("family", "kind", "target", "target_kind", "target_ref", "expected_action"),
    (
        (
            "code_web",
            "sql_injection",
            "svc-web",
            "service",
            "svc-web",
            "initial_access",
        ),
        (
            "secret_exposure",
            "token_in_email",
            "svc-email",
            "asset",
            "idp_admin_cred",
            "collect_secret",
        ),
        (
            "config_identity",
            "weak_password",
            "svc-idp",
            "credential",
            "cred-it_admin-01",
            "abuse_identity",
        ),
        (
            "workflow_abuse",
            "helpdesk_reset_bypass",
            "svc-web",
            "workflow",
            "wf-helpdesk_ticketing",
            "abuse_workflow",
        ),
        (
            "telemetry_blindspot",
            "silent_mail_rule",
            "svc-email",
            "telemetry",
            "svc-email",
            "initial_access",
        ),
    ),
)
def test_probe_planner_builds_family_specific_red_reference_traces(
    family: str,
    kind: str,
    target: str,
    target_kind: str,
    target_ref: str,
    expected_action: str,
) -> None:
    world = _seeded_world()
    weakness = build_catalog_weakness(
        world,
        family,
        kind=kind,
        target=target,
        target_kind=target_kind,
        target_ref=target_ref,
        weakness_id=f"test-{kind}",
    )
    trace = ReferencePlanner(
        world.model_copy(update={"weaknesses": (weakness,)})
    ).build_red_reference(
        start="svc-web",
        exploit=weakness,
        ordinal=1,
    )

    assert any(step.payload.get("weakness_id") == weakness.id for step in trace.steps)
    assert any(step.payload.get("action") == expected_action for step in trace.steps)
    assert any(step.target == weakness.target for step in trace.steps)


def test_probe_planner_uses_phishing_workflow_reference_presets() -> None:
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
    trace = ReferencePlanner(
        world.model_copy(update={"weaknesses": (weakness,)})
    ).build_red_reference(
        start="svc-web",
        exploit=weakness,
        ordinal=1,
    )

    assert [step.payload["action"] for step in trace.steps[:3]] == [
        "deliver_phish",
        "click_lure",
        "abuse_workflow",
    ]


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
