from __future__ import annotations

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


def test_probe_planner_builds_red_reference_for_seeded_weakness() -> None:
    world = _seeded_world()
    weakness = build_catalog_weakness(
        world,
        "workflow_abuse",
        kind="helpdesk_reset_bypass",
        target="svc-web",
        target_kind="workflow",
        target_ref="wf-helpdesk_ticketing",
        weakness_id="test-helpdesk-reset-bypass",
    )
    trace = ReferencePlanner(
        world.model_copy(update={"weaknesses": (weakness,)})
    ).build_red_reference(
        start="svc-web",
        exploit=weakness,
        ordinal=1,
    )

    assert any(step.payload.get("weakness_id") == weakness.id for step in trace.steps)
    assert any(step.target == weakness.target for step in trace.steps)
    assert trace.steps
    assert trace.expected_events


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
    assert finding_step.payload["event"]
    assert contain_step.payload["action"] == "contain"
    assert "DetectionAlertRaised" in blue_trace.expected_events
    assert "ContainmentApplied" in blue_trace.expected_events


def test_probe_planner_uses_resolved_objective_events_for_red_trace() -> None:
    payload = manifest_payload()
    payload["objectives"]["red"] = [{"predicate": "outbound_service(svc-web)"}]
    world = CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(payload)
    )

    trace = ReferencePlanner(world).build_red_reference(ordinal=1)

    assert "PersistenceEstablished" in trace.expected_events
