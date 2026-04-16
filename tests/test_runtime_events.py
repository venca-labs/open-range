from __future__ import annotations

from math import isinf
from types import SimpleNamespace

from open_range.runtime.events import (
    control_directive,
    control_directive_from_payload,
    emit_runtime_event,
    finding_event_type,
    finding_event_type_from_payload,
    telemetry_blindspots,
    visible_events_for_actor,
)
from open_range.runtime_types import Action, RuntimeEvent


def test_control_directive_helpers_keep_current_defaults() -> None:
    action = Action(
        actor_id="blue",
        role="blue",
        kind="control",
        payload={"target": "svc-web"},
    )

    assert control_directive(action, default="contain") == "contain"
    assert control_directive_from_payload({}, default="contain") == "contain"
    assert control_directive_from_payload({"action": "MiTiGaTe"}) == "mitigate"


def test_finding_event_type_helpers_prefer_explicit_event_type() -> None:
    action = Action(
        actor_id="blue",
        role="blue",
        kind="submit_finding",
        payload={"event": "InitialAccess", "event_type": "CredentialObtained"},
    )

    assert finding_event_type(action) == "CredentialObtained"
    assert (
        finding_event_type_from_payload(
            {"event": "InitialAccess", "event_type": "CredentialObtained"},
            default="InitialAccess",
        )
        == "CredentialObtained"
    )
    assert (
        finding_event_type_from_payload({}, default="InitialAccess") == "InitialAccess"
    )


def test_emit_runtime_event_keeps_blue_visibility_delay_and_blindspot_rule() -> None:
    emission = emit_runtime_event(
        event_id="evt-1",
        sim_time=1.5,
        event_type="InitialAccess",
        actor="red",
        source_entity="svc-web",
        target_entity="svc-db",
        malicious=True,
        observability_surfaces=("web_access",),
        telemetry_delay=0.5,
        blindspots={"svc-web"},
    )

    assert emission.event.time == 1.5
    assert emission.visibility["red"] == 1.5
    assert isinf(emission.visibility["blue"])


def test_telemetry_blindspots_ignore_patched_targets() -> None:
    blindspots = telemetry_blindspots(
        (
            SimpleNamespace(family="telemetry_blindspot", target="svc-web"),
            SimpleNamespace(family="code_web", target="svc-idp"),
            SimpleNamespace(family="telemetry_blindspot", target="svc-email"),
        ),
        patched_targets={"svc-email"},
    )

    assert blindspots == {"svc-web"}


def test_visible_events_for_actor_keeps_current_red_and_blue_filters() -> None:
    suspicious = RuntimeEvent(
        id="evt-1",
        event_type="SuspiciousActionObserved",
        actor="red",
        time=1.0,
        source_entity="red",
        target_entity="svc-web",
        malicious=True,
    )
    malicious = RuntimeEvent(
        id="evt-2",
        event_type="InitialAccess",
        actor="red",
        time=1.0,
        source_entity="red",
        target_entity="svc-web",
        malicious=True,
        observability_surfaces=("web_access",),
    )
    containment = RuntimeEvent(
        id="evt-3",
        event_type="ContainmentApplied",
        actor="blue",
        time=1.0,
        source_entity="blue",
        target_entity="svc-web",
        malicious=False,
        observability_surfaces=("svc-siem",),
    )

    blue_visible = visible_events_for_actor(
        "blue",
        events=(suspicious, malicious, containment),
        observed_event_ids=set(),
        event_visibility={
            "evt-1": {"blue": 0.0},
            "evt-2": {"blue": 0.0},
            "evt-3": {"blue": 0.0},
        },
        sim_time=1.0,
    )
    red_visible = visible_events_for_actor(
        "red",
        events=(suspicious, malicious, containment),
        observed_event_ids={"evt-2"},
        event_visibility={
            "evt-1": {"red": 0.0},
            "evt-2": {"red": 0.0},
            "evt-3": {"red": 0.0},
        },
        sim_time=1.0,
    )

    assert [event.id for event in blue_visible] == ["evt-2", "evt-3"]
    assert [event.id for event in red_visible] == ["evt-3"]
