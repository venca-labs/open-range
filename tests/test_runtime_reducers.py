from __future__ import annotations

from itertools import count
from math import isinf
from types import SimpleNamespace

from open_range.admission.models import ReferenceAction
from open_range.contracts.runtime import (
    Action,
    RuntimeEvent,
    control_directive,
    control_directive_from_payload,
    finding_event_type,
    finding_event_type_from_payload,
)
from open_range.runtime.events import (
    emit_runtime_event,
    telemetry_blindspots,
    visible_events_for_actor,
)
from open_range.runtime.execution import ActionExecution
from open_range.runtime.reducers import (
    BLUE_CONTAINMENT_OBJECTIVE,
    BLUE_DETECTION_OBJECTIVE,
    OBSERVATION_ALERT_EVENT_TYPES,
    SERVICE_HEALTH_BLUE_OBJECTIVE,
    blue_objectives_after_continuity,
    continuity_for_service_health,
    reduce_blue_control,
    reduce_blue_finding,
    reduce_observation_state,
    reduce_red_action,
    select_scripted_internal_blue_action,
)


def _emit_event(**kwargs) -> RuntimeEvent:
    event_counter = getattr(_emit_event, "_counter", count(1))
    _emit_event._counter = event_counter
    return RuntimeEvent(
        id=f"evt-{next(event_counter)}",
        time=0.0,
        suspicious=False,
        suspicious_reasons=(),
        **kwargs,
    )


def test_continuity_for_service_health_averages_service_health() -> None:
    assert continuity_for_service_health({}) == 1.0
    assert continuity_for_service_health({"svc-web": 1.0, "svc-db": 0.5}) == 0.75


def test_blue_objectives_after_continuity_tracks_service_health_goal() -> None:
    assert (
        blue_objectives_after_continuity(
            {SERVICE_HEALTH_BLUE_OBJECTIVE},
            continuity=0.4,
            continuity_threshold=0.9,
            continuity_enforced=True,
        )
        == set()
    )
    assert blue_objectives_after_continuity(
        set(),
        continuity=0.95,
        continuity_threshold=0.9,
        continuity_enforced=True,
    ) == {SERVICE_HEALTH_BLUE_OBJECTIVE}
    assert (
        blue_objectives_after_continuity(
            set(),
            continuity=0.2,
            continuity_threshold=0.9,
            continuity_enforced=False,
        )
        == set()
    )


def test_reduce_red_action_appends_blocked_reason_once() -> None:
    reduction = reduce_red_action(
        action=Action(actor_id="red", role="red", kind="shell", payload={}),
        target="svc-web",
        live=ActionExecution(
            stdout="",
            stderr="target svc-web is patched",
            ok=True,
        ),
        blocked_reason="patched",
        matched_reference_step=False,
        expected_reference_step=None,
        last_red_target="",
        emit_event=_emit_event,
        service_surfaces=lambda target: (f"surf:{target}",),
    )

    assert reduction.stderr == "target svc-web is patched"
    assert reduction.progress_advanced is False
    assert reduction.emitted_events == ()


def test_reduce_red_action_emits_reference_events_for_matching_step() -> None:
    reduction = reduce_red_action(
        action=Action(
            actor_id="red",
            role="red",
            kind="shell",
            payload={"target": "svc-web"},
        ),
        target="svc-web",
        live=ActionExecution(stdout="access", stderr="", ok=True),
        blocked_reason="",
        matched_reference_step=True,
        expected_reference_step=ReferenceAction(
            actor="red",
            kind="shell",
            target="svc-web",
            payload={"action": "initial_access"},
        ),
        last_red_target="",
        emit_event=_emit_event,
        service_surfaces=lambda target: (f"surf:{target}",),
    )

    assert reduction.stderr == ""
    assert reduction.progress_advanced is True
    assert reduction.advanced_target == "svc-web"
    assert len(reduction.emitted_events) == 1
    assert reduction.emitted_events[0].event_type == "InitialAccess"


def test_reduce_red_action_nonmatching_step_does_not_advance_reference() -> None:
    reduction = reduce_red_action(
        action=Action(
            actor_id="red",
            role="red",
            kind="shell",
            payload={"target": "svc-web"},
        ),
        target="svc-web",
        live=ActionExecution(stdout="", stderr="", ok=True),
        blocked_reason="",
        matched_reference_step=False,
        expected_reference_step=ReferenceAction(
            actor="red",
            kind="shell",
            target="svc-web",
            payload={"action": "initial_access"},
        ),
        last_red_target="",
        emit_event=_emit_event,
        service_surfaces=lambda target: (f"surf:{target}",),
    )

    assert reduction.stderr == ""
    assert reduction.progress_advanced is False
    assert reduction.emitted_events == ()


def test_reduce_blue_control_marks_path_breaking_containment() -> None:
    transition = reduce_blue_control(
        target="svc-web",
        directive="contain",
        live=ActionExecution(containment_applied=True, ok=True),
        remaining_red_targets={"svc-web"},
        contained_targets=set(),
        patched_targets=set(),
        blue_contained=False,
    )

    assert transition.path_broken is True
    assert transition.blue_contained is True
    assert transition.contained_targets == {"svc-web"}
    assert transition.patched_targets == set()
    assert transition.satisfied_objectives == (BLUE_CONTAINMENT_OBJECTIVE,)
    assert transition.event_spec is not None
    assert transition.event_spec.event_type == "ContainmentApplied"
    assert (
        transition.event_spec.linked_objective_predicates
        == transition.satisfied_objectives
    )


def test_reduce_blue_control_tracks_nonbreaking_mitigation() -> None:
    transition = reduce_blue_control(
        target="svc-web",
        directive="mitigate",
        live=ActionExecution(patch_applied=True, ok=True),
        remaining_red_targets=set(),
        contained_targets={"svc-web"},
        patched_targets=set(),
        blue_contained=True,
    )

    assert transition.path_broken is False
    assert transition.blue_contained is True
    assert transition.contained_targets == set()
    assert transition.patched_targets == {"svc-web"}
    assert transition.satisfied_objectives == ()
    assert transition.event_spec is not None
    assert transition.event_spec.event_type == "PatchApplied"


def test_reduce_blue_control_clears_state_on_recovery() -> None:
    transition = reduce_blue_control(
        target="svc-web",
        directive="recover",
        live=ActionExecution(recovery_applied=True, ok=True, stdout=""),
        remaining_red_targets={"svc-web"},
        contained_targets={"svc-web"},
        patched_targets={"svc-web"},
        blue_contained=True,
    )

    assert transition.path_broken is False
    assert transition.blue_contained is True
    assert transition.contained_targets == set()
    assert transition.patched_targets == set()
    assert transition.satisfied_objectives == ()
    assert transition.event_spec is not None
    assert transition.event_spec.event_type == "RecoveryCompleted"


def test_reduce_blue_finding_records_detection_and_objective() -> None:
    matched_event = RuntimeEvent(
        id="evt-7",
        event_type="InitialAccess",
        actor="red",
        time=1.0,
        source_entity="red",
        target_entity="svc-web",
        malicious=True,
        observability_surfaces=("web_access",),
    )

    transition = reduce_blue_finding(
        matched_event=matched_event,
        detected_event_ids=set(),
        blue_detected=False,
    )

    assert transition.blue_detected is True
    assert transition.detected_event_ids == {"evt-7"}
    assert transition.satisfied_objectives == (BLUE_DETECTION_OBJECTIVE,)
    assert transition.event_spec is not None
    assert transition.event_spec.event_type == "DetectionAlertRaised"


def test_reduce_blue_finding_keeps_false_positive_state() -> None:
    transition = reduce_blue_finding(
        matched_event=None,
        detected_event_ids={"evt-1"},
        blue_detected=True,
    )

    assert transition.blue_detected is True
    assert transition.detected_event_ids == {"evt-1"}
    assert transition.satisfied_objectives == ()
    assert transition.event_spec is None


def test_select_scripted_internal_blue_action_detects_before_containment() -> None:
    visible_events = (
        RuntimeEvent(
            id="evt-1",
            event_type="InitialAccess",
            actor="red",
            time=1.0,
            source_entity="red",
            target_entity="svc-web",
            malicious=True,
            observability_surfaces=("web_access",),
        ),
    )

    action = select_scripted_internal_blue_action(
        visible_events=visible_events,
        detected_event_ids=set(),
        remaining_red_targets={"svc-web"},
        contained_targets=set(),
        blue_detected=False,
    )

    assert action.kind == "submit_finding"
    assert action.payload == {"event_type": "InitialAccess", "target": "svc-web"}


def test_select_scripted_internal_blue_action_contains_after_detection() -> None:
    action = select_scripted_internal_blue_action(
        visible_events=(),
        detected_event_ids={"evt-1"},
        remaining_red_targets={"svc-db", "svc-web"},
        contained_targets={"svc-web"},
        blue_detected=True,
    )

    assert action.kind == "control"
    assert action.payload == {"target": "svc-db", "action": "contain"}


def test_reduce_observation_state_consumes_reward_and_marks_first_observation() -> None:
    visible_events = (
        RuntimeEvent(
            id="evt-1",
            event_type="InitialAccess",
            actor="red",
            time=1.0,
            source_entity="red",
            target_entity="svc-web",
            malicious=True,
        ),
        RuntimeEvent(
            id="evt-2",
            event_type="PatchApplied",
            actor="blue",
            time=2.0,
            source_entity="blue",
            target_entity="svc-web",
            malicious=False,
        ),
    )

    transition = reduce_observation_state(
        visible_events=visible_events,
        previous_reward_delta=0.3,
        observed_event_ids={"evt-0"},
        observation_count=0,
    )

    assert transition.reward_delta == 0.3
    assert transition.first_observation is True
    assert transition.next_observation_count == 1
    assert transition.observed_event_ids == {"evt-0", "evt-1", "evt-2"}
    assert {event.event_type for event in transition.alerts} == {
        "InitialAccess",
        "PatchApplied",
    }


def test_reduce_observation_state_leaves_non_session_reads_stateless() -> None:
    visible_events = (
        RuntimeEvent(
            id="evt-1",
            event_type=next(iter(OBSERVATION_ALERT_EVENT_TYPES)),
            actor="blue",
            time=1.0,
            source_entity="blue",
            target_entity="svc-web",
            malicious=False,
        ),
    )

    transition = reduce_observation_state(
        visible_events=visible_events,
        previous_reward_delta=0.0,
        observed_event_ids=set(),
        observation_count=None,
    )

    assert transition.first_observation is False
    assert transition.next_observation_count is None
    assert transition.alerts == visible_events


def test_control_directive_helpers_normalize_defaults() -> None:
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


def test_emit_runtime_event_applies_blue_delay_and_blindspots() -> None:
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


def test_visible_events_for_actor_filters_by_role_visibility() -> None:
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

    assert {event.id for event in blue_visible} == {"evt-2", "evt-3"}
    assert {event.id for event in red_visible} == {"evt-3"}
