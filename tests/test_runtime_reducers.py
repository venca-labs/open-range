from __future__ import annotations

from itertools import count

from open_range.contracts.runtime import (
    Action,
    RuntimeEvent,
)
from open_range.contracts.validation import ReferenceAction
from open_range.runtime.execution import ActionExecution
from open_range.runtime.reducers import (
    DETECTABLE_EVENT_TYPES,
    OBSERVATION_ALERT_EVENT_TYPES,
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
    assert transition.event_spec is not None
    assert transition.event_spec.event_type == "ContainmentApplied"


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
    assert transition.initial_access_detected is True
    assert transition.detected_event_ids == {"evt-7"}
    assert transition.event_spec is not None
    assert transition.event_spec.event_type == "DetectionAlertRaised"


def test_reduce_blue_finding_keeps_false_positive_state() -> None:
    transition = reduce_blue_finding(
        matched_event=None,
        detected_event_ids={"evt-1"},
        blue_detected=True,
    )

    assert transition.blue_detected is True
    assert transition.initial_access_detected is False
    assert transition.detected_event_ids == {"evt-1"}
    assert transition.event_spec is None


def test_reduce_blue_finding_does_not_award_initial_access_objective_for_later_event() -> (
    None
):
    matched_event = RuntimeEvent(
        id="evt-9",
        event_type="CredentialObtained",
        actor="red",
        time=2.0,
        source_entity="svc-idp",
        target_entity="idp_admin_cred",
        malicious=True,
        observability_surfaces=("idp_auth",),
    )

    transition = reduce_blue_finding(
        matched_event=matched_event,
        detected_event_ids=set(),
        blue_detected=False,
    )

    assert transition.blue_detected is True
    assert transition.initial_access_detected is False


def test_reduce_blue_finding_ignores_duplicate_detection() -> None:
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
        detected_event_ids={"evt-7"},
        blue_detected=True,
    )

    assert transition.blue_detected is True
    assert transition.initial_access_detected is False
    assert transition.detected_event_ids == {"evt-7"}
    assert transition.event_spec is None
    assert transition.stdout == "finding already recorded"


def test_select_scripted_internal_blue_action_detects_before_containment() -> None:
    visible_events = (
        RuntimeEvent(
            id="evt-1",
            event_type="InitialAccess",
            actor="unknown",
            time=1.0,
            source_entity="unknown",
            target_entity="svc-web",
            malicious=False,
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


def test_reduce_observation_state_alerts_on_detectable_event_types() -> None:
    visible_events = tuple(
        RuntimeEvent(
            id="evt-1",
            event_type=next(iter(DETECTABLE_EVENT_TYPES)),
            actor="unknown",
            time=1.0,
            source_entity="unknown",
            target_entity="svc-web",
            malicious=False,
        )
        for _ in range(1)
    )

    transition = reduce_observation_state(
        visible_events=visible_events,
        previous_reward_delta=0.0,
        observed_event_ids=set(),
        observation_count=0,
    )

    assert transition.alerts == visible_events


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
