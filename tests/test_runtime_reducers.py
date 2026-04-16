from __future__ import annotations

from itertools import count

from open_range.admission.models import ReferenceAction
from open_range.execution import ActionExecution
from open_range.runtime_reducers import (
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
from open_range.runtime_types import Action, RuntimeEvent


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


def test_continuity_for_service_health_keeps_current_average_rule() -> None:
    assert continuity_for_service_health({}) == 1.0
    assert continuity_for_service_health({"svc-web": 1.0, "svc-db": 0.5}) == 0.75


def test_blue_objectives_after_continuity_keeps_service_health_rule() -> None:
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

    assert reduction.stdout == "red action had no strategic effect"
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

    assert reduction.stdout == "red advanced on svc-web"
    assert reduction.stderr == ""
    assert reduction.progress_advanced is True
    assert reduction.advanced_target == "svc-web"
    assert len(reduction.emitted_events) == 1
    assert reduction.emitted_events[0].event_type == "InitialAccess"


def test_reduce_red_action_uses_generic_stdout_for_nonmatching_action() -> None:
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

    assert reduction.stdout == "red executed on svc-web"
    assert reduction.stderr == ""
    assert reduction.progress_advanced is False
    assert reduction.emitted_events == ()


def test_reduce_blue_control_keeps_path_breaking_containment_policy() -> None:
    transition = reduce_blue_control(
        target="svc-web",
        directive="contain",
        live=ActionExecution(containment_applied=True, ok=True),
        remaining_red_targets={"svc-web"},
        contained_targets=set(),
        patched_targets=set(),
    )

    assert transition.stdout == "containment applied to svc-web"
    assert transition.path_broken is True
    assert transition.contained_targets == {"svc-web"}
    assert transition.patched_targets == set()
    assert transition.event_spec is not None
    assert transition.event_spec.event_type == "ContainmentApplied"
    assert transition.event_spec.linked_objective_predicates == (
        BLUE_CONTAINMENT_OBJECTIVE,
    )


def test_reduce_blue_control_keeps_nonbreaking_mitigation_wording() -> None:
    transition = reduce_blue_control(
        target="svc-web",
        directive="mitigate",
        live=ActionExecution(patch_applied=True, ok=True),
        remaining_red_targets=set(),
        contained_targets={"svc-web"},
        patched_targets=set(),
    )

    assert transition.stdout == "mitigation on svc-web did not break the remaining path"
    assert transition.path_broken is False
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
    )

    assert transition.stdout == "recovery applied to svc-web"
    assert transition.path_broken is False
    assert transition.contained_targets == set()
    assert transition.patched_targets == set()
    assert transition.event_spec is not None
    assert transition.event_spec.event_type == "RecoveryCompleted"


def test_reduce_blue_finding_keeps_detection_event_and_objective_policy() -> None:
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

    assert transition.stdout == "validated finding for InitialAccess"
    assert transition.blue_detected is True
    assert transition.detected_event_ids == {"evt-7"}
    assert transition.satisfied_objectives == (BLUE_DETECTION_OBJECTIVE,)
    assert transition.event_spec is not None
    assert transition.event_spec.event_type == "DetectionAlertRaised"


def test_reduce_blue_finding_keeps_false_positive_path() -> None:
    transition = reduce_blue_finding(
        matched_event=None,
        detected_event_ids={"evt-1"},
        blue_detected=True,
    )

    assert transition.stdout == "finding rejected as false positive"
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


def test_reduce_observation_state_keeps_non_session_reads_stateless() -> None:
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
