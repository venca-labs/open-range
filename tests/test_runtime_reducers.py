from __future__ import annotations

from itertools import count

from open_range.admission.models import ReferenceAction
from open_range.execution import ActionExecution
from open_range.runtime_reducers import (
    BLUE_CONTAINMENT_OBJECTIVE,
    SERVICE_HEALTH_BLUE_OBJECTIVE,
    blue_objectives_after_continuity,
    continuity_for_service_health,
    reduce_blue_control,
    reduce_red_action,
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
