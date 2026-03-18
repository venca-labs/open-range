"""Shared candidate-generation helpers for training and evaluation."""

from __future__ import annotations

import json

from open_range.probe_planner import runtime_action
from open_range.runtime_types import Action, Observation
from open_range.snapshot import RuntimeSnapshot
from open_range.training_data import (
    TraceCandidate,
    normalize_trace_action,
    render_action_text,
)


def expected_step(steps, index: int):
    if not steps or index >= len(steps):
        return None
    return steps[index]


def teacher_action(snapshot: RuntimeSnapshot, actor: str, expected) -> Action:
    if expected is None:
        return Action(actor_id=actor, role=actor, kind="sleep", payload={})
    return normalize_trace_action(snapshot, runtime_action(actor, expected))


def candidate_actions(
    snapshot: RuntimeSnapshot,
    *,
    actor: str,
    observation: Observation,
    expected_action: Action,
    remaining_targets: set[str],
) -> tuple[TraceCandidate, ...]:
    candidates: list[TraceCandidate] = [
        TraceCandidate(
            label="teacher",
            action=expected_action,
            text=render_action_text(expected_action),
            selected=True,
            counterfactual_label="teacher",
        )
    ]
    if actor == "red":
        candidates.extend(_red_alternatives(expected_action))
    else:
        candidates.extend(
            _blue_alternatives(
                snapshot, observation, expected_action, remaining_targets
            )
        )
    return dedupe_candidates(candidates)


def select_candidate(
    candidates: tuple[TraceCandidate, ...], chosen_action: Action
) -> tuple[TraceCandidate, ...]:
    token = json.dumps(chosen_action.model_dump(mode="json"), sort_keys=True)
    selected = []
    matched = False
    for candidate in candidates:
        candidate_token = json.dumps(
            candidate.action.model_dump(mode="json"), sort_keys=True
        )
        is_match = candidate_token == token and not matched
        matched = matched or is_match
        selected.append(candidate.model_copy(update={"selected": is_match}))
    if matched:
        return tuple(selected)
    fallback = TraceCandidate(
        label="scripted_choice",
        action=chosen_action,
        text=render_action_text(chosen_action),
        selected=True,
        counterfactual_label="alternative",
    )
    return dedupe_candidates(selected + [fallback])


def scripted_choice(
    *,
    actor: str,
    observation: Observation,
    candidates: tuple[TraceCandidate, ...],
    decision_count: int,
) -> Action:
    by_label = {candidate.label: candidate for candidate in candidates}
    if actor == "red":
        if decision_count == 0:
            for label in ("root_probe", "web_probe", "recon_hosts", "recon_net"):
                candidate = by_label.get(label)
                if candidate is not None:
                    return candidate.action
        return by_label.get("teacher", candidates[0]).action
    malicious_visible = any(event.malicious for event in observation.visible_events)
    if malicious_visible:
        detect_now = by_label.get("detect_now")
        if detect_now is not None and decision_count == 0:
            return detect_now.action
    if decision_count == 0:
        false_positive = by_label.get("false_positive")
        if false_positive is not None and not malicious_visible:
            return false_positive.action
    if decision_count == 1:
        over_disruptive = by_label.get("over_disruptive")
        if over_disruptive is not None and malicious_visible:
            return over_disruptive.action
    return by_label.get("teacher", candidates[0]).action


def reference_trace_pairs(
    snapshot: RuntimeSnapshot, mode: str
) -> tuple[tuple[int, int], ...]:
    attack_count = max(1, len(snapshot.reference_bundle.reference_attack_traces))
    defense_count = max(1, len(snapshot.reference_bundle.reference_defense_traces))
    if mode == "red_only":
        return tuple((idx, idx % defense_count) for idx in range(attack_count))
    if mode in {"blue_only_live", "blue_only_from_prefix"}:
        return tuple((idx % attack_count, idx) for idx in range(defense_count))
    count = max(attack_count, defense_count)
    return tuple((idx % attack_count, idx % defense_count) for idx in range(count))


def trace_actions(
    snapshot: RuntimeSnapshot, actor: str, *, trace_index: int
) -> list[Action]:
    trace = (
        snapshot.reference_bundle.reference_attack_traces[trace_index]
        if actor == "red"
        else snapshot.reference_bundle.reference_defense_traces[trace_index]
    )
    actions = [runtime_action(actor, step) for step in trace.steps]
    if actions:
        return actions
    return [Action(actor_id=actor, role=actor, kind="sleep", payload={})]


def dedupe_candidates(candidates: list[TraceCandidate]) -> tuple[TraceCandidate, ...]:
    seen: set[tuple[str, str]] = set()
    deduped: list[TraceCandidate] = []
    selected_seen = False
    for candidate in candidates:
        token = (
            candidate.text,
            json.dumps(candidate.action.model_dump(mode="json"), sort_keys=True),
        )
        if token in seen:
            continue
        seen.add(token)
        if candidate.selected:
            if selected_seen:
                candidate = candidate.model_copy(update={"selected": False})
            selected_seen = True
        deduped.append(candidate)
    return tuple(deduped)


def _red_alternatives(expected_action: Action) -> list[TraceCandidate]:
    target = str(expected_action.payload.get("target", ""))
    alternatives: list[TraceCandidate] = []
    if expected_action.kind == "api":
        root_probe = Action(
            actor_id="red",
            role="red",
            kind="api",
            payload={"target": target, "path": "/"},
        )
        alternatives.append(
            TraceCandidate(
                label="root_probe",
                action=root_probe,
                text=render_action_text(root_probe),
                counterfactual_label="probe",
            )
        )
        if target != "svc-web":
            web_probe = Action(
                actor_id="red",
                role="red",
                kind="api",
                payload={"target": "svc-web", "path": "/"},
            )
            alternatives.append(
                TraceCandidate(
                    label="web_probe",
                    action=web_probe,
                    text=render_action_text(web_probe),
                    counterfactual_label="probe",
                )
            )
    else:
        recon_hosts = Action(
            actor_id="red",
            role="red",
            kind="shell",
            payload={"target": target, "command": "cat /etc/hosts"},
        )
        recon_net = Action(
            actor_id="red",
            role="red",
            kind="shell",
            payload={"target": target, "command": "ip -br a"},
        )
        alternatives.extend(
            [
                TraceCandidate(
                    label="recon_hosts",
                    action=recon_hosts,
                    text=render_action_text(recon_hosts),
                    counterfactual_label="probe",
                ),
                TraceCandidate(
                    label="recon_net",
                    action=recon_net,
                    text=render_action_text(recon_net),
                    counterfactual_label="probe",
                ),
            ]
        )
    sleep = Action(actor_id="red", role="red", kind="sleep", payload={})
    alternatives.append(
        TraceCandidate(
            label="sleep",
            action=sleep,
            text=render_action_text(sleep),
            counterfactual_label="sleep",
        )
    )
    return alternatives


def _blue_alternatives(
    snapshot: RuntimeSnapshot,
    observation: Observation,
    expected_action: Action,
    remaining_targets: set[str],
) -> list[TraceCandidate]:
    target = str(expected_action.payload.get("target", ""))
    alternatives: list[TraceCandidate] = []
    wrong_target = _service_not_in(
        snapshot,
        excluded={
            target,
            *{
                event.target_entity
                for event in observation.visible_events
                if event.malicious
            },
        },
    )
    if expected_action.kind == "submit_finding":
        false_positive = Action(
            actor_id="blue",
            role="blue",
            kind="submit_finding",
            payload={
                "event_type": str(
                    expected_action.payload.get("event_type", "InitialAccess")
                ),
                "target": wrong_target or "svc-email",
            },
        )
        alternatives.append(
            TraceCandidate(
                label="false_positive",
                action=false_positive,
                text=render_action_text(false_positive),
                counterfactual_label="false_positive",
            )
        )
    if expected_action.kind == "control":
        disruptive_target = (
            _service_not_in(snapshot, excluded={target, *remaining_targets})
            or wrong_target
            or target
        )
        disruptive = normalize_trace_action(
            snapshot,
            Action(
                actor_id="blue",
                role="blue",
                kind="control",
                payload={
                    "target": disruptive_target,
                    "action": str(expected_action.payload.get("action", "contain")),
                },
            ),
        )
        alternatives.append(
            TraceCandidate(
                label="over_disruptive",
                action=disruptive,
                text=render_action_text(disruptive),
                counterfactual_label="continuity_damaging",
            )
        )
    if expected_action.kind != "submit_finding" and observation.visible_events:
        visible = next(
            (event for event in observation.visible_events if event.malicious),
            observation.visible_events[0],
        )
        opportunistic = Action(
            actor_id="blue",
            role="blue",
            kind="submit_finding",
            payload={"event_type": visible.event_type, "target": visible.target_entity},
        )
        alternatives.append(
            TraceCandidate(
                label="detect_now",
                action=opportunistic,
                text=render_action_text(opportunistic),
                counterfactual_label="alternative",
            )
        )
    sleep = Action(actor_id="blue", role="blue", kind="sleep", payload={})
    alternatives.append(
        TraceCandidate(
            label="sleep",
            action=sleep,
            text=render_action_text(sleep),
            counterfactual_label="sleep",
        )
    )
    return alternatives


def _service_not_in(snapshot: RuntimeSnapshot, *, excluded: set[str]) -> str:
    for preferred in (
        "svc-email",
        "svc-web",
        "svc-idp",
        "svc-fileshare",
        "svc-db",
        "svc-siem",
    ):
        if preferred not in excluded and any(
            service.id == preferred for service in snapshot.world.services
        ):
            return preferred
    for service in snapshot.world.services:
        if service.id not in excluded:
            return service.id
    return ""
