"""Offline public witness matching for weakness-driven actions."""

from __future__ import annotations

from open_range.contracts.runtime import Action, action_target
from open_range.contracts.world import WeaknessSpec, WorldIR
from open_range.objectives.engine import PredicateEngine

from . import build_reference_plan_for_weakness


def offline_witness_stdout(
    world: WorldIR,
    action: Action,
    active_weaknesses: tuple[WeaknessSpec, ...],
) -> str:
    engine = PredicateEngine(world)
    for weakness in sorted(active_weaknesses, key=lambda item: (item.target, item.id)):
        for step in _offline_witness_steps(world, engine, weakness):
            if _public_action_matches_step(action, step):
                return str(step.payload.get("expect_contains", ""))
    return ""


def _offline_witness_steps(
    world: WorldIR,
    engine: PredicateEngine,
    weakness: WeaknessSpec,
) -> tuple[Action, ...]:
    starts = dict.fromkeys((weakness.target, ""))
    steps: list[Action] = []
    seen: set[tuple[object, ...]] = set()
    for start in starts:
        for step in build_reference_plan_for_weakness(
            world,
            engine,
            start,
            weakness,
        ).steps:
            key = (
                step.kind,
                step.target,
                str(step.payload.get("path", "")),
                tuple(sorted(dict(step.payload.get("query", {})).items()))
                if isinstance(step.payload.get("query"), dict)
                else (),
                str(step.payload.get("to", "")),
                str(step.payload.get("subject", "")),
                str(step.payload.get("expect_contains", "")),
            )
            if key in seen:
                continue
            seen.add(key)
            steps.append(step)
    return tuple(steps)


def _public_action_matches_step(action: Action, step: Action) -> bool:
    if action.kind != step.kind or action_target(action) != step.target:
        return False
    payload = action.payload
    expected = step.payload
    if action.kind == "api":
        return str(payload.get("path", "")) == str(expected.get("path", "")) and (
            dict(payload.get("query", {}))
            if isinstance(payload.get("query"), dict)
            else {}
        ) == (
            dict(expected.get("query", {}))
            if isinstance(expected.get("query"), dict)
            else {}
        )
    if action.kind == "shell":
        expected_path = str(expected.get("path", ""))
        if expected_path:
            return str(payload.get("path", "")) == expected_path
        expected_command = str(expected.get("command", ""))
        if expected_command:
            return str(payload.get("command", "")) == expected_command
        return True
    if action.kind == "mail":
        return str(payload.get("to", "")) == str(expected.get("to", "")) and str(
            payload.get("subject", "")
        ) == str(expected.get("subject", ""))
    return False
