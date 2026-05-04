"""Pure derivations from event streams: activity, actors, and health."""

from __future__ import annotations

from collections.abc import Mapping, Sequence


def activity_summary(events: Sequence[Mapping[str, object]]) -> Mapping[str, object]:
    event_types: dict[str, int] = {}
    actors: dict[str, int] = {}
    actor_kinds: dict[str, int] = {}
    for event in events:
        increment(event_types, str(event.get("type", "")))
        increment(actors, str(event.get("actor", "")))
        data = event.get("data")
        actor_kind = "event"
        if isinstance(data, Mapping):
            actor_kind = str(data.get("actor_kind", actor_kind))
        increment(actor_kinds, actor_kind)
    return {
        "event_types": event_types,
        "actors": actors,
        "actor_kinds": actor_kinds,
    }


def actor_summaries(events: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    summaries: dict[str, dict[str, object]] = {}
    counts_by_actor: dict[str, int] = {}
    targets_by_actor: dict[str, set[str]] = {}
    history_by_actor: dict[str, list[dict[str, object]]] = {}
    for event in events:
        actor = str(event.get("actor", ""))
        summary = summaries.setdefault(
            actor,
            {
                "actor_id": actor,
                "actor_kind": "event",
                "event_count": 0,
                "targets": [],
                "latest_event_type": "",
                "latest_action": None,
                "latest_observation": None,
                "history": [],
            },
        )
        counts_by_actor[actor] = counts_by_actor.get(actor, 0) + 1
        summary["event_count"] = counts_by_actor[actor]
        event_type = str(event.get("type", ""))
        target = str(event.get("target", ""))
        targets_by_actor.setdefault(actor, set()).add(target)
        data = event.get("data")
        actor_kind = "event"
        action: object = None
        observation: object = None
        if isinstance(data, Mapping):
            actor_kind = str(data.get("actor_kind", actor_kind))
            action = data.get("action")
            observation = data.get("observation")
        summary["actor_kind"] = actor_kind
        summary["latest_event_type"] = event_type
        summary["latest_action"] = action
        summary["latest_observation"] = observation
        history_by_actor.setdefault(actor, []).append(
            {
                "event_type": event_type,
                "target": target,
                "action": action,
                "observation": observation,
            },
        )
    return [
        actor_summary(
            summaries[actor],
            targets_by_actor[actor],
            history_by_actor[actor],
        )
        for actor in sorted(summaries)
    ]


def actor_summary(
    summary: Mapping[str, object],
    targets: set[str],
    history: list[dict[str, object]],
) -> dict[str, object]:
    return {
        **dict(summary),
        "targets": sorted(targets),
        "history": history[-10:],
    }


def increment(counts: dict[str, int], key: str) -> None:
    counts[key] = counts.get(key, 0) + 1


def health_summary(events: Sequence[Mapping[str, object]]) -> dict[str, float]:
    values = {"uptime": 100.0, "defense": 100.0, "integrity": 100.0}
    found: set[str] = set()
    for event in reversed(events):
        data = event.get("data")
        if not isinstance(data, Mapping):
            continue
        state = data.get("state")
        if not isinstance(state, Mapping):
            continue
        update_health_value(values, found, "uptime", state, "uptime")
        update_health_value(values, found, "uptime", state, "continuity")
        update_health_value(values, found, "defense", state, "defense")
        update_health_reward(values, found, "defense", state, "blue_reward")
        update_health_value(values, found, "integrity", state, "integrity")
        update_health_reward(values, found, "integrity", state, "red_reward")
        if len(found) == len(values):
            break
    return values


def update_health_value(
    values: dict[str, float],
    found: set[str],
    metric: str,
    state: Mapping[str, object],
    key: str,
) -> None:
    if metric in found:
        return
    percent = percent_value(state.get(key))
    if percent is None:
        return
    values[metric] = percent
    found.add(metric)


def update_health_reward(
    values: dict[str, float],
    found: set[str],
    metric: str,
    state: Mapping[str, object],
    key: str,
) -> None:
    if metric in found:
        return
    reward = numeric_value(state.get(key))
    if reward is None:
        return
    values[metric] = clamp_percent(100.0 - abs(reward) * 100.0)
    found.add(metric)


def percent_value(value: object) -> float | None:
    number = numeric_value(value)
    if number is None:
        return None
    if 0.0 <= number <= 1.0:
        return clamp_percent(number * 100.0)
    return clamp_percent(number)


def numeric_value(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def clamp_percent(value: float) -> float:
    return min(100.0, max(0.0, value))
