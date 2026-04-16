"""Private reference-trace and probe planning for admission."""

from __future__ import annotations

import json
from dataclasses import dataclass

from open_range.admission import (
    ProbeSpec,
    ReferenceAction,
    ReferenceBundle,
    ReferenceTrace,
)
from open_range.build_config import DEFAULT_BUILD_CONFIG, BuildConfig
from open_range.catalog.contracts import ProbeTemplateSpec
from open_range.catalog.probes import (
    DEFAULT_DETERMINISM_PROBE_TEMPLATES,
    DEFAULT_SHORTCUT_PROBE_TEMPLATES,
    detection_for_reference_step_action,
    family_supports_primary_red_reference,
    is_blue_detectable_action,
    necessity_probe_template,
    red_reference_family_priority,
    smoke_probe_template,
)
from open_range.predicates import PredicateEngine
from open_range.runtime_types import Action
from open_range.weakness_families import (
    build_red_reference_plan_for_family,
)
from open_range.world_ir import WorldIR


@dataclass(frozen=True, slots=True)
class ProbePlanner:
    """Construct bounded private reference traces and probes for one world."""

    world: WorldIR
    build_config: BuildConfig = DEFAULT_BUILD_CONFIG

    def build(self) -> ReferenceBundle:
        reference_attack_traces = self.build_red_references()
        reference_defense_traces = self.build_blue_references(reference_attack_traces)
        smoke_tests = tuple(
            _probe_spec_from_template(smoke_probe_template(service.id))
            for service in self.world.services
        )
        shortcut_probes = tuple(
            _probe_spec_from_template(template)
            for template in DEFAULT_SHORTCUT_PROBE_TEMPLATES
        )
        determinism_probes = tuple(
            _probe_spec_from_template(template)
            for template in DEFAULT_DETERMINISM_PROBE_TEMPLATES
        )
        engine = PredicateEngine(self.world)
        necessity_probes = tuple(
            _probe_spec_from_template(necessity_probe_template(weak.id))
            for weak in engine.active_weaknesses()
        )
        return ReferenceBundle(
            reference_attack_traces=reference_attack_traces,
            reference_defense_traces=reference_defense_traces,
            smoke_tests=smoke_tests,
            shortcut_probes=shortcut_probes,
            determinism_probes=determinism_probes,
            necessity_probes=necessity_probes,
        )

    def build_red_references(self) -> tuple[ReferenceTrace, ...]:
        engine = PredicateEngine(self.world)
        starts = tuple(
            service.id
            for service in self.world.services
            if engine.is_public_service(service)
        ) or (self.world.services[0].id,)
        weaknesses = engine.active_weaknesses()
        ranked = sorted(
            weaknesses,
            key=lambda weak: _red_reference_sort_key(
                weak,
                preferred_targets=frozenset(starts),
            ),
        )
        candidates = [
            (start, weak)
            for weak in ranked
            for start in _starts_for_weakness(starts, weak.target)
        ]
        if not candidates:
            candidates = [(starts[0], None)]
        traces: list[ReferenceTrace] = []
        seen: set[str] = set()
        for start, exploit in candidates:
            trace = self.build_red_reference(
                start=start, exploit=exploit, ordinal=len(traces) + 1
            )
            token = json.dumps(
                trace.model_dump(mode="json", exclude={"id"}), sort_keys=True
            )
            if token in seen:
                continue
            seen.add(token)
            traces.append(trace)
            if len(traces) >= self.build_config.red_reference_count:
                break
        if not traces:
            traces.append(
                self.build_red_reference(start=starts[0], exploit=None, ordinal=1)
            )
        return tuple(traces)

    def build_blue_references(
        self, attack_traces: tuple[ReferenceTrace, ...]
    ) -> tuple[ReferenceTrace, ...]:
        if not attack_traces:
            attack_traces = (self.build_red_reference(ordinal=1),)
        count = max(1, self.build_config.blue_reference_count)
        return tuple(
            self.build_blue_reference(
                attack_traces[idx % len(attack_traces)], ordinal=idx + 1
            )
            for idx in range(count)
        )

    def build_red_reference(
        self,
        *,
        start: str | None = None,
        exploit=None,
        ordinal: int = 1,
    ) -> ReferenceTrace:
        engine = PredicateEngine(self.world)
        start = start or next(
            (
                service.id
                for service in self.world.services
                if engine.is_public_service(service)
            ),
            self.world.services[0].id,
        )
        weaknesses = engine.active_weaknesses()
        exploit = exploit or _primary_red_weakness(start, weaknesses)
        satisfied_predicates: set[str] = set()
        steps: list[ReferenceAction] = []
        current = start
        if exploit is not None:
            exploit_steps, current, satisfied_predicates = _weakness_red_steps(
                self.world, engine, start, exploit
            )
            steps.extend(exploit_steps)
        if not steps:
            steps.append(
                ReferenceAction(
                    actor="red",
                    kind="api",
                    target=start,
                    payload={"action": "initial_access"},
                )
            )
        for objective in self.world.red_objectives:
            if objective.predicate in satisfied_predicates:
                continue
            target = engine.objective_target_service(objective.predicate) or current
            path = engine.shortest_path(current, target)
            for service_id in path[1:]:
                steps.append(
                    ReferenceAction(
                        actor="red",
                        kind="api",
                        target=service_id,
                        payload={"action": "traverse"},
                    )
                )
            asset = engine.objective_target_asset(objective.predicate)
            steps.append(
                ReferenceAction(
                    actor="red",
                    kind="api",
                    target=target,
                    payload={
                        "action": "satisfy_objective",
                        "asset": asset.id if asset else "",
                        "objective": objective.predicate,
                    },
                )
            )
            current = target

        events: list[str] = []
        for weak in (exploit,) if exploit is not None else weaknesses:
            if weak is None:
                continue
            events.extend(weak.expected_event_signatures)
        return ReferenceTrace(
            id=f"red-{self.world.world_id}-{ordinal}",
            role="red",
            objective_ids=tuple(
                objective.id for objective in self.world.red_objectives
            ),
            expected_events=tuple(dict.fromkeys(events + ["SensitiveAssetRead"])),
            steps=tuple(steps),
        )

    def build_blue_reference(
        self, red_trace: ReferenceTrace, *, ordinal: int = 1
    ) -> ReferenceTrace:
        blindspot_targets = {
            weak.target
            for weak in PredicateEngine(self.world).active_weaknesses()
            if weak.family == "telemetry_blindspot"
        }
        detect_index = next(
            (
                index
                for index, step in enumerate(red_trace.steps)
                if is_blue_detectable_action(
                    str(step.payload.get("action", "")),
                    target=step.target,
                    source_target=(
                        red_trace.steps[index - 1].target if index > 0 else ""
                    ),
                    blindspot_targets=blindspot_targets,
                )
            ),
            0,
        )
        detect_step = red_trace.steps[detect_index] if red_trace.steps else None
        detect_event, detect_target = detection_for_reference_step_action(
            str(detect_step.payload.get("action", "")) if detect_step else "",
            target=detect_step.target if detect_step else "",
            asset=str(detect_step.payload.get("asset", "")) if detect_step else "",
            objective=(
                str(detect_step.payload.get("objective", "")) if detect_step else ""
            ),
        )
        contain_target = red_trace.steps[-1].target if red_trace.steps else "svc-siem"
        observe_steps = tuple(
            ReferenceAction(
                actor="blue",
                kind="shell",
                target="svc-siem",
                payload={"action": "observe_events"},
            )
            for _ in range(max(1, detect_index + 1))
        )
        return ReferenceTrace(
            id=f"blue-{self.world.world_id}-{ordinal}",
            role="blue",
            objective_ids=tuple(
                objective.id for objective in self.world.blue_objectives
            ),
            expected_events=("DetectionAlertRaised", "ContainmentApplied"),
            steps=observe_steps
            + (
                ReferenceAction(
                    actor="blue",
                    kind="submit_finding",
                    target=detect_target,
                    payload={"event": detect_event},
                ),
                ReferenceAction(
                    actor="blue",
                    kind="control",
                    target=contain_target,
                    payload={"action": "contain"},
                ),
            ),
        )


def build_reference_bundle(
    world: WorldIR, build_config: BuildConfig = DEFAULT_BUILD_CONFIG
) -> ReferenceBundle:
    return ProbePlanner(world=world, build_config=build_config).build()


def runtime_action(actor: str, step: ReferenceAction) -> Action:
    payload = dict(step.payload)
    if step.target:
        payload.setdefault("target", step.target)
    if actor == "blue" and step.kind == "submit_finding":
        event_type = str(
            payload.get("event", payload.get("event_type", "InitialAccess"))
        )
        payload["event_type"] = event_type
    return Action(actor_id=actor, role=actor, kind=step.kind, payload=payload)


def _probe_spec_from_template(template: ProbeTemplateSpec) -> ProbeSpec:
    return ProbeSpec(
        id=template.id,
        kind=template.kind,
        description=template.description,
        command=template.command,
    )


def _primary_red_weakness(start: str, weaknesses):
    ranked = [
        weak
        for weak in weaknesses
        if family_supports_primary_red_reference(weak.family)
    ]
    if not ranked:
        return next(iter(weaknesses), None)
    ranked.sort(
        key=lambda weak: _red_reference_sort_key(
            weak,
            preferred_targets=frozenset((start,)),
        )
    )
    return ranked[0]


def _red_reference_sort_key(
    weakness,
    *,
    preferred_targets: frozenset[str],
) -> tuple[int, int, str]:
    return (
        0 if weakness.target in preferred_targets else 1,
        red_reference_family_priority(weakness.family),
        weakness.id,
    )


def _starts_for_weakness(starts: tuple[str, ...], target: str) -> tuple[str, ...]:
    if target in starts:
        return (target,) + tuple(start for start in starts if start != target)
    return starts


def _weakness_red_steps(
    world,
    engine: PredicateEngine,
    start: str,
    weakness,
) -> tuple[list[ReferenceAction], str, set[str]]:
    plan = build_red_reference_plan_for_family(world, engine, start, weakness)
    return list(plan.steps), plan.current, set(plan.satisfied_predicates)
