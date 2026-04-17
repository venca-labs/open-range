"""Private reference planning and execution for admission."""

from __future__ import annotations

import json
from dataclasses import dataclass

from open_range.admission.actions import runtime_action
from open_range.admission.models import (
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
    blue_containment_payload,
    blue_observe_reference_payload,
    blue_reference_expected_events,
    blue_reference_plan_for_trace,
    blue_submit_finding_payload,
    necessity_probe_template,
    ordered_red_reference_candidates,
    red_reference_starts,
    select_primary_red_reference_weakness,
    smoke_probe_template,
    telemetry_blindspot_targets,
)
from open_range.episode_config import EpisodeConfig
from open_range.objectives.engine import PredicateEngine
from open_range.runtime.execution import PodActionBackend
from open_range.runtime_types import Action
from open_range.snapshot import RuntimeSnapshot
from open_range.weaknesses import build_reference_plan_for_weakness
from open_range.world_ir import WorldIR


@dataclass(frozen=True, slots=True)
class ReferencePlanner:
    """Build bounded private reference traces and probes for one world."""

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
        starts = _reference_starts(self.world, engine)
        weaknesses = engine.active_weaknesses()
        candidates = ordered_red_reference_candidates(starts, weaknesses)
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
        start = start or next(iter(_reference_starts(self.world, engine)), "")
        weaknesses = engine.active_weaknesses()
        exploit = exploit or select_primary_red_reference_weakness(start, weaknesses)
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
            resolved = engine.resolve_objective(objective.predicate)
            target = resolved.target_service or current
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
            steps.append(
                ReferenceAction(
                    actor="red",
                    kind="api",
                    target=target,
                    payload={
                        "action": "satisfy_objective",
                        "asset": (
                            resolved.target_id
                            if resolved.target_kind == "asset"
                            else ""
                        ),
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
        objective_events = [
            resolved.event_type
            for resolved in (
                engine.resolve_objective(objective.predicate)
                for objective in self.world.red_objectives
            )
            if resolved.event_type
        ]
        return ReferenceTrace(
            id=f"red-{self.world.world_id}-{ordinal}",
            role="red",
            objective_ids=tuple(
                objective.id for objective in self.world.red_objectives
            ),
            expected_events=tuple(dict.fromkeys(events + objective_events)),
            steps=tuple(steps),
        )

    def build_blue_reference(
        self, red_trace: ReferenceTrace, *, ordinal: int = 1
    ) -> ReferenceTrace:
        plan = blue_reference_plan_for_trace(
            red_trace,
            blindspot_targets=telemetry_blindspot_targets(self.world),
        )
        observe_steps = tuple(
            ReferenceAction(
                actor="blue",
                kind="shell",
                target="svc-siem",
                payload=blue_observe_reference_payload(),
            )
            for _ in range(plan.observe_step_count)
        )
        return ReferenceTrace(
            id=f"blue-{self.world.world_id}-{ordinal}",
            role="blue",
            objective_ids=tuple(
                objective.id for objective in self.world.blue_objectives
            ),
            expected_events=blue_reference_expected_events(),
            steps=observe_steps
            + (
                ReferenceAction(
                    actor="blue",
                    kind="submit_finding",
                    target=plan.detect_target,
                    payload=blue_submit_finding_payload(detect_event=plan.detect_event),
                ),
                ReferenceAction(
                    actor="blue",
                    kind="control",
                    target=plan.contain_target,
                    payload=blue_containment_payload(),
                ),
            ),
        )


def build_reference_bundle(
    world: WorldIR, build_config: BuildConfig = DEFAULT_BUILD_CONFIG
) -> ReferenceBundle:
    return ReferencePlanner(world=world, build_config=build_config).build()


def run_red_reference(
    snapshot: RuntimeSnapshot,
    backend: PodActionBackend | None = None,
    *,
    episode_seed: int,
    trace_index: int = 0,
):
    from open_range.runtime import OpenRangeRuntime

    del episode_seed
    trace = snapshot.reference_bundle.reference_attack_traces[trace_index]
    runtime = OpenRangeRuntime(action_backend=backend)
    runtime.reset(
        snapshot,
        EpisodeConfig(
            mode="red_only",
            opponent_blue="none",
            episode_horizon_minutes=max(5, len(trace.steps) + 2),
        ),
        reference_attack_index=trace_index,
    )
    outputs: list[str] = []
    for step in trace.steps:
        try:
            decision = runtime.next_decision()
        except RuntimeError:
            if runtime.state().done:
                break
            raise
        if decision.actor != "red":
            break
        result = runtime.act("red", runtime_action("red", step))
        outputs.append(result.stdout or result.stderr)
    score = runtime.score()
    events = tuple(event.model_dump(mode="json") for event in runtime.export_events())
    health = tuple(sorted(runtime.state().service_health.items()))
    return score, events, health, outputs


def run_blue_reference(
    snapshot: RuntimeSnapshot,
    backend: PodActionBackend | None = None,
    *,
    trace_index: int = 0,
):
    from open_range.runtime import OpenRangeRuntime

    trace = snapshot.reference_bundle.reference_defense_traces[trace_index]
    attack_index = trace_index % max(
        1, len(snapshot.reference_bundle.reference_attack_traces)
    )
    runtime = OpenRangeRuntime(action_backend=backend)
    runtime.reset(
        snapshot,
        EpisodeConfig(
            mode="blue_only_live",
            opponent_red="reference",
            episode_horizon_minutes=max(6, len(trace.steps) + 3),
        ),
        reference_attack_index=attack_index,
        reference_defense_index=trace_index,
    )
    outputs: list[str] = []
    step_idx = 0
    while not runtime.state().done:
        try:
            decision = runtime.next_decision()
        except RuntimeError:
            if runtime.state().done:
                break
            raise
        step = trace.steps[step_idx] if step_idx < len(trace.steps) else None
        action = (
            runtime_action("blue", step)
            if step is not None
            else Action(actor_id="blue", role="blue", kind="sleep", payload={})
        )
        result = runtime.act("blue", action)
        outputs.append(result.stdout or result.stderr)
        if decision.actor != "blue":
            break
        if step is not None:
            step_idx += 1
    return runtime.score(), outputs


def _reference_starts(world: WorldIR, engine: PredicateEngine) -> tuple[str, ...]:
    return red_reference_starts(
        tuple(service.id for service in world.services),
        public_service_ids=tuple(
            service.id
            for service in world.services
            if engine.is_public_service(service)
        ),
    )


def _probe_spec_from_template(template: ProbeTemplateSpec) -> ProbeSpec:
    return ProbeSpec(
        id=template.id,
        kind=template.kind,
        description=template.description,
        command=template.command,
    )


def _weakness_red_steps(
    world,
    engine: PredicateEngine,
    start: str,
    weakness,
) -> tuple[list[ReferenceAction], str, set[str]]:
    plan = build_reference_plan_for_weakness(world, engine, start, weakness)
    return list(plan.steps), plan.current, set(plan.satisfied_predicates)
