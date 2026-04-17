"""Internal helpers for replaying reference traces through the runtime."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from open_range.async_utils import run_async
from open_range.catalog.probes import runtime_payload_for_reference_action
from open_range.episode_config import EpisodeConfig
from open_range.objectives import evaluate_objective_grader_live
from open_range.objectives.engine import PredicateEngine
from open_range.runtime.execution import PodActionBackend, clear_runtime_markers
from open_range.runtime_types import (
    Action,
    RuntimeEvent,
    action_target,
    control_directive,
    control_directive_from_payload,
    finding_event_type,
    finding_event_type_from_payload,
)
from open_range.snapshot import RuntimeSnapshot
from open_range.training.trace_exports import normalize_trace_action
from open_range.weaknesses import remediation_command_for_weakness

if TYPE_CHECKING:
    from open_range.render.live import BootedRelease


@dataclass(frozen=True, slots=True)
class ReferencePlayback:
    snapshot: RuntimeSnapshot
    attack_index: int
    defense_index: int

    @classmethod
    def resolve(
        cls,
        snapshot: RuntimeSnapshot,
        *,
        reset_seq: int,
        requested_attack_index: int | None,
        requested_defense_index: int | None,
    ) -> ReferencePlayback:
        attack_count = len(snapshot.reference_bundle.reference_attack_traces)
        attack_index = cls._resolve_index(
            requested_attack_index,
            attack_count,
            fallback=0,
            reset_seq=reset_seq,
        )
        defense_count = len(snapshot.reference_bundle.reference_defense_traces)
        defense_index = cls._resolve_index(
            requested_defense_index,
            defense_count,
            fallback=attack_index,
            reset_seq=reset_seq,
        )
        return cls(
            snapshot=snapshot,
            attack_index=attack_index,
            defense_index=defense_index,
        )

    def attack_trace(self):
        traces = self.snapshot.reference_bundle.reference_attack_traces
        return traces[self.attack_index % len(traces)]

    def defense_trace(self):
        traces = self.snapshot.reference_bundle.reference_defense_traces
        return traces[self.defense_index % len(traces)]

    def next_step(self, actor: str, progress: int):
        trace = self.attack_trace() if actor == "red" else self.defense_trace()
        if progress >= len(trace.steps):
            return None
        return trace.steps[progress]

    @staticmethod
    def _resolve_index(
        requested: int | None,
        count: int,
        *,
        fallback: int,
        reset_seq: int,
    ) -> int:
        if count < 1:
            return 0
        if requested is not None:
            return requested % count
        return (fallback + reset_seq - 1) % count


@dataclass(frozen=True, slots=True)
class ReferenceCheck:
    name: str
    passed: bool
    details: dict[str, Any]
    error: str = ""


def _reference_check(
    name: str, passed: bool, details: dict[str, Any], *, error_message: str
) -> ReferenceCheck:
    return ReferenceCheck(
        name=name,
        passed=passed,
        details=details,
        error="" if passed else error_message,
    )


def action_for_reference_step(
    snapshot: RuntimeSnapshot, actor: str, step: Any | None
) -> Action:
    if step is None:
        return Action(actor_id=actor, role=actor, kind="sleep", payload={})
    return normalize_trace_action(snapshot, runtime_action(actor, step))


def runtime_action(actor: str, step: Any) -> Action:
    payload = runtime_payload_for_reference_action(
        actor,
        getattr(step, "kind", ""),
        target=getattr(step, "target", ""),
        payload=dict(getattr(step, "payload", {})),
    )
    return Action(
        actor_id=actor,
        role=actor,
        kind=getattr(step, "kind", ""),
        payload=payload,
    )


def reference_trace_bindings(
    attack_traces: tuple[Any, ...], active_weaknesses: tuple[Any, ...]
) -> tuple[tuple[int, Any, Any], ...]:
    weakness_by_id = {str(weakness.id): weakness for weakness in active_weaknesses}
    bindings = []
    for trace_index, trace in enumerate(attack_traces):
        weakness = weakness_by_id.get(
            next(
                (
                    step.payload.get("weakness_id") or step.payload.get("weakness")
                    for step in getattr(trace, "steps", ())
                    if isinstance(
                        step.payload.get("weakness_id") or step.payload.get("weakness"),
                        str,
                    )
                ),
                "",
            )
        )
        if weakness is not None:
            bindings.append((trace_index, trace, weakness))
    return tuple(bindings)


def run_red_reference(
    snapshot: RuntimeSnapshot,
    backend: PodActionBackend | None = None,
    trace_index: int = 0,
):
    from open_range.runtime import OpenRangeRuntime

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


def check_red_reference(
    snapshot: RuntimeSnapshot,
    *,
    backend: PodActionBackend | None = None,
    release: BootedRelease | None = None,
    name: str = "red_reference",
    error_message: str = "offline red reference did not satisfy terminal objectives",
) -> ReferenceCheck:
    predicates = PredicateEngine(snapshot.world)
    per_trace = []
    passed = True
    satisfied_all: set[str] = set()
    for trace_index, trace in enumerate(
        snapshot.reference_bundle.reference_attack_traces
    ):
        score, events, health, outputs = run_red_reference(
            snapshot,
            backend,
            trace_index=trace_index,
        )
        satisfied = _satisfied_red_predicates(
            snapshot,
            predicates,
            events=events,
            health=health,
            outputs=outputs,
            release=release,
        )
        trace_passed = (
            score.winner == "red"
            and score.done
            and predicates.red_terminal_satisfied(satisfied)
        )
        passed = passed and trace_passed
        satisfied_all.update(satisfied)
        per_trace.append(
            {
                "trace_id": trace.id,
                "step_count": len(trace.steps),
                "winner": score.winner,
                "event_count": len(events),
                "satisfied_predicates": sorted(satisfied),
                "outputs": outputs,
                "passed": trace_passed,
            }
        )
    return _reference_check(
        name,
        passed,
        {
            "trace_count": len(per_trace),
            "satisfied_predicates": sorted(satisfied_all),
            "traces": per_trace,
        },
        error_message=error_message,
    )


def check_blue_reference(
    snapshot: RuntimeSnapshot,
    *,
    backend: PodActionBackend | None = None,
    name: str = "blue_reference",
    error_message: str = "offline blue reference did not validate detect-and-contain path",
) -> ReferenceCheck:
    per_trace = []
    passed = True
    for trace_index, trace in enumerate(
        snapshot.reference_bundle.reference_defense_traces
    ):
        from open_range.runtime import OpenRangeRuntime

        runtime = OpenRangeRuntime(action_backend=backend)
        runtime.reset(
            snapshot,
            EpisodeConfig(
                mode="blue_only_live",
                opponent_red="reference",
                episode_horizon_minutes=max(6, len(trace.steps) + 3),
            ),
            reference_attack_index=trace_index
            % max(1, len(snapshot.reference_bundle.reference_attack_traces)),
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
        score = runtime.score()
        trace_passed = (
            score.winner == "blue"
            and score.done
            and len(trace.objective_ids) <= len(snapshot.world.blue_objectives)
        )
        passed = passed and trace_passed
        per_trace.append(
            {
                "trace_id": trace.id,
                "step_count": len(trace.steps),
                "winner": score.winner,
                "terminal_reason": score.terminal_reason,
                "outputs": outputs,
                "passed": trace_passed,
            }
        )
    return _reference_check(
        name,
        passed,
        {"trace_count": len(per_trace), "traces": per_trace},
        error_message=error_message,
    )


def check_determinism(
    snapshot: RuntimeSnapshot,
    *,
    backend: PodActionBackend | None = None,
    reference_bundle_stable: bool = True,
    name: str = "determinism",
    error_message: str = "reference execution is not deterministic",
) -> ReferenceCheck:
    trace_results = []
    passed = reference_bundle_stable
    for trace_index, trace in enumerate(
        snapshot.reference_bundle.reference_attack_traces
    ):
        first_score, first_events, first_health, _first_outputs = run_red_reference(
            snapshot,
            backend,
            trace_index=trace_index,
        )
        second_score, second_events, second_health, _second_outputs = run_red_reference(
            snapshot,
            backend,
            trace_index=trace_index,
        )
        trace_passed = (
            first_events == second_events
            and first_health == second_health
            and first_score.winner == second_score.winner
            and first_score.terminal_reason == second_score.terminal_reason
        )
        passed = passed and trace_passed
        trace_results.append(
            {
                "trace_id": trace.id,
                "first_event_count": len(first_events),
                "second_event_count": len(second_events),
                "winner": first_score.winner,
                "passed": trace_passed,
            }
        )
    return _reference_check(
        name,
        passed,
        {"trace_count": len(trace_results), "traces": trace_results},
        error_message=error_message,
    )


def run_live_reference_checks(
    snapshot: RuntimeSnapshot,
    release: BootedRelease,
) -> tuple[ReferenceCheck, ...]:
    backend = PodActionBackend()
    backend.bind(snapshot, release)
    clear_runtime_markers(release, snapshot.world)
    checks = [
        check_red_reference(
            snapshot,
            backend=backend,
            release=release,
            name="live_red_reference",
            error_message="live red reference did not satisfy terminal objectives",
        ),
        _live_siem_ingest_check(release),
    ]
    for check in (
        lambda snapshot, _release, backend: check_blue_reference(
            snapshot,
            backend=backend,
            name="live_blue_reference",
            error_message="live blue reference did not validate detect-and-contain path",
        ),
        lambda snapshot, _release, backend: check_determinism(
            snapshot,
            backend=backend,
            name="live_determinism",
            error_message="live reference replay is not deterministic",
        ),
        _live_necessity_check,
    ):
        clear_runtime_markers(release, snapshot.world)
        checks.append(check(snapshot, release, backend))
    return tuple(checks)


def _satisfied_red_predicates(
    snapshot: RuntimeSnapshot,
    predicates: PredicateEngine,
    *,
    events: tuple[dict[str, Any], ...],
    health: tuple[tuple[str, float], ...],
    outputs: list[str],
    release: BootedRelease | None,
) -> set[str]:
    if release is None:
        return predicates.evaluate_red_objectives(
            snapshot=snapshot,
            events=events,
            service_health=dict(health),
        )
    satisfied: set[str] = set()
    for objective in snapshot.world.red_objectives:
        grader = predicates.objective_grader(objective.predicate)
        if grader is None:
            continue
        if evaluate_objective_grader_live(
            objective.predicate,
            grader,
            snapshot=snapshot,
            pods=release.pods,
            events=events,
            service_health=dict(health),
            outputs=outputs,
        ):
            satisfied.add(objective.predicate)
    return satisfied


def _live_siem_ingest_check(release: BootedRelease) -> ReferenceCheck:
    result = run_async(
        release.pods.exec(
            "svc-siem",
            "grep -q 'InitialAccess' /srv/http/siem/all.log",
            timeout=10.0,
        )
    )
    return _reference_check(
        "live_siem_ingest",
        result.ok,
        {"stdout": result.stdout.strip(), "stderr": result.stderr.strip()},
        error_message="siem log sink did not record reference events",
    )


def _live_necessity_check(
    snapshot: RuntimeSnapshot,
    release: BootedRelease,
    backend: PodActionBackend,
) -> ReferenceCheck:
    engine = PredicateEngine(snapshot.world)
    active_weaknesses = engine.active_weaknesses()
    trace_bindings = reference_trace_bindings(
        snapshot.reference_bundle.reference_attack_traces,
        active_weaknesses,
    )
    red_targets = {
        step.target
        for _trace_index, trace, _weakness in trace_bindings
        for step in trace.steps
    }
    candidate_weaknesses = sorted(
        (weakness for weakness in active_weaknesses if weakness.target in red_targets),
        key=lambda weakness: (
            0 if weakness.instantiation_mode == "exact_code" else 1,
            0
            if trace_bindings
            and weakness.target == trace_bindings[0][1].steps[0].target
            else 1,
            weakness.id,
        ),
    )
    target_weakness = candidate_weaknesses[0] if candidate_weaknesses else None
    trace_index = next(
        (
            candidate_index
            for candidate_index, _trace, weakness in trace_bindings
            if target_weakness is not None and weakness.id == target_weakness.id
        ),
        0,
    )
    if target_weakness is None:
        return _reference_check(
            "live_necessity",
            False,
            {"reason": "no reference-relevant weakness"},
            error_message="no reference-relevant weakness available for live necessity check",
        )
    command = remediation_command_for_weakness(target_weakness)
    if not command:
        return _reference_check(
            "live_necessity",
            False,
            {
                "weakness_id": target_weakness.id,
                "remediation": target_weakness.remediation,
                "remediation_kind": target_weakness.remediation_kind,
            },
            error_message="weakness remediation is not executable",
        )
    apply_result = run_async(
        release.pods.exec(target_weakness.target, command, timeout=10.0)
    )
    score, _events, _health, outputs = run_red_reference(
        snapshot,
        backend,
        trace_index=trace_index,
    )
    run_async(
        release.pods.exec(
            target_weakness.target,
            "rm -f /tmp/openrange-contained /tmp/openrange-patched",
            timeout=10.0,
        )
    )
    passed = apply_result.ok and score.winner != "red"
    return _reference_check(
        "live_necessity",
        passed,
        {
            "weakness_id": target_weakness.id,
            "target": target_weakness.target,
            "winner_after_remediation": score.winner,
            "outputs": outputs,
        },
        error_message="live remediation did not break the reference path",
    )


def matches_reference_step(action: Action, expected: Any, live_stdout: str) -> bool:
    if action.kind != expected.kind or action_target(action) != expected.target:
        return False
    if action.kind == "api":
        expected_path = expected.payload.get("path")
        actual_path = action.payload.get("path")
        if (expected_path or actual_path) and actual_path != expected_path:
            return False
        expected_query = expected.payload.get("query")
        actual_query = action.payload.get("query")
        if (expected_query or actual_query) and actual_query != expected_query:
            return False
        expected_contains = str(expected.payload.get("expect_contains", "")).strip()
        if expected_contains and expected_contains not in live_stdout:
            return False
    if action.kind in {"shell", "mail"}:
        expected_path = expected.payload.get("path")
        actual_path = action.payload.get("path")
        if (expected_path or actual_path) and actual_path != expected_path:
            return False
        expected_contains = str(expected.payload.get("expect_contains", "")).strip()
        if expected_contains and expected_contains not in live_stdout:
            return False
    if action.kind == "control":
        expected_directive = control_directive_from_payload(expected.payload)
        if expected_directive and control_directive(action) != expected_directive:
            return False
    if action.kind == "submit_finding":
        expected_event = finding_event_type_from_payload(expected.payload)
        actual_event = finding_event_type(action)
        if expected_event and actual_event != expected_event:
            return False
    return True


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


def prefix_satisfied(
    start_state: str,
    *,
    step_action: str,
    emitted: tuple[RuntimeEvent, ...],
    red_progress: int,
) -> bool:
    event_types = {event.event_type for event in emitted}
    if start_state == "prefix_delivery":
        return step_action in {"deliver_phish", "deliver_lure"}
    if start_state == "prefix_click":
        return step_action == "click_lure" or "InitialAccess" in event_types
    if start_state == "prefix_foothold":
        return "InitialAccess" in event_types
    if start_state == "prefix_credential_theft":
        return "CredentialObtained" in event_types
    if start_state == "prefix_lateral_movement":
        return "CrossZoneTraversal" in event_types or red_progress >= 2
    return False
