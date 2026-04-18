"""Admission-owned validation checks built on runtime replay mechanics."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from open_range.admission.live_necessity import LiveNecessityRunner
from open_range.admission.models import ValidatorCheckReport
from open_range.config import EpisodeConfig
from open_range.contracts.snapshot import RuntimeSnapshot
from open_range.objectives.engine import PredicateEngine
from open_range.objectives.live import evaluate_objective_grader_live
from open_range.runtime.core import OpenRangeRuntime
from open_range.runtime.execution import PodActionBackend
from open_range.runtime.replay import action_for_reference_step
from open_range.support.async_utils import run_async
from open_range.weaknesses import (
    cleanup_steps_for_weakness,
    remediation_command_for_weakness,
)

if TYPE_CHECKING:
    from open_range.render.live import BootedRelease


def run_red_reference(
    snapshot: RuntimeSnapshot,
    backend: PodActionBackend | None = None,
    trace_index: int = 0,
):
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
        result = runtime._replay_action(
            "red",
            action_for_reference_step(snapshot, "red", step),
        )
        outputs.append(result.stdout or result.stderr)
    score = runtime.score()
    events = tuple(event.model_dump(mode="json") for event in runtime.export_events())
    health = tuple(sorted(runtime.state().service_health.items()))
    return score, events, health, outputs


def _clear_live_reference_markers(
    release: BootedRelease, snapshot: RuntimeSnapshot
) -> None:
    runtime_markers = (
        "rm -f /tmp/openrange-contained /tmp/openrange-patched "
        "/srv/http/siem/egress-canary.log"
    )
    for service in snapshot.world.services:
        run_async(release.pods.exec(service.id, runtime_markers, timeout=5.0))
    for weakness in snapshot.world.weaknesses:
        for target, command in cleanup_steps_for_weakness(weakness):
            run_async(release.pods.exec(target, command, timeout=5.0))


def _evaluate_live_red_objectives(
    snapshot: RuntimeSnapshot,
    *,
    pods: object,
    events: tuple[object, ...],
    service_health: dict[str, float],
    outputs: tuple[str, ...],
) -> set[str]:
    predicates = PredicateEngine(snapshot.world)
    satisfied: set[str] = set()
    for objective in snapshot.world.red_objectives:
        grader = predicates.objective_grader(objective.predicate)
        if grader is None:
            continue
        if evaluate_objective_grader_live(
            objective.predicate,
            grader,
            snapshot=snapshot,
            pods=pods,
            events=events,
            service_health=service_health,
            outputs=outputs,
        ):
            satisfied.add(objective.predicate)
    return satisfied


def reference_trace_bindings(
    attack_traces: tuple[Any, ...], active_weaknesses: tuple[Any, ...]
) -> tuple[tuple[int, Any, tuple[Any, ...]], ...]:
    weakness_by_id = {str(weakness.id): weakness for weakness in active_weaknesses}
    bindings = []
    for trace_index, trace in enumerate(attack_traces):
        weakness_ids = tuple(
            dict.fromkeys(
                str(step.payload.get("weakness_id") or step.payload.get("weakness", ""))
                for step in getattr(trace, "steps", ())
                if isinstance(
                    step.payload.get("weakness_id") or step.payload.get("weakness"),
                    str,
                )
            )
        )
        weaknesses = tuple(
            weakness_by_id[weakness_id]
            for weakness_id in weakness_ids
            if weakness_id in weakness_by_id
        )
        if weaknesses:
            bindings.append((trace_index, trace, weaknesses))
    return tuple(bindings)


def check_red_reference(
    snapshot: RuntimeSnapshot,
    *,
    backend: PodActionBackend | None = None,
    release: BootedRelease | None = None,
    name: str = "red_reference",
    error_message: str = "offline red reference did not satisfy terminal objectives",
) -> ValidatorCheckReport:
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
        satisfied = (
            predicates.evaluate_red_objectives(
                snapshot=snapshot, events=events, service_health=dict(health)
            )
            if release is None
            else _evaluate_live_red_objectives(
                snapshot=snapshot,
                pods=release.pods,
                events=events,
                service_health=dict(health),
                outputs=tuple(outputs),
            )
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
    return ValidatorCheckReport(
        name=name,
        passed=passed,
        details={
            "trace_count": len(per_trace),
            "satisfied_predicates": sorted(satisfied_all),
            "traces": per_trace,
        },
        error="" if passed else error_message,
    )


def check_blue_reference(
    snapshot: RuntimeSnapshot,
    *,
    backend: PodActionBackend | None = None,
    name: str = "blue_reference",
    error_message: str = "offline blue reference did not validate detect-and-contain path",
) -> ValidatorCheckReport:
    per_trace = []
    passed = True
    blue_objectives = {
        objective.id: objective.predicate
        for objective in snapshot.world.blue_objectives
    }
    for trace_index, trace in enumerate(
        snapshot.reference_bundle.reference_defense_traces
    ):
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
            action = action_for_reference_step(snapshot, "blue", step)
            result = runtime.act("blue", action)
            outputs.append(result.stdout or result.stderr)
            if decision.actor != "blue":
                break
            if step is not None:
                step_idx += 1
        score = runtime.score()
        missing_objective_ids = tuple(
            objective_id
            for objective_id in trace.objective_ids
            if objective_id not in blue_objectives
        )
        required_predicates = tuple(
            blue_objectives[objective_id]
            for objective_id in trace.objective_ids
            if objective_id in blue_objectives
        )
        satisfied_predicates = tuple(sorted(score.blue_objectives_satisfied))
        trace_passed = (
            score.winner == "blue"
            and score.done
            and not missing_objective_ids
            and all(
                predicate in score.blue_objectives_satisfied
                for predicate in required_predicates
            )
        )
        passed = passed and trace_passed
        per_trace.append(
            {
                "trace_id": trace.id,
                "step_count": len(trace.steps),
                "winner": score.winner,
                "terminal_reason": score.terminal_reason,
                "required_predicates": required_predicates,
                "satisfied_predicates": satisfied_predicates,
                "missing_objective_ids": missing_objective_ids,
                "outputs": outputs,
                "passed": trace_passed,
            }
        )
    return ValidatorCheckReport(
        name=name,
        passed=passed,
        details={"trace_count": len(per_trace), "traces": per_trace},
        error="" if passed else error_message,
    )


def check_determinism(
    snapshot: RuntimeSnapshot,
    *,
    backend: PodActionBackend | None = None,
    reference_bundle_stable: bool = True,
    name: str = "determinism",
    error_message: str = "reference execution is not deterministic",
) -> ValidatorCheckReport:
    trace_results = []
    passed = reference_bundle_stable
    for trace_index, trace in enumerate(
        snapshot.reference_bundle.reference_attack_traces
    ):
        first_score, first_events, first_health, _ = run_red_reference(
            snapshot,
            backend,
            trace_index=trace_index,
        )
        second_score, second_events, second_health, _ = run_red_reference(
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
    return ValidatorCheckReport(
        name=name,
        passed=passed,
        details={"trace_count": len(trace_results), "traces": trace_results},
        error="" if passed else error_message,
    )


def run_live_reference_checks(
    snapshot: RuntimeSnapshot,
    release: BootedRelease,
    *,
    validation_profile: str,
) -> tuple[ValidatorCheckReport, ...]:
    backend = PodActionBackend()
    backend.bind(snapshot, release)
    _clear_live_reference_markers(release, snapshot)
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
    _clear_live_reference_markers(release, snapshot)
    checks.append(
        check_blue_reference(
            snapshot,
            backend=backend,
            name="live_blue_reference",
            error_message="live blue reference did not validate detect-and-contain path",
        )
    )
    extra_checks = []
    if validation_profile in {"full", "no_necessity"}:
        extra_checks.append(
            lambda current_snapshot, _release, current_backend: check_determinism(
                current_snapshot,
                backend=current_backend,
                name="live_determinism",
                error_message="live reference replay is not deterministic",
            )
        )
    if validation_profile == "full":
        extra_checks.append(_live_necessity_check)
    for check in extra_checks:
        _clear_live_reference_markers(release, snapshot)
        checks.append(check(snapshot, release, backend))
    return tuple(checks)


def _live_siem_ingest_check(release: BootedRelease) -> ValidatorCheckReport:
    result = run_async(
        release.pods.exec(
            "svc-siem",
            "grep -q 'InitialAccess' /srv/http/siem/all.log",
            timeout=10.0,
        )
    )
    return ValidatorCheckReport(
        name="live_siem_ingest",
        passed=result.ok,
        details={"stdout": result.stdout.strip(), "stderr": result.stderr.strip()},
        error="" if result.ok else "siem log sink did not record reference events",
    )


def _live_necessity_check(
    snapshot: RuntimeSnapshot,
    release: BootedRelease,
    backend: PodActionBackend,
) -> ValidatorCheckReport:
    return LiveNecessityRunner(
        snapshot=snapshot,
        release=release,
        backend=backend,
        trace_bindings=reference_trace_bindings(
            snapshot.reference_bundle.reference_attack_traces,
            PredicateEngine(snapshot.world).active_weaknesses(),
        ),
        remediation_for_weakness=remediation_command_for_weakness,
        run_red_reference=run_red_reference,
        clear_reference_markers=_clear_live_reference_markers,
    ).report()
