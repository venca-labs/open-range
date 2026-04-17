"""Admission-owned validation checks built on runtime replay mechanics."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from open_range.admission.models import ValidatorCheckReport
from open_range.async_utils import run_async
from open_range.episode_config import EpisodeConfig
from open_range.objectives.engine import PredicateEngine
from open_range.runtime.execution import PodActionBackend, clear_runtime_markers
from open_range.runtime.replay import action_for_reference_step, run_red_reference
from open_range.snapshot import RuntimeSnapshot
from open_range.weaknesses import remediation_command_for_weakness

if TYPE_CHECKING:
    from open_range.render.live import BootedRelease


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
            else predicates.evaluate_red_objectives_live(
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
            action = action_for_reference_step(snapshot, "blue", step)
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
) -> tuple[ValidatorCheckReport, ...]:
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
        lambda current_snapshot, _release, current_backend: check_blue_reference(
            current_snapshot,
            backend=current_backend,
            name="live_blue_reference",
            error_message="live blue reference did not validate detect-and-contain path",
        ),
        lambda current_snapshot, _release, current_backend: check_determinism(
            current_snapshot,
            backend=current_backend,
            name="live_determinism",
            error_message="live reference replay is not deterministic",
        ),
        _live_necessity_check,
    ):
        clear_runtime_markers(release, snapshot.world)
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
        return ValidatorCheckReport(
            name="live_necessity",
            passed=False,
            details={"reason": "no reference-relevant weakness"},
            error="no reference-relevant weakness available for live necessity check",
        )
    command = remediation_command_for_weakness(target_weakness)
    if not command:
        return ValidatorCheckReport(
            name="live_necessity",
            passed=False,
            details={
                "weakness_id": target_weakness.id,
                "remediation": target_weakness.remediation,
                "remediation_kind": target_weakness.remediation_kind,
            },
            error="weakness remediation is not executable",
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
    return ValidatorCheckReport(
        name="live_necessity",
        passed=passed,
        details={
            "weakness_id": target_weakness.id,
            "target": target_weakness.target,
            "winner_after_remediation": score.winner,
            "outputs": outputs,
        },
        error="" if passed else "live remediation did not break the reference path",
    )
