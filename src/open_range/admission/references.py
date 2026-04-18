"""Private reference planning and execution for admission."""

from __future__ import annotations

import json
from dataclasses import dataclass

from open_range.admission.models import (
    ProbeSpec,
    ReferenceAction,
    ReferenceBundle,
    ReferenceTrace,
    ValidatorReport,
)
from open_range.catalog.contracts import ProbeTemplateSpec
from open_range.catalog.probes import (
    DEFAULT_DETERMINISM_PROBE_TEMPLATES,
    DEFAULT_SHORTCUT_PROBE_TEMPLATES,
    blue_containment_payload,
    blue_observe_reference_payload,
    blue_reference_expected_events,
    blue_submit_finding_payload,
    necessity_probe_template,
    ordered_red_reference_candidates,
    red_reference_family_priority,
    red_reference_starts,
    smoke_probe_template,
)
from open_range.config import DEFAULT_BUILD_CONFIG, BuildConfig
from open_range.contracts.snapshot import KindArtifacts, RuntimeSnapshot, world_hash
from open_range.contracts.world import WorldIR
from open_range.objectives.engine import PredicateEngine
from open_range.weaknesses import build_reference_plan_for_weakness


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
        starters = _starter_weaknesses(self.world, engine)
        candidates = ordered_red_reference_candidates(starts, starters)
        traces: list[ReferenceTrace] = []
        seen: set[str] = set()
        for start, exploit in candidates:
            trace, satisfied = self._build_red_reference_candidate(
                start=start, exploit=exploit, ordinal=len(traces) + 1
            )
            if not _terminal_red_predicates(self.world) <= satisfied:
                continue
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
            fallback, _satisfied = self._build_red_reference_candidate(
                start=starts[0], exploit=None, ordinal=1
            )
            traces.append(fallback)
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
        return self._build_red_reference_candidate(
            start=start,
            exploit=exploit,
            ordinal=ordinal,
        )[0]

    def _build_red_reference_candidate(
        self,
        *,
        start: str | None = None,
        exploit=None,
        ordinal: int = 1,
    ) -> tuple[ReferenceTrace, set[str]]:
        engine = PredicateEngine(self.world)
        start = start or next(iter(_reference_starts(self.world, engine)), "")
        weaknesses = _reference_weaknesses(self.world, engine)
        starter_weaknesses = _starter_weaknesses(self.world, engine)
        exploit = exploit or _select_initial_reference_weakness(
            self.world,
            engine,
            start=start,
            weaknesses=starter_weaknesses,
        )
        satisfied_predicates: set[str] = set()
        steps: list[ReferenceAction] = []
        expected_events: list[str] = []
        current = start
        if exploit is not None:
            current = _append_reference_plan(
                self.world,
                engine,
                start=current,
                weakness=exploit,
                steps=steps,
                expected_events=expected_events,
                satisfied=satisfied_predicates,
            )
        used_weakness_ids = {getattr(exploit, "id", "")} - {""}
        remaining = _terminal_red_predicates(self.world) - satisfied_predicates
        while remaining:
            follow_up = _select_follow_up_weakness(
                self.world,
                engine,
                current=current,
                weaknesses=weaknesses,
                remaining=remaining,
                used_weakness_ids=used_weakness_ids,
            )
            if follow_up is None:
                break
            before = set(satisfied_predicates)
            current = _append_reference_plan(
                self.world,
                engine,
                start=current,
                weakness=follow_up,
                steps=steps,
                expected_events=expected_events,
                satisfied=satisfied_predicates,
            )
            used_weakness_ids.add(follow_up.id)
            if satisfied_predicates == before:
                break
            remaining = _terminal_red_predicates(self.world) - satisfied_predicates

        return (
            ReferenceTrace(
                id=f"red-{self.world.world_id}-{ordinal}",
                role="red",
                objective_ids=tuple(
                    objective.id for objective in self.world.red_objectives
                ),
                expected_events=tuple(dict.fromkeys(expected_events)),
                steps=tuple(steps),
            ),
            satisfied_predicates,
        )

    def build_blue_reference(
        self, red_trace: ReferenceTrace, *, ordinal: int = 1
    ) -> ReferenceTrace:
        detect_index, detect_event, detect_target = _blue_reference_detection(
            self.world,
            red_trace,
        )
        observe_steps = tuple(
            ReferenceAction(
                actor="blue",
                kind="shell",
                target="svc-siem",
                payload=blue_observe_reference_payload(),
            )
            for _ in range(max(0, detect_index))
        )
        contain_target = _blue_reference_containment_target(
            self.world,
            red_trace,
            default=detect_target,
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
                    target=detect_target,
                    payload=blue_submit_finding_payload(detect_event=detect_event),
                ),
                ReferenceAction(
                    actor="blue",
                    kind="control",
                    target=contain_target,
                    payload=blue_containment_payload(),
                ),
            ),
        )


def build_reference_bundle(
    world: WorldIR, build_config: BuildConfig = DEFAULT_BUILD_CONFIG
) -> ReferenceBundle:
    return ReferencePlanner(world=world, build_config=build_config).build()


def ephemeral_runtime_snapshot(
    world: WorldIR, artifacts: KindArtifacts, reference_bundle: ReferenceBundle
) -> RuntimeSnapshot:
    predicates = PredicateEngine(world)
    world_digest = world_hash(world)
    db_seed_state = {
        "services": [service.id for service in world.services if service.kind == "db"]
    }
    file_assets = {asset.id: asset.location for asset in world.assets}
    report = ValidatorReport(
        admitted=True,
        graph_ok=True,
        boot_ok=True,
        workflow_ok=True,
        telemetry_ok=True,
        reference_attack_ok=True,
        reference_defense_ok=True,
        necessity_ok=True,
        shortcut_risk="low",
        determinism_score=1.0,
        flakiness=0.0,
        red_path_depth=predicates.red_path_depth(),
        red_alt_path_count=predicates.red_alt_path_count(),
        blue_signal_points=len({edge.source for edge in world.telemetry_edges}),
        business_continuity_score=1.0,
        benchmark_tags_covered=predicates.benchmark_tags_covered(),
        world_id=world.world_id,
        world_hash=world_digest,
        summary="admission-live-check",
    )
    return RuntimeSnapshot(
        snapshot_id=f"{world.world_id}-admission",
        world_id=world.world_id,
        seed=world.seed,
        artifacts_dir=artifacts.render_dir,
        image_digests=artifacts.pinned_image_digests,
        state_seed_dir=artifacts.render_dir,
        validator_report_path=f"{artifacts.render_dir}/validator_report.json",
        world=world,
        artifacts=artifacts,
        db_seed_state=db_seed_state,
        file_assets=file_assets,
        validator_report=report,
        reference_bundle=reference_bundle,
        world_hash=world_digest,
    )


def _reference_starts(world: WorldIR, engine: PredicateEngine) -> tuple[str, ...]:
    return red_reference_starts(
        tuple(service.id for service in world.services),
        public_service_ids=tuple(
            service.id
            for service in world.services
            if engine.is_public_service(service)
        ),
    )


def _append_reference_plan(
    world: WorldIR,
    engine: PredicateEngine,
    *,
    start: str,
    weakness,
    steps: list[ReferenceAction],
    expected_events: list[str],
    satisfied: set[str],
) -> str:
    plan = build_reference_plan_for_weakness(world, engine, start, weakness)
    steps.extend(plan.steps)
    expected_events.extend(weakness.expected_event_signatures)
    satisfied.update(plan.satisfied_predicates)
    return plan.current


def _reference_weaknesses(
    world: WorldIR, engine: PredicateEngine
) -> tuple[object, ...]:
    terminal = _terminal_red_predicates(world)
    return tuple(
        weakness
        for weakness in engine.active_weaknesses()
        if any(
            _weakness_satisfies_objective(engine, weakness, predicate)
            for predicate in terminal
        )
    )


def _starter_weaknesses(world: WorldIR, engine: PredicateEngine) -> tuple[object, ...]:
    starters = tuple(
        weakness
        for weakness in engine.active_weaknesses()
        if "InitialAccess" in getattr(weakness, "expected_event_signatures", ())
    )
    return starters or _reference_weaknesses(world, engine)


def _terminal_red_predicates(world: WorldIR) -> set[str]:
    return {
        objective.predicate for objective in world.red_objectives if objective.terminal
    }


def _weakness_satisfies_objective(
    engine: PredicateEngine, weakness, predicate: str
) -> bool:
    resolved = engine.resolve_objective(predicate)
    if not resolved.event_type:
        return False
    if resolved.event_type not in getattr(weakness, "expected_event_signatures", ()):
        return False
    if resolved.target_kind == "asset":
        return bool(resolved.target_id) and resolved.target_id == getattr(
            weakness, "target_ref", ""
        )
    target_service = resolved.target_service or getattr(weakness, "target", "")
    return bool(target_service) and target_service == getattr(weakness, "target", "")


def _select_follow_up_weakness(
    world: WorldIR,
    engine: PredicateEngine,
    *,
    current: str,
    weaknesses: tuple[object, ...],
    remaining: set[str],
    used_weakness_ids: set[str],
):
    candidates = [
        weakness
        for weakness in weaknesses
        if getattr(weakness, "id", "") not in used_weakness_ids
        and any(
            _weakness_satisfies_objective(engine, weakness, predicate)
            for predicate in remaining
        )
    ]
    if not candidates:
        return None
    candidates.sort(
        key=lambda weakness: (
            0
            if len(remaining) > 1
            and not any(
                engine.resolve_objective(predicate).event_type == "SensitiveAssetRead"
                and _weakness_satisfies_objective(engine, weakness, predicate)
                for predicate in remaining
            )
            else 1,
            -sum(
                1
                for predicate in remaining
                if _weakness_satisfies_objective(engine, weakness, predicate)
            ),
            0 if getattr(weakness, "target", "") == current else 1,
            red_reference_family_priority(getattr(weakness, "family", "")),
            getattr(weakness, "target", ""),
            getattr(weakness, "id", ""),
        )
    )
    return candidates[0]


def _select_initial_reference_weakness(
    world: WorldIR,
    engine: PredicateEngine,
    *,
    start: str,
    weaknesses: tuple[object, ...],
):
    terminal = _terminal_red_predicates(world)
    if not weaknesses:
        return None
    ranked = [
        weakness
        for weakness in weaknesses
        if getattr(weakness, "target", "") == start
        or "InitialAccess" in getattr(weakness, "expected_event_signatures", ())
    ]
    if not ranked:
        ranked = list(weaknesses)
    ranked.sort(
        key=lambda weakness: (
            0
            if len(terminal) > 1
            and not any(
                _weakness_satisfies_objective(engine, weakness, predicate)
                for predicate in terminal
            )
            else 1,
            red_reference_family_priority(getattr(weakness, "family", "")),
            0 if getattr(weakness, "target", "") == start else 1,
            getattr(weakness, "target", ""),
            getattr(weakness, "id", ""),
        )
    )
    return ranked[0]


def _telemetry_blindspot_targets(world: WorldIR) -> frozenset[str]:
    return frozenset(
        weakness.target
        for weakness in world.weaknesses
        if weakness.family == "telemetry_blindspot"
    )


def _blue_reference_detection(
    world: WorldIR,
    red_trace: ReferenceTrace,
) -> tuple[int, str, str]:
    weakness_by_id = {weakness.id: weakness for weakness in world.weaknesses}
    blindspots = _telemetry_blindspot_targets(world)
    for index, step in enumerate(red_trace.steps):
        action = str(step.payload.get("action", ""))
        if action in {"deliver_phish", "deliver_lure", "click_lure"}:
            continue
        weakness_id = str(
            step.payload.get("weakness_id", step.payload.get("weakness", ""))
        )
        weakness = weakness_by_id.get(weakness_id)
        if weakness is None or weakness.target in blindspots:
            continue
        event_type = next(
            (
                event
                for event in weakness.expected_event_signatures
                if event != "DetectionAlertRaised"
            ),
            "InitialAccess",
        )
        return index, event_type, _reference_event_target(step, weakness, event_type)
    if not red_trace.steps:
        return 0, "InitialAccess", "svc-web"
    step = red_trace.steps[0]
    return 0, "InitialAccess", step.target or "svc-web"


def _blue_reference_containment_target(
    world: WorldIR,
    red_trace: ReferenceTrace,
    *,
    default: str,
) -> str:
    weakness_by_id = {weakness.id: weakness for weakness in world.weaknesses}
    for step in reversed(red_trace.steps):
        weakness_id = str(
            step.payload.get("weakness_id", step.payload.get("weakness", ""))
        )
        weakness = weakness_by_id.get(weakness_id)
        if weakness is None:
            continue
        return getattr(weakness, "target", "") or step.target or default
    return default or (red_trace.steps[-1].target if red_trace.steps else "svc-siem")


def _reference_event_target(step: ReferenceAction, weakness, event_type: str) -> str:
    if event_type in {"CredentialObtained", "SensitiveAssetRead"}:
        payload_asset = str(step.payload.get("asset", ""))
        if payload_asset:
            return payload_asset
        query = step.payload.get("query", {})
        if isinstance(query, dict):
            asset = str(query.get("asset", ""))
            if asset:
                return asset
        return getattr(weakness, "target_ref", "") or getattr(weakness, "target", "")
    return getattr(weakness, "target", "") or step.target


def _probe_spec_from_template(template: ProbeTemplateSpec) -> ProbeSpec:
    return ProbeSpec(
        id=template.id,
        kind=template.kind,
        description=template.description,
        command=template.command,
    )
