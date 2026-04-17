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
    blue_reference_plan_for_trace,
    blue_submit_finding_payload,
    necessity_probe_template,
    ordered_red_reference_candidates,
    red_reference_starts,
    select_primary_red_reference_weakness,
    smoke_probe_template,
    telemetry_blindspot_targets,
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
            plan = build_reference_plan_for_weakness(
                self.world,
                engine,
                start,
                exploit,
            )
            steps.extend(list(plan.steps))
            current = plan.current
            satisfied_predicates = set(plan.satisfied_predicates)
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


def _probe_spec_from_template(template: ProbeTemplateSpec) -> ProbeSpec:
    return ProbeSpec(
        id=template.id,
        kind=template.kind,
        description=template.description,
        command=template.command,
    )
