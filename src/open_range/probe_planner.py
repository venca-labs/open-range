"""Private witness and probe planning for admission."""

from __future__ import annotations

from dataclasses import dataclass
import shlex

from open_range.admission import ProbeSpec, WitnessAction, WitnessBundle, WitnessTrace
from open_range.build_config import BuildConfig, DEFAULT_BUILD_CONFIG
from open_range.code_web import code_web_payload
from open_range.predicates import PredicateEngine
from open_range.runtime_types import Action
from open_range.world_ir import WorldIR


@dataclass(frozen=True, slots=True)
class ProbePlanner:
    """Construct bounded private witnesses and probes for one world."""

    world: WorldIR
    build_config: BuildConfig = DEFAULT_BUILD_CONFIG

    def build(self) -> WitnessBundle:
        red_trace = self.build_red_witness()
        blue_trace = self.build_blue_witness(red_trace)
        smoke_tests = tuple(
            ProbeSpec(
                id=f"smoke-{service.id}",
                kind="smoke",
                description=f"boot and basic health for {service.id}",
                command=f"check {service.id}",
            )
            for service in self.world.services
        )
        shortcut_probes = (
            ProbeSpec(id="shortcut-direct-asset", kind="shortcut", description="direct external crown-jewel access"),
            ProbeSpec(id="shortcut-admin", kind="shortcut", description="direct admin access"),
            ProbeSpec(id="shortcut-cross-zone", kind="shortcut", description="unintended cross-zone reachability"),
            ProbeSpec(id="shortcut-secret", kind="shortcut", description="leaked secrets"),
            ProbeSpec(id="shortcut-unlogged", kind="shortcut", description="unlogged critical actions"),
        )
        determinism_probes = (
            ProbeSpec(id="determinism-red", kind="determinism", description="replay red witness"),
        )
        engine = PredicateEngine(self.world)
        necessity_probes = tuple(
            ProbeSpec(
                id=f"necessity-{weak.id}",
                kind="necessity",
                description=f"remove or remediate {weak.id} and require witness degradation",
            )
            for weak in engine.active_weaknesses()
        )
        red_witnesses = tuple(
            red_trace.model_copy(update={"id": f"{red_trace.id}-{idx}"})
            for idx in range(1, self.build_config.red_witness_count + 1)
        )
        blue_witnesses = tuple(
            blue_trace.model_copy(update={"id": f"{blue_trace.id}-{idx}"})
            for idx in range(1, self.build_config.blue_witness_count + 1)
        )
        return WitnessBundle(
            red_witnesses=red_witnesses,
            blue_witnesses=blue_witnesses,
            smoke_tests=smoke_tests,
            shortcut_probes=shortcut_probes,
            determinism_probes=determinism_probes,
            necessity_probes=necessity_probes,
        )

    def build_red_witness(self) -> WitnessTrace:
        engine = PredicateEngine(self.world)
        start = next(
            (service.id for service in self.world.services if engine.is_public_service(service)),
            self.world.services[0].id,
        )
        weaknesses = engine.active_weaknesses()
        exploit = _primary_red_weakness(start, weaknesses)
        satisfied_predicates: set[str] = set()
        steps: list[WitnessAction] = []
        current = start
        if exploit is not None:
            exploit_steps, current, satisfied_predicates = _weakness_red_steps(self.world, engine, start, exploit)
            steps.extend(exploit_steps)
        if not steps:
            steps.append(
                WitnessAction(
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
                    WitnessAction(
                        actor="red",
                        kind="api",
                        target=service_id,
                        payload={"action": "traverse"},
                    )
                )
            asset = engine.objective_target_asset(objective.predicate)
            steps.append(
                WitnessAction(
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
        for weak in ((exploit,) if exploit is not None else weaknesses):
            if weak is None:
                continue
            events.extend(weak.expected_event_signatures)
        return WitnessTrace(
            id=f"red-{self.world.world_id}",
            role="red",
            objective_ids=tuple(objective.id for objective in self.world.red_objectives),
            expected_events=tuple(dict.fromkeys(events + ["SensitiveAssetRead"])),
            steps=tuple(steps),
        )

    def build_blue_witness(self, red_trace: WitnessTrace) -> WitnessTrace:
        detect_step = next(
            (
                step
                for step in red_trace.steps
                if step.payload.get("action") not in {"deliver_phish", "deliver_lure"}
            ),
            red_trace.steps[0] if red_trace.steps else None,
        )
        detect_target = detect_step.target if detect_step is not None else "svc-web"
        contain_target = red_trace.steps[-1].target if red_trace.steps else "svc-siem"
        return WitnessTrace(
            id=f"blue-{self.world.world_id}",
            role="blue",
            objective_ids=tuple(objective.id for objective in self.world.blue_objectives),
            expected_events=("DetectionAlertRaised", "ContainmentApplied"),
            steps=(
                WitnessAction(actor="blue", kind="shell", target="svc-siem", payload={"action": "observe_events"}),
                WitnessAction(actor="blue", kind="submit_finding", target=detect_target, payload={"event": "InitialAccess"}),
                WitnessAction(actor="blue", kind="control", target=contain_target, payload={"action": "contain"}),
            ),
        )


def build_witness_bundle(world: WorldIR, build_config: BuildConfig = DEFAULT_BUILD_CONFIG) -> WitnessBundle:
    return ProbePlanner(world=world, build_config=build_config).build()


def runtime_action(actor: str, step: WitnessAction) -> Action:
    payload = dict(step.payload)
    if step.target:
        payload.setdefault("target", step.target)
    if actor == "blue" and step.kind == "submit_finding":
        event_type = str(payload.get("event", payload.get("event_type", "InitialAccess")))
        payload["event_type"] = event_type
    return Action(actor_id=actor, role=actor, kind=step.kind, payload=payload)


def _primary_red_weakness(start: str, weaknesses):
    ranked = [
        weak
        for weak in weaknesses
        if weak.family != "telemetry_blindspot"
    ]
    if not ranked:
        return next(iter(weaknesses), None)
    ranked.sort(
        key=lambda weak: (
            0 if weak.target == start else 1,
            0 if weak.family == "code_web" else 1,
            weak.id,
        )
    )
    return ranked[0]


def _weakness_red_steps(
    world,
    engine: PredicateEngine,
    start: str,
    weakness,
) -> tuple[list[WitnessAction], str, set[str]]:
    steps: list[WitnessAction] = []
    satisfied: set[str] = set()
    current = start
    if weakness.family == "code_web":
        payload = {"action": "initial_access", "weakness_id": weakness.id, "weakness": weakness.id}
        payload.update(code_web_payload(world, weakness))
        steps.append(WitnessAction(actor="red", kind="api", target=weakness.target, payload=payload))
        return steps, weakness.target, satisfied

    if weakness.family == "workflow_abuse" and weakness.kind in {"phishing_credential_capture", "internal_request_impersonation"}:
        mailbox_path = _first_realization_path(weakness, kind="mailbox")
        mailbox = _mailbox_from_path(mailbox_path) if mailbox_path else "user@corp.local"
        steps.append(
            WitnessAction(
                actor="red",
                kind="mail",
                target="svc-email",
                payload={
                    "action": "deliver_phish",
                    "weakness_id": weakness.id,
                    "target": "svc-email",
                    "to": mailbox,
                    "subject": weakness.kind,
                    "expect_contains": weakness.kind,
                },
            )
        )
        if mailbox_path:
            steps.append(
                WitnessAction(
                    actor="red",
                    kind="shell",
                    target="svc-email",
                    payload=_shell_payload(
                        action="click_lure",
                        weakness_id=weakness.id,
                        target="svc-email",
                        path=mailbox_path,
                        expect_contains=weakness.kind,
                    ),
                )
            )
        current = "svc-email"
    else:
        if current != weakness.target:
            steps.append(
                WitnessAction(
                    actor="red",
                    kind="api",
                    target=current,
                    payload={"action": "initial_access"},
                )
            )
            path = engine.shortest_path(current, weakness.target)
            for service_id in path[1:]:
                steps.append(
                    WitnessAction(
                        actor="red",
                        kind="api",
                        target=service_id,
                        payload={"action": "traverse"},
                    )
                )
            current = weakness.target

    if weakness.family == "secret_exposure":
        realization_path = _first_realization_path(weakness)
        expect_contains = _secret_expectation(world, weakness)
        payload = _shell_payload(
            action="collect_secret",
            weakness_id=weakness.id,
            target=weakness.target,
            path=realization_path,
            expect_contains=expect_contains,
        )
        if _target_ref_objective(world, weakness.target_ref) is not None:
            payload["asset"] = weakness.target_ref
            payload["objective"] = _target_ref_objective(world, weakness.target_ref)
            satisfied.add(_target_ref_objective(world, weakness.target_ref))
        steps.append(WitnessAction(actor="red", kind="shell", target=weakness.target, payload=payload))
        return steps, weakness.target, satisfied

    if weakness.family == "config_identity":
        realization_path = _first_realization_path(weakness)
        payload = _shell_payload(
            action="abuse_identity",
            weakness_id=weakness.id,
            target=weakness.target,
            path=realization_path,
            expect_contains=weakness.kind,
        )
        objective = _target_ref_objective(world, weakness.target_ref)
        if objective is not None:
            payload["objective"] = objective
            satisfied.add(objective)
        steps.append(WitnessAction(actor="red", kind="shell", target=weakness.target, payload=payload))
        return steps, weakness.target, satisfied

    if weakness.family == "workflow_abuse":
        realization_path = _first_realization_path(weakness, kind="workflow") or _first_realization_path(weakness)
        payload = _shell_payload(
            action="abuse_workflow",
            weakness_id=weakness.id,
            target=weakness.target,
            path=realization_path,
            expect_contains=weakness.kind,
        )
        objective = _target_ref_objective(world, weakness.target_ref)
        if objective is not None:
            payload["objective"] = objective
            satisfied.add(objective)
        steps.append(WitnessAction(actor="red", kind="shell", target=weakness.target, payload=payload))
        return steps, weakness.target, satisfied

    steps.append(
        WitnessAction(
            actor="red",
            kind="api",
            target=current,
            payload={"action": "initial_access", "weakness_id": weakness.id},
        )
    )
    return steps, current, satisfied


def _shell_payload(
    *,
    action: str,
    weakness_id: str,
    target: str,
    path: str | None,
    expect_contains: str,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "action": action,
        "weakness_id": weakness_id,
        "target": target,
        "origin": target,
        "expect_contains": expect_contains,
    }
    if path:
        payload["path"] = path
        payload["command"] = f"cat {shlex.quote(path)}"
    return payload


def _first_realization_path(weakness, *, kind: str | None = None) -> str | None:
    for realization in weakness.realization:
        if kind is not None and realization.kind != kind:
            continue
        return realization.path
    return None


def _secret_expectation(world, weakness) -> str:
    if weakness.kind in {"env_file_leak", "hardcoded_app_secret"}:
        return "OPENRANGE_APP_SECRET"
    if weakness.kind == "backup_leak":
        return "INSERT INTO leaked_credentials"
    if weakness.kind == "token_in_email":
        return _secret_material(world, weakness.target_ref or weakness.target)
    if weakness.kind == "credential_in_share":
        return _secret_material(world, weakness.target_ref or weakness.target)
    return weakness.kind


def _secret_material(world, target_ref: str) -> str:
    asset = next((item for item in world.assets if item.id == target_ref), None)
    if asset is not None:
        return f"seeded-{asset.asset_class}-{asset.id}"
    user = next((item for item in world.users if item.id == target_ref), None)
    if user is not None:
        return f"{user.id}-pass"
    credential = next((item for item in world.credentials if item.id == target_ref), None)
    if credential is not None:
        return f"seeded-secret-{credential.id}"
    return target_ref


def _target_ref_objective(world, target_ref: str) -> str | None:
    for objective in world.red_objectives:
        if target_ref and target_ref in objective.predicate:
            return objective.predicate
    return None


def _mailbox_from_path(path: str) -> str:
    slug = path.split("/mailboxes/", 1)[1].split("/", 1)[0]
    return slug.replace("_at_", "@").replace("_", ".")
