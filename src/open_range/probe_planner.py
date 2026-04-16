"""Private reference-trace and probe planning for admission."""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass

from open_range.admission import (
    ProbeSpec,
    ReferenceAction,
    ReferenceBundle,
    ReferenceTrace,
)
from open_range.build_config import DEFAULT_BUILD_CONFIG, BuildConfig
from open_range.code_web import code_web_payload
from open_range.effect_markers import (
    effect_marker_content,
    effect_marker_path,
    effect_marker_token,
)
from open_range.predicates import PredicateEngine
from open_range.runtime_types import Action
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
            ProbeSpec(
                id=f"smoke-{service.id}",
                kind="smoke",
                description=f"boot and basic health for {service.id}",
                command=f"check {service.id}",
            )
            for service in self.world.services
        )
        shortcut_probes = (
            ProbeSpec(
                id="shortcut-direct-asset",
                kind="shortcut",
                description="direct external crown-jewel access",
            ),
            ProbeSpec(
                id="shortcut-admin", kind="shortcut", description="direct admin access"
            ),
            ProbeSpec(
                id="shortcut-cross-zone",
                kind="shortcut",
                description="unintended cross-zone reachability",
            ),
            ProbeSpec(
                id="shortcut-secret", kind="shortcut", description="leaked secrets"
            ),
            ProbeSpec(
                id="shortcut-unlogged",
                kind="shortcut",
                description="unlogged critical actions",
            ),
        )
        determinism_probes = (
            ProbeSpec(
                id="determinism-red",
                kind="determinism",
                description="replay red reference",
            ),
        )
        engine = PredicateEngine(self.world)
        necessity_probes = tuple(
            ProbeSpec(
                id=f"necessity-{weak.id}",
                kind="necessity",
                description=f"remove or remediate {weak.id} and require reference degradation",
            )
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
            key=lambda weak: (
                0 if weak.family == "code_web" else 1,
                0 if weak.target in starts else 1,
                weak.id,
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
                if _step_is_blue_detectable(red_trace, index, blindspot_targets)
            ),
            0,
        )
        detect_step = red_trace.steps[detect_index] if red_trace.steps else None
        detect_event, detect_target = _detection_for_red_step(detect_step)
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


def _primary_red_weakness(start: str, weaknesses):
    ranked = [weak for weak in weaknesses if weak.family != "telemetry_blindspot"]
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


def _detection_for_red_step(step: ReferenceAction | None) -> tuple[str, str]:
    if step is None:
        return ("InitialAccess", "svc-web")
    action = str(step.payload.get("action", ""))
    objective = str(step.payload.get("objective", ""))
    asset = str(step.payload.get("asset", ""))
    if action in {"initial_access", "click_lure"}:
        return ("InitialAccess", step.target)
    if action == "traverse":
        return ("CrossZoneTraversal", step.target)
    if action in {"collect_secret", "abuse_identity"}:
        target = asset or step.target
        return (
            "CredentialObtained"
            if (asset and ("cred" in asset or "token" in asset))
            else "SensitiveAssetRead",
            target,
        )
    if action == "abuse_workflow":
        target = asset or step.target
        return (
            "CredentialObtained"
            if (asset and ("cred" in asset or "token" in asset))
            else "SensitiveAssetRead",
            target,
        )
    if action == "satisfy_objective" and objective.startswith("credential_obtained("):
        return ("CredentialObtained", asset or step.target)
    if action == "satisfy_objective":
        return ("SensitiveAssetRead", asset or step.target)
    return ("InitialAccess", step.target or "svc-web")


def _step_is_blue_detectable(
    trace: ReferenceTrace,
    index: int,
    blindspot_targets: set[str],
) -> bool:
    if index < 0 or index >= len(trace.steps):
        return False
    step = trace.steps[index]
    action = str(step.payload.get("action", ""))
    if action in {"deliver_phish", "deliver_lure"}:
        return False
    source_target = trace.steps[index - 1].target if index > 0 else ""
    if action in {"initial_access", "click_lure"}:
        return step.target not in blindspot_targets
    if action == "traverse":
        return (
            step.target not in blindspot_targets
            and source_target not in blindspot_targets
        )
    return step.target not in blindspot_targets


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
    steps: list[ReferenceAction] = []
    satisfied: set[str] = set()
    current = start
    if weakness.family == "code_web":
        payload = {
            "action": "initial_access",
            "weakness_id": weakness.id,
            "weakness": weakness.id,
        }
        payload.update(code_web_payload(world, weakness))
        steps.append(
            ReferenceAction(
                actor="red", kind="api", target=weakness.target, payload=payload
            )
        )
        return steps, weakness.target, satisfied

    if weakness.family == "workflow_abuse" and weakness.kind in {
        "phishing_credential_capture",
        "internal_request_impersonation",
    }:
        mailbox_path = _first_realization_path(weakness, kind="mailbox")
        mailbox = (
            _mailbox_from_path(mailbox_path) if mailbox_path else "user@corp.local"
        )
        steps.append(
            ReferenceAction(
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
                ReferenceAction(
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
                ReferenceAction(
                    actor="red",
                    kind="api",
                    target=current,
                    payload={"action": "initial_access"},
                )
            )
            path = engine.shortest_path(current, weakness.target)
            for service_id in path[1:]:
                steps.append(
                    ReferenceAction(
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
        steps.append(
            ReferenceAction(
                actor="red", kind="shell", target=weakness.target, payload=payload
            )
        )
        return steps, weakness.target, satisfied

    if weakness.family == "config_identity":
        realization_path = _first_realization_path(weakness)
        payload = _shell_payload(
            action="abuse_identity",
            weakness_id=weakness.id,
            target=weakness.target,
            path=realization_path,
            expect_contains=effect_marker_token(weakness) or weakness.kind,
        )
        live_command = _identity_effect_command(weakness, realization_path or "")
        payload["command"] = live_command
        payload["service_command"] = live_command
        objective = _target_ref_objective(world, weakness.target_ref)
        if objective is not None:
            payload["objective"] = objective
            satisfied.add(objective)
        steps.append(
            ReferenceAction(
                actor="red", kind="shell", target=weakness.target, payload=payload
            )
        )
        return steps, weakness.target, satisfied

    if weakness.family == "workflow_abuse":
        realization_path = _first_realization_path(
            weakness, kind="workflow"
        ) or _first_realization_path(weakness)
        effect_token = effect_marker_token(weakness)
        payload = _shell_payload(
            action="abuse_workflow",
            weakness_id=weakness.id,
            target=weakness.target,
            path=realization_path,
            expect_contains=effect_token or weakness.kind,
        )
        if effect_token:
            live_command = _workflow_effect_command(weakness, realization_path or "")
            payload["command"] = live_command
            payload["service_command"] = live_command
        objective = _target_ref_objective(world, weakness.target_ref)
        if objective is not None:
            payload["objective"] = objective
            satisfied.add(objective)
        steps.append(
            ReferenceAction(
                actor="red", kind="shell", target=weakness.target, payload=payload
            )
        )
        return steps, weakness.target, satisfied

    steps.append(
        ReferenceAction(
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
    credential = next(
        (item for item in world.credentials if item.id == target_ref), None
    )
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


def _identity_effect_command(weakness, realization_path: str) -> str:
    effect_path = effect_marker_path(weakness)
    effect_content = effect_marker_content(weakness)
    markers = {
        "weak_password": ('"min_password_length": 6', '"password_reuse_allowed": true'),
        "default_credential": (
            '"default_username": "admin"',
            '"default_password": "admin"',
        ),
        "overbroad_service_account": ('"service_account_scope"', "svc-db", "svc-idp"),
        "admin_surface_exposed": ('"admin_surface_public": true',),
        "trust_edge_misconfig": (
            '"trust_scope": "corp-wide"',
            '"peer_validation": false',
        ),
    }[weakness.kind]
    tests = " && ".join(
        [f"test -f {shlex.quote(realization_path)}"]
        + [
            f"grep -Fq {shlex.quote(marker)} {shlex.quote(realization_path)}"
            for marker in markers
        ]
    )
    return (
        f"{tests} && mkdir -p {shlex.quote(effect_path.rsplit('/', 1)[0])} && "
        f"printf %s {shlex.quote(effect_content)} > {shlex.quote(effect_path)} && "
        f"cat {shlex.quote(effect_path)}"
    )


def _workflow_effect_command(weakness, realization_path: str) -> str:
    effect_path = effect_marker_path(weakness)
    effect_content = effect_marker_content(weakness)
    markers = {
        "helpdesk_reset_bypass": (
            '"identity_verification": "none"',
            '"reset_without_ticket_owner": true',
        ),
        "approval_chain_bypass": ('"secondary_approval_skipped": true',),
        "document_share_abuse": ('"share_visibility": "public_link"',),
        "phishing_credential_capture": ('"credential_capture_landing": "/login"',),
        "internal_request_impersonation": ('"internal_alias_trust": true',),
    }[weakness.kind]
    tests = " && ".join(
        [f"test -f {shlex.quote(realization_path)}"]
        + [
            f"grep -Fq {shlex.quote(marker)} {shlex.quote(realization_path)}"
            for marker in markers
        ]
    )
    return (
        f"{tests} && mkdir -p {shlex.quote(effect_path.rsplit('/', 1)[0])} && "
        f"printf %s {shlex.quote(effect_content)} > {shlex.quote(effect_path)} && "
        f"cat {shlex.quote(effect_path)}"
    )
