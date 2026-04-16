"""Config-identity family weakness builder."""

from __future__ import annotations

import json

from open_range.admission import ReferenceAction
from open_range.catalog.probes import (
    identity_effect_markers_for_kind,
    reference_action_for_weakness_family,
)
from open_range.effect_markers import (
    effect_marker_content,
    effect_marker_path,
    effect_marker_token,
)
from open_range.predicates import PredicateEngine
from open_range.weakness_families.common import (
    RedReferencePlan,
    WeaknessBuildContext,
    assemble_weakness_spec,
    effect_marker_command,
    first_realization_path,
    realization_summary,
    shell_payload,
    target_ref_objective,
    traverse_to_target,
    write_text_command,
)
from open_range.world_ir import WeaknessRealizationSpec, WeaknessSpec, WorldIR


def mutation_target_service(world: WorldIR) -> str | None:
    return next(
        (service.id for service in world.services if service.kind == "idp"), None
    )


def mutation_spec(world: WorldIR, target_service: str) -> tuple[str, str, str]:
    if any(user.role == "it_admin" for user in world.users):
        credential = next(
            (
                item
                for item in world.credentials
                if item.subject.startswith("it_admin-")
            ),
            None,
        )
        if credential is not None:
            return ("weak_password", "credential", credential.id)
    return ("admin_surface_exposed", "service", target_service)


def build_red_reference_plan(
    world: WorldIR,
    engine: PredicateEngine,
    start: str,
    weakness: WeaknessSpec,
) -> RedReferencePlan:
    realization_path = first_realization_path(weakness)
    payload = shell_payload(
        action=reference_action_for_weakness_family(weakness.family),
        weakness_id=weakness.id,
        target=weakness.target,
        path=realization_path,
        expect_contains=effect_marker_token(weakness) or weakness.kind,
    )
    live_command = effect_marker_command(
        realization_path=realization_path or "",
        effect_path=effect_marker_path(weakness),
        effect_content=effect_marker_content(weakness),
        markers=identity_effect_markers_for_kind(weakness.kind),
    )
    payload["command"] = live_command
    payload["service_command"] = live_command
    satisfied: list[str] = []
    objective = target_ref_objective(world, weakness.target_ref)
    if objective is not None:
        payload["objective"] = objective
        satisfied.append(objective)
    return RedReferencePlan(
        steps=traverse_to_target(engine, start, weakness.target)
        + (
            ReferenceAction(
                actor="red",
                kind="shell",
                target=weakness.target,
                payload=payload,
            ),
        ),
        current=weakness.target,
        satisfied_predicates=tuple(satisfied),
    )


def render_realization_content(
    world: WorldIR,
    weakness: WeaknessSpec,
    realization: WeaknessRealizationSpec,
) -> str:
    del realization
    payload = {
        "world_id": world.world_id,
        "weakness_id": weakness.id,
        "kind": weakness.kind,
        "target": weakness.target,
        "target_ref": weakness.target_ref,
        "mfa_required": False,
        "privileged_scope_validation": False,
    }
    if weakness.kind == "weak_password":
        payload.update({"min_password_length": 6, "password_reuse_allowed": True})
    elif weakness.kind == "default_credential":
        payload.update({"default_username": "admin", "default_password": "admin"})
    elif weakness.kind == "overbroad_service_account":
        payload.update(
            {"service_account_scope": ["svc-db", "svc-fileshare", "svc-idp"]}
        )
    elif weakness.kind == "admin_surface_exposed":
        payload.update({"admin_surface_public": True, "debug_toggle": True})
    elif weakness.kind == "trust_edge_misconfig":
        payload.update({"trust_scope": "corp-wide", "peer_validation": False})
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def build(context: WeaknessBuildContext):
    realizations = _config_identity_realizations(context)
    return assemble_weakness_spec(
        context,
        realization=realizations,
        remediation_command=_config_identity_remediation_command(
            context.kind, realizations
        ),
    )


def _config_identity_realizations(
    context: WeaknessBuildContext,
) -> tuple[WeaknessRealizationSpec, ...]:
    filename = {
        "weak_password": "password-policy.json",
        "default_credential": "default-credential.json",
        "overbroad_service_account": "service-account-policy.json",
        "admin_surface_exposed": "admin-surface.json",
        "trust_edge_misconfig": "trust-edge.json",
    }[context.kind]
    return (
        WeaknessRealizationSpec(
            kind="config",
            service=context.target,
            path=f"/etc/openrange/{filename}",
            summary=realization_summary("config_identity", context.kind),
        ),
    )


def _config_identity_remediation_command(
    kind: str, realizations: tuple[WeaknessRealizationSpec, ...]
) -> str:
    payload = _config_identity_remediation_payload(kind)
    commands = [
        write_text_command(realization.path, payload) for realization in realizations
    ]
    commands.append("touch /tmp/openrange-patched")
    return "\n".join(commands)


def _config_identity_remediation_payload(kind: str) -> str:
    return (
        "{\n"
        f'  "kind": "{kind}",\n'
        '  "mfa_required": true,\n'
        '  "min_password_length": 14,\n'
        '  "privileged_scope_validation": true,\n'
        '  "default_credentials_disabled": true,\n'
        '  "admin_surface_public": false,\n'
        '  "trust_scope_restricted": true\n'
        "}\n"
    )


def seed_defaults(world: WorldIR) -> tuple[str, str]:
    del world
    return ("svc-idp", "svc-idp")


def default_kind(world: WorldIR, target: str, target_ref: str) -> str:
    del target_ref
    if any(user.role == "it_admin" for user in world.users):
        return "weak_password"
    return "admin_surface_exposed" if target == "svc-idp" else "trust_edge_misconfig"


def normalize_target(
    world: WorldIR,
    kind: str,
    target: str,
    target_kind: str,
    target_ref: str,
) -> tuple[str, str, str]:
    del kind
    service_ids = {service.id for service in world.services}
    if "svc-idp" in service_ids:
        return ("svc-idp", target_kind, target_ref)
    return (target, target_kind, target_ref)
