"""Config-identity family weakness builder."""

from __future__ import annotations

from open_range.weakness_families.common import (
    WeaknessBuildContext,
    assemble_weakness_spec,
    realization_summary,
    write_text_command,
)
from open_range.world_ir import WeaknessRealizationSpec, WorldIR


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
