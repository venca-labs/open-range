"""Secret-exposure family weakness builder."""

from __future__ import annotations

from open_range.predicate_expr import predicate_inner
from open_range.weakness_families.common import (
    WeaknessBuildContext,
    assemble_weakness_spec,
    first_objective_service,
    mailbox_for_ref,
    mailbox_remediated_message,
    mailbox_slug,
    realization_summary,
    write_text_command,
)
from open_range.world_ir import WeaknessRealizationSpec, WorldIR


def mutation_target_service(world: WorldIR) -> str | None:
    service_by_kind = {service.kind: service.id for service in world.services}
    objective_service = first_objective_service(world)
    if objective_service:
        return objective_service
    return (
        service_by_kind.get("fileshare")
        or service_by_kind.get("db")
        or service_by_kind.get("idp")
    )


def mutation_spec(world: WorldIR, target_service: str) -> tuple[str, str, str]:
    exposed_asset = next(
        (asset.id for asset in world.assets if asset.owner_service == target_service),
        predicate_inner(world.red_objectives[0].predicate)
        if world.red_objectives
        else target_service,
    )
    if target_service == "svc-email":
        return ("token_in_email", "asset", exposed_asset)
    if target_service == "svc-fileshare":
        return ("backup_leak", "asset", exposed_asset)
    return ("hardcoded_app_secret", "asset", exposed_asset)


def build(context: WeaknessBuildContext):
    realizations = _secret_exposure_realizations(context)
    return assemble_weakness_spec(
        context,
        realization=realizations,
        remediation_command=_secret_exposure_remediation_command(
            context.kind, realizations
        ),
    )


def _secret_exposure_realizations(
    context: WeaknessBuildContext,
) -> tuple[WeaknessRealizationSpec, ...]:
    if context.kind == "env_file_leak":
        path = (
            "/var/www/html/.env"
            if context.target == "svc-web"
            else "/etc/openrange/.env"
        )
        return (
            WeaknessRealizationSpec(
                kind="config",
                service=context.target,
                path=path,
                summary=realization_summary("secret_exposure", context.kind),
            ),
        )
    if context.kind == "credential_in_share":
        return (
            WeaknessRealizationSpec(
                kind="seed_data",
                service=context.target,
                path=f"/srv/shared/.openrange/exposed-{context.target_ref}.txt",
                summary=realization_summary("secret_exposure", context.kind),
            ),
        )
    if context.kind == "backup_leak":
        path = (
            f"/srv/shared/.openrange/backup-{context.target_ref}.sql"
            if context.target == "svc-fileshare"
            else f"/var/backups/openrange-{context.target_ref}.sql"
        )
        return (
            WeaknessRealizationSpec(
                kind="seed_data",
                service=context.target,
                path=path,
                summary=realization_summary("secret_exposure", context.kind),
            ),
        )
    if context.kind == "token_in_email":
        mailbox = mailbox_for_ref(context.world, context.target_ref)
        return (
            WeaknessRealizationSpec(
                kind="mailbox",
                service="svc-email",
                path=(
                    "/var/spool/openrange/mailboxes/"
                    f"{mailbox_slug(mailbox)}/token-{context.target_ref}.eml"
                ),
                summary=realization_summary("secret_exposure", context.kind),
            ),
        )
    path = (
        "/var/www/html/.openrange/app-secret.php"
        if context.target == "svc-web"
        else "/etc/openrange/app-secret.txt"
    )
    return (
        WeaknessRealizationSpec(
            kind="config",
            service=context.target,
            path=path,
            summary=realization_summary("secret_exposure", context.kind),
        ),
    )


def _secret_exposure_remediation_command(
    kind: str, realizations: tuple[WeaknessRealizationSpec, ...]
) -> str:
    commands = []
    for realization in realizations:
        if realization.kind == "mailbox":
            commands.append(
                write_text_command(realization.path, mailbox_remediated_message(kind))
            )
        else:
            commands.append(write_text_command(realization.path, "access revoked\n"))
    commands.append("touch /tmp/openrange-patched")
    return "\n".join(commands)


def seed_defaults(world: WorldIR) -> tuple[str, str]:
    target = (
        "svc-fileshare"
        if any(service.id == "svc-fileshare" for service in world.services)
        else "svc-idp"
    )
    sensitive_asset = next(
        (asset.id for asset in world.assets if asset.asset_class == "sensitive"),
        world.assets[0].id if world.assets else target,
    )
    return (target, sensitive_asset)


def default_kind(world: WorldIR, target: str, target_ref: str) -> str:
    del world, target_ref
    if target == "svc-email":
        return "token_in_email"
    if target == "svc-fileshare":
        return "credential_in_share"
    return "hardcoded_app_secret"


def normalize_target(
    world: WorldIR,
    kind: str,
    target: str,
    target_kind: str,
    target_ref: str,
) -> tuple[str, str, str]:
    service_ids = {service.id for service in world.services}
    if kind == "token_in_email" and "svc-email" in service_ids:
        return ("svc-email", target_kind, target_ref)
    if kind in {"env_file_leak", "hardcoded_app_secret"} and "svc-web" in service_ids:
        return ("svc-web", target_kind, target_ref)
    if (
        kind in {"credential_in_share", "backup_leak"}
        and "svc-fileshare" in service_ids
    ):
        return ("svc-fileshare", target_kind, target_ref)
    return (target, target_kind, target_ref)
