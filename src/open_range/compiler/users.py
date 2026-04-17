"""User, group, and green persona compilation helpers."""

from __future__ import annotations

from open_range.catalog.roles import home_service_for_role, routine_for_role
from open_range.catalog.services import host_for_service
from open_range.config import BuildConfig
from open_range.contracts.world import CredentialSpec, GreenPersona, GroupSpec, UserSpec
from open_range.manifest import EnterpriseSaaSManifest, NPCProfileSpec


def expand_users(
    manifest: EnterpriseSaaSManifest,
    build_config: BuildConfig,
) -> tuple[
    tuple[UserSpec, ...],
    tuple[GroupSpec, ...],
    tuple[CredentialSpec, ...],
    tuple[GreenPersona, ...],
]:
    users: list[UserSpec] = []
    groups: list[GroupSpec] = []
    credentials: list[CredentialSpec] = []
    personas: list[GreenPersona] = []

    for role, count in manifest.users.roles.items():
        if build_config.topology_scale == "small":
            scaled_count = 1
        elif build_config.topology_scale == "large":
            scaled_count = max(1, count * 2)
        else:
            scaled_count = count

        member_ids: list[str] = []
        home_service = home_service_for_role(role)
        home_host = host_for_service(home_service)

        for idx in range(1, scaled_count + 1):
            user_id = f"{role}-{idx:02d}"
            member_ids.append(user_id)
            users.append(
                UserSpec(
                    id=user_id,
                    role=role,
                    department=role,
                    primary_host=home_host,
                    groups=(f"group-{role}",),
                    email=f"{user_id}@corp.local",
                )
            )
            credentials.append(
                CredentialSpec(
                    id=f"cred-{user_id}",
                    subject=user_id,
                    secret_ref=f"secret://idp/{user_id}",
                    scope=("svc-idp", home_service),
                )
            )
            personas.append(
                persona_for_user(
                    id=user_id,
                    role=role,
                    department=role,
                    home_host=home_host,
                    mailbox=f"{user_id}@corp.local",
                    profile=manifest.npc_profiles.get(role),
                )
            )

        groups.append(
            GroupSpec(
                id=f"group-{role}",
                members=tuple(member_ids),
                privileges=(home_service,),
            )
        )

    return tuple(users), tuple(groups), tuple(credentials), tuple(personas)


def validate_npc_profiles(manifest: EnterpriseSaaSManifest) -> None:
    if not manifest.npc_profiles:
        return
    declared_roles = set(manifest.users.roles)
    unknown_roles = sorted(set(manifest.npc_profiles) - declared_roles)
    if not unknown_roles:
        return
    declared = ", ".join(sorted(declared_roles))
    unknown = ", ".join(repr(role) for role in unknown_roles)
    raise ValueError(
        f"npc_profiles references unknown role(s): {unknown}; declared manifest roles: {declared}"
    )


def persona_for_user(
    *,
    id: str,
    role: str,
    department: str,
    home_host: str,
    mailbox: str,
    profile: NPCProfileSpec | None,
) -> GreenPersona:
    persona = GreenPersona(
        id=id,
        role=role,
        department=department,
        home_host=home_host,
        mailbox=mailbox,
        routine=routine_for_role(role),
    )
    if profile is None:
        return persona
    updates = {"susceptibility": profile.susceptibility}
    if profile.awareness is not None:
        updates["awareness"] = profile.awareness
    if profile.routine is not None:
        updates["routine"] = profile.routine
    return persona.model_copy(update=updates)
