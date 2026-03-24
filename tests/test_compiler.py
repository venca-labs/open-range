from __future__ import annotations

import pytest

from open_range.compiler import EnterpriseSaaSManifestCompiler
from tests.support import manifest_payload


def _manifest_payload() -> dict:
    payload = manifest_payload()
    payload["objectives"]["red"] = [
        {"predicate": "asset_read(finance_docs)"},
        {"predicate": "credential_obtained(idp_admin_cred)"},
    ]
    payload["security"]["code_flaw_kinds"] = [
        "sql_injection",
        "broken_authorization",
        "path_traversal",
    ]
    payload["security"]["phishing_surface_enabled"] = False
    payload["difficulty"]["target_red_path_depth"] = 8
    payload["mutation_bounds"]["allow_patch_old_weaknesses"] = True
    return payload


def test_compiler_builds_hand_checkable_world_ir():
    world = EnterpriseSaaSManifestCompiler().compile(_manifest_payload())

    assert world.world_id == "enterprise_saas_v1-1337"
    assert world.allowed_service_kinds == (
        "web_app",
        "email",
        "idp",
        "fileshare",
        "db",
        "siem",
    )
    assert world.allowed_weakness_families == (
        "config_identity",
        "workflow_abuse",
        "secret_exposure",
        "code_web",
        "telemetry_blindspot",
    )
    assert world.allowed_code_flaw_kinds == (
        "sql_injection",
        "broken_authorization",
        "path_traversal",
    )
    assert world.target_weakness_count == 2
    assert world.phishing_surface_enabled is False
    assert world.mutation_bounds.max_new_hosts == 2
    assert {service.kind for service in world.services} == {
        "web_app",
        "email",
        "idp",
        "fileshare",
        "db",
        "siem",
    }
    assert len(world.users) == 5
    assert len(world.green_personas) == 5
    assert {asset.owner_service for asset in world.assets} == {
        "svc-fileshare",
        "svc-db",
        "svc-idp",
    }
    assert world.red_objectives[0].objective_tags == ("file_access",)
    assert world.red_objectives[1].objective_tags == ("privilege_escalation",)
    assert any(
        edge.kind == "telemetry" and edge.target == "svc-siem"
        for edge in world.telemetry_edges
    )


def test_compiler_creates_role_groups_and_identity_credentials():
    world = EnterpriseSaaSManifestCompiler().compile(_manifest_payload())

    assert {group.id for group in world.groups} == {
        "group-sales",
        "group-engineer",
        "group-finance",
        "group-it_admin",
    }
    assert len(world.credentials) == len(world.users)
    assert all(
        cred.secret_ref.startswith("secret://idp/") for cred in world.credentials
    )


def test_compiler_threads_pinned_weaknesses_into_world():
    payload = _manifest_payload()
    payload["security"]["pinned_weaknesses"] = [
        {
            "family": "secret_exposure",
            "kind": "credential_in_share",
            "target": "asset:finance_docs",
        },
    ]

    world = EnterpriseSaaSManifestCompiler().compile(payload)

    assert len(world.pinned_weaknesses) == 1
    assert world.pinned_weaknesses[0].family == "secret_exposure"
    assert world.pinned_weaknesses[0].kind == "credential_in_share"
    assert world.pinned_weaknesses[0].target == "asset:finance_docs"


def test_compiler_applies_partial_npc_profile_overrides_and_keeps_defaults():
    payload = _manifest_payload()
    payload["npc_profiles"] = {
        "sales": {
            "awareness": 0.25,
        }
    }

    world = EnterpriseSaaSManifestCompiler().compile(payload)

    sales_personas = [
        persona for persona in world.green_personas if persona.role == "sales"
    ]

    assert sales_personas
    assert all(persona.awareness == 0.25 for persona in sales_personas)
    assert all(persona.susceptibility == {} for persona in sales_personas)
    assert all(
        persona.routine == ("check_mail", "browse_app", "access_fileshare")
        for persona in sales_personas
    )


def test_compiler_treats_empty_npc_profiles_as_noop():
    baseline = EnterpriseSaaSManifestCompiler().compile(_manifest_payload())
    payload = _manifest_payload()
    payload["npc_profiles"] = {}

    world = EnterpriseSaaSManifestCompiler().compile(payload)

    assert world.green_personas == baseline.green_personas


def test_compiler_rejects_npc_profiles_for_unknown_roles():
    payload = _manifest_payload()
    payload["npc_profiles"] = {"legal": {"awareness": 0.5}}

    with pytest.raises(ValueError, match="npc_profiles references unknown role"):
        EnterpriseSaaSManifestCompiler().compile(payload)
