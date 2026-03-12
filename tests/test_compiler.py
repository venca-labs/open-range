from __future__ import annotations

from open_range.compiler import EnterpriseSaaSManifestCompiler


def _manifest_payload() -> dict:
    return {
        "version": 1,
        "world_family": "enterprise_saas_v1",
        "seed": 1337,
        "business": {
            "archetype": "healthcare_saas",
            "workflows": [
                "helpdesk_ticketing",
                "payroll_approval",
                "document_sharing",
                "internal_email",
            ],
        },
        "topology": {
            "zones": ["external", "dmz", "corp", "data", "management"],
            "services": ["web_app", "email", "idp", "fileshare", "db", "siem"],
        },
        "users": {
            "roles": {
                "sales": 2,
                "engineer": 1,
                "finance": 1,
                "it_admin": 1,
            },
        },
        "assets": [
            {"id": "finance_docs", "class": "crown_jewel"},
            {"id": "payroll_db", "class": "crown_jewel"},
            {"id": "idp_admin_cred", "class": "sensitive"},
        ],
        "objectives": {
            "red": [
                {"predicate": "asset_read(finance_docs)"},
                {"predicate": "credential_obtained(idp_admin_cred)"},
            ],
            "blue": [
                {"predicate": "intrusion_detected(initial_access)"},
                {"predicate": "intrusion_contained(before_asset_read)"},
                {"predicate": "service_health_above(0.9)"},
            ],
        },
        "security": {
            "allowed_weakness_families": [
                "config_identity",
                "workflow_abuse",
                "secret_exposure",
                "code_web",
                "telemetry_blindspot",
            ],
            "code_flaw_kinds": [
                "sql_injection",
                "broken_authorization",
                "path_traversal",
            ],
            "phishing_surface_enabled": False,
            "observability": {
                "require_web_logs": True,
                "require_idp_logs": True,
                "require_email_logs": True,
                "require_siem_ingest": True,
            },
        },
        "difficulty": {
            "target_red_path_depth": 8,
            "target_blue_signal_points": 4,
            "target_noise_density": "medium",
        },
        "mutation_bounds": {
            "max_new_hosts": 2,
            "max_new_services": 1,
            "max_new_users": 5,
            "max_new_weaknesses": 2,
            "allow_patch_old_weaknesses": True,
        },
    }


def test_compiler_builds_hand_checkable_world_ir():
    world = EnterpriseSaaSManifestCompiler().compile(_manifest_payload())

    assert world.world_id == "enterprise_saas_v1-1337"
    assert world.allowed_service_kinds == ("web_app", "email", "idp", "fileshare", "db", "siem")
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
    assert world.red_objectives[1].objective_tags == ("unauthorized_admin_login",)
    assert any(edge.kind == "telemetry" and edge.target == "svc-siem" for edge in world.telemetry_edges)


def test_compiler_creates_role_groups_and_identity_credentials():
    world = EnterpriseSaaSManifestCompiler().compile(_manifest_payload())

    assert {group.id for group in world.groups} == {
        "group-sales",
        "group-engineer",
        "group-finance",
        "group-it_admin",
    }
    assert len(world.credentials) == len(world.users)
    assert all(cred.secret_ref.startswith("secret://idp/") for cred in world.credentials)


def test_compiler_threads_pinned_weaknesses_into_world():
    payload = _manifest_payload()
    payload["security"]["pinned_weaknesses"] = [
        {"family": "secret_exposure", "kind": "credential_in_share", "target": "asset:finance_docs"},
    ]

    world = EnterpriseSaaSManifestCompiler().compile(payload)

    assert len(world.pinned_weaknesses) == 1
    assert world.pinned_weaknesses[0].family == "secret_exposure"
    assert world.pinned_weaknesses[0].kind == "credential_in_share"
    assert world.pinned_weaknesses[0].target == "asset:finance_docs"
