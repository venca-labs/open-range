from __future__ import annotations

from copy import deepcopy

from open_range.build_config import OFFLINE_BUILD_CONFIG, OFFLINE_REFERENCE_BUILD_CONFIG

__all__ = ["OFFLINE_BUILD_CONFIG", "OFFLINE_REFERENCE_BUILD_CONFIG", "manifest_payload"]


_BASE_MANIFEST_PAYLOAD = {
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
            {"predicate": "credential_obtained(idp_admin_cred)"},
            {"predicate": "asset_read(finance_docs)"},
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
        "observability": {
            "require_web_logs": True,
            "require_idp_logs": True,
            "require_email_logs": True,
            "require_siem_ingest": True,
        },
    },
    "difficulty": {
        "target_red_path_depth": 4,
        "target_blue_signal_points": 4,
        "target_noise_density": "medium",
    },
    "mutation_bounds": {
        "max_new_hosts": 2,
        "max_new_services": 1,
        "max_new_users": 5,
        "max_new_weaknesses": 2,
    },
}


def manifest_payload(*, seed: int = 1337) -> dict:
    payload = deepcopy(_BASE_MANIFEST_PAYLOAD)
    payload["seed"] = seed
    return payload
