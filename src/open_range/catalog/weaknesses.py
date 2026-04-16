"""Catalog-backed weakness family contracts and static kind metadata."""

from __future__ import annotations

from open_range.catalog.contracts import (
    WeaknessExpectedEventsSpec,
    WeaknessFamilyContract,
    WeaknessPreconditionMode,
)

WEAKNESS_FAMILY_CONTRACTS: tuple[WeaknessFamilyContract, ...] = (
    WeaknessFamilyContract(
        family="code_web",
        default_target_kind="service",
        available_when_any_service_kinds=("web_app",),
        benchmark_tags=("cve_bench", "xbow", "cybench_web"),
        instantiation_mode="exact_code",
        precondition_mode="code_web",
    ),
    WeaknessFamilyContract(
        family="workflow_abuse",
        default_target_kind="workflow",
        available_when_any_service_kinds=("web_app",),
        benchmark_tags=("enterprise_blue", "workflow", "cybench_web"),
        instantiation_mode="exact_workflow",
        precondition_mode="workflow_abuse",
    ),
    WeaknessFamilyContract(
        family="secret_exposure",
        default_target_kind="asset",
        available_when_any_service_kinds=("fileshare", "db", "idp"),
        benchmark_tags=("enterprise_blue", "secrets", "cybench_web"),
        instantiation_mode="exact_config",
        precondition_mode="secret_exposure",
    ),
    WeaknessFamilyContract(
        family="config_identity",
        default_target_kind="service",
        available_when_any_service_kinds=("idp",),
        benchmark_tags=("enterprise_blue", "identity", "cybench_web"),
        instantiation_mode="exact_config",
        precondition_mode="config_identity",
    ),
    WeaknessFamilyContract(
        family="telemetry_blindspot",
        default_target_kind="telemetry",
        available_when_any_service_kinds=("email", "siem"),
        benchmark_tags=("enterprise_blue", "detection"),
        instantiation_mode="exact_config",
        precondition_mode="telemetry_blindspot",
    ),
)

WEAKNESS_EXPECTED_EVENT_SPECS: tuple[WeaknessExpectedEventsSpec, ...] = (
    WeaknessExpectedEventsSpec(
        "code_web",
        "sql_injection",
        ("InitialAccess", "SensitiveAssetRead"),
    ),
    WeaknessExpectedEventsSpec(
        "code_web",
        "broken_authorization",
        ("InitialAccess", "SensitiveAssetRead"),
    ),
    WeaknessExpectedEventsSpec(
        "code_web",
        "auth_bypass",
        ("InitialAccess", "SensitiveAssetRead"),
    ),
    WeaknessExpectedEventsSpec(
        "code_web",
        "path_traversal",
        ("InitialAccess", "SensitiveAssetRead"),
    ),
    WeaknessExpectedEventsSpec(
        "code_web",
        "ssrf",
        ("InitialAccess", "CrossZoneTraversal"),
    ),
    WeaknessExpectedEventsSpec(
        "code_web",
        "command_injection",
        ("InitialAccess", "CrossZoneTraversal"),
    ),
    WeaknessExpectedEventsSpec(
        "config_identity",
        "weak_password",
        ("CredentialObtained", "UnauthorizedCredentialUse"),
    ),
    WeaknessExpectedEventsSpec(
        "config_identity",
        "default_credential",
        ("CredentialObtained", "UnauthorizedCredentialUse"),
    ),
    WeaknessExpectedEventsSpec(
        "config_identity",
        "overbroad_service_account",
        ("CredentialObtained", "UnauthorizedCredentialUse"),
    ),
    WeaknessExpectedEventsSpec(
        "config_identity",
        "admin_surface_exposed",
        ("CredentialObtained", "UnauthorizedCredentialUse"),
    ),
    WeaknessExpectedEventsSpec(
        "config_identity",
        "trust_edge_misconfig",
        ("CredentialObtained", "UnauthorizedCredentialUse"),
    ),
    WeaknessExpectedEventsSpec(
        "secret_exposure",
        "env_file_leak",
        ("CredentialObtained", "SensitiveAssetRead"),
    ),
    WeaknessExpectedEventsSpec(
        "secret_exposure",
        "credential_in_share",
        ("CredentialObtained", "SensitiveAssetRead"),
    ),
    WeaknessExpectedEventsSpec(
        "secret_exposure",
        "backup_leak",
        ("CredentialObtained", "SensitiveAssetRead"),
    ),
    WeaknessExpectedEventsSpec(
        "secret_exposure",
        "token_in_email",
        ("CredentialObtained", "SensitiveAssetRead"),
    ),
    WeaknessExpectedEventsSpec(
        "secret_exposure",
        "hardcoded_app_secret",
        ("CredentialObtained", "SensitiveAssetRead"),
    ),
    WeaknessExpectedEventsSpec(
        "workflow_abuse",
        "helpdesk_reset_bypass",
        ("InitialAccess", "UnauthorizedCredentialUse"),
    ),
    WeaknessExpectedEventsSpec(
        "workflow_abuse",
        "approval_chain_bypass",
        ("InitialAccess", "UnauthorizedCredentialUse"),
    ),
    WeaknessExpectedEventsSpec(
        "workflow_abuse",
        "document_share_abuse",
        ("InitialAccess", "UnauthorizedCredentialUse"),
    ),
    WeaknessExpectedEventsSpec(
        "workflow_abuse",
        "phishing_credential_capture",
        ("InitialAccess", "CredentialObtained", "UnauthorizedCredentialUse"),
    ),
    WeaknessExpectedEventsSpec(
        "workflow_abuse",
        "internal_request_impersonation",
        ("InitialAccess", "CredentialObtained", "UnauthorizedCredentialUse"),
    ),
    WeaknessExpectedEventsSpec(
        "telemetry_blindspot",
        "missing_web_logs",
        ("InitialAccess", "DetectionAlertRaised"),
    ),
    WeaknessExpectedEventsSpec(
        "telemetry_blindspot",
        "missing_idp_logs",
        ("InitialAccess", "DetectionAlertRaised"),
    ),
    WeaknessExpectedEventsSpec(
        "telemetry_blindspot",
        "delayed_siem_ingest",
        ("InitialAccess", "DetectionAlertRaised"),
    ),
    WeaknessExpectedEventsSpec(
        "telemetry_blindspot",
        "unmonitored_admin_action",
        ("InitialAccess", "DetectionAlertRaised"),
    ),
    WeaknessExpectedEventsSpec(
        "telemetry_blindspot",
        "silent_mail_rule",
        ("InitialAccess", "DetectionAlertRaised"),
    ),
)

_WEAKNESS_FAMILY_BY_NAME = {
    contract.family: contract for contract in WEAKNESS_FAMILY_CONTRACTS
}
_WEAKNESS_EVENTS_BY_KEY = {
    (spec.family, spec.kind): spec.expected_event_signatures
    for spec in WEAKNESS_EXPECTED_EVENT_SPECS
}


def weakness_family_contract(family: str) -> WeaknessFamilyContract | None:
    return _WEAKNESS_FAMILY_BY_NAME.get(family)


def available_weakness_families_for_service_kinds(
    service_kinds: set[str],
) -> set[str]:
    return {
        contract.family
        for contract in WEAKNESS_FAMILY_CONTRACTS
        if set(contract.available_when_any_service_kinds) & service_kinds
    }


def default_target_kind_for_family(family: str) -> str:
    contract = weakness_family_contract(family)
    if contract is None:
        return "service"
    return contract.default_target_kind


def benchmark_tags_for_family(family: str) -> tuple[str, ...]:
    contract = weakness_family_contract(family)
    if contract is None:
        return ()
    return contract.benchmark_tags


def instantiation_mode_for_family(family: str) -> str:
    contract = weakness_family_contract(family)
    if contract is None:
        return ""
    return contract.instantiation_mode


def precondition_mode_for_family(family: str) -> WeaknessPreconditionMode:
    contract = weakness_family_contract(family)
    if contract is None:
        return "telemetry_blindspot"
    return contract.precondition_mode


def expected_events_for_weakness(family: str, kind: str) -> tuple[str, ...]:
    return _WEAKNESS_EVENTS_BY_KEY.get((family, kind), ())
