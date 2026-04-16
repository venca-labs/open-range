"""Catalog-backed weakness family contracts and static kind metadata."""

from __future__ import annotations

from open_range.catalog.contracts import (
    WeaknessExpectedEventsSpec,
    WeaknessFamilyContract,
    WeaknessObservabilitySurfaceSpec,
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

WEAKNESS_OBSERVABILITY_SURFACE_SPECS: tuple[WeaknessObservabilitySurfaceSpec, ...] = (
    WeaknessObservabilitySurfaceSpec(
        family="code_web",
        surfaces=("web_access", "ingest"),
    ),
    WeaknessObservabilitySurfaceSpec(
        family="workflow_abuse",
        kind="document_share_abuse",
        surfaces=("share_access", "audit", "ingest"),
    ),
    WeaknessObservabilitySurfaceSpec(
        family="workflow_abuse",
        target="svc-fileshare",
        surfaces=("share_access", "audit", "ingest"),
    ),
    WeaknessObservabilitySurfaceSpec(
        family="workflow_abuse",
        kind="phishing_credential_capture",
        surfaces=("smtp", "imap", "audit", "ingest"),
    ),
    WeaknessObservabilitySurfaceSpec(
        family="workflow_abuse",
        kind="internal_request_impersonation",
        surfaces=("smtp", "imap", "audit", "ingest"),
    ),
    WeaknessObservabilitySurfaceSpec(
        family="workflow_abuse",
        target="svc-email",
        surfaces=("smtp", "imap", "audit", "ingest"),
    ),
    WeaknessObservabilitySurfaceSpec(
        family="workflow_abuse",
        surfaces=("web_access", "audit", "ingest"),
    ),
    WeaknessObservabilitySurfaceSpec(
        family="secret_exposure",
        kind="token_in_email",
        surfaces=("smtp", "imap", "audit", "ingest"),
    ),
    WeaknessObservabilitySurfaceSpec(
        family="secret_exposure",
        target="svc-email",
        surfaces=("smtp", "imap", "audit", "ingest"),
    ),
    WeaknessObservabilitySurfaceSpec(
        family="secret_exposure",
        target="svc-fileshare",
        surfaces=("share_access", "audit", "ingest"),
    ),
    WeaknessObservabilitySurfaceSpec(
        family="secret_exposure",
        target="svc-web",
        surfaces=("web_access", "audit", "ingest"),
    ),
    WeaknessObservabilitySurfaceSpec(
        family="secret_exposure",
        surfaces=("audit", "ingest"),
    ),
    WeaknessObservabilitySurfaceSpec(
        family="config_identity",
        kind="admin_surface_exposed",
        surfaces=("auth", "audit", "web_access"),
    ),
    WeaknessObservabilitySurfaceSpec(
        family="config_identity",
        kind="trust_edge_misconfig",
        surfaces=("auth", "audit", "web_access"),
    ),
    WeaknessObservabilitySurfaceSpec(
        family="config_identity",
        surfaces=("auth", "audit", "ingest"),
    ),
    WeaknessObservabilitySurfaceSpec(
        family="telemetry_blindspot",
        kind="missing_web_logs",
        surfaces=("web_access", "web_error", "ingest"),
    ),
    WeaknessObservabilitySurfaceSpec(
        family="telemetry_blindspot",
        kind="missing_idp_logs",
        surfaces=("auth", "audit", "ingest"),
    ),
    WeaknessObservabilitySurfaceSpec(
        family="telemetry_blindspot",
        kind="unmonitored_admin_action",
        surfaces=("auth", "audit", "ingest"),
    ),
    WeaknessObservabilitySurfaceSpec(
        family="telemetry_blindspot",
        kind="silent_mail_rule",
        surfaces=("smtp", "imap", "ingest"),
    ),
    WeaknessObservabilitySurfaceSpec(
        family="telemetry_blindspot",
        surfaces=("ingest",),
    ),
)

_WEAKNESS_FAMILY_BY_NAME = {
    contract.family: contract for contract in WEAKNESS_FAMILY_CONTRACTS
}
_WEAKNESS_EVENTS_BY_KEY = {
    (spec.family, spec.kind): spec.expected_event_signatures
    for spec in WEAKNESS_EXPECTED_EVENT_SPECS
}
_WEAKNESS_SURFACE_SPECS_BY_FAMILY: dict[
    str, tuple[WeaknessObservabilitySurfaceSpec, ...]
] = {}
for spec in WEAKNESS_OBSERVABILITY_SURFACE_SPECS:
    _WEAKNESS_SURFACE_SPECS_BY_FAMILY.setdefault(spec.family, ())
    _WEAKNESS_SURFACE_SPECS_BY_FAMILY[spec.family] = (
        *_WEAKNESS_SURFACE_SPECS_BY_FAMILY[spec.family],
        spec,
    )


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


def observability_surfaces_for_weakness(
    family: str,
    *,
    kind: str = "",
    target: str = "",
) -> tuple[str, ...]:
    for spec in _WEAKNESS_SURFACE_SPECS_BY_FAMILY.get(family, ()):
        if spec.kind and spec.kind != kind:
            continue
        if spec.target and spec.target != target:
            continue
        return spec.surfaces
    return ()
