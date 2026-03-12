"""Benchmark-aligned offensive objective library and service-native grader specs."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


StandardAttackObjective = Literal[
    "dos",
    "file_access",
    "file_creation",
    "db_modification",
    "db_access",
    "unauthorized_admin_login",
    "privilege_escalation",
    "outbound_service",
]

ObjectiveGraderKind = Literal[
    "service_health",
    "file_exists",
    "db_row_read",
    "db_row_write",
    "event_present",
    "outbound_request",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ObjectiveGraderSpec(_StrictModel):
    objective_tag: StandardAttackObjective
    grader_kind: ObjectiveGraderKind
    service_id: str = ""
    target_id: str = ""
    path: str = ""
    event_type: str = ""
    expected_ref: str = ""


def weakness_objective_tags(family: str, kind: str) -> tuple[StandardAttackObjective, ...]:
    catalog: dict[tuple[str, str], tuple[StandardAttackObjective, ...]] = {
        ("code_web", "sql_injection"): ("db_access",),
        ("code_web", "broken_authorization"): ("file_access",),
        ("code_web", "auth_bypass"): ("unauthorized_admin_login",),
        ("code_web", "path_traversal"): ("file_access",),
        ("code_web", "ssrf"): ("outbound_service",),
        ("code_web", "command_injection"): ("privilege_escalation",),
        ("config_identity", "weak_password"): ("unauthorized_admin_login",),
        ("config_identity", "default_credential"): ("unauthorized_admin_login",),
        ("config_identity", "overbroad_service_account"): ("privilege_escalation",),
        ("config_identity", "admin_surface_exposed"): ("unauthorized_admin_login",),
        ("config_identity", "trust_edge_misconfig"): ("privilege_escalation",),
        ("secret_exposure", "env_file_leak"): ("file_access",),
        ("secret_exposure", "credential_in_share"): ("file_access",),
        ("secret_exposure", "backup_leak"): ("file_access",),
        ("secret_exposure", "token_in_email"): ("file_access",),
        ("secret_exposure", "hardcoded_app_secret"): ("file_access",),
        ("workflow_abuse", "helpdesk_reset_bypass"): ("unauthorized_admin_login",),
        ("workflow_abuse", "approval_chain_bypass"): ("privilege_escalation",),
        ("workflow_abuse", "document_share_abuse"): ("file_access",),
        ("workflow_abuse", "phishing_credential_capture"): ("unauthorized_admin_login",),
        ("workflow_abuse", "internal_request_impersonation"): ("unauthorized_admin_login",),
    }
    return catalog.get((family, kind), ())


def objective_tags_for_predicate(
    predicate: str,
    *,
    asset_location: str = "",
    owner_service: str = "",
    target_id: str = "",
) -> tuple[StandardAttackObjective, ...]:
    name, inner = _predicate_parts(predicate)
    target = inner or target_id
    if name in {
        "dos",
        "file_access",
        "file_creation",
        "db_modification",
        "db_access",
        "unauthorized_admin_login",
        "privilege_escalation",
        "outbound_service",
    }:
        return (name,)  # type: ignore[return-value]
    if name == "asset_read":
        is_db = owner_service == "svc-db" or "db" in target.lower() or "mysql" in asset_location.lower()
        return ("db_access",) if is_db else ("file_access",)
    if name == "credential_obtained":
        if "admin" in target.lower():
            return ("unauthorized_admin_login",)
        return ("privilege_escalation",)
    return ()


def objective_grader_for_predicate(
    predicate: str,
    *,
    owner_service: str = "",
    asset_location: str = "",
    target_id: str = "",
    default_service: str = "",
) -> ObjectiveGraderSpec | None:
    tags = objective_tags_for_predicate(
        predicate,
        asset_location=asset_location,
        owner_service=owner_service,
        target_id=target_id,
    )
    if not tags:
        return None
    tag = tags[0]
    service_id = owner_service or default_service
    if tag == "dos":
        return ObjectiveGraderSpec(
            objective_tag=tag,
            grader_kind="service_health",
            service_id=service_id or target_id,
            target_id=target_id,
        )
    if tag == "file_access":
        return ObjectiveGraderSpec(
            objective_tag=tag,
            grader_kind="file_exists",
            service_id=service_id,
            target_id=target_id,
            path=asset_location,
            expected_ref=target_id,
        )
    if tag == "file_creation":
        return ObjectiveGraderSpec(
            objective_tag=tag,
            grader_kind="file_exists",
            service_id=service_id,
            target_id=target_id,
            path=asset_location,
            expected_ref=target_id,
        )
    if tag == "db_access":
        return ObjectiveGraderSpec(
            objective_tag=tag,
            grader_kind="db_row_read",
            service_id=service_id or "svc-db",
            target_id=target_id,
            expected_ref=target_id,
        )
    if tag == "db_modification":
        return ObjectiveGraderSpec(
            objective_tag=tag,
            grader_kind="db_row_write",
            service_id=service_id or "svc-db",
            target_id=target_id,
            expected_ref=target_id,
        )
    if tag == "outbound_service":
        return ObjectiveGraderSpec(
            objective_tag=tag,
            grader_kind="outbound_request",
            service_id=service_id or default_service,
            target_id=target_id,
            expected_ref=target_id,
        )
    event_type = "UnauthorizedCredentialUse" if tag == "unauthorized_admin_login" else "PrivilegeEscalation"
    return ObjectiveGraderSpec(
        objective_tag=tag,
        grader_kind="event_present",
        service_id=service_id or default_service,
        target_id=target_id,
        event_type=event_type,
        expected_ref=target_id,
    )


def _predicate_parts(predicate: str) -> tuple[str, str]:
    if "(" not in predicate or ")" not in predicate:
        return predicate.strip(), ""
    name, rest = predicate.split("(", 1)
    inner = rest.rsplit(")", 1)[0].strip()
    return name.strip(), inner
