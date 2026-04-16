"""Registered objective resolution rules and weakness objective tags."""

from __future__ import annotations

from typing import cast

from open_range.objectives import (
    STANDARD_ATTACK_OBJECTIVE_NAMES,
    ObjectiveGraderSpec,
    StandardAttackObjective,
    _build_resolution_for_tag,
    _ObjectiveContext,
    _ObjectiveResolution,
    objective_rule,
    register_weakness_objective_tags,
)
from open_range.predicate_expr import PredicateExpr


def _register_weakness_tag_rules() -> None:
    catalog: tuple[tuple[str, str, tuple[StandardAttackObjective, ...]], ...] = (
        ("code_web", "sql_injection", ("db_access",)),
        ("code_web", "broken_authorization", ("file_access",)),
        ("code_web", "auth_bypass", ("unauthorized_admin_login",)),
        ("code_web", "path_traversal", ("file_access",)),
        ("code_web", "ssrf", ("outbound_service",)),
        ("code_web", "command_injection", ("privilege_escalation",)),
        ("config_identity", "weak_password", ("unauthorized_admin_login",)),
        ("config_identity", "default_credential", ("unauthorized_admin_login",)),
        ("config_identity", "overbroad_service_account", ("privilege_escalation",)),
        ("config_identity", "admin_surface_exposed", ("unauthorized_admin_login",)),
        ("config_identity", "trust_edge_misconfig", ("privilege_escalation",)),
        ("secret_exposure", "env_file_leak", ("file_access",)),
        ("secret_exposure", "credential_in_share", ("file_access",)),
        ("secret_exposure", "backup_leak", ("file_access",)),
        ("secret_exposure", "token_in_email", ("file_access",)),
        ("secret_exposure", "hardcoded_app_secret", ("file_access",)),
        ("workflow_abuse", "helpdesk_reset_bypass", ("unauthorized_admin_login",)),
        ("workflow_abuse", "approval_chain_bypass", ("privilege_escalation",)),
        ("workflow_abuse", "document_share_abuse", ("file_access",)),
        (
            "workflow_abuse",
            "phishing_credential_capture",
            ("unauthorized_admin_login",),
        ),
        (
            "workflow_abuse",
            "internal_request_impersonation",
            ("unauthorized_admin_login",),
        ),
    )
    for family, kind, objective_tags in catalog:
        register_weakness_objective_tags(
            family=family,
            kind=kind,
            objective_tags=objective_tags,
        )


@objective_rule(*STANDARD_ATTACK_OBJECTIVE_NAMES)
def _direct_objective_rule(
    expr: PredicateExpr, ctx: _ObjectiveContext
) -> _ObjectiveResolution:
    return _build_resolution_for_tag(
        cast(StandardAttackObjective, expr.name),
        ctx.resolved_target(expr),
        ctx,
    )


@objective_rule("asset_read")
def _asset_read_rule(
    expr: PredicateExpr, ctx: _ObjectiveContext
) -> _ObjectiveResolution:
    resolved_target = ctx.resolved_target(expr)
    tag: StandardAttackObjective = (
        "db_access" if ctx.is_db_target(resolved_target) else "file_access"
    )
    return _build_resolution_for_tag(tag, resolved_target, ctx)


@objective_rule("credential_obtained")
def _credential_obtained_rule(
    expr: PredicateExpr, ctx: _ObjectiveContext
) -> _ObjectiveResolution:
    resolved_target = ctx.resolved_target(expr)
    service_id = ctx.owner_service or ctx.default_service or "svc-idp"
    return _ObjectiveResolution(
        objective_tags=("privilege_escalation",),
        grader=ObjectiveGraderSpec(
            objective_tag="privilege_escalation",
            grader_kind="event_present",
            service_id=service_id,
            target_id=resolved_target,
            event_type="CredentialObtained",
            expected_ref=resolved_target,
        ),
    )


@objective_rule("intrusion_detected", "intrusion_contained", "service_health_above")
def _observation_only_rule(
    _expr: PredicateExpr, _ctx: _ObjectiveContext
) -> _ObjectiveResolution:
    return _ObjectiveResolution()


_register_weakness_tag_rules()
