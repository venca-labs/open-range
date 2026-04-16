"""Catalog-backed objective and weakness rule data."""

from __future__ import annotations

from open_range.catalog.contracts import (
    STANDARD_ATTACK_OBJECTIVE_NAMES,
    ObjectiveRuleSpec,
    WeaknessObjectiveTagSpec,
)

OBJECTIVE_RULE_SPECS: tuple[ObjectiveRuleSpec, ...] = (
    *(
        ObjectiveRuleSpec(
            predicate_name=objective_tag,
            resolution_kind="direct_objective",
            objective_tag=objective_tag,
        )
        for objective_tag in STANDARD_ATTACK_OBJECTIVE_NAMES
    ),
    ObjectiveRuleSpec(
        predicate_name="asset_read",
        resolution_kind="asset_read",
    ),
    ObjectiveRuleSpec(
        predicate_name="credential_obtained",
        resolution_kind="credential_obtained",
    ),
    ObjectiveRuleSpec(
        predicate_name="intrusion_detected",
        resolution_kind="observation_only",
    ),
    ObjectiveRuleSpec(
        predicate_name="intrusion_contained",
        resolution_kind="observation_only",
    ),
    ObjectiveRuleSpec(
        predicate_name="service_health_above",
        resolution_kind="observation_only",
    ),
)

WEAKNESS_OBJECTIVE_TAG_SPECS: tuple[WeaknessObjectiveTagSpec, ...] = (
    WeaknessObjectiveTagSpec("code_web", "sql_injection", ("db_access",)),
    WeaknessObjectiveTagSpec("code_web", "broken_authorization", ("file_access",)),
    WeaknessObjectiveTagSpec("code_web", "auth_bypass", ("unauthorized_admin_login",)),
    WeaknessObjectiveTagSpec("code_web", "path_traversal", ("file_access",)),
    WeaknessObjectiveTagSpec("code_web", "ssrf", ("outbound_service",)),
    WeaknessObjectiveTagSpec(
        "code_web", "command_injection", ("privilege_escalation",)
    ),
    WeaknessObjectiveTagSpec(
        "config_identity",
        "weak_password",
        ("unauthorized_admin_login",),
    ),
    WeaknessObjectiveTagSpec(
        "config_identity",
        "default_credential",
        ("unauthorized_admin_login",),
    ),
    WeaknessObjectiveTagSpec(
        "config_identity",
        "overbroad_service_account",
        ("privilege_escalation",),
    ),
    WeaknessObjectiveTagSpec(
        "config_identity",
        "admin_surface_exposed",
        ("unauthorized_admin_login",),
    ),
    WeaknessObjectiveTagSpec(
        "config_identity",
        "trust_edge_misconfig",
        ("privilege_escalation",),
    ),
    WeaknessObjectiveTagSpec("secret_exposure", "env_file_leak", ("file_access",)),
    WeaknessObjectiveTagSpec(
        "secret_exposure",
        "credential_in_share",
        ("file_access",),
    ),
    WeaknessObjectiveTagSpec("secret_exposure", "backup_leak", ("file_access",)),
    WeaknessObjectiveTagSpec("secret_exposure", "token_in_email", ("file_access",)),
    WeaknessObjectiveTagSpec(
        "secret_exposure",
        "hardcoded_app_secret",
        ("file_access",),
    ),
    WeaknessObjectiveTagSpec(
        "workflow_abuse",
        "helpdesk_reset_bypass",
        ("unauthorized_admin_login",),
    ),
    WeaknessObjectiveTagSpec(
        "workflow_abuse",
        "approval_chain_bypass",
        ("privilege_escalation",),
    ),
    WeaknessObjectiveTagSpec(
        "workflow_abuse",
        "document_share_abuse",
        ("file_access",),
    ),
    WeaknessObjectiveTagSpec(
        "workflow_abuse",
        "phishing_credential_capture",
        ("unauthorized_admin_login",),
    ),
    WeaknessObjectiveTagSpec(
        "workflow_abuse",
        "internal_request_impersonation",
        ("unauthorized_admin_login",),
    ),
)

_OBJECTIVE_RULES_BY_NAME = {rule.predicate_name: rule for rule in OBJECTIVE_RULE_SPECS}
_WEAKNESS_OBJECTIVE_TAGS = {
    (rule.family, rule.kind): rule.objective_tags
    for rule in WEAKNESS_OBJECTIVE_TAG_SPECS
}


def public_objective_predicate_names() -> tuple[str, ...]:
    return tuple(rule.predicate_name for rule in OBJECTIVE_RULE_SPECS)


def objective_rule_for_predicate_name(predicate_name: str) -> ObjectiveRuleSpec | None:
    return _OBJECTIVE_RULES_BY_NAME.get(predicate_name)


def weakness_objective_tags_for_kind(
    family: str,
    kind: str,
) -> tuple[str, ...]:
    return _WEAKNESS_OBJECTIVE_TAGS.get((family, kind), ())
