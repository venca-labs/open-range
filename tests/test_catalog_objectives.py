from __future__ import annotations

from open_range.catalog.contracts import STANDARD_ATTACK_OBJECTIVE_NAMES
from open_range.catalog.objectives import (
    objective_rule_for_predicate_name,
    public_objective_predicate_names,
    weakness_objective_tags_for_kind,
)
from open_range.objectives import (
    PUBLIC_OBJECTIVE_PREDICATE_NAMES,
    objective_event_for_predicate,
    resolve_objective,
)


def test_catalog_public_objective_names_drive_public_allowlist() -> None:
    assert public_objective_predicate_names() == PUBLIC_OBJECTIVE_PREDICATE_NAMES


def test_catalog_has_rule_data_for_direct_and_special_objectives() -> None:
    for objective_tag in STANDARD_ATTACK_OBJECTIVE_NAMES:
        rule = objective_rule_for_predicate_name(objective_tag)
        assert rule is not None
        assert rule.resolution_kind == "direct_objective"
        assert rule.objective_tag == objective_tag

    assert objective_rule_for_predicate_name("asset_read") is not None
    assert (
        objective_rule_for_predicate_name("asset_read").resolution_kind == "asset_read"
    )
    assert objective_rule_for_predicate_name("credential_obtained") is not None
    assert (
        objective_rule_for_predicate_name("credential_obtained").resolution_kind
        == "credential_obtained"
    )
    assert objective_rule_for_predicate_name("outbound_service").event_type == (
        "PersistenceEstablished"
    )
    assert objective_rule_for_predicate_name("intrusion_detected").default_service == (
        "svc-siem"
    )


def test_catalog_objective_resolution_keeps_event_and_target_contracts() -> None:
    outbound = resolve_objective(
        "outbound_service(svc-web)",
        target_id="svc-web",
        service_ids=frozenset({"svc-web", "svc-idp"}),
    )
    assert outbound.target_service == "svc-web"
    assert outbound.event_type == "PersistenceEstablished"

    credential = resolve_objective(
        "credential_obtained(idp_admin_cred)",
        target_id="idp_admin_cred",
    )
    assert credential.target_kind == "asset"
    assert credential.target_service == "svc-idp"
    assert credential.event_type == "CredentialObtained"
    assert objective_event_for_predicate(
        "privilege_escalation(svc-idp)",
        target_id="svc-idp",
        default_service="svc-idp",
    ) == ("PrivilegeEscalation", "svc-idp")


def test_catalog_weakness_objective_tags_cover_current_examples() -> None:
    assert weakness_objective_tags_for_kind("code_web", "sql_injection") == (
        "db_access",
    )
    assert weakness_objective_tags_for_kind(
        "config_identity",
        "overbroad_service_account",
    ) == ("privilege_escalation",)
    assert weakness_objective_tags_for_kind(
        "workflow_abuse",
        "document_share_abuse",
    ) == ("file_access",)
