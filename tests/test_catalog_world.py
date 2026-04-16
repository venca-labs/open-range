from __future__ import annotations

from open_range.catalog.assets import (
    asset_confidentiality_for_class,
    asset_placement_rule_for_id,
)
from open_range.catalog.roles import (
    home_service_for_role,
    role_defaults_for_role,
    routine_for_role,
)
from open_range.catalog.workflows import workflow_step_templates_for_name


def test_role_catalog_keeps_role_home_and_routine_defaults() -> None:
    finance = role_defaults_for_role("finance")

    assert finance.home_service == "svc-fileshare"
    assert finance.routine == (
        "check_mail",
        "open_payroll_dashboard",
        "access_fileshare",
    )
    assert home_service_for_role("it_admin") == "svc-idp"
    assert routine_for_role("engineer") == (
        "check_mail",
        "browse_app",
        "access_fileshare",
    )


def test_role_catalog_keeps_generic_defaults_for_unknown_roles() -> None:
    legal = role_defaults_for_role("legal")

    assert legal.home_service == "svc-web"
    assert legal.routine == ("check_mail", "browse_app", "access_fileshare")


def test_asset_catalog_keeps_current_placement_and_confidentiality_rules() -> None:
    finance_docs = asset_placement_rule_for_id("finance_docs")
    payroll_db = asset_placement_rule_for_id("payroll_db")
    idp_admin_cred = asset_placement_rule_for_id("idp_admin_cred")

    assert finance_docs.owner_service == "svc-fileshare"
    assert (
        finance_docs.location_template.format(asset_id="finance_docs")
        == "svc-fileshare:/srv/shared/finance_docs.txt"
    )
    assert payroll_db.owner_service == "svc-db"
    assert (
        payroll_db.location_template.format(asset_id="payroll_db")
        == "svc-db://main/payroll_db"
    )
    assert idp_admin_cred.owner_service == "svc-idp"
    assert (
        idp_admin_cred.location_template.format(asset_id="idp_admin_cred")
        == "svc-idp://secrets/idp_admin_cred"
    )
    assert asset_confidentiality_for_class("crown_jewel") == "critical"
    assert asset_confidentiality_for_class("sensitive") == "high"
    assert asset_confidentiality_for_class("operational") == "medium"


def test_asset_catalog_keeps_ordered_rule_precedence_and_web_fallback() -> None:
    db_share_backup = asset_placement_rule_for_id("db_share_backup")
    status_report = asset_placement_rule_for_id("status_report")

    assert db_share_backup.owner_service == "svc-db"
    assert (
        db_share_backup.location_template.format(asset_id="db_share_backup")
        == "svc-db://main/db_share_backup"
    )
    assert status_report.owner_service == "svc-web"
    assert (
        status_report.location_template.format(asset_id="status_report")
        == "svc-web:/var/www/html/content/status_report.txt"
    )


def test_workflow_catalog_keeps_named_templates_and_fallback() -> None:
    helpdesk = workflow_step_templates_for_name("helpdesk_ticketing")
    payroll = workflow_step_templates_for_name("payroll_approval")
    document = workflow_step_templates_for_name("document_sharing")
    email = workflow_step_templates_for_name("internal_email")
    fallback = workflow_step_templates_for_name("custom_review")

    assert [
        (step.id, step.actor_role, step.action, step.service, step.asset)
        for step in helpdesk
    ] == [
        ("open-ticket", "sales", "open_ticket", "svc-web", ""),
        ("mail-update", "sales", "send_update", "svc-email", ""),
    ]
    assert [
        (step.id, step.actor_role, step.action, step.service, step.asset)
        for step in payroll
    ] == [
        ("view-payroll", "finance", "view_payroll", "svc-web", "payroll_db"),
        ("approve-payroll", "finance", "approve_payroll", "svc-db", "payroll_db"),
    ]
    assert [
        (step.id, step.actor_role, step.action, step.service, step.asset)
        for step in document
    ] == [
        ("share-doc", "sales", "share_document", "svc-fileshare", "finance_docs"),
    ]
    assert [
        (step.id, step.actor_role, step.action, step.service, step.asset)
        for step in email
    ] == [
        ("check-mail", "sales", "check_mail", "svc-email", ""),
    ]
    assert [
        (step.id, step.actor_role, step.action, step.service, step.asset)
        for step in fallback
    ] == [
        ("custom_review-step-1", "sales", "custom_review", "svc-web", ""),
    ]
