from __future__ import annotations

import json
from pathlib import Path

from open_range.admission.controller import LocalAdmissionController
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.render import EnterpriseSaaSKindRenderer
from open_range.synth import EnterpriseSaaSWorldSynthesizer
from open_range.weaknesses import CatalogWeaknessSeeder
from tests.support import OFFLINE_BUILD_CONFIG, manifest_payload


def _manifest_payload() -> dict:
    payload = manifest_payload()
    payload["security"]["code_flaw_kinds"] = [
        "sql_injection",
        "path_traversal",
    ]
    payload["security"]["phishing_surface_enabled"] = True
    payload["mutation_bounds"]["allow_patch_old_weaknesses"] = True
    return payload


def test_synthesizer_generates_bounded_seed_artifacts(tmp_path: Path):
    world = CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(_manifest_payload())
    )

    synth = EnterpriseSaaSWorldSynthesizer().synthesize(world, tmp_path / "synth")

    assert Path(synth.summary_path).exists()
    assert "svc-web" in synth.service_payloads
    assert any(
        file.mount_path == "/var/www/html/index.html"
        for file in synth.service_payloads["svc-web"]
    )
    assert any(
        file.mount_path == "/docker-entrypoint-initdb.d/01-init.sql"
        for file in synth.service_payloads["svc-db"]
    )
    assert synth.mailboxes
    realized = [
        file.mount_path
        for files in synth.service_payloads.values()
        for file in files
        if ".openrange/" in file.mount_path
        or "/opt/openrange/" in file.mount_path
        or "openrange/exposed-" in file.mount_path
    ]
    assert realized


def test_synthesizer_realizes_pinned_weaknesses_and_can_disable_phishing_surface(
    tmp_path: Path,
):
    payload = _manifest_payload()
    payload["security"]["phishing_surface_enabled"] = False
    payload["security"]["pinned_weaknesses"] = [
        {
            "family": "secret_exposure",
            "kind": "credential_in_share",
            "target": "asset:finance_docs",
        },
        {
            "family": "workflow_abuse",
            "kind": "helpdesk_reset_bypass",
            "target": "workflow:helpdesk_ticketing",
        },
    ]
    world = CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(payload)
    )

    synth = EnterpriseSaaSWorldSynthesizer().synthesize(world, tmp_path / "synth")

    fileshare_payloads = synth.service_payloads["svc-fileshare"]
    web_payloads = synth.service_payloads["svc-web"]
    assert any(
        file.mount_path.endswith("exposed-finance_docs.txt")
        for file in fileshare_payloads
    )
    assert any(
        file.mount_path.endswith("helpdesk_reset_bypass.json") for file in web_payloads
    )
    assert all(
        "Password reset review" not in "\n".join(messages)
        for messages in synth.mailboxes.values()
    )


def test_synthesizer_realizes_exact_code_web_templates_and_witness_routes(
    tmp_path: Path,
):
    expected_routes = {
        "sql_injection": "/var/www/html/search.php",
        "broken_authorization": "/var/www/html/records.php",
        "auth_bypass": "/var/www/html/admin.php",
        "path_traversal": "/var/www/html/download.php",
        "ssrf": "/var/www/html/fetch.php",
        "command_injection": "/var/www/html/ops.php",
    }

    for kind, route in expected_routes.items():
        payload = _manifest_payload()
        payload["security"]["code_flaw_kinds"] = [kind]
        payload["security"]["pinned_weaknesses"] = [
            {"family": "code_web", "kind": kind, "target": "service:web_app"},
        ]
        world = CatalogWeaknessSeeder().apply(
            EnterpriseSaaSManifestCompiler().compile(payload)
        )
        synth = EnterpriseSaaSWorldSynthesizer().synthesize(world, tmp_path / kind)
        web_payloads = synth.service_payloads["svc-web"]
        assert any(
            file.mount_path == route and file.content.startswith("<?php")
            for file in web_payloads
        )
        artifacts = EnterpriseSaaSKindRenderer().render(
            world, synth, tmp_path / f"{kind}-render"
        )
        reference_bundle, report = LocalAdmissionController(mode="fail_fast").admit(
            world, artifacts, OFFLINE_BUILD_CONFIG
        )
        assert report.admitted is True
        first_step = reference_bundle.reference_attack_traces[0].steps[0]
        assert first_step.payload["path"] == route.removeprefix("/var/www/html")
        assert first_step.payload["query"]
        if kind in {"auth_bypass", "ssrf", "command_injection"}:
            assert first_step.payload["expect_contains"].startswith("OPENRANGE-EFFECT:")
        else:
            assert first_step.payload["expect_contains"].startswith(
                "OPENRANGE-FOOTHOLD:"
            )
        assert not any(
            file.mount_path.startswith("/var/www/html/openrange-foothold-")
            for file in web_payloads
        )


def test_synthesizer_realizes_required_non_code_catalog(tmp_path: Path):
    cases = (
        (
            "config_identity",
            "weak_password",
            "credential:it_admin-01",
            "svc-idp",
            "/etc/openrange/password-policy.json",
            "min_password_length",
        ),
        (
            "config_identity",
            "default_credential",
            "service:idp",
            "svc-idp",
            "/etc/openrange/default-credential.json",
            "default_password",
        ),
        (
            "config_identity",
            "overbroad_service_account",
            "service:idp",
            "svc-idp",
            "/etc/openrange/service-account-policy.json",
            "service_account_scope",
        ),
        (
            "config_identity",
            "admin_surface_exposed",
            "service:idp",
            "svc-idp",
            "/etc/openrange/admin-surface.json",
            "admin_surface_public",
        ),
        (
            "config_identity",
            "trust_edge_misconfig",
            "service:idp",
            "svc-idp",
            "/etc/openrange/trust-edge.json",
            "trust_scope",
        ),
        (
            "secret_exposure",
            "env_file_leak",
            "service:web_app",
            "svc-web",
            "/var/www/html/.env",
            "OPENRANGE_APP_SECRET",
        ),
        (
            "secret_exposure",
            "credential_in_share",
            "asset:finance_docs",
            "svc-fileshare",
            "/srv/shared/.openrange/exposed-finance_docs.txt",
            "secret_material=",
        ),
        (
            "secret_exposure",
            "backup_leak",
            "asset:payroll_db",
            "svc-fileshare",
            "/srv/shared/.openrange/backup-payroll_db.sql",
            "INSERT INTO leaked_credentials",
        ),
        (
            "secret_exposure",
            "hardcoded_app_secret",
            "service:web_app",
            "svc-web",
            "/var/www/html/.openrange/app-secret.php",
            "OPENRANGE_APP_SECRET",
        ),
        (
            "workflow_abuse",
            "helpdesk_reset_bypass",
            "workflow:helpdesk_ticketing",
            "svc-web",
            "/var/www/html/.openrange/weaknesses/helpdesk_reset_bypass.json",
            "identity_verification",
        ),
        (
            "workflow_abuse",
            "approval_chain_bypass",
            "workflow:payroll_approval",
            "svc-web",
            "/var/www/html/.openrange/weaknesses/approval_chain_bypass.json",
            "secondary_approval_skipped",
        ),
        (
            "workflow_abuse",
            "document_share_abuse",
            "workflow:document_sharing",
            "svc-fileshare",
            "/srv/shared/.openrange/workflows/document_share_abuse.json",
            "share_visibility",
        ),
        (
            "telemetry_blindspot",
            "missing_web_logs",
            "service:web_app",
            "svc-web",
            "/etc/openrange/missing_web_logs.json",
            "access_logs_enabled",
        ),
        (
            "telemetry_blindspot",
            "missing_idp_logs",
            "service:idp",
            "svc-idp",
            "/etc/openrange/missing_idp_logs.json",
            "auth_logs_enabled",
        ),
        (
            "telemetry_blindspot",
            "delayed_siem_ingest",
            "service:email",
            "svc-email",
            "/etc/openrange/delayed_siem_ingest.json",
            "delay_seconds",
        ),
        (
            "telemetry_blindspot",
            "unmonitored_admin_action",
            "service:idp",
            "svc-idp",
            "/etc/openrange/unmonitored_admin_action.json",
            "admin_actions_logged",
        ),
        (
            "telemetry_blindspot",
            "silent_mail_rule",
            "service:email",
            "svc-email",
            "/etc/openrange/silent_mail_rule.json",
            "mail_rule_logging",
        ),
    )

    for family, kind, target, service_id, mount_path, snippet in cases:
        payload = _manifest_payload()
        payload["security"]["pinned_weaknesses"] = [
            {"family": family, "kind": kind, "target": target}
        ]
        world = CatalogWeaknessSeeder().apply(
            EnterpriseSaaSManifestCompiler().compile(payload)
        )
        synth = EnterpriseSaaSWorldSynthesizer().synthesize(world, tmp_path / kind)
        service_payloads = synth.service_payloads[service_id]
        file = next(
            (item for item in service_payloads if item.mount_path == mount_path), None
        )
        assert file is not None, f"missing realization for {family}:{kind}"
        assert snippet in file.content
        assert world.weaknesses[0].kind == kind
        assert world.weaknesses[0].remediation_command


def test_synthesizer_keeps_core_config_identity_json_payloads(tmp_path: Path):
    cases = (
        (
            "weak_password",
            "credential:it_admin-01",
            {
                "target": "svc-idp",
                "target_ref": "cred-it_admin-01",
                "min_password_length": 6,
                "password_reuse_allowed": True,
            },
        ),
        (
            "default_credential",
            "service:idp",
            {
                "target": "svc-idp",
                "target_ref": "svc-idp",
                "default_username": "admin",
                "default_password": "admin",
            },
        ),
        (
            "trust_edge_misconfig",
            "service:idp",
            {
                "target": "svc-idp",
                "target_ref": "svc-idp",
                "peer_validation": False,
                "trust_scope": "corp-wide",
            },
        ),
    )

    for kind, target, expected_fields in cases:
        payload = _manifest_payload()
        payload["security"]["pinned_weaknesses"] = [
            {"family": "config_identity", "kind": kind, "target": target}
        ]
        world = CatalogWeaknessSeeder().apply(
            EnterpriseSaaSManifestCompiler().compile(payload)
        )
        synth = EnterpriseSaaSWorldSynthesizer().synthesize(world, tmp_path / kind)
        file = next(
            item
            for item in synth.service_payloads["svc-idp"]
            if item.mount_path.startswith("/etc/openrange/")
        )

        data = json.loads(file.content)

        assert data["world_id"] == world.world_id
        assert "weakness_id" not in data
        assert "kind" not in data
        for key, value in expected_fields.items():
            assert data[key] == value


def test_synthesizer_keeps_core_telemetry_json_payloads(tmp_path: Path):
    cases = (
        (
            "missing_web_logs",
            "service:web_app",
            "svc-web",
            {
                "access_logs_enabled": False,
                "error_logs_enabled": False,
                "ship_to_siem": False,
                "target": "svc-web",
            },
        ),
        (
            "missing_idp_logs",
            "service:idp",
            "svc-idp",
            {
                "audit_logs_enabled": False,
                "auth_logs_enabled": False,
                "ship_to_siem": False,
                "target": "svc-idp",
            },
        ),
        (
            "delayed_siem_ingest",
            "service:email",
            "svc-email",
            {
                "delay_seconds": 180,
                "ship_to_siem": False,
                "target": "svc-email",
            },
        ),
        (
            "silent_mail_rule",
            "service:email",
            "svc-email",
            {
                "mail_rule_logging": False,
                "mailbox_auto_forward_alerting": False,
                "ship_to_siem": False,
                "target": "svc-email",
            },
        ),
    )

    for kind, target, service_id, expected_fields in cases:
        payload = _manifest_payload()
        payload["security"]["pinned_weaknesses"] = [
            {"family": "telemetry_blindspot", "kind": kind, "target": target}
        ]
        world = CatalogWeaknessSeeder().apply(
            EnterpriseSaaSManifestCompiler().compile(payload)
        )
        synth = EnterpriseSaaSWorldSynthesizer().synthesize(world, tmp_path / kind)
        file = next(
            item
            for item in synth.service_payloads[service_id]
            if item.mount_path == f"/etc/openrange/{kind}.json"
        )

        data = json.loads(file.content)

        assert data["world_id"] == world.world_id
        assert "weakness_id" not in data
        assert "kind" not in data
        for key, value in expected_fields.items():
            assert data[key] == value


def test_synthesizer_keeps_core_workflow_json_payloads(tmp_path: Path):
    cases = (
        (
            "helpdesk_reset_bypass",
            "workflow:helpdesk_ticketing",
            "svc-web",
            {
                "approval_guard": "disabled",
                "identity_verification": "none",
                "reset_without_ticket_owner": True,
                "target_ref": "wf-helpdesk_ticketing",
            },
        ),
        (
            "document_share_abuse",
            "workflow:document_sharing",
            "svc-fileshare",
            {
                "approval_guard": "disabled",
                "expiration_required": False,
                "share_visibility": "public_link",
                "target_ref": "wf-document_sharing",
            },
        ),
        (
            "phishing_credential_capture",
            "workflow:internal_email",
            "svc-email",
            {
                "approval_guard": "disabled",
                "credential_capture_landing": "/login",
                "mail_filtering": "allow",
                "target_ref": "wf-internal_email",
            },
        ),
    )

    for kind, target, service_id, expected_fields in cases:
        payload = _manifest_payload()
        payload["security"]["pinned_weaknesses"] = [
            {"family": "workflow_abuse", "kind": kind, "target": target}
        ]
        world = CatalogWeaknessSeeder().apply(
            EnterpriseSaaSManifestCompiler().compile(payload)
        )
        synth = EnterpriseSaaSWorldSynthesizer().synthesize(world, tmp_path / kind)
        file = next(
            item
            for item in synth.service_payloads[service_id]
            if item.mount_path.endswith(f"{kind}.json")
        )

        data = json.loads(file.content)

        assert data["world_id"] == world.world_id
        assert "weakness_id" not in data
        assert "kind" not in data
        for key, value in expected_fields.items():
            assert data[key] == value


def test_synthesizer_seeds_mailbox_realizations_for_email_borne_kinds(tmp_path: Path):
    cases = (
        (
            "secret_exposure",
            "token_in_email",
            "asset:idp_admin_cred",
            "token-idp_admin_cred.eml",
        ),
        (
            "workflow_abuse",
            "phishing_credential_capture",
            "workflow:internal_email",
            "phishing_credential_capture.eml",
        ),
        (
            "workflow_abuse",
            "internal_request_impersonation",
            "workflow:internal_email",
            "internal_request_impersonation.eml",
        ),
    )

    for family, kind, target, suffix in cases:
        payload = _manifest_payload()
        payload["security"]["pinned_weaknesses"] = [
            {"family": family, "kind": kind, "target": target}
        ]
        world = CatalogWeaknessSeeder().apply(
            EnterpriseSaaSManifestCompiler().compile(payload)
        )
        synth = EnterpriseSaaSWorldSynthesizer().synthesize(
            world, tmp_path / f"mail-{kind}"
        )
        email_payloads = synth.service_payloads["svc-email"]
        assert any(file.mount_path.endswith(suffix) for file in email_payloads)
        assert all(
            "weakness_id=" not in "\n".join(messages)
            and "kind=" not in "\n".join(messages)
            for messages in synth.mailboxes.values()
        )


def test_synthesizer_keeps_workflow_mailbox_templates(tmp_path: Path):
    cases = (
        (
            "phishing_credential_capture",
            "Subject: Password reset verification",
            "action=Confirm your account details to complete the request.",
        ),
        (
            "internal_request_impersonation",
            "Subject: Urgent internal request",
            "action=Please share the requested file and credentials for the finance review.",
        ),
    )

    for kind, expected_subject, expected_action in cases:
        payload = _manifest_payload()
        payload["security"]["pinned_weaknesses"] = [
            {
                "family": "workflow_abuse",
                "kind": kind,
                "target": "workflow:internal_email",
            }
        ]
        world = CatalogWeaknessSeeder().apply(
            EnterpriseSaaSManifestCompiler().compile(payload)
        )
        synth = EnterpriseSaaSWorldSynthesizer().synthesize(
            world, tmp_path / f"mail-{kind}"
        )

        mailbox_file = next(
            file
            for file in synth.service_payloads["svc-email"]
            if file.mount_path.endswith(f"{kind}.eml")
        )
        assert expected_subject in mailbox_file.content
        assert expected_action in mailbox_file.content
        assert any(
            expected_subject in "\n".join(messages)
            for messages in synth.mailboxes.values()
        )


def test_synthesizer_keeps_secret_material_content_templates(tmp_path: Path):
    cases = (
        (
            "credential_in_share",
            "asset:finance_docs",
            "svc-fileshare",
            "exposed-finance_docs.txt",
            (
                "exposed_ref=finance_docs",
                "secret_material=seeded-crown_jewel-finance_docs",
            ),
        ),
        (
            "token_in_email",
            "asset:idp_admin_cred",
            "svc-email",
            "token-idp_admin_cred.eml",
            (
                "Subject: Security review follow-up",
                "secret_material=seeded-sensitive-idp_admin_cred",
            ),
        ),
        (
            "env_file_leak",
            "service:web_app",
            "svc-web",
            ".env",
            (
                "OPENRANGE_WORLD_ID=enterprise_saas_v1-1337",
                "OPENRANGE_APP_SECRET=svc-web",
            ),
        ),
        (
            "backup_leak",
            "asset:payroll_db",
            "svc-fileshare",
            "backup-payroll_db.sql",
            ("INSERT INTO leaked_credentials", "seeded-crown_jewel-payroll_db"),
        ),
        (
            "hardcoded_app_secret",
            "service:web_app",
            "svc-web",
            "app-secret.php",
            (
                "define('OPENRANGE_WORLD_ID', 'enterprise_saas_v1-1337');",
                "define('OPENRANGE_APP_SECRET', 'svc-web');",
            ),
        ),
    )

    for kind, target, service_id, suffix, snippets in cases:
        payload = _manifest_payload()
        payload["security"]["pinned_weaknesses"] = [
            {"family": "secret_exposure", "kind": kind, "target": target}
        ]
        world = CatalogWeaknessSeeder().apply(
            EnterpriseSaaSManifestCompiler().compile(payload)
        )
        synth = EnterpriseSaaSWorldSynthesizer().synthesize(
            world, tmp_path / f"secret-{kind}"
        )

        file = next(
            item
            for item in synth.service_payloads[service_id]
            if item.mount_path.endswith(suffix)
        )
        assert all(snippet in file.content for snippet in snippets)
        assert "weakness_id=" not in file.content
        assert "kind=" not in file.content
        if service_id == "svc-email":
            assert any(
                all(snippet in "\n".join(messages) for snippet in snippets)
                for messages in synth.mailboxes.values()
            )
