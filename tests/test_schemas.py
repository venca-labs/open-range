from __future__ import annotations

import json
from pathlib import Path

from open_range import (
    EnterpriseSaaSManifest,
    ValidatorReport,
    WitnessBundle,
    WorldIR,
    validate_manifest,
)
from open_range.admission import ProbeSpec, ValidatorCheckReport, ValidatorStageReport, WitnessAction, WitnessTrace
from open_range.world_ir import (
    GreenWorkloadSpec,
    HostSpec,
    LineageSpec,
    MutationBoundsSpec,
    ObjectiveSpec,
)


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
                "sales": 8,
                "engineer": 6,
                "finance": 2,
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
                "auth_bypass",
            ],
            "phishing_surface_enabled": True,
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


def test_manifest_accepts_spec_example_shape():
    manifest = validate_manifest(_manifest_payload())

    assert isinstance(manifest, EnterpriseSaaSManifest)
    assert manifest.world_family == "enterprise_saas_v1"
    assert manifest.assets[0].asset_class == "crown_jewel"


def test_manifest_rejects_unknown_fields():
    payload = _manifest_payload()
    payload["golden_path"] = []

    try:
        validate_manifest(payload)
    except Exception as exc:  # noqa: BLE001
        assert "golden_path" in str(exc)
    else:
        raise AssertionError("manifest unexpectedly accepted forbidden field")


def test_manifest_accepts_pinned_weaknesses():
    payload = _manifest_payload()
    payload["security"]["pinned_weaknesses"] = [
        {"family": "secret_exposure", "kind": "credential_in_share", "target": "asset:finance_docs"},
        {"family": "workflow_abuse", "kind": "helpdesk_reset_bypass", "target": "workflow:helpdesk_ticketing"},
    ]

    manifest = validate_manifest(payload)

    assert manifest.security.code_flaw_kinds == (
        "sql_injection",
        "broken_authorization",
        "auth_bypass",
    )
    assert manifest.security.pinned_weaknesses[0].kind == "credential_in_share"
    assert manifest.security.pinned_weaknesses[1].target == "workflow:helpdesk_ticketing"


def test_manifest_rejects_pinned_kind_from_wrong_family():
    payload = _manifest_payload()
    payload["security"]["pinned_weaknesses"] = [
        {"family": "secret_exposure", "kind": "sql_injection", "target": "asset:finance_docs"},
    ]

    try:
        validate_manifest(payload)
    except Exception as exc:  # noqa: BLE001
        assert "unsupported kind" in str(exc)
    else:
        raise AssertionError("manifest unexpectedly accepted mismatched pinned weakness kind")


def test_world_ir_serializes_minimal_core_objects():
    world = WorldIR(
        world_id="world-001",
        seed=1337,
        business_archetype="healthcare_saas",
        allowed_service_kinds=("web_app", "db", "siem"),
        allowed_weakness_families=("code_web",),
        allowed_code_flaw_kinds=("sql_injection",),
        target_weakness_count=1,
        phishing_surface_enabled=False,
        target_red_path_depth=4,
        target_blue_signal_points=3,
        zones=("external", "dmz", "corp", "data", "management"),
        hosts=(HostSpec(id="web-1", zone="dmz", services=("svc-web",)),),
        services=(),
        users=(),
        groups=(),
        credentials=(),
        assets=(),
        workflows=(),
        edges=(),
        weaknesses=(),
        red_objectives=(ObjectiveSpec(id="o-red", owner="red", predicate="asset_read(finance_docs)"),),
        blue_objectives=(ObjectiveSpec(id="o-blue", owner="blue", predicate="intrusion_detected(initial_access)"),),
        green_personas=(),
        green_workload=GreenWorkloadSpec(noise_density="medium"),
        mutation_bounds=MutationBoundsSpec(max_new_hosts=1, max_new_services=1, max_new_users=1, max_new_weaknesses=1),
        lineage=LineageSpec(seed=1337),
    )

    payload = world.model_dump()

    assert payload["world_id"] == "world-001"
    assert payload["green_workload"]["noise_density"] == "medium"
    assert payload["allowed_code_flaw_kinds"] == ("sql_injection",)
    assert payload["target_weakness_count"] == 1
    assert payload["phishing_surface_enabled"] is False


def test_validator_report_and_witness_bundle_round_trip():
    report = ValidatorReport(
        admitted=True,
        world_id="world-001",
        world_hash="abc123",
        stages=(
            ValidatorStageReport(
                name="static",
                passed=True,
                checks=(ValidatorCheckReport(name="manifest", passed=True),),
            ),
        ),
    )
    bundle = WitnessBundle(
        red_witnesses=(
            WitnessTrace(
                id="red-1",
                role="red",
                steps=(WitnessAction(actor="red", kind="shell", target="web-1"),),
            ),
        ),
        blue_witnesses=(),
        smoke_tests=(ProbeSpec(id="smoke-1", kind="smoke", description="web boot"),),
        shortcut_probes=(),
        determinism_probes=(),
        necessity_probes=(),
    )

    assert ValidatorReport.model_validate(report.model_dump()) == report
    assert WitnessBundle.model_validate(bundle.model_dump()) == bundle


def test_generated_schema_files_exist_and_match_titles():
    root = Path(__file__).resolve().parent.parent
    manifest_schema = json.loads((root / "schemas" / "manifest.schema.json").read_text(encoding="utf-8"))
    report_schema = json.loads((root / "schemas" / "validator_report.schema.json").read_text(encoding="utf-8"))
    bundle_schema = json.loads((root / "schemas" / "witness_bundle.schema.json").read_text(encoding="utf-8"))

    assert manifest_schema["title"] == "EnterpriseSaaSManifest"
    assert report_schema["title"] == "ValidatorReport"
    assert bundle_schema["title"] == "WitnessBundle"
