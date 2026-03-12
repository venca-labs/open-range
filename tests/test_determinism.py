from __future__ import annotations

from pathlib import Path

from open_range.admit import LocalAdmissionController
from open_range.pipeline import BuildPipeline


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
            "roles": {"sales": 2, "engineer": 1, "finance": 1, "it_admin": 1},
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


def test_build_pipeline_is_repeatable_for_same_manifest(tmp_path: Path):
    pipeline = BuildPipeline()

    candidate_a = pipeline.build(_manifest_payload(), tmp_path / "render-a")
    candidate_b = pipeline.build(_manifest_payload(), tmp_path / "render-b")

    assert candidate_a.world == candidate_b.world
    assert candidate_a.artifacts.chart_values == candidate_b.artifacts.chart_values
    assert candidate_a.artifacts.pinned_image_digests == candidate_b.artifacts.pinned_image_digests


def test_admission_is_repeatable_for_same_world(tmp_path: Path):
    pipeline = BuildPipeline()
    candidate = pipeline.build(_manifest_payload(), tmp_path / "render")
    admission = LocalAdmissionController(mode="fail_fast")

    bundle_a, report_a = admission.admit(candidate.world, candidate.artifacts)
    bundle_b, report_b = admission.admit(candidate.world, candidate.artifacts)

    assert bundle_a == bundle_b
    assert report_a.model_dump(exclude={"build_logs", "health_info"}) == report_b.model_dump(
        exclude={"build_logs", "health_info"}
    )
