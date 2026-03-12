from __future__ import annotations

from pathlib import Path

from open_range.build_config import BuildConfig
from open_range.episode_config import EpisodeConfig
from open_range.pipeline import BuildPipeline
from open_range.store import FileSnapshotStore


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
            "code_flaw_kinds": ["sql_injection", "path_traversal"],
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
            "allow_patch_old_weaknesses": True,
        },
    }


def test_episode_config_control_flags():
    assert EpisodeConfig(mode="red_only").controls_red is True
    assert EpisodeConfig(mode="red_only").controls_blue is False
    assert EpisodeConfig(mode="blue_only_live").controls_red is False
    assert EpisodeConfig(mode="blue_only_live").controls_blue is True
    assert EpisodeConfig().reward_profile == "terminal_plus_shaping"
    assert EpisodeConfig().prompt_mode == "zero_day"


def test_build_config_threads_through_build_and_admission(tmp_path: Path):
    store = FileSnapshotStore(tmp_path / "snapshots")
    pipeline = BuildPipeline(store=store)
    build_config = BuildConfig(
        workflows_enabled=("helpdesk_ticketing",),
        weakness_families_enabled=("code_web",),
        topology_scale="small",
        red_witness_count=2,
        blue_witness_count=2,
    )

    candidate = pipeline.build(_manifest_payload(), tmp_path / "rendered", build_config)
    snapshot = pipeline.admit(candidate, split="train")

    assert candidate.build_config == build_config
    assert candidate.world.allowed_service_kinds == ("web_app", "email", "idp", "fileshare", "db", "siem")
    assert len(candidate.world.workflows) == 1
    assert len(candidate.world.users) == 4
    assert all(weak.family == "code_web" for weak in candidate.world.weaknesses)
    assert len(snapshot.witness_bundle.red_witnesses) == 2
    assert len(snapshot.witness_bundle.blue_witnesses) == 2


def test_build_config_can_filter_services_without_touching_manifest_schema(tmp_path: Path):
    pipeline = BuildPipeline(store=FileSnapshotStore(tmp_path / "snapshots"))
    candidate = pipeline.build(
        _manifest_payload(),
        tmp_path / "rendered-filtered",
        BuildConfig(services_enabled=("web_app", "idp", "siem")),
    )

    assert candidate.world.allowed_service_kinds == ("web_app", "idp", "siem")
