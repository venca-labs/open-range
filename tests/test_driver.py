from __future__ import annotations

from pathlib import Path

from open_range.admit import LocalAdmissionController
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.driver import ScriptedRuntimeAgent, TandemEpisodeDriver
from open_range.episode_config import EpisodeConfig
from open_range.render import EnterpriseSaaSKindRenderer
from open_range.runtime import WitnessDrivenRuntime
from open_range.runtime_types import Action
from open_range.store import FileSnapshotStore
from open_range.synth import EnterpriseSaaSWorldSynthesizer
from open_range.weaknesses import CatalogWeaknessSeeder


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


def _snapshot(tmp_path: Path):
    world = CatalogWeaknessSeeder().apply(EnterpriseSaaSManifestCompiler().compile(_manifest_payload()))
    synth = EnterpriseSaaSWorldSynthesizer().synthesize(world, tmp_path / "synth")
    artifacts = EnterpriseSaaSKindRenderer().render(world, synth, tmp_path / "rendered")
    witness_bundle, report = LocalAdmissionController(mode="fail_fast").admit(world, artifacts)
    return FileSnapshotStore(tmp_path / "snapshots").create(world, artifacts, witness_bundle, report, synth=synth)


def test_tandem_driver_runs_joint_pool_episode(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    runtime = WitnessDrivenRuntime()
    driver = TandemEpisodeDriver(runtime)

    red_trace = snapshot.witness_bundle.red_witnesses[0].steps
    blue_target = red_trace[1].target
    red_agent = ScriptedRuntimeAgent(
        [
            Action(
                actor_id="red",
                role="red",
                kind=red_trace[0].kind,
                payload={"target": red_trace[0].target, **red_trace[0].payload},
            ),
            Action(actor_id="red", role="red", kind="sleep", payload={}),
        ]
    )
    blue_agent = ScriptedRuntimeAgent(
        [
            Action(actor_id="blue", role="blue", kind="submit_finding", payload={"event_type": "InitialAccess", "target": red_trace[0].target}),
            Action(actor_id="blue", role="blue", kind="control", payload={"target": blue_target, "action": "contain"}),
        ]
    )

    episode = driver.run_episode(
        snapshot,
        red_agent=red_agent,
        blue_agent=blue_agent,
        episode_config=EpisodeConfig(mode="joint_pool", green_enabled=False),
    )

    assert episode.done is True
    assert episode.winner == "blue"
    assert [turn.role for turn in episode.turns] == ["red", "blue", "red", "blue"]
    assert all(turn.observation.actor_id == turn.role for turn in episode.turns)


def test_driver_can_run_blue_only_prefix_episode(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    runtime = WitnessDrivenRuntime()
    driver = TandemEpisodeDriver(runtime)

    red_trace = snapshot.witness_bundle.red_witnesses[0].steps
    red_agent = ScriptedRuntimeAgent([Action(actor_id="red", role="red", kind="sleep", payload={})])
    blue_agent = ScriptedRuntimeAgent(
        [
            Action(actor_id="blue", role="blue", kind="submit_finding", payload={"event_type": "InitialAccess", "target": red_trace[0].target}),
            Action(
                actor_id="blue",
                role="blue",
                kind="control",
                payload={"target": snapshot.witness_bundle.blue_witnesses[0].steps[2].target, "action": "contain"},
            ),
        ]
    )

    episode = driver.run_episode(
        snapshot,
        red_agent=red_agent,
        blue_agent=blue_agent,
        episode_config=EpisodeConfig(mode="blue_only_from_prefix", start_state="prefix_foothold", green_enabled=False),
    )

    assert episode.done is True
    assert all(turn.role == "blue" for turn in episode.turns)
