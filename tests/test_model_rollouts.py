from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from open_range.admit import LocalAdmissionController
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.render import EnterpriseSaaSKindRenderer
from open_range.synth import EnterpriseSaaSWorldSynthesizer
from open_range.store import FileSnapshotStore
from open_range.weaknesses import CatalogWeaknessSeeder


def _load_module(name: str, relpath: str):
    path = Path(__file__).resolve().parents[1] / relpath
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _snapshot(tmp_path: Path):
    manifest = {
        "version": 1,
        "world_family": "enterprise_saas_v1",
        "seed": 1337,
        "business": {"archetype": "healthcare_saas", "workflows": ["helpdesk_ticketing", "document_sharing", "internal_email"]},
        "topology": {"zones": ["external", "dmz", "corp", "data", "management"], "services": ["web_app", "email", "idp", "fileshare", "db", "siem"]},
        "users": {"roles": {"sales": 2, "engineer": 1, "finance": 1, "it_admin": 1}},
        "assets": [{"id": "finance_docs", "class": "crown_jewel"}, {"id": "idp_admin_cred", "class": "sensitive"}],
        "objectives": {
            "red": [{"predicate": "credential_obtained(idp_admin_cred)"}, {"predicate": "asset_read(finance_docs)"}],
            "blue": [{"predicate": "intrusion_detected(initial_access)"}, {"predicate": "intrusion_contained(before_asset_read)"}, {"predicate": "service_health_above(0.9)"}],
        },
        "security": {
            "allowed_weakness_families": ["code_web", "config_identity", "secret_exposure", "workflow_abuse", "telemetry_blindspot"],
            "observability": {
                "require_web_logs": True,
                "require_idp_logs": True,
                "require_email_logs": True,
                "require_siem_ingest": True,
            },
        },
        "difficulty": {"target_red_path_depth": 4, "target_blue_signal_points": 3, "target_noise_density": "medium"},
        "mutation_bounds": {"max_new_hosts": 1, "max_new_services": 1, "max_new_users": 2, "max_new_weaknesses": 1, "allow_patch_old_weaknesses": True},
    }
    world = CatalogWeaknessSeeder().apply(EnterpriseSaaSManifestCompiler().compile(manifest))
    synth = EnterpriseSaaSWorldSynthesizer().synthesize(world, tmp_path / "synth")
    artifacts = EnterpriseSaaSKindRenderer().render(world, synth, tmp_path / "rendered")
    witness_bundle, report = LocalAdmissionController(mode="fail_fast").admit(world, artifacts)
    return FileSnapshotStore(tmp_path / "snapshots").create(world, artifacts, witness_bundle, report, synth=synth)


def test_model_rollout_helpers_build_prompt_and_candidates(tmp_path: Path) -> None:
    mod = _load_module("eval_model_rollouts", "scripts/eval_model_rollouts.py")
    snapshot = _snapshot(tmp_path)
    runtime = mod.WitnessDrivenRuntime()
    runtime.reset(snapshot, mod.EpisodeConfig(mode="red_only", scheduler_mode="strict_turns", opponent_blue="scripted"))
    decision = runtime.next_decision()

    candidates = mod.red_candidates(runtime, snapshot)
    prompt = mod.build_prompt(snapshot, decision.obs, candidates, 0)

    assert "candidate_actions:" in prompt
    assert candidates
    assert any(candidate.label == "teacher" for candidate in candidates)
    assert all(candidate.text for candidate in candidates)


def test_teacher_pick_rate_counts_teacher_labels() -> None:
    mod = _load_module("eval_model_rollouts_rate", "scripts/eval_model_rollouts.py")

    rate = mod.teacher_pick_rate(
        [
            {"chosen_label": "teacher"},
            {"chosen_label": "probe"},
            {"chosen_label": "teacher"},
        ]
    )

    assert rate == 2 / 3
