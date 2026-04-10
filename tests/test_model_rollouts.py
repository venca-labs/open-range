from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import get_type_hints

from open_range._runtime_store import hydrate_runtime_snapshot
from open_range.admit import LocalAdmissionController
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.render import EnterpriseSaaSKindRenderer
from open_range.store import FileSnapshotStore
from open_range.synth import EnterpriseSaaSWorldSynthesizer
from open_range.weaknesses import CatalogWeaknessSeeder
from tests.support import OFFLINE_BUILD_CONFIG, manifest_payload


def _load_module(name: str, relpath: str):
    path = Path(__file__).resolve().parents[1] / relpath
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _snapshot(tmp_path: Path):
    manifest = manifest_payload()
    manifest["business"]["workflows"] = [
        "helpdesk_ticketing",
        "document_sharing",
        "internal_email",
    ]
    manifest["assets"] = [
        {"id": "finance_docs", "class": "crown_jewel"},
        {"id": "idp_admin_cred", "class": "sensitive"},
    ]
    manifest["difficulty"]["target_blue_signal_points"] = 3
    manifest["mutation_bounds"] = {
        "max_new_hosts": 1,
        "max_new_services": 1,
        "max_new_users": 2,
        "max_new_weaknesses": 1,
        "allow_patch_old_weaknesses": True,
    }
    world = CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(manifest)
    )
    synth = EnterpriseSaaSWorldSynthesizer().synthesize(world, tmp_path / "synth")
    artifacts = EnterpriseSaaSKindRenderer().render(world, synth, tmp_path / "rendered")
    reference_bundle, report = LocalAdmissionController(mode="fail_fast").admit(
        world, artifacts, OFFLINE_BUILD_CONFIG
    )
    store = FileSnapshotStore(tmp_path / "snapshots")
    return hydrate_runtime_snapshot(
        store, store.create(world, artifacts, reference_bundle, report, synth=synth)
    )


def test_model_rollout_helpers_build_prompt_and_candidates(tmp_path: Path) -> None:
    mod = _load_module("eval_model_rollouts", "scripts/eval_model_rollouts.py")
    snapshot = _snapshot(tmp_path)
    runtime = mod.ReferenceDrivenRuntime()
    runtime.reset(
        snapshot,
        mod.EpisodeConfig(
            mode="red_only", scheduler_mode="strict_turns", opponent_blue="scripted"
        ),
    )
    decision = runtime.next_decision()

    candidates = mod.red_candidates(runtime, snapshot, decision.obs)
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


def test_model_rollout_score_candidates_type_hints_resolve() -> None:
    mod = _load_module("eval_model_rollouts_hints", "scripts/eval_model_rollouts.py")

    hints = get_type_hints(mod.score_candidates, globalns=vars(mod), localns=vars(mod))

    assert "return" in hints
