from __future__ import annotations

import importlib.util
from pathlib import Path

import open_range
import open_range.runtime as runtime_module


def test_top_level_package_keeps_internal_runtime_and_sft_helpers_private() -> None:
    forbidden = {
        "build_decision_prompt",
        "render_action_completion",
        "render_decision_prompt",
        "system_prompt_for_role",
    }

    exported = set(open_range.__all__)

    assert forbidden.isdisjoint(exported)
    assert all(not hasattr(open_range, name) for name in forbidden)


def test_internal_reference_helpers_are_not_exposed_as_public_modules() -> None:
    assert not hasattr(runtime_module, "ReferenceDrivenRuntime")
    assert importlib.util.find_spec("open_range._code_web_common") is None
    assert importlib.util.find_spec("open_range._code_web_remediation") is None
    assert importlib.util.find_spec("open_range._code_web_render") is None
    assert importlib.util.find_spec("open_range._code_web_specs") is None
    assert importlib.util.find_spec("open_range._decision_sft") is None
    assert importlib.util.find_spec("open_range._reference_replay") is None
    assert importlib.util.find_spec("open_range._reference_sim") is None
    assert importlib.util.find_spec("open_range._runtime_hooks") is None
    assert importlib.util.find_spec("open_range.encryption_enforcement") is None
    assert importlib.util.find_spec("open_range.identity_enforcement") is None
    assert importlib.util.find_spec("open_range.render.credential_lifecycle") is None
    assert importlib.util.find_spec("open_range.render.envelope_crypto") is None
    assert importlib.util.find_spec("open_range.render.identity_provider") is None
    assert importlib.util.find_spec("open_range.render.mtls") is None
    assert importlib.util.find_spec("open_range.render.security_integrator") is None
    assert importlib.util.find_spec("open_range.render.session_traffic") is None
    assert importlib.util.find_spec("open_range.render.vault") is None
    assert importlib.util.find_spec("open_range.runtime_events") is None
    assert importlib.util.find_spec("open_range.runtime_reducers") is None
    assert importlib.util.find_spec("open_range.driver") is None
    assert importlib.util.find_spec("open_range.live_checks") is None
    assert importlib.util.find_spec("open_range.mtls_enforcement") is None
    assert importlib.util.find_spec("open_range.probe_planner") is None
    assert importlib.util.find_spec("open_range.probe_runner") is None
    assert importlib.util.find_spec("open_range.sim") is None
    assert importlib.util.find_spec("open_range.training_data") is None
    assert importlib.util.find_spec("open_range.counterfactuals") is None


def test_top_level_private_helper_module_allowlist_only_shrinks() -> None:
    root = Path(open_range.__file__).resolve().parent
    private_helpers = {
        path.name for path in root.glob("_*.py") if path.name != "__init__.py"
    }

    assert private_helpers == set()


def test_public_docs_avoid_candidate_action_menu_language() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    docs = (
        repo_root / "README.md",
        repo_root / "docs" / "architecture.md",
        repo_root / "docs" / "how-an-episode-works.md",
        repo_root / "docs" / "training-data-spec.md",
    )

    for path in docs:
        text = path.read_text(encoding="utf-8").lower()
        assert "candidate_actions" not in text
        assert "candidate actions" not in text
