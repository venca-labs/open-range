from __future__ import annotations

import importlib.util
from pathlib import Path

import open_range
import open_range.runtime as runtime_module


def test_top_level_package_keeps_internal_runtime_and_sft_helpers_private() -> None:
    forbidden = {
        "bundled_docs_dir",
        "build_decision_prompt",
        "load_bundled_doc",
        "render_action_completion",
        "render_decision_prompt",
        "system_prompt_for_role",
    }

    exported = set(open_range.__all__)

    assert forbidden.isdisjoint(exported)
    assert all(not hasattr(open_range, name) for name in forbidden)


def test_internal_reference_helpers_are_not_exposed_as_public_modules() -> None:
    assert not hasattr(runtime_module, "ReferenceDrivenRuntime")
    assert importlib.util.find_spec("open_range.driver") is None
    assert importlib.util.find_spec("open_range.sim") is None


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
