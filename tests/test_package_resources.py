from __future__ import annotations

from pathlib import Path

from open_range.resources import (
    bundled_docs_dir,
    bundled_schema_dir,
    load_bundled_doc,
    load_bundled_schema,
    resource_root,
)


def test_bundled_resource_tree_exists():
    root = resource_root()

    assert root.exists()
    assert (root / "manifests").exists()
    assert bundled_schema_dir().exists()
    assert bundled_docs_dir().exists()


def test_bundled_schemas_match_checked_in_schemas():
    repo_dir = Path("schemas")
    for name in (
        "manifest.schema.json",
        "validator_report.schema.json",
        "reference_bundle.schema.json",
    ):
        assert (bundled_schema_dir() / name).read_text(encoding="utf-8") == (
            repo_dir / name
        ).read_text(encoding="utf-8")
        assert isinstance(load_bundled_schema(name), dict)


def test_load_bundled_doc_reads_source_of_truth_docs():
    contents = load_bundled_doc("architecture.md")
    weakness_contents = load_bundled_doc("weakness-lifecycle.md")
    npc_contents = load_bundled_doc("npc-profiles.md")

    assert "Python control plane" in contents
    assert "Blue has two distinct control actions" in weakness_contents
    assert "NPC Profile Spec" in npc_contents
    assert "Current Scope" in npc_contents


def test_repo_checkout_uses_single_docs_source_of_truth():
    assert bundled_docs_dir().resolve() == Path("docs").resolve()
    assert tuple((Path("src/open_range/_resources/docs")).glob("*.md")) == ()
