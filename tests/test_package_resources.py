from __future__ import annotations

from pathlib import Path

from open_range import (
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
    for name in ("manifest.schema.json", "validator_report.schema.json", "witness_bundle.schema.json"):
        assert (bundled_schema_dir() / name).read_text(encoding="utf-8") == (repo_dir / name).read_text(encoding="utf-8")
        assert isinstance(load_bundled_schema(name), dict)


def test_bundled_docs_are_readable():
    contents = load_bundled_doc("architecture.md")
    weakness_contents = load_bundled_doc("weakness-lifecycle.md")

    assert "Python control plane" in contents
    assert "Blue has two distinct control actions" in weakness_contents
