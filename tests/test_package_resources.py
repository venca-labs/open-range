from __future__ import annotations

from pathlib import Path

from open_range.resources import (
    bundled_schema_dir,
    load_bundled_schema,
    resource_root,
)


def test_bundled_resource_tree_exists():
    root = resource_root()

    assert root.exists()
    assert (root / "manifests").exists()
    assert bundled_schema_dir().exists()
    assert not (root / "docs").exists()


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
