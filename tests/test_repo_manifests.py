from __future__ import annotations

from pathlib import Path

import yaml

from open_range.manifest import validate_manifest
from open_range.pipeline import BuildPipeline
from open_range.resources import (
    bundled_manifest_names,
    bundled_manifest_path,
    load_bundled_manifest,
    load_bundled_manifest_registry,
)


def test_checked_in_manifests_validate_and_compile(tmp_path: Path):
    pipeline = BuildPipeline()
    manifest_paths = sorted(Path("manifests").glob("tier*.yaml"))

    assert manifest_paths
    for path in manifest_paths:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        manifest = validate_manifest(payload)
        candidate = pipeline.build(manifest, tmp_path / path.stem)
        assert candidate.world.world_family == "enterprise_saas_v1"
        assert candidate.world.allowed_service_kinds


def test_manifest_registry_points_to_existing_examples():
    payload = yaml.safe_load(
        Path("manifests/registry.yaml").read_text(encoding="utf-8")
    )

    manifests_dir = Path("manifests")
    families = payload["families"]
    assert families
    for entry in families.values():
        manifest_path = manifests_dir / entry["manifest"]
        assert manifest_path.exists(), manifest_path


def test_bundled_manifests_match_repo_examples():
    repo_manifests = {
        path.name: path.read_text(encoding="utf-8")
        for path in Path("manifests").glob("tier*.yaml")
    }

    assert tuple(sorted(repo_manifests)) == bundled_manifest_names()
    for name, content in repo_manifests.items():
        assert bundled_manifest_path(name).read_text(encoding="utf-8") == content
        assert load_bundled_manifest(name)["world_family"] == "enterprise_saas_v1"


def test_bundled_registry_matches_repo_registry():
    repo_registry = yaml.safe_load(
        Path("manifests/registry.yaml").read_text(encoding="utf-8")
    )
    assert load_bundled_manifest_registry() == repo_registry
