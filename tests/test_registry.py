"""Tests for the family registry.

Covers:
- Loading registry from YAML
- Filtering by tag
- Filtering by difficulty range
- Looking up families by name (valid and invalid)
- Verifying all registered manifests exist and validate
"""

from __future__ import annotations

from pathlib import Path

import pytest

from open_range.registry import FamilyInfo, Registry

ROOT = Path(__file__).parent.parent
MANIFESTS_DIR = ROOT / "manifests"
REGISTRY_PATH = MANIFESTS_DIR / "registry.yaml"


# ===================================================================
# Loading
# ===================================================================


class TestRegistryLoading:
    """Registry loads correctly from YAML."""

    def test_load_default_registry(self):
        reg = Registry.load(REGISTRY_PATH)
        assert len(reg) > 0

    def test_load_returns_registry_instance(self):
        reg = Registry.load(REGISTRY_PATH)
        assert isinstance(reg, Registry)

    def test_file_not_found_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            Registry.load(tmp_path / "nonexistent.yaml")

    def test_malformed_yaml_raises(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("not_families: {}")
        with pytest.raises(ValueError, match="families"):
            Registry.load(bad)

    def test_repr(self):
        reg = Registry.load(REGISTRY_PATH)
        r = repr(reg)
        assert "Registry(" in r
        assert "families" in r


# ===================================================================
# list_families
# ===================================================================


class TestListFamilies:
    """list_families returns all families sorted by difficulty."""

    def test_returns_list(self):
        reg = Registry.load(REGISTRY_PATH)
        families = reg.list_families()
        assert isinstance(families, list)
        assert all(isinstance(f, FamilyInfo) for f in families)

    def test_sorted_by_difficulty(self):
        reg = Registry.load(REGISTRY_PATH)
        families = reg.list_families()
        difficulties = [f.difficulty for f in families]
        assert difficulties == sorted(difficulties)

    def test_all_families_have_required_fields(self):
        reg = Registry.load(REGISTRY_PATH)
        for fam in reg.list_families():
            assert fam.name
            assert fam.display_name
            assert fam.manifest
            assert fam.difficulty >= 1


# ===================================================================
# get_family
# ===================================================================


class TestGetFamily:
    """get_family looks up by registry key."""

    def test_valid_name(self):
        reg = Registry.load(REGISTRY_PATH)
        fam = reg.get_family("tier1_basic_enterprise")
        assert fam.name == "tier1_basic_enterprise"
        assert fam.manifest == "tier1_basic.yaml"

    def test_invalid_name_raises_key_error(self):
        reg = Registry.load(REGISTRY_PATH)
        with pytest.raises(KeyError, match="nonexistent"):
            reg.get_family("nonexistent")

    def test_contains_operator(self):
        reg = Registry.load(REGISTRY_PATH)
        assert "tier1_basic_enterprise" in reg
        assert "nonexistent" not in reg


# ===================================================================
# filter_by_tag
# ===================================================================


class TestFilterByTag:
    """filter_by_tag returns families matching a tag."""

    def test_healthcare_tag(self):
        reg = Registry.load(REGISTRY_PATH)
        results = reg.filter_by_tag("healthcare")
        assert len(results) >= 1
        for fam in results:
            assert "healthcare" in [t.lower() for t in fam.tags]

    def test_case_insensitive(self):
        reg = Registry.load(REGISTRY_PATH)
        lower = reg.filter_by_tag("healthcare")
        upper = reg.filter_by_tag("Healthcare")
        assert len(lower) == len(upper)

    def test_nonexistent_tag_returns_empty(self):
        reg = Registry.load(REGISTRY_PATH)
        results = reg.filter_by_tag("zzz_nonexistent_tag")
        assert results == []

    def test_hard_tag(self):
        reg = Registry.load(REGISTRY_PATH)
        results = reg.filter_by_tag("hard")
        assert len(results) >= 2
        for fam in results:
            assert "hard" in [t.lower() for t in fam.tags]

    def test_tier_1_tag(self):
        reg = Registry.load(REGISTRY_PATH)
        results = reg.filter_by_tag("tier-1")
        assert len(results) >= 1


# ===================================================================
# filter_by_difficulty
# ===================================================================


class TestFilterByDifficulty:
    """filter_by_difficulty returns families in a difficulty range."""

    def test_difficulty_1(self):
        reg = Registry.load(REGISTRY_PATH)
        results = reg.filter_by_difficulty(1, 1)
        assert len(results) >= 1
        for fam in results:
            assert fam.difficulty == 1

    def test_difficulty_range(self):
        reg = Registry.load(REGISTRY_PATH)
        results = reg.filter_by_difficulty(1, 3)
        assert len(results) >= 3  # at least tier1, tier2, tier3
        for fam in results:
            assert 1 <= fam.difficulty <= 3

    def test_wide_range_returns_all(self):
        reg = Registry.load(REGISTRY_PATH)
        all_fam = reg.list_families()
        wide = reg.filter_by_difficulty(1, 5)
        assert len(wide) == len(all_fam)

    def test_empty_range(self):
        reg = Registry.load(REGISTRY_PATH)
        results = reg.filter_by_difficulty(5, 5)
        # May be empty if no difficulty-5 families exist
        for fam in results:
            assert fam.difficulty == 5


# ===================================================================
# Manifest existence and validation
# ===================================================================


class TestManifestIntegrity:
    """All registered manifests exist on disk and validate."""

    def test_all_manifest_files_exist(self):
        reg = Registry.load(REGISTRY_PATH)
        for fam in reg.list_families():
            manifest_path = MANIFESTS_DIR / fam.manifest
            assert manifest_path.exists(), (
                f"Family '{fam.name}' references '{fam.manifest}' "
                f"but {manifest_path} does not exist"
            )

    def test_all_manifests_validate(self):
        from manifests.schema import load_manifest

        reg = Registry.load(REGISTRY_PATH)
        for fam in reg.list_families():
            manifest_path = MANIFESTS_DIR / fam.manifest
            m = load_manifest(manifest_path)
            assert m.name, f"Manifest {fam.manifest} loaded but has empty name"
            assert m.tier >= 1
            assert len(m.topology.hosts) >= 1
            assert len(m.bug_families) >= 1

    def test_learning_goals_non_empty(self):
        reg = Registry.load(REGISTRY_PATH)
        for fam in reg.list_families():
            assert len(fam.learning_goals) >= 1, (
                f"Family '{fam.name}' has no learning_goals"
            )

    def test_tags_non_empty(self):
        reg = Registry.load(REGISTRY_PATH)
        for fam in reg.list_families():
            assert len(fam.tags) >= 1, (
                f"Family '{fam.name}' has no tags"
            )
