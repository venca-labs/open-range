"""Tests for the manifest authoring lint (issue #19)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from manifests.schema import Manifest, load_manifest
from open_range.lint import lint_file, lint_manifest


ROOT = Path(__file__).parent.parent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_manifest(**overrides) -> dict:
    """Return a minimal valid manifest dict that can be tweaked."""
    base = {
        "name": "test_range",
        "tier": 1,
        "topology": {
            "hosts": [
                {
                    "name": "web",
                    "zone": "dmz",
                    "services": ["nginx", "php-fpm"],
                    "connects_to": ["db"],
                },
                {
                    "name": "db",
                    "zone": "internal",
                    "services": ["mysql"],
                    "connects_to": [],
                },
            ],
            "networks": [
                {"name": "dmz"},
                {"name": "internal"},
            ],
            "firewall_rules": [
                {
                    "action": "allow",
                    "from_zone": "dmz",
                    "to_zone": "internal",
                    "ports": [3306],
                },
            ],
        },
        "bug_families": ["sqli"],
        "difficulty": {"max_steps": 12, "min_vulns": 1, "max_vulns": 2},
        "users": [
            {
                "username": "admin",
                "full_name": "Admin User",
                "hosts": ["web", "db"],
            },
        ],
        "npc_personas": [
            {
                "username": "admin",
                "security_awareness": 0.5,
            },
        ],
        "data_inventory": [
            {
                "name": "Test data",
                "host": "db",
                "classification": "internal",
            },
        ],
        "business_processes": [
            {
                "name": "Data query",
                "data_flow": ["web:nginx", "db:mysql"],
            },
        ],
        "trust_relationships": [
            {
                "type": "delegates_access",
                "from": "admin",
                "to": "admin",
            },
        ],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Tests: valid manifest passes all checks
# ---------------------------------------------------------------------------


class TestValidManifest:
    def test_minimal_manifest_passes(self):
        data = _minimal_manifest()
        manifest = Manifest(**data)
        results = lint_manifest(manifest)
        for check_name, errors in results.items():
            assert errors == [], f"Check '{check_name}' failed: {errors}"

    def test_tier1_manifest_loads(self):
        """Tier 1 manifest should load and pass lint checks."""
        result = lint_file(ROOT / "manifests" / "tier1_basic.yaml")
        assert result["schema_error"] is None, result["schema_error"]
        assert result["valid"] is True, result["checks"]


# ---------------------------------------------------------------------------
# Tests: invalid host references
# ---------------------------------------------------------------------------


class TestInvalidHostRefs:
    def test_connects_to_invalid_host(self):
        data = _minimal_manifest()
        data["topology"]["hosts"][0]["connects_to"] = ["nonexistent"]
        manifest = Manifest(**data)
        results = lint_manifest(manifest)
        errors = results["connects_to references"]
        assert len(errors) == 1
        assert "nonexistent" in errors[0]

    def test_user_references_invalid_host(self):
        data = _minimal_manifest()
        data["users"] = [
            {
                "username": "admin",
                "full_name": "Admin",
                "hosts": ["web", "ghost_host"],
            },
        ]
        manifest = Manifest(**data)
        results = lint_manifest(manifest)
        errors = results["user host references"]
        assert len(errors) == 1
        assert "ghost_host" in errors[0]

    def test_data_inventory_invalid_host(self):
        data = _minimal_manifest()
        data["data_inventory"] = [
            {
                "name": "Secret data",
                "host": "nonexistent_server",
                "classification": "internal",
            },
        ]
        manifest = Manifest(**data)
        results = lint_manifest(manifest)
        errors = results["data inventory hosts"]
        assert len(errors) == 1
        assert "nonexistent_server" in errors[0]


# ---------------------------------------------------------------------------
# Tests: invalid user references
# ---------------------------------------------------------------------------


class TestInvalidUserRefs:
    def test_npc_references_invalid_username(self):
        data = _minimal_manifest()
        data["npc_personas"] = [
            {
                "username": "ghost_user",
                "security_awareness": 0.5,
            },
        ]
        manifest = Manifest(**data)
        results = lint_manifest(manifest)
        errors = results["NPC persona usernames"]
        assert len(errors) == 1
        assert "ghost_user" in errors[0]

    def test_trust_relationship_invalid_source_identifier(self):
        data = _minimal_manifest()
        data["trust_relationships"] = [
            {
                "type": "delegates_access",
                "from": "bad actor!",
                "to": "admin",
            },
        ]
        manifest = Manifest(**data)
        results = lint_manifest(manifest)
        errors = results["trust relationship principals"]
        assert len(errors) == 1
        assert "bad actor!" in errors[0]

    def test_trust_relationship_invalid_target_identifier(self):
        data = _minimal_manifest()
        data["trust_relationships"] = [
            {
                "type": "delegates_access",
                "from": "admin",
                "to": "phantom user",
            },
        ]
        manifest = Manifest(**data)
        results = lint_manifest(manifest)
        errors = results["trust relationship principals"]
        assert len(errors) == 1
        assert "phantom user" in errors[0]


# ---------------------------------------------------------------------------
# Tests: business process data flows
# ---------------------------------------------------------------------------


class TestBusinessProcessFlows:
    def test_invalid_host_in_data_flow(self):
        data = _minimal_manifest()
        data["business_processes"] = [
            {
                "name": "Bad flow",
                "data_flow": ["ghost:nginx"],
            },
        ]
        manifest = Manifest(**data)
        results = lint_manifest(manifest)
        errors = results["business process data flows"]
        assert len(errors) == 1
        assert "ghost" in errors[0]

    def test_invalid_service_in_data_flow(self):
        data = _minimal_manifest()
        data["business_processes"] = [
            {
                "name": "Bad service",
                "data_flow": ["web:redis"],
            },
        ]
        manifest = Manifest(**data)
        results = lint_manifest(manifest)
        errors = results["business process data flows"]
        assert len(errors) == 1
        assert "redis" in errors[0]

    def test_missing_colon_in_data_flow(self):
        data = _minimal_manifest()
        data["business_processes"] = [
            {
                "name": "Bad format",
                "data_flow": ["web_nginx"],
            },
        ]
        manifest = Manifest(**data)
        results = lint_manifest(manifest)
        errors = results["business process data flows"]
        assert len(errors) == 1
        assert "host:service" in errors[0]


# ---------------------------------------------------------------------------
# Tests: lint_file with file paths
# ---------------------------------------------------------------------------


class TestLintFile:
    def test_nonexistent_file(self, tmp_path):
        result = lint_file(tmp_path / "missing.yaml")
        assert result["valid"] is False
        assert result["schema_error"] is not None

    def test_invalid_yaml_content(self, tmp_path):
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("name: test\n")  # Missing required fields
        result = lint_file(bad_file)
        assert result["valid"] is False
        assert result["schema_error"] is not None

    def test_valid_file(self, tmp_path):
        data = _minimal_manifest()
        good_file = tmp_path / "good.yaml"
        good_file.write_text(yaml.dump(data))
        result = lint_file(good_file)
        assert result["valid"] is True
        assert result["schema_error"] is None
