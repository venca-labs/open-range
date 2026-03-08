"""Tests for YAML manifest schema validation."""

import pytest
from pydantic import ValidationError

from manifests.schema import ExposurePolicy, Host, Manifest, load_manifest


class TestManifestLoading:
    """All three manifests load and validate."""

    def test_tier1_loads(self, manifests_dir):
        m = load_manifest(manifests_dir / "tier1_basic.yaml")
        assert m.name == "tier1_basic_enterprise"
        assert m.tier == 1

    def test_tier2_loads(self, manifests_dir):
        m = load_manifest(manifests_dir / "tier2_corporate.yaml")
        assert m.name == "tier2_corporate"
        assert m.tier == 2

    def test_tier3_loads(self, manifests_dir):
        m = load_manifest(manifests_dir / "tier3_enterprise.yaml")
        assert m.name == "tier3_enterprise"
        assert m.tier == 3


class TestManifestValidation:
    """Invalid manifests are rejected."""

    def test_missing_name_rejected(self):
        with pytest.raises(ValidationError):
            Manifest(
                tier=1,
                topology={
                    "hosts": [{"name": "web", "zone": "dmz", "services": []}],
                    "networks": [{"name": "dmz"}],
                },
                bug_families=["sqli"],
                difficulty={"max_steps": 10},
            )

    def test_missing_topology_rejected(self):
        with pytest.raises(ValidationError):
            Manifest(
                name="bad",
                tier=1,
                bug_families=["sqli"],
                difficulty={"max_steps": 10},
            )

    def test_empty_hosts_rejected(self):
        with pytest.raises(ValidationError):
            Manifest(
                name="bad",
                tier=1,
                topology={"hosts": [], "networks": [{"name": "dmz"}]},
                bug_families=["sqli"],
                difficulty={"max_steps": 10},
            )

    def test_empty_bug_families_rejected(self):
        with pytest.raises(ValidationError):
            Manifest(
                name="bad",
                tier=1,
                topology={
                    "hosts": [{"name": "web", "zone": "dmz"}],
                    "networks": [{"name": "dmz"}],
                },
                bug_families=[],
                difficulty={"max_steps": 10},
            )

    def test_file_not_found(self, manifests_dir):
        with pytest.raises(FileNotFoundError):
            load_manifest(manifests_dir / "nonexistent.yaml")


class TestTier1Structure:
    """Tier 1 manifest has expected structure."""

    def test_tier1_has_8_hosts(self, manifests_dir):
        m = load_manifest(manifests_dir / "tier1_basic.yaml")
        assert len(m.topology.hosts) == 8

    def test_tier1_host_names(self, manifests_dir):
        m = load_manifest(manifests_dir / "tier1_basic.yaml")
        names = {h.name for h in m.topology.hosts}
        expected = {"attacker", "firewall", "web", "mail", "db", "files", "ldap", "siem"}
        assert names == expected

    def test_tier1_has_4_networks(self, manifests_dir):
        m = load_manifest(manifests_dir / "tier1_basic.yaml")
        assert len(m.topology.networks) == 4

    def test_firewall_rules_reference_valid_zones(self, manifests_dir):
        m = load_manifest(manifests_dir / "tier1_basic.yaml")
        zone_names = {n.name for n in m.topology.networks}
        for rule in m.topology.firewall_rules:
            assert rule.from_zone in zone_names, f"from_zone '{rule.from_zone}' not in zones"
            assert rule.to_zone in zone_names, f"to_zone '{rule.to_zone}' not in zones"

    def test_invalid_zone_reference_rejected(self):
        """Host referencing nonexistent zone is rejected."""
        with pytest.raises(ValidationError, match="zone"):
            Manifest(
                name="bad",
                tier=1,
                topology={
                    "hosts": [{"name": "web", "zone": "nonexistent"}],
                    "networks": [{"name": "dmz"}],
                },
                bug_families=["sqli"],
                difficulty={"max_steps": 10},
            )


class TestBugFamilies:
    """Bug families contain expected vulnerability classes."""

    def test_tier1_bug_families(self, manifests_dir):
        m = load_manifest(manifests_dir / "tier1_basic.yaml")
        # Core OWASP types must be present across all layers
        required = {"sqli", "xss", "idor", "command_injection", "ssrf",
                    "weak_creds", "broken_auth", "credential_reuse",
                    "lfi", "rce", "ssti", "smb_misconfig", "mail_misconfig"}
        assert required.issubset(set(m.bug_families)), (
            f"Missing required bug families: {required - set(m.bug_families)}"
        )

    def test_all_tiers_have_sqli(self, manifests_dir):
        for fname in ["tier1_basic.yaml", "tier2_corporate.yaml", "tier3_enterprise.yaml"]:
            m = load_manifest(manifests_dir / fname)
            assert "sqli" in m.bug_families

    def test_difficulty_max_steps_positive(self, manifests_dir):
        m = load_manifest(manifests_dir / "tier1_basic.yaml")
        assert m.difficulty.max_steps > 0

    def test_difficulty_min_le_max_vulns(self, manifests_dir):
        m = load_manifest(manifests_dir / "tier1_basic.yaml")
        assert m.difficulty.min_vulns <= m.difficulty.max_vulns


class TestExposurePolicy:
    """ExposurePolicy validates correctly (#18)."""

    def test_default_exposure_policy(self):
        ep = ExposurePolicy()
        assert ep.level == "public"
        assert ep.auth_required is False
        assert ep.notes == ""

    def test_custom_exposure_policy(self):
        ep = ExposurePolicy(level="hidden", auth_required=True, notes="Internal only")
        assert ep.level == "hidden"
        assert ep.auth_required is True
        assert ep.notes == "Internal only"

    def test_invalid_level_rejected(self):
        with pytest.raises(ValidationError):
            ExposurePolicy(level="nonexistent")

    def test_all_valid_levels(self):
        for level in ("public", "hidden", "authenticated", "misconfigured"):
            ep = ExposurePolicy(level=level)
            assert ep.level == level

    def test_host_with_exposure_field(self):
        h = Host(
            name="web",
            zone="dmz",
            exposure=ExposurePolicy(level="authenticated", auth_required=True),
        )
        assert h.exposure.level == "authenticated"
        assert h.exposure.auth_required is True

    def test_host_default_exposure(self):
        h = Host(name="web", zone="dmz")
        assert h.exposure.level == "public"
        assert h.exposure.auth_required is False

    def test_existing_manifests_still_load_with_exposure(self, manifests_dir):
        """Adding the exposure field must not break existing manifests."""
        m = load_manifest(manifests_dir / "tier1_basic.yaml")
        # All hosts should have default exposure policies
        for host in m.topology.hosts:
            assert host.exposure.level == "public"
