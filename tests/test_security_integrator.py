"""Tests for the SecurityIntegrator builder integration module (v1)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from open_range.security_runtime import materialize_security_runtime
from open_range.security_integrator import (
    DEFAULT_TIER_MAP,
    SecurityIntegrator,
    SecurityIntegratorConfig,
    _default_scopes_for_service,
)


def _has_cryptography() -> bool:
    try:
        import cryptography  # noqa: F401

        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_world():
    """Minimal WorldIR for testing."""
    from tests.support import manifest_payload

    from open_range.pipeline import BuildPipeline

    pipeline = BuildPipeline()
    candidate = pipeline.build(manifest_payload(), Path("/tmp/test-integrator"))
    return candidate.world


@pytest.fixture
def render_dir(tmp_path: Path) -> Path:
    """Temporary render directory."""
    return tmp_path / "render"


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------


class TestSecurityIntegratorConfig:
    def test_defaults_disabled(self):
        config = SecurityIntegratorConfig()
        assert config.enabled is False

    def test_from_env_disabled(self, monkeypatch):
        monkeypatch.delenv("OPENRANGE_SECURITY_INTEGRATION", raising=False)
        config = SecurityIntegratorConfig.from_env()
        assert config.enabled is False

    def test_from_env_enabled(self, monkeypatch):
        monkeypatch.setenv("OPENRANGE_SECURITY_INTEGRATION", "true")
        config = SecurityIntegratorConfig.from_env()
        assert config.enabled is True

    def test_tier_map_defaults(self):
        config = SecurityIntegratorConfig()
        assert config.tier_map[1].identity_provider is False
        assert config.tier_map[2].identity_provider is True
        assert config.tier_map[2].mtls is False
        assert config.tier_map[3].mtls is True
        assert config.tier_map[3].npc_credential_lifecycle is True


class TestSecurityTierConfig:
    def test_tier1_no_features(self):
        cfg = DEFAULT_TIER_MAP[1]
        assert not cfg.identity_provider
        assert not cfg.envelope_encryption
        assert not cfg.mtls
        assert not cfg.npc_credential_lifecycle

    def test_tier3_all_features(self):
        cfg = DEFAULT_TIER_MAP[3]
        assert cfg.identity_provider
        assert cfg.envelope_encryption
        assert cfg.mtls
        assert cfg.npc_credential_lifecycle


# ---------------------------------------------------------------------------
# Integrator tests -- disabled
# ---------------------------------------------------------------------------


class TestIntegratorDisabled:
    def test_noop_when_disabled(self, sample_world, render_dir):
        integrator = SecurityIntegrator(SecurityIntegratorConfig(enabled=False))
        ctx = integrator.integrate(sample_world, render_dir=render_dir, tier=3)
        assert ctx.tier == 3
        assert not ctx.identity_provider
        assert not ctx.encryption
        assert not ctx.service_runtime

    def test_noop_for_tier1(self, sample_world, render_dir):
        integrator = SecurityIntegrator(SecurityIntegratorConfig(enabled=True))
        ctx = integrator.integrate(sample_world, render_dir=render_dir, tier=1)
        # Tier 1 has no security features
        assert not ctx.identity_provider
        assert not ctx.encryption


# ---------------------------------------------------------------------------
# Identity provider integration
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _has_cryptography(), reason="cryptography library not available"
)
class TestIdentityIntegration:
    def test_identity_provider_added_for_tier2(self, sample_world, render_dir):
        integrator = SecurityIntegrator(SecurityIntegratorConfig(enabled=True))
        ctx = integrator.integrate(sample_world, render_dir=render_dir, tier=2)

        assert ctx.identity_provider
        assert ctx.identity_provider["enabled"] is True
        assert "service_identities" in ctx.identity_provider

    def test_idp_config_written(self, sample_world, render_dir):
        integrator = SecurityIntegrator(SecurityIntegratorConfig(enabled=True))
        integrator.integrate(sample_world, render_dir=render_dir, tier=2)

        data = json.loads(
            (render_dir / "security" / "idp" / "config.json").read_text(
                encoding="utf-8"
            )
        )
        assert data["enabled"] is True

    def test_idp_runtime_files_written(self, sample_world, render_dir):
        integrator = SecurityIntegrator(SecurityIntegratorConfig(enabled=True))
        integrator.integrate(sample_world, render_dir=render_dir, tier=2)

        assert (render_dir / "security" / "idp" / "startup.sh").exists()
        assert (
            render_dir / "security" / "idp" / "identity_provider_server.py"
        ).exists()

    def test_idp_sidecar_patch_uses_explicit_service_inheritance(
        self, sample_world, render_dir
    ):
        integrator = SecurityIntegrator(SecurityIntegratorConfig(enabled=True))
        ctx = integrator.integrate(sample_world, render_dir=render_dir, tier=2)

        idp_sidecar = ctx.service_runtime["svc-idp"].sidecars[0]

        assert idp_sidecar.name == "idp-helper"
        assert idp_sidecar.image_source == "service"
        assert idp_sidecar.include_service_payloads is True

    def test_render_extensions_export_security_runtime_and_summary(
        self, sample_world, render_dir
    ):
        integrator = SecurityIntegrator(SecurityIntegratorConfig(enabled=True))
        ctx = integrator.integrate(sample_world, render_dir=render_dir, tier=2)
        render_world = sample_world.model_copy(update={"security_runtime": ctx})
        extensions = materialize_security_runtime(render_world, render_dir)

        assert "svc-idp" in extensions.services
        assert extensions.values["security"]["tier"] == 2
        assert extensions.summary_updates["security_tier"] == 2
        assert any(
            path.endswith("security/security-context.json")
            for path in extensions.rendered_files
        )

    def test_spiffe_ids_in_identities(self, sample_world, render_dir):
        integrator = SecurityIntegrator(SecurityIntegratorConfig(enabled=True))
        ctx = integrator.integrate(sample_world, render_dir=render_dir, tier=2)

        for svc_name, identity in ctx.identity_provider["service_identities"].items():
            assert identity["identity_uri"].startswith("spiffe://range.local/")


# ---------------------------------------------------------------------------
# Encryption integration
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _has_cryptography(), reason="cryptography library not available"
)
class TestEncryptionIntegration:
    def test_encryption_for_tier2(self, sample_world, render_dir):
        integrator = SecurityIntegrator(
            SecurityIntegratorConfig(enabled=True, encryption_fraction=1.0)
        )
        ctx = integrator.integrate(sample_world, render_dir=render_dir, tier=2)

        assert ctx.encryption
        assert ctx.encryption["enabled"] is True

    def test_wrapped_dek_written(self, sample_world, render_dir):
        integrator = SecurityIntegrator(
            SecurityIntegratorConfig(enabled=True, encryption_fraction=1.0)
        )
        integrator.integrate(sample_world, render_dir=render_dir, tier=2)

        data = json.loads(
            (render_dir / "security" / "encryption" / "wrapped_dek.json").read_text(
                encoding="utf-8"
            )
        )
        assert isinstance(data, dict)
        assert len(data) >= 1


# ---------------------------------------------------------------------------
# mTLS integration
# ---------------------------------------------------------------------------


class TestMTLSIntegration:
    @pytest.mark.skipif(
        not _has_cryptography(), reason="cryptography library not available"
    )
    def test_mtls_certs_generated_for_tier3(self, sample_world, render_dir):
        integrator = SecurityIntegrator(SecurityIntegratorConfig(enabled=True))
        ctx = integrator.integrate(sample_world, render_dir=render_dir, tier=3)

        assert ctx.mtls
        assert ctx.mtls["enabled"] is True
        cert_files = list((render_dir / "security" / "mtls").glob("*/*.pem"))
        assert len(cert_files) >= 3
        assert ctx.service_runtime["svc-idp"].env["LDAP_TLS_VERIFY_CLIENT"] == "demand"
        assert ctx.service_runtime["svc-idp"].env["LDAP_TLS_CRT_FILENAME"] == "ldap.crt"
        assert any(
            payload.mount_path == "/container/service/slapd/assets/certs/ldap.crt"
            for payload in ctx.service_runtime["svc-idp"].payloads
        )
        assert any(port.port == 636 for port in ctx.service_runtime["svc-idp"].ports)
        assert any(
            payload.mount_path == "/etc/mysql/conf.d/openrange-mtls.cnf"
            for payload in ctx.service_runtime["svc-db"].payloads
        )

    @pytest.mark.skipif(
        not _has_cryptography(), reason="cryptography library not available"
    )
    def test_mtls_not_for_tier2(self, sample_world, render_dir):
        integrator = SecurityIntegrator(SecurityIntegratorConfig(enabled=True))
        ctx = integrator.integrate(sample_world, render_dir=render_dir, tier=2)
        assert not ctx.mtls


# ---------------------------------------------------------------------------
# NPC credential lifecycle integration
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _has_cryptography(), reason="cryptography library not available"
)
class TestNPCLifecycleIntegration:
    def test_npc_lifecycle_configured_for_tier3(self, sample_world, render_dir):
        integrator = SecurityIntegrator(SecurityIntegratorConfig(enabled=True))
        ctx = integrator.integrate(sample_world, render_dir=render_dir, tier=3)

        assert ctx.npc_credential_lifecycle
        assert ctx.npc_credential_lifecycle["enabled"] is True
        assert ctx.npc_credential_lifecycle["token_ttl_minutes"] == 5

    def test_npc_lifecycle_not_for_tier2(self, sample_world, render_dir):
        integrator = SecurityIntegrator(SecurityIntegratorConfig(enabled=True))
        ctx = integrator.integrate(sample_world, render_dir=render_dir, tier=2)
        assert not ctx.npc_credential_lifecycle


# ---------------------------------------------------------------------------
# Helper tests
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_default_scopes_for_known_service(self):
        scopes = _default_scopes_for_service("web")
        assert any("patients" in s for s in scopes)

    def test_default_scopes_for_service_id_alias(self):
        scopes = _default_scopes_for_service("svc-web")
        assert any("patients" in s for s in scopes)

    def test_default_scopes_for_unknown_service(self):
        scopes = _default_scopes_for_service("custom_svc")
        assert scopes == ["service:access:custom_svc"]


# ---------------------------------------------------------------------------
# Full integration test
# ---------------------------------------------------------------------------


class TestFullIntegration:
    @pytest.mark.skipif(
        not _has_cryptography(), reason="cryptography library not available"
    )
    def test_tier3_full_stack(self, sample_world, render_dir):
        """Tier 3 should integrate all security modules."""
        integrator = SecurityIntegrator(SecurityIntegratorConfig(enabled=True))
        ctx = integrator.integrate(sample_world, render_dir=render_dir, tier=3)

        assert ctx.identity_provider
        assert ctx.encryption
        assert ctx.mtls
        assert ctx.npc_credential_lifecycle

        assert (render_dir / "security" / "security-context.json").exists()
