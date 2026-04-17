from __future__ import annotations

from open_range.render.security.integrator import (
    DEFAULT_TIER_MAP,
    SecurityIntegratorConfig,
    _default_scopes_for_service,
)


def test_security_integrator_config_defaults_disabled() -> None:
    config = SecurityIntegratorConfig()

    assert config.enabled is False
    assert config.tier_map[1].identity_provider is False
    assert config.tier_map[2].identity_provider is True
    assert config.tier_map[3].mtls is True
    assert config.tier_map[3].npc_credential_lifecycle is True


def test_security_integrator_config_reads_env(monkeypatch) -> None:
    monkeypatch.delenv("OPENRANGE_SECURITY_INTEGRATION", raising=False)
    assert SecurityIntegratorConfig.from_env().enabled is False

    monkeypatch.setenv("OPENRANGE_SECURITY_INTEGRATION", "true")
    assert SecurityIntegratorConfig.from_env().enabled is True


def test_default_tier_map_keeps_baseline_and_full_stack_edges() -> None:
    assert DEFAULT_TIER_MAP[1].envelope_encryption is False
    assert DEFAULT_TIER_MAP[2].envelope_encryption is True
    assert DEFAULT_TIER_MAP[2].mtls is False
    assert DEFAULT_TIER_MAP[3].mtls is True


def test_default_scopes_cover_known_and_unknown_services() -> None:
    assert any("patients" in scope for scope in _default_scopes_for_service("web"))
    assert any("patients" in scope for scope in _default_scopes_for_service("svc-web"))
    assert _default_scopes_for_service("custom_svc") == ["service:access:custom_svc"]
