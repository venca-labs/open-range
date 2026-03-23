"""Tests for NPC credential lifecycle (Idea 5).

Tests session creation, token refresh, credential rotation, weakness
injection, session file generation, auth header formatting, and traffic
log entries.  No Docker or network dependency.
"""

from __future__ import annotations

import json
import time

import pytest

jwt = pytest.importorskip("jwt", reason="PyJWT not installed")

from open_range.credential_lifecycle import (  # noqa: E402
    CredentialLifecycleConfig,
    CredentialLifecycleManager,
    NPCSession,
    _DEFAULT_JWT_SECRET,
    reset_predictable_counter,
)
from open_range.session_traffic import (  # noqa: E402
    generate_authenticated_http_traffic,
    generate_session_cleanup_script,
    generate_token_refresh_script,
)


# ===================================================================
# Fixtures
# ===================================================================


@pytest.fixture(autouse=True)
def _reset_counter():
    """Reset the predictable session counter between tests."""
    reset_predictable_counter()
    yield
    reset_predictable_counter()


@pytest.fixture
def default_config() -> CredentialLifecycleConfig:
    """Config with lifecycle enabled, no weaknesses."""
    return CredentialLifecycleConfig(enabled=True)


@pytest.fixture
def manager(default_config: CredentialLifecycleConfig) -> CredentialLifecycleManager:
    return CredentialLifecycleManager(default_config)


@pytest.fixture
def weak_config() -> CredentialLifecycleConfig:
    """Config with all weaknesses enabled."""
    return CredentialLifecycleConfig(
        enabled=True,
        weaknesses=[
            "predictable_session_id",
            "no_token_expiry",
            "session_fixation",
            "token_in_url",
            "reusable_token",
            "plaintext_session_storage",
        ],
    )


@pytest.fixture
def weak_manager(weak_config: CredentialLifecycleConfig) -> CredentialLifecycleManager:
    return CredentialLifecycleManager(weak_config)


# ===================================================================
# Session creation
# ===================================================================


class TestSessionCreation:
    def test_create_session_returns_npc_session(
        self, manager: CredentialLifecycleManager
    ):
        session = manager.create_session("jsmith", "web")
        assert isinstance(session, NPCSession)

    def test_session_has_uuid_session_id(self, manager: CredentialLifecycleManager):
        session = manager.create_session("jsmith", "web")
        # UUID hex is 32 characters
        assert len(session.session_id) == 32
        # Should be valid hex
        int(session.session_id, 16)

    def test_session_has_bearer_token(self, manager: CredentialLifecycleManager):
        session = manager.create_session("jsmith", "web")
        assert session.bearer_token is not None
        assert len(session.bearer_token) > 0

    def test_bearer_token_is_valid_jwt(self, manager: CredentialLifecycleManager):
        session = manager.create_session("jsmith", "web")
        assert session.bearer_token is not None
        decoded = jwt.decode(
            session.bearer_token,
            _DEFAULT_JWT_SECRET,
            algorithms=["HS256"],
            audience="open-range",
        )
        assert decoded["sub"] == "jsmith"
        assert decoded["iss"] == "open-range-npc"
        assert decoded["aud"] == "open-range"
        assert "jti" in decoded
        assert "exp" in decoded
        assert "iat" in decoded

    def test_session_has_token_jti(self, manager: CredentialLifecycleManager):
        session = manager.create_session("jsmith", "web")
        assert session.token_jti is not None
        assert len(session.token_jti) > 0

    def test_session_expiry_matches_config(self, manager: CredentialLifecycleManager):
        before = time.time()
        session = manager.create_session("jsmith", "web")
        after = time.time()
        expected_ttl = manager.config.session_ttl_minutes * 60
        assert session.session_expires_at >= before + expected_ttl
        assert session.session_expires_at <= after + expected_ttl

    def test_token_expiry_matches_config(self, manager: CredentialLifecycleManager):
        before = time.time()
        session = manager.create_session("jsmith", "web")
        after = time.time()
        assert session.token_expires_at is not None
        expected_ttl = manager.config.token_ttl_minutes * 60
        assert session.token_expires_at >= before + expected_ttl
        assert session.token_expires_at <= after + expected_ttl

    def test_session_stores_username_and_host(
        self, manager: CredentialLifecycleManager
    ):
        session = manager.create_session("jsmith", "web")
        assert session.username == "jsmith"
        assert session.host == "web"

    def test_last_refresh_at_set_on_creation(self, manager: CredentialLifecycleManager):
        before = time.time()
        session = manager.create_session("jsmith", "web")
        assert session.last_refresh_at is not None
        assert session.last_refresh_at >= before

    def test_no_password_stored_by_default(self, manager: CredentialLifecycleManager):
        session = manager.create_session("jsmith", "web")
        assert session.password is None


# ===================================================================
# Token refresh
# ===================================================================


class TestTokenRefresh:
    def test_should_refresh_false_when_token_fresh(
        self, manager: CredentialLifecycleManager
    ):
        session = manager.create_session("jsmith", "web")
        assert not manager.should_refresh(session)

    def test_should_refresh_true_near_expiry(self, manager: CredentialLifecycleManager):
        session = manager.create_session("jsmith", "web")
        # Simulate time passing to near token expiry
        assert session.token_expires_at is not None
        session.token_expires_at = time.time() + 10  # 10s left, margin is 30s
        assert manager.should_refresh(session)

    def test_should_refresh_true_past_expiry(self, manager: CredentialLifecycleManager):
        session = manager.create_session("jsmith", "web")
        session.token_expires_at = time.time() - 60  # already expired
        assert manager.should_refresh(session)

    def test_refresh_generates_new_token(self, manager: CredentialLifecycleManager):
        session = manager.create_session("jsmith", "web")
        old_token = session.bearer_token
        old_jti = session.token_jti
        manager.refresh_token(session)
        assert session.bearer_token != old_token
        assert session.token_jti != old_jti

    def test_refresh_updates_last_refresh_at(self, manager: CredentialLifecycleManager):
        session = manager.create_session("jsmith", "web")
        before = time.time()
        manager.refresh_token(session)
        assert session.last_refresh_at is not None
        assert session.last_refresh_at >= before

    def test_refreshed_token_is_valid_jwt(self, manager: CredentialLifecycleManager):
        session = manager.create_session("jsmith", "web")
        manager.refresh_token(session)
        assert session.bearer_token is not None
        decoded = jwt.decode(
            session.bearer_token,
            _DEFAULT_JWT_SECRET,
            algorithms=["HS256"],
            audience="open-range",
        )
        assert decoded["sub"] == "jsmith"
        assert decoded["jti"] == session.token_jti


# ===================================================================
# Session expiry detection
# ===================================================================


class TestSessionExpiry:
    def test_session_not_expired_initially(self, manager: CredentialLifecycleManager):
        session = manager.create_session("jsmith", "web")
        assert session.session_expires_at > time.time()

    def test_session_expired_after_ttl(self, manager: CredentialLifecycleManager):
        session = manager.create_session("jsmith", "web")
        # Simulate session having expired
        session.session_expires_at = time.time() - 1
        assert session.session_expires_at < time.time()


# ===================================================================
# Predictable session ID weakness
# ===================================================================


class TestPredictableSessionId:
    def test_predictable_session_ids_are_sequential(
        self, weak_manager: CredentialLifecycleManager
    ):
        s1 = weak_manager.create_session("user1", "web")
        s2 = weak_manager.create_session("user2", "web")
        # Should be sequential hex integers
        id1 = int(s1.session_id, 16)
        id2 = int(s2.session_id, 16)
        assert id2 == id1 + 1

    def test_predictable_ids_are_short_hex(
        self, weak_manager: CredentialLifecycleManager
    ):
        session = weak_manager.create_session("user1", "web")
        assert len(session.session_id) == 8  # 8 hex chars
        int(session.session_id, 16)  # valid hex

    def test_default_session_ids_are_not_predictable(
        self, manager: CredentialLifecycleManager
    ):
        s1 = manager.create_session("user1", "web")
        s2 = manager.create_session("user2", "web")
        # UUIDs should differ in a non-sequential way
        assert abs(int(s1.session_id, 16) - int(s2.session_id, 16)) > 1


# ===================================================================
# No token expiry weakness
# ===================================================================


class TestNoTokenExpiry:
    def test_no_expiry_means_no_exp_claim(
        self, weak_manager: CredentialLifecycleManager
    ):
        session = weak_manager.create_session("jsmith", "web")
        assert session.token_expires_at is None
        assert session.bearer_token is not None
        decoded = jwt.decode(
            session.bearer_token,
            _DEFAULT_JWT_SECRET,
            algorithms=["HS256"],
            audience="open-range",
            options={"verify_exp": False},
        )
        assert "exp" not in decoded

    def test_should_refresh_always_false_without_expiry(
        self, weak_manager: CredentialLifecycleManager
    ):
        session = weak_manager.create_session("jsmith", "web")
        assert not weak_manager.should_refresh(session)


# ===================================================================
# Reusable token weakness
# ===================================================================


class TestReusableToken:
    def test_reusable_token_keeps_jti_on_refresh(
        self, weak_manager: CredentialLifecycleManager
    ):
        session = weak_manager.create_session("jsmith", "web")
        original_jti = session.token_jti
        weak_manager.refresh_token(session)
        assert session.token_jti == original_jti


# ===================================================================
# Plaintext session storage weakness
# ===================================================================


class TestPlaintextSessionStorage:
    def test_password_stored_in_session_when_weakness_active(
        self, weak_manager: CredentialLifecycleManager
    ):
        weak_manager.set_initial_password("jsmith", "P@ssw0rd!")
        session = weak_manager.create_session("jsmith", "web")
        assert session.password == "P@ssw0rd!"

    def test_session_file_contains_password(
        self, weak_manager: CredentialLifecycleManager
    ):
        weak_manager.set_initial_password("jsmith", "P@ssw0rd!")
        session = weak_manager.create_session("jsmith", "web")
        content = weak_manager.generate_session_file(session)
        data = json.loads(content)
        assert data["password"] == "P@ssw0rd!"


# ===================================================================
# Session file generation
# ===================================================================


class TestSessionFileGeneration:
    def test_session_file_is_valid_json(self, manager: CredentialLifecycleManager):
        session = manager.create_session("jsmith", "web")
        content = manager.generate_session_file(session)
        data = json.loads(content)
        assert isinstance(data, dict)

    def test_session_file_contains_expected_fields(
        self, manager: CredentialLifecycleManager
    ):
        session = manager.create_session("jsmith", "web")
        content = manager.generate_session_file(session)
        data = json.loads(content)
        assert data["username"] == "jsmith"
        assert data["session_id"] == session.session_id
        assert data["token_jti"] == session.token_jti
        assert "session_created_at" in data
        assert "session_expires_at" in data
        assert "last_refresh_at" in data
        assert "bearer_token" in data
        assert "token_expires_at" in data

    def test_session_file_no_password_by_default(
        self, manager: CredentialLifecycleManager
    ):
        session = manager.create_session("jsmith", "web")
        content = manager.generate_session_file(session)
        data = json.loads(content)
        assert "password" not in data


# ===================================================================
# Auth headers format
# ===================================================================


class TestAuthHeaders:
    def test_headers_contain_cookie(self, manager: CredentialLifecycleManager):
        session = manager.create_session("jsmith", "web")
        headers = manager.generate_auth_headers(session)
        assert "Cookie" in headers
        assert f"session={session.session_id}" == headers["Cookie"]

    def test_headers_contain_authorization(self, manager: CredentialLifecycleManager):
        session = manager.create_session("jsmith", "web")
        headers = manager.generate_auth_headers(session)
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Bearer ")
        assert headers["Authorization"] == f"Bearer {session.bearer_token}"

    def test_headers_without_bearer_token(self, manager: CredentialLifecycleManager):
        session = manager.create_session("jsmith", "web")
        session.bearer_token = None
        headers = manager.generate_auth_headers(session)
        assert "Cookie" in headers
        assert "Authorization" not in headers


# ===================================================================
# Traffic log entry with session context
# ===================================================================


class TestTrafficLogEntry:
    def test_log_entry_includes_session_context(
        self, manager: CredentialLifecycleManager
    ):
        session = manager.create_session("jsmith", "web")
        entry = manager.get_traffic_log_entry(session, "browse", "http://web/index.php")
        assert entry["session_id"] == session.session_id
        assert entry["token_jti"] == session.token_jti
        assert entry["username"] == "jsmith"
        assert entry["action"] == "browse"
        assert entry["target"] == "http://web/index.php"
        assert "timestamp" in entry
        assert entry["type"] == "npc_browse"
        assert entry["label"] == "benign"

    def test_token_in_url_weakness_appends_token(
        self, weak_manager: CredentialLifecycleManager
    ):
        session = weak_manager.create_session("jsmith", "web")
        entry = weak_manager.get_traffic_log_entry(
            session, "browse", "http://web/index.php"
        )
        assert "token=" in entry["target"]
        assert session.bearer_token is not None
        assert session.bearer_token in entry["target"]

    def test_token_in_url_uses_ampersand_when_query_exists(
        self, weak_manager: CredentialLifecycleManager
    ):
        session = weak_manager.create_session("jsmith", "web")
        entry = weak_manager.get_traffic_log_entry(
            session, "browse", "http://web/search?q=test"
        )
        assert "&token=" in entry["target"]

    def test_no_token_in_url_without_weakness(
        self, manager: CredentialLifecycleManager
    ):
        session = manager.create_session("jsmith", "web")
        entry = manager.get_traffic_log_entry(session, "browse", "http://web/index.php")
        assert "token=" not in entry["target"]


# ===================================================================
# Credential rotation
# ===================================================================


class TestCredentialRotation:
    def test_rotate_returns_old_and_new(self, manager: CredentialLifecycleManager):
        manager.set_initial_password("jsmith", "OldPass1!")
        result = manager.rotate_credentials("jsmith")
        assert result["old_password"] == "OldPass1!"
        assert result["new_password"] != "OldPass1!"
        assert len(result["new_password"]) > 0

    def test_rotate_updates_stored_password(self, manager: CredentialLifecycleManager):
        manager.set_initial_password("jsmith", "OldPass1!")
        result = manager.rotate_credentials("jsmith")
        # Rotate again to verify the stored password was updated
        result2 = manager.rotate_credentials("jsmith")
        assert result2["old_password"] == result["new_password"]

    def test_rotate_with_no_initial_password(self, manager: CredentialLifecycleManager):
        result = manager.rotate_credentials("newuser")
        assert result["old_password"] == ""
        assert len(result["new_password"]) > 0


# ===================================================================
# Session traffic scripts
# ===================================================================


class TestSessionTrafficScripts:
    def test_authenticated_http_traffic_script(
        self, manager: CredentialLifecycleManager
    ):
        session = manager.create_session("jsmith", "web")
        script = generate_authenticated_http_traffic(
            session, "http://web", ["/index.php", "/dashboard"]
        )
        assert "#!/bin/sh" in script
        assert "curl" in script
        assert "Cookie: session=" in script
        assert "Authorization: Bearer" in script
        assert "/index.php" in script
        assert "/dashboard" in script

    def test_authenticated_traffic_without_bearer(
        self, manager: CredentialLifecycleManager
    ):
        session = manager.create_session("jsmith", "web")
        session.bearer_token = None
        script = generate_authenticated_http_traffic(
            session, "http://web", ["/index.php"]
        )
        assert "Cookie: session=" in script
        assert "Authorization" not in script

    def test_token_refresh_script(self, default_config: CredentialLifecycleConfig):
        script = generate_token_refresh_script(default_config, "jsmith")
        assert "#!/bin/sh" in script
        assert "jsmith" in script
        assert "/tmp/sessions/" in script
        assert "sleep" in script
        assert "token_jti" in script

    def test_session_cleanup_script(self):
        script = generate_session_cleanup_script()
        assert "#!/bin/sh" in script
        assert "/tmp/sessions" in script
        assert "session_expires_at" in script
        assert "rm -f" in script


# ===================================================================
# Config defaults (lifecycle disabled by default)
# ===================================================================


class TestConfigDefaults:
    def test_disabled_by_default(self):
        config = CredentialLifecycleConfig()
        assert config.enabled is False

    def test_default_ttls(self):
        config = CredentialLifecycleConfig()
        assert config.session_ttl_minutes == 30
        assert config.token_ttl_minutes == 5
        assert config.token_refresh_margin_seconds == 30
        assert config.credential_rotation_hours == 24

    def test_no_weaknesses_by_default(self):
        config = CredentialLifecycleConfig()
        assert config.weaknesses == []
