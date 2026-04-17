"""NPC credential lifecycle -- token refresh, session management, rotation.

Manages NPC credential state over time so that NPCs have rotating session
tokens, bearer JWTs in HTTP headers, and periodic credential changes.
This creates realistic traffic patterns and new attack surfaces (token
theft, session hijack, replay).

Ported from k3s-istio-vault-platform's OAuth token lifecycle pattern:
- Short-lived tokens (5-min default TTL)
- Automatic refresh before expiry (configurable margin)
- Token JTI tracking for audit correlation
- Session files written to container filesystem (accessible to Red)

This module is completely optional -- the NPC system works without it.
When ``CredentialLifecycleConfig.enabled`` is False (default), no
sessions or tokens are generated.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
import uuid
from typing import Any

import jwt
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Range-local HMAC secret used for HS256 JWTs.  In a live range this
# would be provisioned per-range; here we use a deterministic default
# so that tests are reproducible and tokens are verifiable within the
# same process.
_DEFAULT_JWT_SECRET = "open-range-npc-jwt-secret-do-not-use-in-prod"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class CredentialLifecycleConfig(BaseModel):
    """Configuration for NPC credential lifecycle.

    All fields have safe defaults so that a bare
    ``CredentialLifecycleConfig()`` disables the lifecycle and changes
    nothing about existing NPC behaviour.
    """

    enabled: bool = False
    session_ttl_minutes: int = 30
    token_ttl_minutes: int = 5  # Matches k3s-istio-vault-platform's 5-min default
    token_refresh_margin_seconds: int = 30
    credential_rotation_hours: int = 24
    jwt_secret: str = _DEFAULT_JWT_SECRET
    jwt_issuer: str = "open-range-npc"
    jwt_audience: str = "open-range"

    # Weaknesses that create attack surfaces
    weaknesses: list[str] = Field(default_factory=list)
    # Recognised values:
    #   "predictable_session_id"    -- session IDs are sequential hex
    #   "no_token_expiry"           -- JWTs have no exp claim
    #   "session_fixation"          -- session ID never rotates on re-auth
    #   "token_in_url"              -- bearer token appears in URL query params
    #   "reusable_token"            -- refreshed tokens keep the same jti
    #   "plaintext_session_storage" -- session file includes plaintext password


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------


class NPCSession(BaseModel):
    """Active session state for an NPC."""

    username: str
    host: str = ""
    session_id: str  # UUID or predictable hex depending on weakness
    bearer_token: str | None = None  # JWT if identity provider is configured
    token_jti: str | None = None  # Token ID for audit correlation
    token_expires_at: float | None = None  # Unix timestamp
    session_created_at: float
    session_expires_at: float
    last_refresh_at: float | None = None
    password: str | None = None  # Only stored when plaintext_session_storage


# ---------------------------------------------------------------------------
# Predictable session counter (weakness)
# ---------------------------------------------------------------------------

_predictable_counter: int = 0


def _next_predictable_session_id() -> str:
    """Return a short, incrementing hex session ID (guessable)."""
    global _predictable_counter
    _predictable_counter += 1
    return f"{_predictable_counter:08x}"


def reset_predictable_counter() -> None:
    """Reset the predictable counter (for tests)."""
    global _predictable_counter
    _predictable_counter = 0


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class CredentialLifecycleManager:
    """Manages NPC session tokens and credential rotation.

    Ported from k3s-istio-vault-platform's OAuth token lifecycle pattern:
    - Short-lived tokens (5-min default)
    - Automatic refresh before expiry
    - Token JTI tracking for audit correlation
    - Session files written to container filesystem (accessible to Red)
    """

    def __init__(self, config: CredentialLifecycleConfig) -> None:
        self._config = config
        # Track credentials per username for rotation
        self._credentials: dict[str, str] = {}
        # Track active sessions per username
        self._sessions: dict[str, NPCSession] = {}

    @property
    def config(self) -> CredentialLifecycleConfig:
        """Return the lifecycle configuration."""
        return self._config

    # ------------------------------------------------------------------
    # Session creation
    # ------------------------------------------------------------------

    def create_session(self, username: str, host: str) -> NPCSession:
        """Create a new NPC session with tokens.

        Generates a session ID (UUID or predictable depending on weakness
        config), a bearer JWT, and tracks the session for later refresh
        and rotation.
        """
        now = time.time()

        # Session ID generation
        if "predictable_session_id" in self._config.weaknesses:
            session_id = _next_predictable_session_id()
        else:
            session_id = uuid.uuid4().hex

        # Token JTI
        jti = secrets.token_urlsafe(16)

        # Token expiry
        if "no_token_expiry" in self._config.weaknesses:
            token_expires_at = None
        else:
            token_expires_at = now + self._config.token_ttl_minutes * 60

        # Build JWT
        bearer_token = self._issue_jwt(
            username=username,
            jti=jti,
            issued_at=now,
            expires_at=token_expires_at,
        )

        session = NPCSession(
            username=username,
            host=host,
            session_id=session_id,
            bearer_token=bearer_token,
            token_jti=jti,
            token_expires_at=token_expires_at,
            session_created_at=now,
            session_expires_at=now + self._config.session_ttl_minutes * 60,
            last_refresh_at=now,
        )

        # Store plaintext password reference when weakness is active
        if "plaintext_session_storage" in self._config.weaknesses:
            session.password = self._credentials.get(username)

        self._sessions[username] = session
        return session

    # ------------------------------------------------------------------
    # Token refresh
    # ------------------------------------------------------------------

    def should_refresh(self, session: NPCSession) -> bool:
        """Check if token needs refresh (within margin of expiry).

        Returns False when the ``no_token_expiry`` weakness is active
        (tokens never expire, so they never need refreshing).
        """
        if session.token_expires_at is None:
            return False
        margin = self._config.token_refresh_margin_seconds
        return time.time() >= (session.token_expires_at - margin)

    def refresh_token(self, session: NPCSession) -> NPCSession:
        """Refresh an expired or near-expired token.

        Issues a new JWT with a fresh (or reused, if weakness) JTI and
        updates the session in place.
        """
        now = time.time()

        # JTI handling
        if "reusable_token" in self._config.weaknesses:
            jti = session.token_jti or secrets.token_urlsafe(16)
        else:
            jti = secrets.token_urlsafe(16)

        # Token expiry
        if "no_token_expiry" in self._config.weaknesses:
            token_expires_at = None
        else:
            token_expires_at = now + self._config.token_ttl_minutes * 60

        bearer_token = self._issue_jwt(
            username=session.username,
            jti=jti,
            issued_at=now,
            expires_at=token_expires_at,
        )

        session.bearer_token = bearer_token
        session.token_jti = jti
        session.token_expires_at = token_expires_at
        session.last_refresh_at = now

        self._sessions[session.username] = session
        return session

    # ------------------------------------------------------------------
    # Credential rotation
    # ------------------------------------------------------------------

    def rotate_credentials(self, username: str) -> dict[str, str]:
        """Rotate NPC password.

        Returns ``{"old_password": ..., "new_password": ...}``.
        The new password is stored internally for subsequent session
        creation.
        """
        old_password = self._credentials.get(username, "")
        new_password = _generate_password()
        self._credentials[username] = new_password
        return {"old_password": old_password, "new_password": new_password}

    def set_initial_password(self, username: str, password: str) -> None:
        """Seed the initial password for a username (before first rotation)."""
        self._credentials[username] = password

    # ------------------------------------------------------------------
    # Session file generation
    # ------------------------------------------------------------------

    def generate_session_file(self, session: NPCSession) -> str:
        """Generate JSON content for ``/tmp/sessions/{username}.json``.

        This file is written to the container filesystem and is
        accessible to Red if they compromise the container.

        When the ``plaintext_session_storage`` weakness is active the
        file additionally contains the NPC's plaintext password.
        """
        data: dict[str, Any] = {
            "username": session.username,
            "session_id": session.session_id,
            "token_jti": session.token_jti,
            "session_created_at": session.session_created_at,
            "session_expires_at": session.session_expires_at,
            "last_refresh_at": session.last_refresh_at,
        }

        if session.bearer_token is not None:
            data["bearer_token"] = session.bearer_token

        if session.token_expires_at is not None:
            data["token_expires_at"] = session.token_expires_at

        if "plaintext_session_storage" in self._config.weaknesses:
            password = session.password or self._credentials.get(session.username, "")
            if password:
                data["password"] = password

        return json.dumps(data, indent=2)

    # ------------------------------------------------------------------
    # HTTP headers
    # ------------------------------------------------------------------

    def generate_auth_headers(self, session: NPCSession) -> dict[str, str]:
        """Generate HTTP headers for NPC requests.

        Returns headers like::

            {"Cookie": "session=<session_id>", "Authorization": "Bearer <jwt>"}
        """
        headers: dict[str, str] = {
            "Cookie": f"session={session.session_id}",
        }
        if session.bearer_token is not None:
            headers["Authorization"] = f"Bearer {session.bearer_token}"
        return headers

    # ------------------------------------------------------------------
    # Traffic log entries
    # ------------------------------------------------------------------

    def get_traffic_log_entry(
        self,
        session: NPCSession,
        action: str,
        target: str,
    ) -> dict[str, Any]:
        """Generate a structured log entry for an NPC action with session context.

        Adds ``session_id`` and ``token_jti`` to the log entry for
        forensic/audit correlation.  When the ``token_in_url`` weakness
        is active, the target URL is rewritten to include the bearer
        token as a query parameter.
        """
        log_target = target
        if (
            "token_in_url" in self._config.weaknesses
            and session.bearer_token is not None
        ):
            separator = "&" if "?" in target else "?"
            log_target = f"{target}{separator}token={session.bearer_token}"

        entry: dict[str, Any] = {
            "timestamp": time.time(),
            "type": f"npc_{action}",
            "label": "benign",
            "username": session.username,
            "session_id": session.session_id,
            "token_jti": session.token_jti,
            "action": action,
            "target": log_target,
        }
        return entry

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _issue_jwt(
        self,
        username: str,
        jti: str,
        issued_at: float,
        expires_at: float | None,
    ) -> str:
        """Issue a compact HS256 JWT for the given NPC.

        Mirrors the claim structure from k3s-istio-vault-platform's
        ``issueToken`` but uses HS256 with a range-local secret for
        simplicity (no RSA key management needed in the range).
        """
        payload: dict[str, Any] = {
            "sub": username,
            "iss": self._config.jwt_issuer,
            "aud": self._config.jwt_audience,
            "jti": jti,
            "iat": int(issued_at),
        }
        if expires_at is not None:
            payload["exp"] = int(expires_at)

        return jwt.encode(
            payload,
            self._config.jwt_secret,
            algorithm="HS256",
        )


# ---------------------------------------------------------------------------
# Password generation
# ---------------------------------------------------------------------------


def _generate_password(length: int = 16) -> str:
    """Generate a random password suitable for NPC credential rotation."""
    # Use secrets for cryptographic randomness; mix in a readable prefix
    # so forensic analysts can recognise rotated NPC passwords in logs.
    raw = secrets.token_urlsafe(length)
    return f"NPC-{raw[:length]}"
