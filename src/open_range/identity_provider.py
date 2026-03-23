"""Simulated OAuth/OIDC identity provider for range environments.

Ported from k3s-istio-vault-platform's oauth-svid-as pattern.  Generates
RS256 JWTs with SPIFFE-style service identities and configurable weaknesses
that create identity-based attack surfaces for Red/Blue training.

This module is entirely optional -- open-range works without it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import textwrap
import time
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy crypto imports -- fall back gracefully
# ---------------------------------------------------------------------------

_RSA_AVAILABLE = False

try:
    from cryptography.hazmat.primitives import hashes, serialization  # noqa: F401
    from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: F401

    _RSA_AVAILABLE = True
except ImportError:
    try:
        import jwt as _pyjwt  # noqa: F401

        _RSA_AVAILABLE = True
    except ImportError:
        pass

# We use PyJWT for token encode/decode regardless.
try:
    import jwt as pyjwt
except ImportError:  # pragma: no cover
    pyjwt = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Known plantable weaknesses
# ---------------------------------------------------------------------------

KNOWN_WEAKNESSES: frozenset[str] = frozenset(
    {
        "accept_expired",
        "no_audience_check",
        "weak_signing_hs256",
        "overly_broad_scopes",
        "predictable_jti",
        "missing_scope_check",
    }
)


# ---------------------------------------------------------------------------
# Pydantic configuration models
# ---------------------------------------------------------------------------


class ServiceIdentity(BaseModel):
    """Identity for a range service (inspired by SPIFFE).

    ``identity_uri`` follows the SPIFFE ID format:
        spiffe://range.local/ns/{zone}/sa/{service_name}

    ``allowed_scopes`` uses hierarchical colon-separated format ported from
    the k3s-istio-vault-platform authorization policy:
        data:read:tenant/env/app/*
    """

    identity_uri: str = ""
    allowed_scopes: list[str] = Field(default_factory=list)


class IdentityProviderConfig(BaseModel):
    """Configuration for the simulated identity provider.

    All fields have sensible defaults so an empty ``IdentityProviderConfig()``
    is valid.  Set ``enabled=True`` to activate the IdP in a range build.
    """

    enabled: bool = False
    issuer: str = "https://idp.range.local"
    token_ttl_seconds: int = 300  # 5 min -- matches k3s-istio-vault-platform
    signing_algorithm: str = "RS256"

    # Configurable weaknesses the Builder can plant for Red to exploit.
    weaknesses: list[str] = Field(default_factory=list)

    # Service identities keyed by logical service name.
    service_identities: dict[str, ServiceIdentity] = Field(default_factory=dict)

    # Port the in-container token server listens on.
    token_endpoint_port: int = 8443

    # Trust domain for SPIFFE ID generation.
    trust_domain: str = "range.local"


# ---------------------------------------------------------------------------
# Simulated Identity Provider
# ---------------------------------------------------------------------------


class SimulatedIdentityProvider:
    """Lightweight OAuth token service for range environments.

    Ported from k3s-istio-vault-platform's ``oauth-svid-as`` pattern.
    Generates RS256 JWTs with scopes, TTLs, and plantable weaknesses.

    Usage::

        config = IdentityProviderConfig(enabled=True, weaknesses=["accept_expired"])
        idp = SimulatedIdentityProvider(config)
        token = idp.issue_token("spiffe://range.local/ns/dmz/sa/web", ["data:read:patients/*"])
        claims = idp.validate_token(token)
    """

    def __init__(self, config: IdentityProviderConfig) -> None:
        self.config = config
        self._private_key_pem: bytes = b""
        self._public_key_pem: bytes = b""
        self._kid: str = ""
        self._n_b64: str = ""
        self._e_b64: str = ""
        # HMAC secret used when weak_signing_hs256 weakness is active.
        self._hmac_secret: str = "range-hmac-secret"

        if config.enabled:
            self._private_key_pem, self._public_key_pem = self.generate_keypair()
            self._kid = self._compute_kid(self._public_key_pem)
            self._extract_jwk_components()

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate an RSA 2048-bit keypair for JWT signing.

        Returns (private_pem, public_pem) as bytes.
        """
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

            private_key = _rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            public_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return private_pem, public_pem
        except Exception:
            # Fallback: use PyJWT's built-in RSA support if available.
            if pyjwt is not None:
                try:
                    from cryptography.hazmat.primitives.asymmetric import (
                        rsa as _rsa2,
                    )

                    key = _rsa2.generate_private_key(65537, 2048)
                    priv = key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                    pub = key.public_key().public_bytes(
                        serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    return priv, pub
                except Exception:
                    pass

            logger.warning(
                "identity_provider: no RSA backend available -- "
                "token issuance will use HS256 fallback"
            )
            return b"", b""

    @staticmethod
    def _compute_kid(public_key_pem: bytes) -> str:
        """Derive a key ID from the public key (matches oauth-svid-as pattern)."""
        digest = hashlib.sha256(public_key_pem).digest()
        return base64.urlsafe_b64encode(digest[:8]).decode().rstrip("=")

    def _extract_jwk_components(self) -> None:
        """Extract RSA n and e in base64url for JWKS endpoint."""
        if not self._public_key_pem:
            return
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_public_key

            pub_key = load_pem_public_key(self._public_key_pem)
            pub_numbers = pub_key.public_numbers()  # type: ignore[union-attr]
            n_bytes = pub_numbers.n.to_bytes(
                (pub_numbers.n.bit_length() + 7) // 8, byteorder="big"
            )
            e_bytes = pub_numbers.e.to_bytes(
                (pub_numbers.e.bit_length() + 7) // 8, byteorder="big"
            )
            self._n_b64 = base64.urlsafe_b64encode(n_bytes).decode().rstrip("=")
            self._e_b64 = base64.urlsafe_b64encode(e_bytes).decode().rstrip("=")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Token issuance (mirrors oauth-svid-as issueToken)
    # ------------------------------------------------------------------

    def issue_token(
        self,
        subject: str,
        scopes: list[str],
        audience: str = "range-api",
    ) -> str:
        """Issue a JWT token.

        *subject* is typically a SPIFFE-style identity URI.
        Returns the signed JWT string.
        """
        if pyjwt is None:
            raise RuntimeError(
                "PyJWT is required for token issuance. "
                "Install with: pip install pyjwt[crypto]"
            )

        now = int(time.time())
        ttl = self.config.token_ttl_seconds

        # Token ID -- predictable if that weakness is active.
        if "predictable_jti" in self.config.weaknesses:
            jti = f"token-{now}-0001"
        else:
            jti = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("=")

        # Scopes -- overly_broad_scopes replaces requested scopes with wildcard.
        effective_scopes = list(scopes)
        if "overly_broad_scopes" in self.config.weaknesses:
            effective_scopes = ["*:*:*"]

        claims: dict[str, Any] = {
            "iss": self.config.issuer,
            "sub": subject,
            "aud": audience,
            "exp": now + ttl,
            "iat": now,
            "nbf": now - 30,
            "jti": jti,
            "scp": effective_scopes,
            "scope": " ".join(effective_scopes),
        }

        # Choose signing algorithm -- weak_signing_hs256 downgrades to HS256.
        if "weak_signing_hs256" in self.config.weaknesses:
            token = pyjwt.encode(
                claims,
                self._hmac_secret,
                algorithm="HS256",
                headers={"kid": self._kid, "typ": "JWT"},
            )
        elif self._private_key_pem:
            token = pyjwt.encode(
                claims,
                self._private_key_pem,
                algorithm="RS256",
                headers={"kid": self._kid, "typ": "JWT"},
            )
        else:
            # No RSA key -- fall back to HS256.
            token = pyjwt.encode(
                claims,
                self._hmac_secret,
                algorithm="HS256",
                headers={"kid": self._kid, "typ": "JWT"},
            )

        return token

    # ------------------------------------------------------------------
    # Token validation
    # ------------------------------------------------------------------

    def validate_token(
        self,
        token: str,
        expected_audience: str = "range-api",
    ) -> dict[str, Any] | None:
        """Validate a JWT.  Returns claims dict or ``None`` if invalid.

        Respects configured weaknesses:
        - ``accept_expired``: expired tokens pass validation
        - ``no_audience_check``: audience is not verified
        - ``missing_scope_check``: scopes are not checked
        """
        if pyjwt is None:
            logger.error("PyJWT not available -- cannot validate tokens")
            return None

        options: dict[str, bool] = {}

        if "accept_expired" in self.config.weaknesses:
            options["verify_exp"] = False

        if "no_audience_check" in self.config.weaknesses:
            options["verify_aud"] = False
            expected_audience = ""

        # Try RS256 with public key first, then HS256 fallback.
        decode_keys: list[tuple[Any, list[str]]] = []
        if self._public_key_pem:
            decode_keys.append((self._public_key_pem, ["RS256"]))
        decode_keys.append((self._hmac_secret, ["HS256"]))

        for key, algs in decode_keys:
            try:
                kwargs: dict[str, Any] = {
                    "algorithms": algs,
                    "options": options,
                }
                if expected_audience:
                    kwargs["audience"] = expected_audience
                claims = pyjwt.decode(token, key, **kwargs)
                return dict(claims)
            except pyjwt.InvalidTokenError:
                continue

        return None

    # ------------------------------------------------------------------
    # JWKS endpoint data
    # ------------------------------------------------------------------

    def jwks(self) -> dict[str, Any]:
        """Return JWKS (JSON Web Key Set) for token verification.

        Follows the same structure as ``oauth-svid-as``'s
        ``/.well-known/jwks.json`` handler.
        """
        keys: list[dict[str, str]] = []
        if self._n_b64 and self._e_b64:
            keys.append(
                {
                    "kty": "RSA",
                    "kid": self._kid,
                    "use": "sig",
                    "alg": "RS256",
                    "n": self._n_b64,
                    "e": self._e_b64,
                }
            )
        return {"keys": keys}

    # ------------------------------------------------------------------
    # Batch service token generation
    # ------------------------------------------------------------------

    def generate_service_tokens(self) -> dict[str, str]:
        """Generate initial tokens for all configured service identities.

        Returns a dict of ``{service_name: jwt_string}``.
        """
        tokens: dict[str, str] = {}
        for svc_name, identity in self.config.service_identities.items():
            token = self.issue_token(
                subject=identity.identity_uri,
                scopes=identity.allowed_scopes,
            )
            tokens[svc_name] = token
        return tokens

    # ------------------------------------------------------------------
    # Startup script generation (injected into containers)
    # ------------------------------------------------------------------

    def generate_startup_script(self) -> str:
        """Generate a shell script that runs a minimal token endpoint.

        The script is injected into the web/ldap container as a payload.
        It serves:
          - ``POST /oauth/token`` (client_credentials grant)
          - ``GET /.well-known/jwks.json``
          - ``POST /oauth/introspect``

        The embedded Python server uses only stdlib when PyJWT is unavailable.
        """
        port = self.config.token_endpoint_port
        issuer = self.config.issuer
        ttl = self.config.token_ttl_seconds
        weaknesses = json.dumps(self.config.weaknesses)

        # Embed the private key (base64 to avoid shell quoting issues).
        priv_key_b64 = (
            base64.b64encode(self._private_key_pem).decode()
            if self._private_key_pem
            else ""
        )
        pub_key_b64 = (
            base64.b64encode(self._public_key_pem).decode()
            if self._public_key_pem
            else ""
        )

        # Service identities as JSON.
        identities_json = json.dumps(
            {
                name: {"uri": ident.identity_uri, "scopes": ident.allowed_scopes}
                for name, ident in self.config.service_identities.items()
            }
        )

        jwks_json = json.dumps(self.jwks())
        hmac_secret = self._hmac_secret

        return textwrap.dedent(f"""\
            #!/bin/bash
            # OpenRange Identity Provider - Auto-generated token endpoint
            # Launched as a background service inside the range container.
            set -e

            echo "[openrange-idp] Starting identity provider on port {port}..."

            python3 /opt/openrange/identity_provider_server.py \\
                --port {port} \\
                --issuer '{issuer}' \\
                --ttl {ttl} \\
                --weaknesses '{weaknesses}' \\
                --private-key-b64 '{priv_key_b64}' \\
                --public-key-b64 '{pub_key_b64}' \\
                --jwks '{jwks_json}' \\
                --identities '{identities_json}' \\
                --hmac-secret '{hmac_secret}' \\
                &

            echo "[openrange-idp] Identity provider started (PID $!)"
        """)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def build_spiffe_id(
    trust_domain: str,
    zone: str,
    service_name: str,
) -> str:
    """Build a SPIFFE-style identity URI.

    Format: ``spiffe://{trust_domain}/ns/{zone}/sa/{service_name}``
    """
    return f"spiffe://{trust_domain}/ns/{zone}/sa/{service_name}"


def default_service_identities(
    trust_domain: str = "range.local",
) -> dict[str, ServiceIdentity]:
    """Return a reasonable default set of service identities for a range.

    These mirror a typical enterprise IdP setup with scoped access.
    """
    return {
        "web": ServiceIdentity(
            identity_uri=build_spiffe_id(trust_domain, "dmz", "web"),
            allowed_scopes=[
                "data:read:patients/*",
                "data:read:referrals/*",
                "api:call:internal/*",
            ],
        ),
        "db": ServiceIdentity(
            identity_uri=build_spiffe_id(trust_domain, "internal", "db"),
            allowed_scopes=[
                "data:read:patients/*",
                "data:write:patients/*",
                "data:read:referrals/*",
                "data:write:referrals/*",
            ],
        ),
        "ldap": ServiceIdentity(
            identity_uri=build_spiffe_id(trust_domain, "internal", "ldap"),
            allowed_scopes=[
                "directory:read:users/*",
                "directory:write:users/*",
                "auth:bind:*",
            ],
        ),
        "siem": ServiceIdentity(
            identity_uri=build_spiffe_id(trust_domain, "management", "siem"),
            allowed_scopes=[
                "logs:read:*",
                "logs:write:*",
                "alerts:read:*",
            ],
        ),
    }
