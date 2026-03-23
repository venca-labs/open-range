#!/usr/bin/env python3
"""OpenRange Identity Provider -- in-container token endpoint server.

Self-contained OAuth token service injected into range containers.
Serves:
  POST /oauth/token          -- client_credentials grant (issue JWT)
  GET  /.well-known/jwks.json -- JWKS public key set
  POST /oauth/introspect     -- RFC 7662 token introspection
  GET  /healthz              -- health check

Uses stdlib http.server + json.  PyJWT used when available; falls back
to manual HMAC-SHA256 signing with stdlib only.

Ported from k3s-istio-vault-platform oauth-svid-as pattern.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import secrets
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

# ---------------------------------------------------------------------------
# Try importing PyJWT; fall back to manual JWT construction
# ---------------------------------------------------------------------------

_HAS_PYJWT = False
try:
    import jwt as pyjwt

    _HAS_PYJWT = True
except ImportError:
    pyjwt = None  # type: ignore[assignment]

_HAS_CRYPTOGRAPHY = False
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, utils

    _HAS_CRYPTOGRAPHY = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Configuration (populated from CLI args at startup)
# ---------------------------------------------------------------------------

CONFIG: dict[str, Any] = {
    "port": 8443,
    "issuer": "https://idp.range.local",
    "ttl": 300,
    "weaknesses": [],
    "private_key_pem": b"",
    "public_key_pem": b"",
    "jwks": {"keys": []},
    "identities": {},
    "hmac_secret": "range-hmac-secret",
}


# ---------------------------------------------------------------------------
# Manual JWT helpers (stdlib-only fallback)
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding_needed = 4 - len(s) % 4
    if padding_needed != 4:
        s += "=" * padding_needed
    return base64.urlsafe_b64decode(s)


def _manual_jwt_hs256(payload: dict[str, Any], secret: str, kid: str = "") -> str:
    """Create an HS256-signed JWT using only stdlib."""
    header = {"alg": "HS256", "typ": "JWT"}
    if kid:
        header["kid"] = kid

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}"

    signature = hmac.new(
        secret.encode("utf-8"),
        signing_input.encode("ascii"),
        hashlib.sha256,
    ).digest()
    sig_b64 = _b64url_encode(signature)

    return f"{signing_input}.{sig_b64}"


def _manual_jwt_rs256(
    payload: dict[str, Any],
    private_key_pem: bytes,
    kid: str = "",
) -> str:
    """Create an RS256-signed JWT using cryptography library."""
    if not _HAS_CRYPTOGRAPHY:
        raise RuntimeError("cryptography library required for RS256")

    from cryptography.hazmat.primitives.asymmetric import padding as _padding
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    header = {"alg": "RS256", "typ": "JWT"}
    if kid:
        header["kid"] = kid

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    private_key = load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(  # type: ignore[union-attr]
        signing_input,
        _padding.PKCS1v15(),
        hashes.SHA256(),
    )
    sig_b64 = _b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def _decode_jwt_claims(token: str) -> dict[str, Any] | None:
    """Decode JWT claims without verification (for introspection)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload_bytes = _b64url_decode(parts[1])
        return json.loads(payload_bytes)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Token issuance
# ---------------------------------------------------------------------------


def issue_token(
    subject: str,
    scopes: list[str],
    audience: str = "range-api",
) -> str:
    """Issue a JWT token following the oauth-svid-as pattern."""
    now = int(time.time())
    ttl = CONFIG["ttl"]
    weaknesses = CONFIG["weaknesses"]

    # Predictable JTI weakness.
    if "predictable_jti" in weaknesses:
        jti = f"token-{now}-0001"
    else:
        jti = _b64url_encode(secrets.token_bytes(16))

    # Overly broad scopes weakness.
    effective_scopes = list(scopes)
    if "overly_broad_scopes" in weaknesses:
        effective_scopes = ["*:*:*"]

    claims: dict[str, Any] = {
        "iss": CONFIG["issuer"],
        "sub": subject,
        "aud": audience,
        "exp": now + ttl,
        "iat": now,
        "nbf": now - 30,
        "jti": jti,
        "scp": effective_scopes,
        "scope": " ".join(effective_scopes),
    }

    kid = ""
    jwks_keys = CONFIG["jwks"].get("keys", [])
    if jwks_keys:
        kid = jwks_keys[0].get("kid", "")

    # Choose signing method.
    if "weak_signing_hs256" in weaknesses:
        if _HAS_PYJWT:
            return pyjwt.encode(claims, CONFIG["hmac_secret"], algorithm="HS256",
                                headers={"kid": kid, "typ": "JWT"})
        return _manual_jwt_hs256(claims, CONFIG["hmac_secret"], kid=kid)

    private_key = CONFIG["private_key_pem"]
    if private_key:
        if _HAS_PYJWT:
            return pyjwt.encode(claims, private_key, algorithm="RS256",
                                headers={"kid": kid, "typ": "JWT"})
        if _HAS_CRYPTOGRAPHY:
            return _manual_jwt_rs256(claims, private_key, kid=kid)

    # Final fallback: HS256.
    if _HAS_PYJWT:
        return pyjwt.encode(claims, CONFIG["hmac_secret"], algorithm="HS256",
                            headers={"kid": kid, "typ": "JWT"})
    return _manual_jwt_hs256(claims, CONFIG["hmac_secret"], kid=kid)


def validate_token(token: str, expected_audience: str = "range-api") -> dict[str, Any] | None:
    """Validate a JWT and return claims or None."""
    weaknesses = CONFIG["weaknesses"]

    # Fast path with PyJWT.
    if _HAS_PYJWT:
        options: dict[str, bool] = {}
        if "accept_expired" in weaknesses:
            options["verify_exp"] = False
        if "no_audience_check" in weaknesses:
            options["verify_aud"] = False
            expected_audience = ""

        decode_keys: list[tuple[Any, list[str]]] = []
        if CONFIG["private_key_pem"]:
            decode_keys.append((CONFIG["public_key_pem"], ["RS256"]))
        decode_keys.append((CONFIG["hmac_secret"], ["HS256"]))

        for key, algs in decode_keys:
            try:
                kwargs: dict[str, Any] = {"algorithms": algs, "options": options}
                if expected_audience:
                    kwargs["audience"] = expected_audience
                return dict(pyjwt.decode(token, key, **kwargs))
            except Exception:
                continue
        return None

    # Stdlib fallback: decode without cryptographic verification.
    claims = _decode_jwt_claims(token)
    if claims is None:
        return None

    now = int(time.time())
    if "accept_expired" not in weaknesses:
        exp = claims.get("exp", 0)
        if isinstance(exp, (int, float)) and now > exp:
            return None

    if "no_audience_check" not in weaknesses and expected_audience:
        aud = claims.get("aud", "")
        if isinstance(aud, str) and aud != expected_audience:
            return None
        if isinstance(aud, list) and expected_audience not in aud:
            return None

    return claims


# ---------------------------------------------------------------------------
# HTTP Request Handler
# ---------------------------------------------------------------------------


class TokenHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler for the identity provider endpoints."""

    server_version = "OpenRange-IdP/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        """Log with [openrange-idp] prefix."""
        sys.stderr.write(
            f"[openrange-idp] {self.address_string()} - "
            f"{format % args}\n"
        )

    def _send_json(self, status: int, body: dict[str, Any]) -> None:
        payload = json.dumps(body, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    # --- GET endpoints ---

    def do_GET(self) -> None:
        path = self.path.split("?")[0]

        if path == "/.well-known/jwks.json":
            self._handle_jwks()
        elif path == "/healthz":
            self._handle_healthz()
        else:
            self._send_json(404, {"error": "not_found"})

    # --- POST endpoints ---

    def do_POST(self) -> None:
        path = self.path.split("?")[0]

        if path == "/oauth/token":
            self._handle_token()
        elif path == "/oauth/introspect":
            self._handle_introspect()
        else:
            self._send_json(404, {"error": "not_found"})

    # --- Handlers ---

    def _handle_jwks(self) -> None:
        self._send_json(200, CONFIG["jwks"])

    def _handle_healthz(self) -> None:
        self._send_json(200, {"status": "ok"})

    def _handle_token(self) -> None:
        """Handle POST /oauth/token (client_credentials grant).

        Expects form-encoded body with:
          grant_type=client_credentials
          scope=<space-separated scopes>
          client_id=<service name or SPIFFE URI>
        """
        body = self._read_body()
        content_type = self.headers.get("Content-Type", "")

        if "application/x-www-form-urlencoded" in content_type:
            params = dict(urllib.parse.parse_qsl(body.decode("utf-8", errors="replace")))
        elif "application/json" in content_type:
            try:
                params = json.loads(body)
            except json.JSONDecodeError:
                self._send_json(400, {"error": "invalid_request"})
                return
        else:
            # Try form-encoded as default.
            params = dict(urllib.parse.parse_qsl(body.decode("utf-8", errors="replace")))

        grant_type = params.get("grant_type", "")
        if grant_type != "client_credentials":
            self._send_json(400, {"error": "unsupported_grant_type"})
            return

        client_id = params.get("client_id", "")
        requested_scopes_str = params.get("scope", "")
        requested_scopes = requested_scopes_str.split() if requested_scopes_str else []
        audience = params.get("audience", "range-api")

        # Resolve subject from client_id.
        identities = CONFIG.get("identities", {})
        subject = client_id
        allowed_scopes: list[str] | None = None

        if client_id in identities:
            identity_info = identities[client_id]
            subject = identity_info.get("uri", client_id)
            allowed_scopes = identity_info.get("scopes", [])
        elif client_id.startswith("spiffe://"):
            subject = client_id

        # Scope enforcement (unless missing_scope_check weakness is active).
        weaknesses = CONFIG["weaknesses"]
        if allowed_scopes is not None and "missing_scope_check" not in weaknesses:
            if not requested_scopes:
                requested_scopes = list(allowed_scopes)
            else:
                allowed_set = set(allowed_scopes)
                for scope in requested_scopes:
                    if scope not in allowed_set:
                        self._send_json(403, {"error": "scope_not_allowed",
                                              "scope": scope})
                        return
        elif not requested_scopes:
            requested_scopes = ["default"]

        try:
            token = issue_token(subject, requested_scopes, audience)
        except Exception as exc:
            self._send_json(500, {"error": "token_issue_failed",
                                  "detail": str(exc)})
            return

        self._send_json(200, {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": CONFIG["ttl"],
            "scope": " ".join(requested_scopes),
        })

    def _handle_introspect(self) -> None:
        """Handle POST /oauth/introspect (RFC 7662).

        Expects form-encoded body with:
          token=<JWT>
        """
        body = self._read_body()
        params = dict(urllib.parse.parse_qsl(body.decode("utf-8", errors="replace")))
        token_str = params.get("token", "")

        if not token_str:
            self._send_json(400, {"error": "invalid_request",
                                  "detail": "missing token parameter"})
            return

        claims = validate_token(token_str)
        if claims is None:
            self._send_json(200, {"active": False})
            return

        response: dict[str, Any] = {
            "active": True,
            "sub": claims.get("sub", ""),
            "iss": claims.get("iss", ""),
            "aud": claims.get("aud", ""),
            "exp": claims.get("exp", 0),
            "iat": claims.get("iat", 0),
            "scope": claims.get("scope", ""),
            "jti": claims.get("jti", ""),
            "token_type": "Bearer",
        }
        self._send_json(200, response)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenRange Identity Provider Server")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--issuer", default="https://idp.range.local")
    parser.add_argument("--ttl", type=int, default=300)
    parser.add_argument("--weaknesses", default="[]")
    parser.add_argument("--private-key-b64", default="")
    parser.add_argument("--public-key-b64", default="")
    parser.add_argument("--jwks", default='{"keys":[]}')
    parser.add_argument("--identities", default="{}")
    parser.add_argument("--hmac-secret", default="range-hmac-secret")
    args = parser.parse_args()

    CONFIG["port"] = args.port
    CONFIG["issuer"] = args.issuer
    CONFIG["ttl"] = args.ttl
    CONFIG["hmac_secret"] = args.hmac_secret

    try:
        CONFIG["weaknesses"] = json.loads(args.weaknesses)
    except json.JSONDecodeError:
        CONFIG["weaknesses"] = []

    try:
        CONFIG["jwks"] = json.loads(args.jwks)
    except json.JSONDecodeError:
        CONFIG["jwks"] = {"keys": []}

    try:
        CONFIG["identities"] = json.loads(args.identities)
    except json.JSONDecodeError:
        CONFIG["identities"] = {}

    if args.private_key_b64:
        try:
            CONFIG["private_key_pem"] = base64.b64decode(args.private_key_b64)
        except Exception:
            CONFIG["private_key_pem"] = b""

    if args.public_key_b64:
        try:
            CONFIG["public_key_pem"] = base64.b64decode(args.public_key_b64)
        except Exception:
            CONFIG["public_key_pem"] = b""

    server = HTTPServer(("0.0.0.0", args.port), TokenHandler)
    print(f"[openrange-idp] Listening on 0.0.0.0:{args.port}", file=sys.stderr)
    print(f"[openrange-idp] Issuer: {args.issuer}", file=sys.stderr)
    print(f"[openrange-idp] TTL: {args.ttl}s", file=sys.stderr)
    print(f"[openrange-idp] Weaknesses: {CONFIG['weaknesses']}", file=sys.stderr)
    print(f"[openrange-idp] PyJWT available: {_HAS_PYJWT}", file=sys.stderr)
    print(f"[openrange-idp] cryptography available: {_HAS_CRYPTOGRAPHY}", file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[openrange-idp] Shutting down.", file=sys.stderr)
        server.server_close()


if __name__ == "__main__":
    main()
