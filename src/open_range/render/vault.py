"""Optional Vault integration for OpenRange secret management.

Provides a lightweight Vault HTTP client for:
- KV v2 secret storage (LLM API keys, range credentials)
- Transit encryption / decryption (envelope encryption for sensitive data)

When Vault is not configured the module degrades gracefully:
- ``get_vault_client()`` returns ``None``
- ``VaultCredentialProvider`` falls back to environment variables and defaults

Configuration is driven entirely by environment variables or an explicit
``VaultConfig`` pydantic model, keeping the integration fully optional.

Adapted from the k3s-istio-vault-platform secret-runtime Vault client.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import ssl
import urllib.error
import urllib.request
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class VaultError(Exception):
    """Base exception for all Vault client errors."""


class VaultUnavailableError(VaultError):
    """Raised when Vault is not configured or unreachable."""


class VaultAuthError(VaultError):
    """Raised when authentication to Vault fails."""


class VaultRequestError(VaultError):
    """Raised when a Vault API request returns a non-success status."""

    def __init__(
        self, message: str, status_code: int = 0, errors: list[str] | None = None
    ):
        self.status_code = status_code
        self.errors = errors or []
        super().__init__(message)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class VaultConfig(BaseModel):
    """Pydantic v2 configuration for the Vault client.

    All fields have sensible defaults.  At minimum ``addr`` and one auth
    method (``token`` or ``kubernetes_role``) must be supplied for the
    client to be usable.
    """

    addr: str = Field(
        default="",
        description="Vault server address, e.g. http://127.0.0.1:8200",
    )
    token: str = Field(
        default="",
        description="Vault token for token-based authentication.",
    )
    namespace: str = Field(
        default="",
        description="Vault namespace (enterprise feature).",
    )

    # KV v2 settings
    kv_mount: str = Field(
        default="secret",
        description="Mount path for the KV v2 secrets engine.",
    )

    # Transit settings
    transit_mount: str = Field(
        default="transit",
        description="Mount path for the Transit secrets engine.",
    )
    transit_key: str = Field(
        default="openrange/credentials",
        description="Default Transit key name for encrypt/decrypt operations.",
    )

    # Kubernetes auth (optional)
    kubernetes_role: str = Field(
        default="",
        description="Vault Kubernetes auth role. When set, enables K8s auth.",
    )
    kubernetes_mount: str = Field(
        default="kubernetes",
        description="Mount path for the Kubernetes auth method.",
    )
    kubernetes_token_path: str = Field(
        default="/var/run/secrets/kubernetes.io/serviceaccount/token",
        description="Path to the Kubernetes service account JWT.",
    )

    # TLS
    ca_cert: str = Field(
        default="",
        description="Path to a CA certificate bundle for TLS verification.",
    )
    skip_verify: bool = Field(
        default=False,
        description="Skip TLS verification (development only).",
    )

    # Timeouts
    timeout: float = Field(
        default=10.0,
        description="HTTP request timeout in seconds.",
    )

    @classmethod
    def from_env(cls) -> VaultConfig:
        """Build configuration from ``VAULT_*`` / ``OPENRANGE_VAULT_*`` environment variables."""
        return cls(
            addr=os.getenv("VAULT_ADDR", os.getenv("OPENRANGE_VAULT_ADDR", "")),
            token=os.getenv("VAULT_TOKEN", os.getenv("OPENRANGE_VAULT_TOKEN", "")),
            namespace=os.getenv("VAULT_NAMESPACE", ""),
            kv_mount=os.getenv("OPENRANGE_VAULT_KV_MOUNT", "secret"),
            transit_mount=os.getenv("OPENRANGE_VAULT_TRANSIT_MOUNT", "transit"),
            transit_key=os.getenv(
                "OPENRANGE_VAULT_TRANSIT_KEY", "openrange/credentials"
            ),
            kubernetes_role=os.getenv("OPENRANGE_VAULT_K8S_ROLE", ""),
            kubernetes_mount=os.getenv("OPENRANGE_VAULT_K8S_MOUNT", "kubernetes"),
            kubernetes_token_path=os.getenv(
                "OPENRANGE_VAULT_K8S_TOKEN_PATH",
                "/var/run/secrets/kubernetes.io/serviceaccount/token",
            ),
            ca_cert=os.getenv("VAULT_CACERT", ""),
            skip_verify=os.getenv("VAULT_SKIP_VERIFY", "").lower()
            in ("1", "true", "yes"),
            timeout=float(os.getenv("OPENRANGE_VAULT_TIMEOUT", "10")),
        )

    @property
    def is_configured(self) -> bool:
        """Return True when enough information is present to attempt a connection."""
        if not self.addr:
            return False
        return bool(self.token or self.kubernetes_role)


# ---------------------------------------------------------------------------
# Low-level Vault HTTP client
# ---------------------------------------------------------------------------


class VaultClient:
    """Lightweight Vault HTTP client using only the Python standard library.

    Supports token auth and Kubernetes auth.  Provides KV v2 read/write
    and Transit encrypt/decrypt/generate-data-key operations.
    """

    def __init__(self, config: VaultConfig) -> None:
        if not config.is_configured:
            raise VaultUnavailableError(
                "Vault is not configured. Set VAULT_ADDR and either VAULT_TOKEN "
                "or OPENRANGE_VAULT_K8S_ROLE to enable Vault integration."
            )
        self._config = config
        self._addr = config.addr.rstrip("/")
        self._token: str = config.token
        self._ssl_context = self._build_ssl_context()

    # -- SSL ----------------------------------------------------------------

    def _build_ssl_context(self) -> ssl.SSLContext | None:
        if not self._addr.startswith("https"):
            return None
        ctx = ssl.create_default_context()
        if self._config.ca_cert:
            ctx.load_verify_locations(self._config.ca_cert)
        if self._config.skip_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # -- HTTP helpers -------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        token: str | None = None,
    ) -> dict[str, Any]:
        """Execute an HTTP request against Vault and return the parsed JSON response."""
        url = f"{self._addr}{path}"
        data = json.dumps(body).encode() if body else None

        headers: dict[str, str] = {"Content-Type": "application/json"}
        effective_token = token or self._token
        if effective_token:
            headers["X-Vault-Token"] = effective_token
        if self._config.namespace:
            headers["X-Vault-Namespace"] = self._config.namespace

        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(
                req,
                timeout=self._config.timeout,
                context=self._ssl_context,
            ) as resp:
                resp_body = resp.read()
                if not resp_body:
                    return {}
                return json.loads(resp_body)
        except urllib.error.HTTPError as exc:
            resp_body = exc.read().decode(errors="replace")
            errors: list[str] = []
            try:
                errors = json.loads(resp_body).get("errors", [])
            except (json.JSONDecodeError, AttributeError):
                if resp_body:
                    errors = [resp_body]
            msg = f"Vault {method} {path} returned {exc.code}: {'; '.join(errors)}"
            if exc.code in (401, 403):
                raise VaultAuthError(msg) from exc
            raise VaultRequestError(msg, status_code=exc.code, errors=errors) from exc
        except urllib.error.URLError as exc:
            raise VaultUnavailableError(
                f"Cannot reach Vault at {self._addr}: {exc.reason}"
            ) from exc

    # -- Authentication -----------------------------------------------------

    def authenticate(self) -> None:
        """Authenticate to Vault, obtaining or refreshing the client token.

        If a static token is already set, this is a no-op.
        For Kubernetes auth, exchanges the service-account JWT for a Vault token.
        """
        if self._token:
            return

        if self._config.kubernetes_role:
            self._kubernetes_login()
            return

        raise VaultAuthError(
            "No authentication method available. Provide VAULT_TOKEN or "
            "configure Kubernetes auth via OPENRANGE_VAULT_K8S_ROLE."
        )

    def _kubernetes_login(self) -> None:
        """Authenticate via Kubernetes service account JWT."""
        try:
            with open(self._config.kubernetes_token_path) as fh:
                jwt = fh.read().strip()
        except OSError as exc:
            raise VaultAuthError(
                f"Cannot read Kubernetes SA token at "
                f"{self._config.kubernetes_token_path}: {exc}"
            ) from exc

        mount = self._config.kubernetes_mount
        resp = self._request(
            "POST",
            f"/v1/auth/{mount}/login",
            body={"role": self._config.kubernetes_role, "jwt": jwt},
        )
        auth = resp.get("auth", {})
        self._token = auth.get("client_token", "")
        if not self._token:
            raise VaultAuthError(
                "Kubernetes auth succeeded but no client_token returned."
            )
        logger.info(
            "Vault: authenticated via Kubernetes auth (role=%s)",
            self._config.kubernetes_role,
        )

    @property
    def is_authenticated(self) -> bool:
        return bool(self._token)

    # -- KV v2 operations ---------------------------------------------------

    def read_secret(self, path: str) -> dict[str, Any] | None:
        """Read a secret from KV v2.

        Args:
            path: Secret path relative to the KV mount, e.g. ``openrange/llm-api-key``.

        Returns:
            The ``data`` dict from the KV v2 response, or ``None`` if the secret
            does not exist.
        """
        self.authenticate()
        mount = self._config.kv_mount
        try:
            resp = self._request("GET", f"/v1/{mount}/data/{path}")
        except VaultRequestError as exc:
            if exc.status_code == 404:
                return None
            raise
        data = resp.get("data", {})
        return data.get("data")

    def write_secret(self, path: str, data: dict[str, Any]) -> dict[str, Any]:
        """Write a secret to KV v2.

        Args:
            path: Secret path relative to the KV mount.
            data: Key-value pairs to store.

        Returns:
            The full Vault response metadata.
        """
        self.authenticate()
        mount = self._config.kv_mount
        resp = self._request("POST", f"/v1/{mount}/data/{path}", body={"data": data})
        return resp.get("data", {})

    # -- Transit operations -------------------------------------------------

    def encrypt(self, plaintext: str | bytes, key_name: str | None = None) -> str:
        """Encrypt data using the Transit secrets engine.

        Args:
            plaintext: Data to encrypt.  Strings are UTF-8 encoded first.
            key_name: Transit key name.  Defaults to ``config.transit_key``.

        Returns:
            Vault ciphertext string (``vault:v1:...``).
        """
        self.authenticate()
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        b64 = base64.b64encode(plaintext).decode()
        key = key_name or self._config.transit_key
        mount = self._config.transit_mount
        resp = self._request(
            "POST",
            f"/v1/{mount}/encrypt/{key}",
            body={"plaintext": b64},
        )
        return resp["data"]["ciphertext"]

    def decrypt(self, ciphertext: str, key_name: str | None = None) -> bytes:
        """Decrypt data using the Transit secrets engine.

        Args:
            ciphertext: Vault ciphertext string (``vault:v1:...``).
            key_name: Transit key name.  Defaults to ``config.transit_key``.

        Returns:
            Decrypted bytes.
        """
        self.authenticate()
        key = key_name or self._config.transit_key
        mount = self._config.transit_mount
        resp = self._request(
            "POST",
            f"/v1/{mount}/decrypt/{key}",
            body={"ciphertext": ciphertext},
        )
        b64 = resp["data"]["plaintext"]
        return base64.b64decode(b64)

    def generate_data_key(
        self, key_name: str | None = None, *, bits: int = 256
    ) -> tuple[bytes, str]:
        """Generate a Transit data key for envelope encryption.

        Returns a tuple of ``(plaintext_key_bytes, wrapped_ciphertext)`` so the
        caller can use the plaintext key locally and persist only the wrapped
        (encrypted) copy.

        Args:
            key_name: Transit key name.  Defaults to ``config.transit_key``.
            bits: Key size in bits (128 or 256).

        Returns:
            ``(plaintext_key, wrapped_key)`` tuple.
        """
        self.authenticate()
        key = key_name or self._config.transit_key
        mount = self._config.transit_mount
        resp = self._request(
            "POST",
            f"/v1/{mount}/datakey/plaintext/{key}",
            body={"bits": bits},
        )
        plaintext_b64 = resp["data"]["plaintext"]
        ciphertext = resp["data"]["ciphertext"]
        return base64.b64decode(plaintext_b64), ciphertext

    # -- Health check -------------------------------------------------------

    def health(self) -> dict[str, Any]:
        """Check Vault health (does not require authentication)."""
        return self._request("GET", "/v1/sys/health")


# ---------------------------------------------------------------------------
# Credential provider (high-level interface)
# ---------------------------------------------------------------------------

# LLM API key names that open-range checks via environment variables.
# See: open_range/builder/builder.py  _BUILDER_PROVIDER_ENV_VARS
_LLM_API_KEY_ENV_VARS = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "LITELLM_API_KEY",
    "AZURE_API_KEY",
    "AZURE_OPENAI_API_KEY",
)

# Default KV paths within the openrange Vault namespace.
_KV_LLM_API_KEYS = "openrange/llm-api-keys"
_KV_RANGE_CREDENTIALS = "openrange/range-credentials"


class VaultCredentialProvider:
    """High-level credential provider that reads secrets from Vault KV
    and falls back to environment variables / hardcoded defaults when
    Vault is unavailable.

    Usage::

        provider = VaultCredentialProvider.from_env()
        api_key = provider.get_llm_api_key("OPENAI_API_KEY")
        mysql_pw = provider.get_range_credential("mysql_root_password", default="r00tP@ss!")
    """

    def __init__(self, client: VaultClient | None = None) -> None:
        self._client = client

    @classmethod
    def from_env(cls) -> VaultCredentialProvider:
        """Create a provider using environment-based Vault configuration.

        Returns a provider backed by Vault when configuration is present,
        or an env-var-only provider when Vault is not configured.
        """
        client = get_vault_client()
        return cls(client=client)

    @property
    def vault_available(self) -> bool:
        """Return True when a functional Vault client is present."""
        return self._client is not None

    # -- LLM API Keys ------------------------------------------------------

    def get_llm_api_key(self, key_name: str) -> str | None:
        """Retrieve an LLM API key, trying Vault first then the environment.

        Args:
            key_name: Environment variable style name, e.g. ``OPENAI_API_KEY``.

        Returns:
            The API key string, or ``None`` if not found anywhere.
        """
        # Try Vault KV first.
        if self._client is not None:
            try:
                secret = self._client.read_secret(_KV_LLM_API_KEYS)
                if secret and key_name in secret:
                    logger.debug("Vault: resolved LLM API key %s from KV", key_name)
                    return str(secret[key_name])
            except VaultError as exc:
                logger.warning(
                    "Vault: failed to read LLM API key %s: %s", key_name, exc
                )

        # Fallback to environment variable.
        value = os.getenv(key_name)
        if value:
            logger.debug("Resolved LLM API key %s from environment", key_name)
        return value

    def get_all_llm_api_keys(self) -> dict[str, str]:
        """Return all available LLM API keys from Vault and/or the environment.

        Keys found in Vault take precedence over environment variables.
        """
        keys: dict[str, str] = {}

        # Gather from environment first (lower priority).
        for name in _LLM_API_KEY_ENV_VARS:
            val = os.getenv(name)
            if val:
                keys[name] = val

        # Overlay with Vault values (higher priority).
        if self._client is not None:
            try:
                secret = self._client.read_secret(_KV_LLM_API_KEYS)
                if secret:
                    for name in _LLM_API_KEY_ENV_VARS:
                        if name in secret:
                            keys[name] = str(secret[name])
            except VaultError as exc:
                logger.warning("Vault: failed to read LLM API keys: %s", exc)

        return keys

    # -- Range Credentials (DB passwords, LDAP, etc.) ----------------------

    def get_range_credential(self, name: str, *, default: str = "") -> str:
        """Retrieve a range credential (e.g. ``mysql_root_password``).

        Checks Vault KV at ``openrange/range-credentials`` first, then falls
        back to the provided default.

        Args:
            name: Credential key, e.g. ``mysql_root_password``, ``ldap_admin_password``.
            default: Fallback value when credential is not in Vault.

        Returns:
            The credential value.
        """
        if self._client is not None:
            try:
                secret = self._client.read_secret(_KV_RANGE_CREDENTIALS)
                if secret and name in secret:
                    logger.debug("Vault: resolved range credential %s from KV", name)
                    return str(secret[name])
            except VaultError as exc:
                logger.warning(
                    "Vault: failed to read range credential %s: %s", name, exc
                )

        return default

    def store_range_credential(self, name: str, value: str) -> bool:
        """Write or update a single range credential in Vault KV.

        Merges with any existing credentials at the path.  Returns ``False``
        if Vault is unavailable.
        """
        if self._client is None:
            logger.debug("Vault unavailable; cannot store credential %s", name)
            return False
        try:
            existing = self._client.read_secret(_KV_RANGE_CREDENTIALS) or {}
            existing[name] = value
            self._client.write_secret(_KV_RANGE_CREDENTIALS, existing)
            logger.info("Vault: stored range credential %s", name)
            return True
        except VaultError as exc:
            logger.warning("Vault: failed to store range credential %s: %s", name, exc)
            return False

    def get_mysql_root_password(self, *, default: str = "r00tP@ss!") -> str:
        """Convenience method for the MySQL root password used by range containers."""
        return self.get_range_credential("mysql_root_password", default=default)

    def get_ldap_admin_password(self, *, default: str = "admin") -> str:
        """Convenience method for the LDAP admin password used by range containers."""
        return self.get_range_credential("ldap_admin_password", default=default)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

_cached_client: VaultClient | None = None
_client_attempted: bool = False


def get_vault_client() -> VaultClient | None:
    """Return a configured ``VaultClient`` or ``None`` if Vault is not available.

    The result is cached for the process lifetime.  Call ``reset_vault_client()``
    to force re-initialization (useful in tests).
    """
    global _cached_client, _client_attempted
    if _client_attempted:
        return _cached_client

    _client_attempted = True
    config = VaultConfig.from_env()
    if not config.is_configured:
        logger.debug("Vault integration disabled (VAULT_ADDR / auth not configured)")
        return None

    try:
        client = VaultClient(config)
        client.authenticate()
        _cached_client = client
        logger.info("Vault client initialized (addr=%s)", config.addr)
        return _cached_client
    except VaultError as exc:
        logger.warning(
            "Vault client initialization failed: %s. Continuing without Vault.", exc
        )
        return None


def reset_vault_client() -> None:
    """Reset the cached Vault client.  Primarily useful for testing."""
    global _cached_client, _client_attempted
    _cached_client = None
    _client_attempted = False
