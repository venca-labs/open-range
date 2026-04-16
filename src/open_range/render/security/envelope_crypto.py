"""Envelope encryption for range flags and secrets-at-rest.

Implements AES-256-GCM envelope encryption ported from the
k3s-istio-vault-platform ``secret-runtime`` write path:

    1. Generate a fresh 256-bit Data Encryption Key (DEK) per write
    2. Encrypt plaintext locally with AES-256-GCM using a random 12-byte nonce
    3. Wrap the DEK with the master key (or Vault Transit)
    4. Store ciphertext + wrapped DEK + nonce; zero the plaintext DEK

Red agents must locate the wrapped DEK and master key (or Vault access)
to decrypt flags.  Blue agents validate that encrypted paths contain only
ciphertext and that DEKs are not exposed alongside encrypted data.

The module is **completely optional**: it imports ``cryptography`` at call
time and raises a clear ``ImportError`` when the library is absent.  All
Pydantic models use v2 conventions.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy crypto imports — we defer so the rest of the package works even when
# the ``cryptography`` library is not installed.
# ---------------------------------------------------------------------------

_CRYPTO_BACKEND: str | None = None


def _get_cipher_module() -> Any:
    """Return the AES-GCM primitives from ``cryptography`` (preferred) or
    ``Crypto.Cipher`` (pycryptodome fallback).

    Raises ``ImportError`` with a helpful message when neither is available.
    """
    global _CRYPTO_BACKEND

    # Prefer the ``cryptography`` library (already in uv.lock).
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        _CRYPTO_BACKEND = "cryptography"
        return AESGCM
    except ImportError:
        pass

    # Fallback: pycryptodome
    try:
        from Crypto.Cipher import AES  # type: ignore[import-untyped]

        _CRYPTO_BACKEND = "pycryptodome"
        return AES
    except ImportError:
        pass

    raise ImportError(
        "Envelope encryption requires the 'cryptography' package "
        "(pip install cryptography) or 'pycryptodome' as a fallback.  "
        "Neither is currently installed."
    )


def _aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """AES-256-GCM encrypt using whichever backend is available."""
    mod = _get_cipher_module()

    if _CRYPTO_BACKEND == "cryptography":
        # ``mod`` is AESGCM class
        aesgcm = mod(key)
        return aesgcm.encrypt(nonce, plaintext, aad)

    # pycryptodome path
    cipher = mod.new(key, mod.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return ct + tag  # append 16-byte tag like ``cryptography`` does


def _aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """AES-256-GCM decrypt using whichever backend is available."""
    mod = _get_cipher_module()

    if _CRYPTO_BACKEND == "cryptography":
        aesgcm = mod(key)
        return aesgcm.decrypt(nonce, ciphertext, aad)

    # pycryptodome: last 16 bytes are the GCM tag
    tag = ciphertext[-16:]
    ct = ciphertext[:-16]
    cipher = mod.new(key, mod.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ct, tag)


# ---------------------------------------------------------------------------
# Pydantic configuration models
# ---------------------------------------------------------------------------


class EncryptionConfig(BaseModel):
    """Configuration for envelope encryption of range secrets."""

    enabled: bool = False
    encrypted_paths: list[str] = Field(default_factory=list)
    # e.g. ["files:/srv/shares/compliance/hipaa_audit_2024.txt", "db:flags.secrets.value"]
    master_key_source: str = "env_var"  # "vault_transit" or "env_var"
    master_key_env_var: str = "OPENRANGE_MASTER_KEY"
    dek_storage_path: str = "/etc/openrange/wrapped_dek.json"
    # Where the wrapped DEK is stored in the range (Red must find this)


class EncryptedBundle(BaseModel):
    """Encrypted data bundle following k3s-istio-vault-platform pattern."""

    ciphertext: str  # base64-encoded AES-256-GCM ciphertext
    nonce: str  # base64-encoded 12-byte nonce
    wrapped_dek: str  # base64-encoded wrapped DEK
    aad: str  # canonical Additional Authenticated Data
    key_version: int = 1


# ---------------------------------------------------------------------------
# Core envelope encryption engine
# ---------------------------------------------------------------------------


class EnvelopeCrypto:
    """AES-256-GCM envelope encryption ported from k3s-istio-vault-platform.

    Pattern: generate DEK -> encrypt locally with AES-256-GCM -> wrap DEK ->
    store wrapped DEK + ciphertext. Plaintext DEK zeroed after use.
    """

    _KEY_BYTES = 32  # AES-256
    _NONCE_BYTES = 12  # GCM standard nonce size

    def __init__(self, master_key: bytes | None = None) -> None:
        if master_key is not None and len(master_key) != self._KEY_BYTES:
            raise ValueError(
                f"Master key must be exactly {self._KEY_BYTES} bytes, "
                f"got {len(master_key)}"
            )
        self._master_key: bytes | None = master_key

    # -- Key management -----------------------------------------------------

    @staticmethod
    def generate_master_key() -> bytes:
        """Generate a 256-bit master key."""
        return secrets.token_bytes(32)

    def generate_dek(self) -> tuple[bytes, str]:
        """Generate a fresh DEK and return ``(plaintext_dek, wrapped_dek_b64)``.

        The wrapped DEK is encrypted with the master key using AES-256-GCM.
        If Vault Transit is available in the future, this method can be
        extended to delegate wrapping to Vault via
        ``VaultClient.generate_data_key()``.
        """
        if self._master_key is None:
            raise RuntimeError(
                "Cannot generate DEK: no master key configured. "
                "Supply a master key or configure Vault Transit."
            )
        plaintext_dek = secrets.token_bytes(self._KEY_BYTES)
        nonce = secrets.token_bytes(self._NONCE_BYTES)

        # Wrap the DEK with the master key (AES-256-GCM, mirroring the
        # Vault Transit wrapping concept from k3s-istio-vault-platform).
        wrapped_ct = _aes_gcm_encrypt(
            self._master_key, nonce, plaintext_dek, b"dek-wrap"
        )
        # Encode nonce + ciphertext together for storage.
        wrapped_blob = nonce + wrapped_ct
        wrapped_b64 = base64.b64encode(wrapped_blob).decode()
        return plaintext_dek, wrapped_b64

    def _unwrap_dek(self, wrapped_dek_b64: str) -> bytes:
        """Unwrap a DEK using the master key."""
        if self._master_key is None:
            raise RuntimeError("Cannot unwrap DEK: no master key configured.")
        blob = base64.b64decode(wrapped_dek_b64)
        nonce = blob[: self._NONCE_BYTES]
        wrapped_ct = blob[self._NONCE_BYTES :]
        return _aes_gcm_decrypt(self._master_key, nonce, wrapped_ct, b"dek-wrap")

    # -- Encrypt / Decrypt --------------------------------------------------

    def encrypt(self, plaintext: str | bytes, aad: str = "") -> EncryptedBundle:
        """Encrypt plaintext with a fresh per-write DEK.

        Following k3s-istio-vault-platform pattern:

        1. Generate fresh DEK via ``generate_dek()``
        2. Generate random 12-byte nonce
        3. AES-256-GCM encrypt with nonce and AAD
        4. Zero plaintext DEK
        5. Return bundle with ciphertext + wrapped DEK + nonce
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()

        # Step 1: fresh DEK
        dek_bytes, wrapped_dek_b64 = self.generate_dek()
        dek = bytearray(dek_bytes)

        try:
            # Step 2: random nonce
            nonce = secrets.token_bytes(self._NONCE_BYTES)

            # Step 3: AES-256-GCM encrypt
            aad_bytes = aad.encode() if aad else b""
            ct = _aes_gcm_encrypt(bytes(dek), nonce, plaintext, aad_bytes)

            # Step 5: build bundle
            return EncryptedBundle(
                ciphertext=base64.b64encode(ct).decode(),
                nonce=base64.b64encode(nonce).decode(),
                wrapped_dek=wrapped_dek_b64,
                aad=aad,
                key_version=1,
            )
        finally:
            # Step 4: zero the plaintext DEK
            self.zero_key(dek)

    def decrypt(self, bundle: EncryptedBundle) -> bytes:
        """Decrypt an encrypted bundle.

        1. Unwrap DEK using master key
        2. AES-256-GCM decrypt with nonce and AAD
        3. Zero DEK
        4. Return plaintext
        """
        # Step 1: unwrap DEK
        dek_bytes = self._unwrap_dek(bundle.wrapped_dek)
        dek = bytearray(dek_bytes)

        try:
            # Step 2: decrypt
            ct = base64.b64decode(bundle.ciphertext)
            nonce = base64.b64decode(bundle.nonce)
            aad_bytes = bundle.aad.encode() if bundle.aad else b""
            return _aes_gcm_decrypt(bytes(dek), nonce, ct, aad_bytes)
        finally:
            # Step 3: zero the DEK
            self.zero_key(dek)

    # -- Canonical AAD ------------------------------------------------------

    @staticmethod
    def build_canonical_aad(
        tenant: str,
        environment: str,
        app: str,
        name: str,
        version: int = 1,
    ) -> str:
        """Build canonical AAD string from components.

        Follows k3s-istio-vault-platform pattern: JSON-encoded dict of
        ``{tenant, environment, app, name, version}`` with keys in a
        deterministic order (guaranteed by ``json.dumps(sort_keys=True)``).
        """
        aad_dict = {
            "app": app,
            "environment": environment,
            "name": name,
            "tenant": tenant,
            "version": version,
        }
        return json.dumps(aad_dict, sort_keys=True, separators=(",", ":"))

    # -- Key zeroing --------------------------------------------------------

    @staticmethod
    def zero_key(key: bytearray) -> None:
        """Zero out a key in memory (security pattern from k3s-istio-vault-platform)."""
        for i in range(len(key)):
            key[i] = 0


# ---------------------------------------------------------------------------
# High-level helpers for flag encryption / decryption
# ---------------------------------------------------------------------------


def encrypt_flag_content(
    flag_value: str,
    config: EncryptionConfig,
    host: str,
    path: str,
) -> tuple[str, dict]:
    """Encrypt a flag value for deployment into a range.

    Returns ``(encrypted_file_content, dek_metadata_dict)``.
    The ``dek_metadata_dict`` should be written to ``config.dek_storage_path``
    inside the range so that Red agents can discover and use it.

    Args:
        flag_value: The plaintext flag string (e.g. ``FLAG{...}``).
        config: Encryption configuration for the range.
        host: Host where the flag resides (used in AAD).
        path: File path where the flag will be stored (used in AAD).

    Returns:
        A tuple of ``(base64_bundle_json, dek_metadata)``.  The first element
        is a JSON string containing the :class:`EncryptedBundle`; the second
        is a dict suitable for persisting alongside (or inside) the wrapped
        DEK file.
    """
    master_key = _resolve_master_key(config)
    crypto = EnvelopeCrypto(master_key)

    aad = EnvelopeCrypto.build_canonical_aad(
        tenant="openrange",
        environment="range",
        app=host,
        name=path,
        version=1,
    )

    bundle = crypto.encrypt(flag_value, aad=aad)

    # The encrypted file content is the JSON-serialised bundle.
    encrypted_content = bundle.model_dump_json()

    # Metadata dict for the DEK storage file.
    dek_metadata: dict[str, Any] = {
        "wrapped_dek": bundle.wrapped_dek,
        "aad": bundle.aad,
        "key_version": bundle.key_version,
        "host": host,
        "path": path,
        "dek_storage_path": config.dek_storage_path,
    }
    return encrypted_content, dek_metadata


def decrypt_flag_content(
    encrypted_content: str,
    dek_metadata: dict,
    master_key: bytes,
) -> str:
    """Decrypt a flag value.  Used by validators to verify flags.

    Args:
        encrypted_content: JSON string produced by :func:`encrypt_flag_content`.
        dek_metadata: The metadata dict written alongside the wrapped DEK.
        master_key: The 256-bit master key bytes.

    Returns:
        The original plaintext flag string.
    """
    bundle = EncryptedBundle.model_validate_json(encrypted_content)
    crypto = EnvelopeCrypto(master_key)
    plaintext_bytes = crypto.decrypt(bundle)
    return plaintext_bytes.decode()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_master_key(config: EncryptionConfig) -> bytes:
    """Resolve the master key from the configured source."""
    if config.master_key_source == "env_var":
        raw = os.environ.get(config.master_key_env_var, "")
        if not raw:
            raise RuntimeError(
                f"Envelope encryption enabled but master key env var "
                f"'{config.master_key_env_var}' is not set."
            )
        # Accept either raw base64 or hex-encoded keys.
        try:
            key = base64.b64decode(raw)
            if len(key) == 32:
                return key
        except Exception:
            pass
        try:
            key = bytes.fromhex(raw)
            if len(key) == 32:
                return key
        except Exception:
            pass
        raise RuntimeError(
            f"Master key in '{config.master_key_env_var}' must be 32 bytes "
            f"encoded as base64 or hex."
        )

    if config.master_key_source == "vault_transit":
        # Vault Transit mode delegates key management to Vault entirely.
        # The VaultClient.generate_data_key() handles DEK generation and
        # wrapping, so we do not need a local master key.  For now, raise
        # NotImplementedError; the integration point is in
        # EnvelopeCrypto.generate_dek().
        raise NotImplementedError(
            "Vault Transit master key source is not yet wired. "
            "Use 'env_var' or integrate VaultClient.generate_data_key() directly."
        )

    raise ValueError(f"Unknown master_key_source: '{config.master_key_source}'")
