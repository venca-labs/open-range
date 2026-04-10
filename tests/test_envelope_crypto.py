"""Tests for the envelope encryption module (Idea 3).

Covers:
- Encrypt / decrypt roundtrip
- Different AAD produces different ciphertext
- Tampered ciphertext is rejected
- zero_key clears a bytearray
- EncryptionConfig model validation
- Canonical AAD building
- High-level encrypt_flag_content / decrypt_flag_content helpers
- EncryptionEnforcementCheck validator
"""

from __future__ import annotations

import base64
import json
import os

import pytest

pytest.importorskip("cryptography", reason="cryptography not installed")

from open_range.envelope_crypto import (
    EncryptedBundle,
    EncryptionConfig,
    EnvelopeCrypto,
    decrypt_flag_content,
    encrypt_flag_content,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def master_key() -> bytes:
    """A deterministic 256-bit master key for reproducible tests."""
    return EnvelopeCrypto.generate_master_key()


@pytest.fixture
def crypto(master_key: bytes) -> EnvelopeCrypto:
    return EnvelopeCrypto(master_key)


# ---------------------------------------------------------------------------
# EnvelopeCrypto core
# ---------------------------------------------------------------------------


class TestGenerateMasterKey:
    def test_length(self):
        key = EnvelopeCrypto.generate_master_key()
        assert len(key) == 32

    def test_uniqueness(self):
        k1 = EnvelopeCrypto.generate_master_key()
        k2 = EnvelopeCrypto.generate_master_key()
        assert k1 != k2


class TestGenerateDEK:
    def test_returns_dek_and_wrapped(self, crypto: EnvelopeCrypto):
        dek, wrapped_b64 = crypto.generate_dek()
        assert len(dek) == 32
        assert isinstance(wrapped_b64, str)
        # Wrapped DEK should be valid base64.
        decoded = base64.b64decode(wrapped_b64)
        # At least nonce (12) + ciphertext (32) + GCM tag (16) = 60 bytes
        assert len(decoded) >= 60

    def test_each_dek_is_unique(self, crypto: EnvelopeCrypto):
        dek1, _ = crypto.generate_dek()
        dek2, _ = crypto.generate_dek()
        assert dek1 != dek2

    def test_no_master_key_raises(self):
        c = EnvelopeCrypto(master_key=None)
        with pytest.raises(RuntimeError, match="no master key"):
            c.generate_dek()


class TestEncryptDecryptRoundtrip:
    def test_string_roundtrip(self, crypto: EnvelopeCrypto):
        plaintext = "FLAG{envelope_encryption_works_42}"
        bundle = crypto.encrypt(plaintext)
        recovered = crypto.decrypt(bundle)
        assert recovered == plaintext.encode()

    def test_bytes_roundtrip(self, crypto: EnvelopeCrypto):
        plaintext = b"\x00\x01\x02binary\xfe\xff"
        bundle = crypto.encrypt(plaintext)
        recovered = crypto.decrypt(bundle)
        assert recovered == plaintext

    def test_empty_plaintext(self, crypto: EnvelopeCrypto):
        bundle = crypto.encrypt(b"")
        assert crypto.decrypt(bundle) == b""

    def test_large_plaintext(self, crypto: EnvelopeCrypto):
        plaintext = b"A" * 1_000_000
        bundle = crypto.encrypt(plaintext)
        assert crypto.decrypt(bundle) == plaintext

    def test_with_aad(self, crypto: EnvelopeCrypto):
        aad = EnvelopeCrypto.build_canonical_aad(
            tenant="test", environment="dev", app="web", name="flag1"
        )
        bundle = crypto.encrypt("secret", aad=aad)
        assert bundle.aad == aad
        assert crypto.decrypt(bundle) == b"secret"


class TestDifferentAAD:
    def test_different_aad_different_ciphertext(self, crypto: EnvelopeCrypto):
        plaintext = "same_data"
        aad1 = EnvelopeCrypto.build_canonical_aad("t", "e", "a", "n1")
        aad2 = EnvelopeCrypto.build_canonical_aad("t", "e", "a", "n2")

        b1 = crypto.encrypt(plaintext, aad=aad1)
        b2 = crypto.encrypt(plaintext, aad=aad2)

        # Ciphertexts differ (different DEK + nonce + AAD).
        assert b1.ciphertext != b2.ciphertext

    def test_wrong_aad_fails_decrypt(self, crypto: EnvelopeCrypto):
        aad_correct = EnvelopeCrypto.build_canonical_aad("t", "e", "a", "n1")
        bundle = crypto.encrypt("secret", aad=aad_correct)

        # Tamper with the AAD in the bundle.
        wrong_aad = EnvelopeCrypto.build_canonical_aad("t", "e", "a", "WRONG")
        tampered = bundle.model_copy(update={"aad": wrong_aad})

        with pytest.raises(Exception):
            crypto.decrypt(tampered)


class TestTamperedCiphertext:
    def test_bit_flip_detected(self, crypto: EnvelopeCrypto):
        bundle = crypto.encrypt("FLAG{tamper_me}")
        ct_bytes = bytearray(base64.b64decode(bundle.ciphertext))
        # Flip a bit in the middle of the ciphertext.
        ct_bytes[len(ct_bytes) // 2] ^= 0xFF
        tampered = bundle.model_copy(
            update={"ciphertext": base64.b64encode(bytes(ct_bytes)).decode()}
        )
        with pytest.raises(Exception):
            crypto.decrypt(tampered)

    def test_truncated_ciphertext_fails(self, crypto: EnvelopeCrypto):
        bundle = crypto.encrypt("FLAG{truncate}")
        ct_bytes = base64.b64decode(bundle.ciphertext)
        truncated = bundle.model_copy(
            update={"ciphertext": base64.b64encode(ct_bytes[:8]).decode()}
        )
        with pytest.raises(Exception):
            crypto.decrypt(truncated)

    def test_wrong_master_key_fails(self, master_key: bytes):
        crypto1 = EnvelopeCrypto(master_key)
        bundle = crypto1.encrypt("FLAG{wrong_key}")

        other_key = EnvelopeCrypto.generate_master_key()
        crypto2 = EnvelopeCrypto(other_key)
        with pytest.raises(Exception):
            crypto2.decrypt(bundle)


class TestZeroKey:
    def test_zeroes_bytearray(self):
        key = bytearray(b"\xab" * 32)
        EnvelopeCrypto.zero_key(key)
        assert key == bytearray(32)

    def test_empty_bytearray(self):
        key = bytearray()
        EnvelopeCrypto.zero_key(key)
        assert key == bytearray()

    def test_single_byte(self):
        key = bytearray(b"\xff")
        EnvelopeCrypto.zero_key(key)
        assert key == bytearray(1)


# ---------------------------------------------------------------------------
# Canonical AAD
# ---------------------------------------------------------------------------


class TestCanonicalAAD:
    def test_structure(self):
        aad = EnvelopeCrypto.build_canonical_aad(
            tenant="acme", environment="prod", app="web", name="db_password", version=3
        )
        parsed = json.loads(aad)
        assert parsed == {
            "app": "web",
            "environment": "prod",
            "name": "db_password",
            "tenant": "acme",
            "version": 3,
        }

    def test_default_version(self):
        aad = EnvelopeCrypto.build_canonical_aad("t", "e", "a", "n")
        parsed = json.loads(aad)
        assert parsed["version"] == 1

    def test_deterministic(self):
        """Same inputs always produce the same AAD string."""
        a1 = EnvelopeCrypto.build_canonical_aad("t", "e", "a", "n", 1)
        a2 = EnvelopeCrypto.build_canonical_aad("t", "e", "a", "n", 1)
        assert a1 == a2

    def test_compact_json(self):
        """AAD uses compact separators (no spaces)."""
        aad = EnvelopeCrypto.build_canonical_aad("t", "e", "a", "n")
        assert " " not in aad


# ---------------------------------------------------------------------------
# EncryptionConfig model
# ---------------------------------------------------------------------------


class TestEncryptionConfig:
    def test_defaults(self):
        cfg = EncryptionConfig()
        assert cfg.enabled is False
        assert cfg.encrypted_paths == []
        assert cfg.master_key_source == "env_var"
        assert cfg.master_key_env_var == "OPENRANGE_MASTER_KEY"
        assert cfg.dek_storage_path == "/etc/openrange/wrapped_dek.json"

    def test_custom_values(self):
        cfg = EncryptionConfig(
            enabled=True,
            encrypted_paths=["files:/srv/flag.txt", "db:flags.secrets.value"],
            master_key_source="vault_transit",
            dek_storage_path="/tmp/dek.json",
        )
        assert cfg.enabled is True
        assert len(cfg.encrypted_paths) == 2
        assert cfg.master_key_source == "vault_transit"

    def test_json_roundtrip(self):
        cfg = EncryptionConfig(
            enabled=True,
            encrypted_paths=["files:/data/secret.bin"],
        )
        js = cfg.model_dump_json()
        cfg2 = EncryptionConfig.model_validate_json(js)
        assert cfg2.enabled is True
        assert cfg2.encrypted_paths == ["files:/data/secret.bin"]


# ---------------------------------------------------------------------------
# EncryptedBundle model
# ---------------------------------------------------------------------------


class TestEncryptedBundle:
    def test_from_dict(self):
        b = EncryptedBundle(
            ciphertext="AAAA",
            nonce="BBBB",
            wrapped_dek="CCCC",
            aad="{}",
            key_version=2,
        )
        assert b.key_version == 2

    def test_json_roundtrip(self, crypto: EnvelopeCrypto):
        bundle = crypto.encrypt("FLAG{bundle_test}")
        js = bundle.model_dump_json()
        bundle2 = EncryptedBundle.model_validate_json(js)
        assert crypto.decrypt(bundle2) == b"FLAG{bundle_test}"


# ---------------------------------------------------------------------------
# High-level flag helpers
# ---------------------------------------------------------------------------


class TestFlagHelpers:
    def test_encrypt_decrypt_flag(self, master_key: bytes):
        b64_key = base64.b64encode(master_key).decode()
        os.environ["OPENRANGE_MASTER_KEY"] = b64_key
        try:
            config = EncryptionConfig(
                enabled=True,
                encrypted_paths=["files:/var/flags/flag1.txt"],
            )
            encrypted, metadata = encrypt_flag_content(
                "FLAG{helpers_work}",
                config,
                host="db",
                path="/var/flags/flag1.txt",
            )

            # encrypted should be valid JSON.
            parsed = json.loads(encrypted)
            assert "ciphertext" in parsed
            assert "wrapped_dek" in parsed

            # metadata should contain routing info.
            assert metadata["host"] == "db"
            assert metadata["path"] == "/var/flags/flag1.txt"
            assert "wrapped_dek" in metadata

            # Roundtrip.
            recovered = decrypt_flag_content(encrypted, metadata, master_key)
            assert recovered == "FLAG{helpers_work}"
        finally:
            os.environ.pop("OPENRANGE_MASTER_KEY", None)

    def test_missing_env_var_raises(self):
        os.environ.pop("OPENRANGE_MASTER_KEY", None)
        config = EncryptionConfig(enabled=True)
        with pytest.raises(RuntimeError, match="not set"):
            encrypt_flag_content("FLAG{fail}", config, host="h", path="/p")

    def test_hex_encoded_master_key(self, master_key: bytes):
        hex_key = master_key.hex()
        os.environ["OPENRANGE_MASTER_KEY"] = hex_key
        try:
            config = EncryptionConfig(enabled=True)
            encrypted, _ = encrypt_flag_content(
                "FLAG{hex_key}", config, host="h", path="/p"
            )
            recovered = decrypt_flag_content(encrypted, {}, master_key)
            assert recovered == "FLAG{hex_key}"
        finally:
            os.environ.pop("OPENRANGE_MASTER_KEY", None)


# ---------------------------------------------------------------------------
# EnvelopeCrypto edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_invalid_master_key_length(self):
        with pytest.raises(ValueError, match="32 bytes"):
            EnvelopeCrypto(master_key=b"tooshort")

    def test_unicode_plaintext(self, crypto: EnvelopeCrypto):
        text = "FLAG{unicode_\u2603_\U0001f512}"
        bundle = crypto.encrypt(text)
        assert crypto.decrypt(bundle) == text.encode()

    def test_per_write_dek_isolation(self, crypto: EnvelopeCrypto):
        """Each encrypt() call uses a different DEK (different wrapped_dek)."""
        b1 = crypto.encrypt("same")
        b2 = crypto.encrypt("same")
        assert b1.wrapped_dek != b2.wrapped_dek
        assert b1.nonce != b2.nonce


# ---------------------------------------------------------------------------
# Encryption enforcement check (v1 CheckFunc pattern)
# ---------------------------------------------------------------------------


def test_enforcement_no_config_passes(tmp_path):
    """No security/encryption dir → vacuously passes."""
    from open_range.encryption_enforcement import check_encryption_enforcement
    from open_range.snapshot import KindArtifacts

    artifacts = KindArtifacts(
        render_dir=str(tmp_path),
        chart_dir=str(tmp_path / "chart"),
        values_path=str(tmp_path / "values.yaml"),
        kind_config_path=str(tmp_path / "kind-config.yaml"),
        manifest_summary_path=str(tmp_path / "summary.json"),
    )
    # WorldIR is not used by this check when no config exists
    result = check_encryption_enforcement(None, artifacts)  # type: ignore[arg-type]
    assert result.passed is True
    assert result.advisory is True


def test_enforcement_disabled_passes(tmp_path):
    from open_range.encryption_enforcement import check_encryption_enforcement
    from open_range.snapshot import KindArtifacts

    enc_dir = tmp_path / "security" / "encryption"
    enc_dir.mkdir(parents=True)
    (enc_dir / "config.json").write_text(json.dumps({"enabled": False}))

    artifacts = KindArtifacts(
        render_dir=str(tmp_path),
        chart_dir=str(tmp_path / "chart"),
        values_path=str(tmp_path / "values.yaml"),
        kind_config_path=str(tmp_path / "kind-config.yaml"),
        manifest_summary_path=str(tmp_path / "summary.json"),
    )
    result = check_encryption_enforcement(None, artifacts)  # type: ignore[arg-type]
    assert result.passed is True


def test_enforcement_missing_dek_file(tmp_path):
    from open_range.encryption_enforcement import check_encryption_enforcement
    from open_range.snapshot import KindArtifacts

    enc_dir = tmp_path / "security" / "encryption"
    enc_dir.mkdir(parents=True)
    (enc_dir / "config.json").write_text(
        json.dumps(
            {
                "enabled": True,
                "encrypted_paths": ["cred_admin"],
            }
        )
    )
    # No wrapped_dek.json → should flag it

    artifacts = KindArtifacts(
        render_dir=str(tmp_path),
        chart_dir=str(tmp_path / "chart"),
        values_path=str(tmp_path / "values.yaml"),
        kind_config_path=str(tmp_path / "kind-config.yaml"),
        manifest_summary_path=str(tmp_path / "summary.json"),
    )
    result = check_encryption_enforcement(None, artifacts)  # type: ignore[arg-type]
    assert result.passed is False


def test_enforcement_passes_with_valid_bundle(tmp_path):
    from open_range.encryption_enforcement import check_encryption_enforcement
    from open_range.snapshot import KindArtifacts

    mk = EnvelopeCrypto.generate_master_key()
    crypto_obj = EnvelopeCrypto(mk)
    bundle = crypto_obj.encrypt("FLAG{test_sqli_123}", aad="test")

    enc_dir = tmp_path / "security" / "encryption"
    enc_dir.mkdir(parents=True)
    (enc_dir / "config.json").write_text(
        json.dumps(
            {
                "enabled": True,
                "encrypted_paths": ["cred_admin"],
            }
        )
    )
    (enc_dir / "wrapped_dek.json").write_text(
        json.dumps(
            {
                "cred_admin": bundle.model_dump(),
            }
        )
    )

    artifacts = KindArtifacts(
        render_dir=str(tmp_path),
        chart_dir=str(tmp_path / "chart"),
        values_path=str(tmp_path / "values.yaml"),
        kind_config_path=str(tmp_path / "kind-config.yaml"),
        manifest_summary_path=str(tmp_path / "summary.json"),
    )
    result = check_encryption_enforcement(None, artifacts)  # type: ignore[arg-type]
    assert result.passed is True
