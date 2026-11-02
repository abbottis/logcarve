"""AI settings store unit tests: encryption, separation, policy, binding.

Pure offline tests with temporary databases and synthetic secrets:
no network, no provider account. No real keys anywhere.
"""

import base64

import pytest

from app.ai import settings_store
from app.ai.settings_store import SettingsStoreError
from app.db.migrations_runner import migrate

TEST_KEY_HEX = "11" * 32
TEST_KEY_B64 = base64.b64encode(bytes.fromhex(TEST_KEY_HEX)).decode("ascii")


@pytest.fixture
def key_env(monkeypatch):
    monkeypatch.setenv("AI_SETTINGS_KEY", TEST_KEY_HEX)
    for name in (
        "SESSION_SECRET",
        "HMAC_KEY",
        "ORIGINAL_IP_KEY",
        "MODEL_API_KEY",
        "META_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    return TEST_KEY_HEX


def test_key_parse_accepts_hex_and_base64(key_env):
    assert settings_store.parse_settings_key(TEST_KEY_HEX) == bytes.fromhex(TEST_KEY_HEX)
    assert settings_store.parse_settings_key(TEST_KEY_B64) == bytes.fromhex(TEST_KEY_HEX)
    with pytest.raises(SettingsStoreError):
        settings_store.parse_settings_key("")
    with pytest.raises(SettingsStoreError):
        settings_store.parse_settings_key("short")
    with pytest.raises(SettingsStoreError):
        settings_store.parse_settings_key(None)


def test_missing_key_fails_closed():
    with pytest.raises(SettingsStoreError) as exc:
        settings_store.require_settings_key(None)
    assert exc.value.code == "key_unavailable"


def test_encrypt_decrypt_roundtrip_per_provider(key_env):
    key = settings_store.require_settings_key()
    for provider in ("meta", "openai", "gemini", "anthropic"):
        blob = settings_store.encrypt_provider_key(provider, "synthetic-secret", key=key)
        assert "synthetic-secret" not in blob
        assert settings_store.decrypt_provider_key(provider, blob, key=key) == "synthetic-secret"


def test_associated_data_binds_ciphertext_to_provider(key_env):
    key = settings_store.require_settings_key()
    blob = settings_store.encrypt_provider_key("openai", "synthetic-secret", key=key)
    # Same blob under another provider fails closed: no cross-provider
    # credential reuse is possible.
    with pytest.raises(SettingsStoreError):
        settings_store.decrypt_provider_key("gemini", blob, key=key)
    tampered = base64.b64decode(blob.encode("ascii"))
    tampered = base64.b64encode(tampered[:-1] + bytes([tampered[-1] ^ 1])).decode("ascii")
    with pytest.raises(SettingsStoreError):
        settings_store.decrypt_provider_key("openai", tampered, key=key)


def test_wrong_settings_key_fails_closed(key_env):
    key = settings_store.require_settings_key()
    blob = settings_store.encrypt_provider_key("meta", "synthetic-secret", key=key)
    other = bytes(0x22 for _ in range(32))
    with pytest.raises(SettingsStoreError):
        settings_store.decrypt_provider_key("meta", blob, key=other)


def test_strict_key_separation(key_env, monkeypatch):
    # The settings key must never equal another server secret; such a
    # configuration fails closed instead of sharing key material.
    monkeypatch.setenv("MODEL_API_KEY", TEST_KEY_HEX)
    with pytest.raises(SettingsStoreError):
        settings_store.require_settings_key()


def test_strict_key_separation_covers_all_provider_keys(key_env, monkeypatch):
    # The exact reported boundary: AI_SETTINGS_KEY equal to any
    # product provider key (hex or base64 form) is rejected.
    key_b64 = base64.b64encode(bytes.fromhex(TEST_KEY_HEX)).decode("ascii")
    for name, value in (
        ("OPENAI_API_KEY", TEST_KEY_HEX),
        ("GEMINI_API_KEY", key_b64),
        ("ANTHROPIC_API_KEY", TEST_KEY_HEX),
        ("META_API_KEY", key_b64),
    ):
        monkeypatch.setenv(name, value)
        with pytest.raises(SettingsStoreError):
            settings_store.require_settings_key()
        monkeypatch.delenv(name, raising=False)
    # Unrelated short values are not parseable settings keys and stay
    # out of the comparison (no false rejection).
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-short-value")
    assert settings_store.require_settings_key() == bytes.fromhex(TEST_KEY_HEX)


def test_new_stored_plaintext_must_not_reuse_settings_key(key_env):
    key = settings_store.require_settings_key()
    # A new provider key that IS the settings key (hex or base64) is
    # rejected: no crypto fallback, fixed code, no echo.
    with pytest.raises(SettingsStoreError) as exc:
        settings_store.reject_settings_key_reuse(TEST_KEY_HEX, key=key)
    assert exc.value.code == "key_invalid"
    with pytest.raises(SettingsStoreError):
        settings_store.reject_settings_key_reuse(TEST_KEY_B64, key=key)
    # Ordinary provider credentials pass the separation check.
    settings_store.reject_settings_key_reuse("synthetic-openai-credential", key=key)
    settings_store.reject_settings_key_reuse("", key=key)


def test_key_fingerprint_is_stable_and_opaque():
    first = settings_store.key_fingerprint("synthetic-secret")
    assert first == settings_store.key_fingerprint("synthetic-secret")
    assert first != settings_store.key_fingerprint("synthetic-other")
    assert "synthetic-secret" not in first
    assert len(first) == 64


def test_provider_model_validation():
    settings_store.validate_provider_model("openai", "gpt-6.1-terra")
    settings_store.validate_provider_model("gemini", "gemini-3.8-flash")
    settings_store.validate_provider_model("anthropic", "claude-sonnet-5-5")
    settings_store.validate_provider_model("meta", "muse-spark-1.3")
    with pytest.raises(SettingsStoreError):
        settings_store.validate_provider_model("openai", "muse-spark-1.3")
    with pytest.raises(SettingsStoreError):
        settings_store.validate_provider_model("nope", "gpt-6.1-terra")
    assert settings_store.validate_policy("synthetic") == "synthetic"
    assert settings_store.validate_policy("real") == "real"
    with pytest.raises(SettingsStoreError):
        settings_store.validate_policy("free-tier")


def test_overlay_set_get_delete_roundtrip(tmp_path, key_env):
    from app.db.database import writer_transaction

    db = tmp_path / "settings.sqlite3"
    migrate(db)
    with writer_transaction(db) as conn:
        assert settings_store.get_setting(conn, "ai.provider") is None
        settings_store.set_setting(conn, "ai.provider", "openai")
        settings_store.set_setting(conn, "ai.key.openai", "blob-bytes-not-a-secret")
        assert settings_store.get_setting(conn, "ai.provider") == "openai"
        settings_store.delete_setting(conn, "ai.key.openai")
        assert settings_store.get_setting(conn, "ai.key.openai") is None


def test_require_key_uses_explicit_over_env(key_env, monkeypatch):
    explicit_hex = "33" * 32
    key = settings_store.require_settings_key(explicit_hex)
    assert key == bytes.fromhex(explicit_hex)
    monkeypatch.delenv("AI_SETTINGS_KEY")
    with pytest.raises(SettingsStoreError):
        settings_store.require_settings_key(None)


def test_env_isolation_for_key_material(monkeypatch):
    monkeypatch.delenv("AI_SETTINGS_KEY", raising=False)
    assert settings_store.load_settings_key() is None
