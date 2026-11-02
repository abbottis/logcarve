"""Effective settings boundary regressions (independent review F1/F2).

Pure offline tests with temporary databases and synthetic secrets: no
network, no provider account, no real keys. Each test pins one
corrected boundary: configured modes are never relabeled, unknown
providers are rejected (not replaced), stored-but-invalid keys never
fall back to env, the store failing closed keeps deterministic pages
alive, and key material never appears in repr/asdict.
"""

import dataclasses
from types import SimpleNamespace

import pytest
from pydantic import SecretStr

from app.ai import effective as ai_effective
from app.ai import gate, settings_store
from app.ai.gate import GateBlocked
from app.ai.providers.base import BackendUnavailable
from app.ai.service import select_provider
from app.db.database import writer_transaction
from app.db.migrations_runner import migrate

TEST_KEY_HEX = "33" * 32
ENV_SECRET = "synthetic-env-secret-never-a-real-key"


def _base(**overrides):
    fields = {
        "ai_enabled": True,
        "model_provider": "meta",
        "model_id": "muse-spark-1.3",
        "model_service_tier": "standard",
        "model_data_policy_verified": True,
        "model_allow_real_data": True,
        "model_api_key": "",
        "ai_settings_key": None,
        "model_endpoint": "",
        "ai_synthetic_source": False,
        "anthropic_workspace_id": "",
    }
    fields.update(overrides)
    return SimpleNamespace(**fields)


def _db_with(tmp_path, pairs, name="effective.sqlite3"):
    db = tmp_path / name
    migrate(db)
    with writer_transaction(db) as conn:
        for key, value in pairs:
            settings_store.set_setting(conn, key, value)
    return db


def _stored_blob(provider, plaintext):
    key = settings_store.require_settings_key(TEST_KEY_HEX)
    return settings_store.encrypt_provider_key(provider, plaintext, key=key)


def test_contributor_mode_preserved_and_blocked(tmp_path, monkeypatch):
    # Exact reported boundary: configured Contributor handling with a
    # verified policy must NOT resolve to tier "standard" and pass.
    monkeypatch.setenv("AI_SETTINGS_KEY", TEST_KEY_HEX)
    db = _db_with(tmp_path, [])
    base = _base(model_service_tier="contributor")
    resolved = ai_effective.resolve(db, base)
    assert resolved.model_service_tier == "contributor"
    with pytest.raises(GateBlocked):
        gate.validate_for_real_data(resolved)


def test_unknown_persisted_provider_rejected_not_replaced(tmp_path, monkeypatch):
    # A stored unknown provider is kept verbatim so the gate rejects
    # it; it is never silently replaced with the env Meta default.
    monkeypatch.setenv("AI_SETTINGS_KEY", TEST_KEY_HEX)
    db = _db_with(tmp_path, [("ai.provider", "nope"), ("ai.model", "gpt-6.1-terra")])
    resolved = ai_effective.resolve(db, _base())
    assert resolved.model_provider == "nope"
    with pytest.raises(GateBlocked) as exc:
        gate.validate_for_real_data(resolved)
    assert exc.value.code == "unknown_provider"
    with pytest.raises(BackendUnavailable):
        select_provider(resolved)


def test_tampered_stored_key_never_falls_back_to_env(tmp_path, monkeypatch):
    # Stored tampered row plus a valid env key: the stored row is
    # authoritative, so resolution fails closed instead of dispatching
    # with the env fallback.
    monkeypatch.setenv("AI_SETTINGS_KEY", TEST_KEY_HEX)
    blob = _stored_blob("meta", "synthetic-stored-secret")
    db = _db_with(tmp_path, [("ai.key.meta", blob)])
    with writer_transaction(db) as conn:
        conn.execute(
            "UPDATE admin_settings SET value = ? WHERE key = 'ai.key.meta'",
            ("tampered-not-base64!!!",),
        )
    resolved = ai_effective.resolve(db, _base(model_api_key=ENV_SECRET))
    assert resolved.ai_key_stored is True
    assert resolved.ai_key_error is True
    assert resolved.ai_key_source == "missing"
    assert resolved.model_api_key.get_secret_value() == ""
    with pytest.raises(BackendUnavailable):
        select_provider(resolved)


def test_empty_corrupt_row_fails_closed(tmp_path, monkeypatch):
    # An empty stored row counts as an existing-but-invalid row: no
    # silent env fallback either.
    monkeypatch.setenv("AI_SETTINGS_KEY", TEST_KEY_HEX)
    db = _db_with(tmp_path, [("ai.key.meta", "")])
    resolved = ai_effective.resolve(db, _base(model_api_key=ENV_SECRET))
    assert resolved.ai_key_stored is True
    assert resolved.ai_key_error is True
    with pytest.raises(BackendUnavailable):
        select_provider(resolved)


def test_env_fallback_only_for_genuinely_absent_row(tmp_path, monkeypatch):
    # No stored row at all: the operator env fallback still applies.
    monkeypatch.setenv("AI_SETTINGS_KEY", TEST_KEY_HEX)
    db = _db_with(tmp_path, [])
    resolved = ai_effective.resolve(db, _base(model_api_key=ENV_SECRET))
    assert resolved.ai_key_stored is False
    assert resolved.ai_key_error is False
    assert resolved.ai_key_source == "env"
    assert resolved.model_api_key.get_secret_value() == ENV_SECRET


def test_base_settings_key_used_for_decrypt(tmp_path, monkeypatch):
    # Decryption resolves through base.ai_settings_key consistently,
    # not only os.environ: with no env var but a valid base key the
    # stored row decrypts; with a wrong base key it fails closed.
    monkeypatch.delenv("AI_SETTINGS_KEY", raising=False)
    blob = _stored_blob("openai", "synthetic-openai-stored")
    db = _db_with(
        tmp_path,
        [
            ("ai.provider", "openai"),
            ("ai.model", "gpt-6.1-terra"),
            ("ai.key.openai", blob),
            ("ai.policy.openai", "synthetic"),
        ],
    )
    good = ai_effective.resolve(
        db,
        _base(
            model_provider="openai",
            model_id="gpt-6.1-terra",
            ai_settings_key=SecretStr(TEST_KEY_HEX),
            ai_synthetic_source=True,
        ),
    )
    assert good.ai_key_source == "stored"
    assert good.model_api_key.get_secret_value() == "synthetic-openai-stored"
    bad = ai_effective.resolve(
        db,
        _base(
            model_provider="openai",
            model_id="gpt-6.1-terra",
            ai_settings_key=SecretStr("44" * 32),
            ai_synthetic_source=True,
        ),
    )
    assert bad.ai_key_error is True
    with pytest.raises(BackendUnavailable):
        select_provider(bad)


def test_repr_and_asdict_never_carry_plaintext(tmp_path, monkeypatch):
    # EffectiveAISettings holds the secret repr-safe: the generated
    # repr, str and asdict never expose the plaintext key.
    monkeypatch.setenv("AI_SETTINGS_KEY", TEST_KEY_HEX)
    db = _db_with(tmp_path, [])
    resolved = ai_effective.resolve(db, _base(model_api_key=ENV_SECRET))
    assert resolved.ai_key_source == "env"
    assert ENV_SECRET not in repr(resolved)
    assert ENV_SECRET not in str(resolved)
    flat = dataclasses.asdict(resolved)
    assert ENV_SECRET not in repr(flat)
    for value in flat.values():
        assert value != ENV_SECRET


def test_binding_pins_tier_endpoint_and_workspace(tmp_path, monkeypatch):
    # The pinned binding covers mode/workspace/endpoint, not just
    # provider/model/key/policy/enable.
    monkeypatch.setenv("AI_SETTINGS_KEY", TEST_KEY_HEX)
    db = _db_with(tmp_path, [])
    first = ai_effective.resolve(db, _base())
    for field, value in (
        ("model_service_tier", "paid"),
        ("model_endpoint", "https://api.meta.ai:443/v1/other-responses"),
        ("workspace_id", "wrkspc_abc123"),
    ):
        changed = dataclasses.replace(first, **{field: value})
        assert ai_effective.binding_of(first) != ai_effective.binding_of(changed)


def test_corrupt_store_fails_ai_closed_without_exception(tmp_path, monkeypatch):
    # A corrupt store file resolves to a disabled value (fixed code),
    # never an exception: deterministic analytics stay online.
    monkeypatch.setenv("AI_SETTINGS_KEY", TEST_KEY_HEX)
    db = tmp_path / "corrupt.sqlite3"
    db.write_bytes(b"not-a-sqlite-database")
    resolved = ai_effective.resolve(db, _base())
    assert resolved.ai_enabled is False
    assert resolved.ai_store_error == "settings_unavailable"
    with pytest.raises(GateBlocked) as exc:
        gate.validate_for_real_data(resolved)
    assert exc.value.code == "settings_unavailable"
    with pytest.raises(BackendUnavailable):
        select_provider(resolved)


def test_missing_store_file_fails_ai_closed(tmp_path, monkeypatch):
    # A missing/deleted store file cannot prove no overlay ever
    # existed: it fails closed instead of resurrecting the env base.
    monkeypatch.setenv("AI_SETTINGS_KEY", TEST_KEY_HEX)
    db = tmp_path / "missing.sqlite3"
    assert not db.exists()
    resolved = ai_effective.resolve(db, _base(model_api_key=ENV_SECRET))
    assert resolved.ai_enabled is False
    assert resolved.ai_store_error == "settings_unavailable"
    assert resolved.model_data_policy_verified is False
    assert resolved.model_allow_real_data is False
    assert ENV_SECRET not in repr(resolved)
    with pytest.raises(GateBlocked) as exc:
        gate.validate_for_real_data(resolved)
    assert exc.value.code == "settings_unavailable"
    with pytest.raises(BackendUnavailable):
        select_provider(resolved)


def test_store_without_settings_table_fails_closed(tmp_path, monkeypatch):
    # A store without the settings table cannot prove no overlay ever
    # existed either: missing table fails closed, never empty.
    import sqlite3

    monkeypatch.setenv("AI_SETTINGS_KEY", TEST_KEY_HEX)
    db = tmp_path / "notable.sqlite3"
    conn = sqlite3.connect(str(db))
    try:
        conn.execute("CREATE TABLE other (id INTEGER PRIMARY KEY)")
        conn.commit()
    finally:
        conn.close()
    resolved = ai_effective.resolve(db, _base(model_api_key=ENV_SECRET))
    assert resolved.ai_enabled is False
    assert resolved.ai_store_error == "settings_unavailable"
    with pytest.raises(GateBlocked) as exc:
        gate.validate_for_real_data(resolved)
    assert exc.value.code == "settings_unavailable"
    with pytest.raises(BackendUnavailable):
        select_provider(resolved)


def test_invalid_policy_row_blocks_legacy_env_resurrection(tmp_path, monkeypatch):
    # An invalid persisted policy value must fail AI closed, never
    # normalize away to re-enable the legacy Meta env permission.
    monkeypatch.setenv("AI_SETTINGS_KEY", TEST_KEY_HEX)
    for bad in ("unexpected-value", "REAL", "sometimes", "1"):
        db = _db_with(tmp_path, [("ai.policy.meta", bad)], name=f"policy-{bad}.sqlite3")
        resolved = ai_effective.resolve(db, _base(model_api_key=ENV_SECRET))
        assert resolved.ai_policy == ""
        assert resolved.model_data_policy_verified is False
        assert resolved.model_allow_real_data is False
        with pytest.raises(BackendUnavailable):
            select_provider(resolved)


def test_present_but_empty_policy_is_unacknowledged_not_legacy(tmp_path, monkeypatch):
    # A present-but-empty policy row (cleared/revoked acknowledgment)
    # is explicit UNACKNOWLEDGED: the permissive legacy Meta env
    # flags must not resurrect a real adapter from it.
    monkeypatch.setenv("AI_SETTINGS_KEY", TEST_KEY_HEX)
    db = _db_with(tmp_path, [("ai.policy.meta", "")])
    resolved = ai_effective.resolve(db, _base(model_api_key=ENV_SECRET))
    assert resolved.ai_policy == ""
    assert resolved.synthetic_only is False
    assert resolved.model_data_policy_verified is False
    assert resolved.model_allow_real_data is False
    with pytest.raises(BackendUnavailable):
        select_provider(resolved)


def test_empty_provider_and_model_rows_fail_closed(tmp_path, monkeypatch):
    # Persisted-but-empty provider/model rows are corrupt config, not
    # absent config: they fail closed instead of falling back to the
    # env base pair.
    monkeypatch.setenv("AI_SETTINGS_KEY", TEST_KEY_HEX)
    db = _db_with(tmp_path, [("ai.provider", ""), ("ai.model", "muse-spark-1.3")])
    resolved = ai_effective.resolve(db, _base(model_api_key=ENV_SECRET))
    assert resolved.model_provider == ""
    with pytest.raises(GateBlocked) as exc:
        gate.validate_for_real_data(resolved)
    assert exc.value.code == "unknown_provider"
    with pytest.raises(BackendUnavailable):
        select_provider(resolved)
    db = _db_with(
        tmp_path,
        [("ai.provider", "meta"), ("ai.model", "")],
        name="empty-model.sqlite3",
    )
    resolved = ai_effective.resolve(db, _base(model_api_key=ENV_SECRET))
    assert resolved.model_id == ""
    with pytest.raises(GateBlocked) as exc:
        gate.validate_for_real_data(resolved)
    assert exc.value.code == "unapproved_model"
    with pytest.raises(BackendUnavailable):
        select_provider(resolved)


def test_cleared_ack_tombstone_blocks_permissive_legacy_env(tmp_path, monkeypatch):
    # A user clear/revocation persists the explicit unacknowledged
    # tombstone: with permissive legacy Meta env flags set, the
    # cleared row must still fail AI closed.
    monkeypatch.setenv("AI_SETTINGS_KEY", TEST_KEY_HEX)
    db = _db_with(
        tmp_path,
        [
            ("ai.enabled", "1"),
            ("ai.provider", "meta"),
            ("ai.model", "muse-spark-1.3"),
            ("ai.policy.meta", ""),
            ("ai.synthetic_source", "0"),
        ],
    )
    resolved = ai_effective.resolve(
        db,
        _base(
            model_api_key=ENV_SECRET,
            model_data_policy_verified=True,
            model_allow_real_data=True,
        ),
    )
    assert resolved.ai_enabled is True
    assert resolved.ai_policy == ""
    assert resolved.model_data_policy_verified is False
    assert resolved.model_allow_real_data is False
    with pytest.raises(BackendUnavailable):
        select_provider(resolved)


def test_never_saved_meta_env_still_applies_legacy_permission(tmp_path, monkeypatch):
    # The backwards-compatible demo path is preserved: a genuinely
    # never-managed store (readable table, no ai.* rows) still honors
    # the operator Meta env flags.
    monkeypatch.setenv("AI_SETTINGS_KEY", TEST_KEY_HEX)
    db = _db_with(tmp_path, [])
    resolved = ai_effective.resolve(
        db,
        _base(
            model_api_key=ENV_SECRET,
            model_data_policy_verified=True,
            model_allow_real_data=True,
        ),
    )
    assert resolved.ai_store_error == ""
    assert resolved.model_data_policy_verified is True
    assert resolved.model_allow_real_data is True


def test_store_lost_after_initial_resolution_fails_closed(tmp_path, monkeypatch):
    # Mid-investigation store loss (the settings_loader re-resolution
    # path): the live settings fail closed and differ from the pinned
    # binding, so the run stops instead of dispatching on stale env.
    monkeypatch.setenv("AI_SETTINGS_KEY", TEST_KEY_HEX)
    db = _db_with(tmp_path, [])
    base = _base(
        model_api_key=ENV_SECRET,
        model_data_policy_verified=True,
        model_allow_real_data=True,
    )
    first = ai_effective.resolve(db, base)
    assert first.ai_store_error == ""
    assert first.model_allow_real_data is True
    db.unlink()
    live = ai_effective.resolve(db, base)
    assert live.ai_store_error == "settings_unavailable"
    assert live.model_allow_real_data is False
    assert ai_effective.binding_of(first) != ai_effective.binding_of(live)
    with pytest.raises(GateBlocked) as exc:
        gate.validate_for_real_data(live)
    assert exc.value.code == "settings_unavailable"
    with pytest.raises(BackendUnavailable):
        select_provider(live)
