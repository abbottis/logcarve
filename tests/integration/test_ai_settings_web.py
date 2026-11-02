"""Backend AI settings web tests: auth, bounds, encryption, semantics.

Admin session + CSRF on all mutations; scoped analytics tokens can
neither read/manage settings nor invoke models. Synthetic fixtures
and secrets only; no network (blocked sockets where dispatch could
occur), no provider account, no real keys.
"""

from datetime import UTC, datetime

import pytest

from app.ai import effective as ai_effective
from app.db.database import writer_transaction

TEST_SETTINGS_KEY = "22" * 32


def _login(client):
    response = client.post(
        "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
    )
    assert response.status_code == 200
    return response.json()["csrf_token"]


def _post_ai(client, csrf, fields):
    body = dict(fields)
    body.setdefault("csrf_token", csrf)
    return client.post("/settings/ai", data=body, follow_redirects=False)


def _valid_fields(**overrides):
    fields = {
        "ai_enabled": "1",
        "ai_provider": "openai",
        "ai_model": "gpt-6.1-terra",
        "ai_policy": "synthetic",
        "ai_synthetic_source": "1",
        "ai_workspace": "",
        "ai_key_meta": "",
        "ai_key_openai": "",
        "ai_key_gemini": "",
        "ai_key_anthropic": "",
    }
    fields.update(overrides)
    # The hidden identity binds the acknowledgment to the intended
    # provider; explicit overrides can simulate a stale form.
    fields.setdefault("ai_policy_provider", fields["ai_provider"])
    return fields


@pytest.fixture
def key_env(monkeypatch):
    monkeypatch.setenv("AI_SETTINGS_KEY", TEST_SETTINGS_KEY)
    for name in (
        "SESSION_SECRET",
        "HMAC_KEY",
        "ORIGINAL_IP_KEY",
        "MODEL_API_KEY",
        "META_API_KEY",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "ANTHROPIC_API_KEY",
    ):
        if name not in ("SESSION_SECRET", "HMAC_KEY"):
            monkeypatch.delenv(name, raising=False)
    return TEST_SETTINGS_KEY


def test_settings_page_requires_login(web):
    client, _ = web
    response = client.get("/settings", follow_redirects=False)
    assert response.status_code in (302, 303)


def test_settings_page_shows_providers_without_key_material(web, key_env):
    client, _ = web
    _login(client)
    response = client.get("/settings")
    assert response.status_code == 200
    text = response.text
    for label in ("Meta", "OpenAI", "Google Gemini", "Anthropic Claude"):
        assert label in text
    assert "gpt-6.1-terra" in text
    assert "gemini-3.8-flash" in text
    assert "claude-sonnet-5-5" in text
    assert TEST_SETTINGS_KEY not in text
    # Password inputs never carry values.
    assert 'type="password"' in text
    assert 'value=""' in text


def test_save_requires_session_and_csrf(web):
    client, _ = web
    assert client.post("/settings/ai", data=_valid_fields()).status_code == 401
    _login(client)
    bad = _post_ai(client, "wrong-token", _valid_fields())
    assert bad.status_code == 403


def test_save_rejects_unknown_provider_model_and_policy(web, key_env):
    client, _ = web
    csrf = _login(client)
    for fields in (
        _valid_fields(ai_provider="nope", ai_model="gpt-6.1-terra"),
        _valid_fields(ai_provider="openai", ai_model="muse-spark-1.3"),
        _valid_fields(ai_provider="openai", ai_model="gpt-6.1-terra", ai_policy="free"),
        _valid_fields(ai_provider="meta", ai_model="muse-spark-1.3", ai_workspace="wrkspc_x"),
        _valid_fields(ai_provider="openai", ai_model="gpt-6.1-terra", ai_key_openai="x" * 513),
    ):
        assert _post_ai(client, csrf, fields).status_code == 400


def test_save_rejects_oversized_body(web, key_env):
    client, _ = web
    csrf = _login(client)
    fields = _valid_fields(ai_key_openai="k" * 20000)
    assert _post_ai(client, csrf, fields).status_code == 413


def test_save_stores_encrypted_key_blank_keeps_remove_deletes(web, key_env):
    client, db = web
    csrf = _login(client)
    secret = "synthetic-openai-key-1"
    response = _post_ai(client, csrf, _valid_fields(ai_key_openai=secret))
    assert response.status_code == 303
    from app.db.database import connect

    conn = connect(db, read_only=True)
    try:
        blob = conn.execute(
            "SELECT value FROM admin_settings WHERE key = 'ai.key.openai'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert secret not in blob
    assert secret not in client.get("/settings").text
    # Blank keeps the stored key.
    assert _post_ai(client, csrf, _valid_fields()).status_code == 303
    conn = connect(db, read_only=True)
    try:
        kept = conn.execute(
            "SELECT value FROM admin_settings WHERE key = 'ai.key.openai'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert kept == blob
    # Explicit remove deletes the stored key.
    assert _post_ai(client, csrf, _valid_fields(ai_remove_key_openai="1")).status_code == 303
    conn = connect(db, read_only=True)
    try:
        gone = conn.execute(
            "SELECT value FROM admin_settings WHERE key = 'ai.key.openai'"
        ).fetchone()
    finally:
        conn.close()
    assert gone is None


def test_missing_settings_key_blocks_key_storage_not_analytics(web, monkeypatch):
    monkeypatch.delenv("AI_SETTINGS_KEY", raising=False)
    client, _db = web
    csrf = _login(client)
    response = _post_ai(client, csrf, _valid_fields(ai_key_openai="synthetic-openai-key-2"))
    assert response.status_code == 400
    assert "AI settings key is unavailable" in response.text
    # Deterministic analytics keep working without any settings key.
    assert client.get("/settings").status_code == 200
    assert client.get("/healthz").status_code == 200


def test_env_fallback_is_honest_env_managed(web, key_env, monkeypatch):
    client, _db = web
    csrf = _login(client)
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-env-key")
    assert _post_ai(client, csrf, _valid_fields()).status_code == 303
    text = client.get("/settings").text
    assert "Managed by environment" in text


def test_tampered_blob_fails_closed_without_breaking_pages(web, key_env):
    client, db = web
    csrf = _login(client)
    assert (
        _post_ai(client, csrf, _valid_fields(ai_key_openai="synthetic-openai-key-3")).status_code
        == 303
    )
    with writer_transaction(db) as conn:
        conn.execute(
            "UPDATE admin_settings SET value = ? WHERE key = 'ai.key.openai'",
            ("tampered-not-base64!!!",),
        )
    # Pages still render; status reports stored-unreadable, never secrets.
    text = client.get("/settings").text
    assert "Stored key unreadable" in text
    assert "synthetic-openai-key-3" not in text
    assert "tampered-not-base64" not in text


def test_provider_switch_does_not_inherit_policy(web, key_env):
    client, db = web
    csrf = _login(client)
    assert (
        _post_ai(
            client,
            csrf,
            _valid_fields(ai_provider="openai", ai_model="gpt-6.1-terra", ai_policy="real"),
        ).status_code
        == 303
    )
    # The actual UI behavior without touching the policy select: the
    # stale form still carries the previous provider's "real" value
    # with the OLD provider identity and no explicit confirmation.
    # The server must reject it instead of persisting a new
    # acknowledgment for Gemini.
    assert (
        _post_ai(
            client,
            csrf,
            _valid_fields(
                ai_provider="gemini",
                ai_model="gemini-3.8-flash",
                ai_policy="real",
                ai_policy_provider="openai",
            ),
        ).status_code
        == 400
    )
    from app.config import load_settings

    effective = ai_effective.resolve(db, load_settings())
    assert effective.model_provider == "openai"
    # Deliberate acknowledgment for the new provider (policy select
    # re-chosen, or the explicit confirmation without JS) saves.
    assert (
        _post_ai(
            client,
            csrf,
            _valid_fields(
                ai_provider="gemini",
                ai_model="gemini-3.8-flash",
                ai_policy="synthetic",
                ai_policy_provider="gemini",
            ),
        ).status_code
        == 303
    )
    # Same flow through the no-JS explicit confirmation contract.
    assert (
        _post_ai(
            client,
            csrf,
            _valid_fields(
                ai_provider="anthropic",
                ai_model="claude-sonnet-5-5",
                ai_policy="synthetic",
                ai_policy_provider="gemini",
                ai_policy_confirm="1",
            ),
        ).status_code
        == 303
    )
    effective = ai_effective.resolve(db, load_settings())
    assert effective.model_provider == "anthropic"
    assert effective.model_allow_real_data is False
    assert effective.model_data_policy_verified is False
    # The other providers' acknowledgment rows are untouched in storage.
    from app.db.database import connect

    conn = connect(db, read_only=True)
    try:
        kept = conn.execute(
            "SELECT value FROM admin_settings WHERE key = 'ai.policy.openai'"
        ).fetchone()[0]
        missing = conn.execute(
            "SELECT value FROM admin_settings WHERE key = 'ai.policy.gemini'"
        ).fetchone()
    finally:
        conn.close()
    assert kept == "real"
    assert missing is not None and missing[0] == "synthetic"


def test_clearing_policy_persists_tombstone_and_blocks_legacy_env(web, key_env, monkeypatch):
    # A user clear/revocation persists an explicit unacknowledged
    # tombstone (not a deletion), so permissive legacy Meta env flags
    # cannot resurrect a real-data permission from the cleared row.
    client, db = web
    csrf = _login(client)
    assert (
        _post_ai(
            client,
            csrf,
            _valid_fields(
                ai_provider="meta",
                ai_model="muse-spark-1.3",
                ai_policy="real",
                ai_synthetic_source="0",
            ),
        ).status_code
        == 303
    )
    assert (
        _post_ai(
            client,
            csrf,
            _valid_fields(
                ai_provider="meta",
                ai_model="muse-spark-1.3",
                ai_policy="",
                ai_synthetic_source="0",
            ),
        ).status_code
        == 303
    )
    from app.db.database import connect

    conn = connect(db, read_only=True)
    try:
        row = conn.execute(
            "SELECT value FROM admin_settings WHERE key = 'ai.policy.meta'"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None and row[0] == ""
    monkeypatch.setenv("MODEL_API_KEY", "synthetic-env-key")
    monkeypatch.setenv("MODEL_DATA_POLICY_VERIFIED", "true")
    monkeypatch.setenv("MODEL_ALLOW_REAL_DATA", "true")
    from app.ai.providers.base import BackendUnavailable
    from app.ai.service import select_provider
    from app.config import load_settings

    resolved = ai_effective.resolve(db, load_settings())
    assert resolved.ai_policy == ""
    assert resolved.model_data_policy_verified is False
    assert resolved.model_allow_real_data is False
    with pytest.raises(BackendUnavailable):
        select_provider(resolved)


def test_restart_persistence_rereads_same_overlay(web, key_env):
    client, db = web
    csrf = _login(client)
    assert (
        _post_ai(
            client,
            csrf,
            _valid_fields(
                ai_provider="anthropic",
                ai_model="claude-sonnet-5-5",
                ai_policy="synthetic",
                ai_synthetic_source="1",
                ai_workspace="wrkspc_test123",
            ),
        ).status_code
        == 303
    )
    from app.config import load_settings

    first = ai_effective.resolve(db, load_settings())
    second = ai_effective.resolve(db, load_settings())
    assert (first.model_provider, first.model_id, first.ai_policy) == (
        "anthropic",
        "claude-sonnet-5-5",
        "synthetic",
    )
    assert (second.model_provider, second.model_id, second.ai_policy) == (
        "anthropic",
        "claude-sonnet-5-5",
        "synthetic",
    )
    assert second.workspace_id == "wrkspc_test123"


def test_analytics_token_cannot_manage_settings_or_chat(web, key_env):
    client, db = web
    with writer_transaction(db) as conn:
        from app.auth.tokens import issue_token

        _, token = issue_token(conn, name="api", site_id="default")
    headers = {"Authorization": f"Bearer {token}"}
    assert client.post("/settings/ai", data=_valid_fields(), headers=headers).status_code == 401
    chat_body = {
        "question": "What crawlers are visible?",
        "site_id": "default",
        "time_from": datetime(2026, 10, 27, tzinfo=UTC).isoformat(),
        "time_to": datetime(2026, 10, 28, tzinfo=UTC).isoformat(),
    }
    response = client.post("/api/v1/chat/ask", json=chat_body, headers=headers)
    assert response.status_code in (401, 403)


def test_chat_disabled_reports_safe_error_with_ai_off(web, key_env):
    client, _ = web
    _login(client)
    chat_body = {
        "question": "What crawlers are visible?",
        "site_id": "default",
        "time_from": datetime(2026, 10, 27, tzinfo=UTC).isoformat(),
        "time_to": datetime(2026, 10, 28, tzinfo=UTC).isoformat(),
    }
    csrf = client.post(
        "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
    ).json()["csrf_token"]
    response = client.post("/api/v1/chat/ask", json=chat_body, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 409
    assert response.json()["code"] == "ai_disabled"


def test_mid_run_disable_fails_closed(web, key_env, monkeypatch):
    monkeypatch.setenv("LLM_DAILY_LIMIT_USD", "50.0")
    monkeypatch.setenv("LLM_BUDGET_USD", "150.0")
    monkeypatch.setenv("LLM_WARN_AT_USD", "120.0")
    monkeypatch.setenv("LLM_STOP_AT_USD", "140.0")
    from pathlib import Path

    from app.ai.providers.base import ProviderResponse, ToolCall
    from app.ai.providers.fake import FakeProvider
    from app.ai.service import Actor, InvestigationError, run_investigation
    from app.analytics.rules import load_rules
    from app.config import load_settings

    client, db = web
    csrf = _login(client)
    assert _post_ai(client, csrf, _valid_fields(ai_enabled="1")).status_code == 303
    enabled = ai_effective.resolve(db, load_settings())
    # Simulate the operator disabling mid-investigation: flip the
    # binding the loader hands out on its second call.
    calls = {"n": 0}

    def loader():
        import dataclasses

        calls["n"] += 1
        if calls["n"] == 1:
            return enabled
        return dataclasses.replace(enabled, ai_enabled=False)

    fake = FakeProvider(
        script=[
            ProviderResponse(
                text="",
                input_tokens=10,
                output_tokens=5,
                tool_calls=(ToolCall(name="get_summary", arguments={"limit": 5}),),
            ),
            ProviderResponse(
                text="done",
                input_tokens=10,
                output_tokens=5,
                tool_calls=(),
            ),
        ]
    )
    config_root = Path(__file__).resolve().parent.parent.parent / "config"
    rules = (
        load_rules(config_root / "bot_rules.yaml").rules
        + load_rules(config_root / "security_rules.yaml").rules
    )
    with pytest.raises(InvestigationError) as exc:
        run_investigation(
            db_path=db,
            rules=rules,
            settings=enabled,
            provider=fake,
            actor=Actor(kind="admin", username="admin", session_id="s1"),
            question="What crawlers are visible?",
            site_id="default",
            time_from=datetime(2026, 10, 27, tzinfo=UTC),
            time_to=datetime(2026, 10, 28, tzinfo=UTC),
            now=datetime(2026, 10, 29, 12, tzinfo=UTC),
            smoke_enforced=False,
            settings_loader=loader,
        )
    assert exc.value.code == "egress_blocked"


def test_malformed_form_body_is_rejected_safely(web, key_env):
    client, _ = web
    csrf = _login(client)
    response = client.post(
        "/settings/ai",
        content=b"ai_provider=%ZZ&csrf_token=" + csrf.encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code in (400, 403)
