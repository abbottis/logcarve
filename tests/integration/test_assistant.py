"""T7 assistant integration: fake-provider investigations and chat transport."""

import re
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from app.ai import budget, egress
from app.ai.providers.base import ProviderError, ProviderResponse, ToolCall
from app.ai.providers.fake import FakeProvider
from app.ai.service import Actor, InvestigationError, run_investigation
from app.analytics.rules import load_rules
from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user, issue_token
from app.config import Settings
from app.db.database import writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.sources import SourceConfig

NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)
FROM = datetime(2026, 10, 27, tzinfo=UTC)
TO = datetime(2026, 10, 28, tzinfo=UTC)
ROOT = Path(__file__).resolve().parent.parent.parent
HMAC_KEY = b"synthetic-test-hmac-key"
ACTOR = Actor(kind="admin", username="admin", session_id="s1")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes(
        (ROOT / "tests" / "fixtures" / "combined" / "nginx_combined.txt").read_bytes()
    )
    db = tmp_path / "ai.sqlite3"
    migrate(db)
    run_import(
        db,
        source=SourceConfig(
            source_id="example-combined",
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="access.log",
        ),
        site_id="default",
        site_name="s",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="access.log",
        hmac_key=HMAC_KEY,
    )
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
        _, token = issue_token(conn, name="api", site_id="default")
    rules = (
        load_rules(ROOT / "config" / "bot_rules.yaml").rules
        + load_rules(ROOT / "config" / "security_rules.yaml").rules
    )
    settings = Settings(
        ai_enabled=True,
        model_data_policy_verified=True,
        model_allow_real_data=True,
        llm_daily_limit_usd=50.0,
        llm_budget_usd=150.0,
        llm_warn_at_usd=120.0,
        llm_stop_at_usd=140.0,
    )
    return {"db": db, "rules": rules, "settings": settings, "token": token}


def _investigate(env, fake, **overrides):
    params = {
        "db_path": env["db"],
        "rules": env["rules"],
        "settings": env["settings"],
        "provider": fake,
        "actor": ACTOR,
        "question": "What claimed crawler activity is visible?",
        "site_id": "default",
        "source_id": None,
        "time_from": FROM,
        "time_to": TO,
        "now": NOW,
    }
    params.update(overrides)
    return run_investigation(**params)


def _scripted_summary():
    return [
        ProviderResponse(
            text="",
            input_tokens=100,
            output_tokens=20,
            tool_calls=(
                ToolCall(name="get_summary", arguments={"limit": 5}),
                ToolCall(name="get_crawler_claims", arguments={"limit": 5}),
            ),
        ),
        ProviderResponse(
            text="Claimed crawlers with 10 requests.", input_tokens=200, output_tokens=30
        ),
    ]


def test_bounded_investigation_returns_traceable_evidence(env):
    fake = FakeProvider(script=_scripted_summary())
    result = _investigate(env, fake)
    assert result.tool_calls == 2
    assert len(result.evidence) == 2
    assert result.answer_text.startswith("Claimed crawlers")
    assert result.provider == "fake"
    assert result.usage["input_tokens"] == 300
    for item in result.evidence:
        assert item["tool_call_id"].startswith(result.investigation_id[:8])
        assert item["filters"]["site_id"] == "default"
        assert "observation_time" in item and "coverage" in item
    # Every captured outgoing prompt passes the egress boundary.
    assert fake.outgoing, "fake must have captured prompts"
    for prompt in fake.captured_prompts():
        egress.check_outgoing(prompt, context="replay")
    assert not _IPV4.search("\n".join(fake.captured_prompts()))
    # Measured spend is charged exactly once.
    assert budget.lifetime_micro_usd(env["db"]) == budget.outstanding_micro_usd(
        env["db"], day="2026-10-29"
    )
    assert budget.lifetime_micro_usd(env["db"]) > 0


def test_model_scope_arguments_are_overridden_by_trusted_scope(env):
    fake = FakeProvider(
        script=[
            ProviderResponse(
                text="",
                input_tokens=10,
                output_tokens=5,
                tool_calls=(
                    ToolCall(
                        name="get_summary",
                        arguments={
                            "site_id": "other",
                            "source_id": "elsewhere",
                            "time_from": "2020-01-01T00:00:00+00:00",
                            "time_to": "2020-01-02T00:00:00+00:00",
                        },
                    ),
                ),
            ),
            ProviderResponse(text="Scoped answer.", input_tokens=10, output_tokens=5),
        ]
    )
    result = _investigate(env, fake)
    assert result.evidence[0]["filters"]["site_id"] == "default"
    assert result.evidence[0]["filters"]["time_from"] == FROM.isoformat()


def test_unknown_tool_from_model_is_rejected_without_execution(env):
    fake = FakeProvider(
        script=[
            ProviderResponse(
                text="",
                input_tokens=10,
                output_tokens=5,
                tool_calls=(ToolCall(name="run_sql", arguments={"sql": "SELECT 1"}),),
            )
        ]
    )
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(env, fake)
    assert excinfo.value.code == "tool_rejected"


def test_secret_in_question_blocks_before_dispatch(env):
    fake = FakeProvider(script=_scripted_summary())
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(env, fake, question="look at lc_abcdefghijklmnop now")
    assert excinfo.value.code == "egress_blocked"
    assert fake.outgoing == []
    assert budget.lifetime_micro_usd(env["db"]) == 0


def test_mid_session_tier_switch_blocks_second_investigation(env):
    assert _investigate(env, FakeProvider(script=_scripted_summary())).tool_calls == 2
    env["settings"].model_service_tier = "contributor"
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(env, FakeProvider(script=_scripted_summary()))
    assert excinfo.value.code == "egress_blocked"


def test_replay_runs_twice_and_accumulates_usage(env):
    first = _investigate(env, FakeProvider(script=_scripted_summary()))
    mid = budget.lifetime_micro_usd(env["db"])
    second = _investigate(env, FakeProvider(script=_scripted_summary()))
    assert first.investigation_id != second.investigation_id
    # Both runs passed the egress boundary again and both charges persist.
    assert budget.lifetime_micro_usd(env["db"]) == mid + budget.usd_to_micro(
        second.usage["estimated_cost_usd"]
    )
    assert mid == budget.usd_to_micro(first.usage["estimated_cost_usd"])


def test_cancel_before_dispatch_releases_reservation(env):
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(env, FakeProvider(script=_scripted_summary(), delay_s=30), cancel=cancel)
    assert excinfo.value.code == "cancelled"
    assert budget.lifetime_micro_usd(env["db"]) == 0


def test_cancel_in_flight_keeps_conservative_charge(env):
    cancel = threading.Event()
    fake = FakeProvider(script=_scripted_summary(), delay_s=30)
    outcomes = []

    def _run():
        try:
            _investigate(env, fake, cancel=cancel, timeout_s=60)
        except InvestigationError as exc:
            outcomes.append(exc.code)

    thread = threading.Thread(target=_run)
    thread.start()
    threading.Event().wait(0.5)
    cancel.set()
    thread.join(timeout=60)
    assert outcomes == ["cancelled"]
    assert budget.lifetime_micro_usd(env["db"]) > 0


def test_timeout_charges_conservatively_and_preserves_api(env):
    fake = FakeProvider(script=_scripted_summary(), delay_s=30)
    before = budget.lifetime_micro_usd(env["db"])
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(env, fake, timeout_s=0.2)
    assert excinfo.value.code == "provider_unavailable"
    assert budget.lifetime_micro_usd(env["db"]) > before
    from app.main import create_app

    client = TestClient(create_app(db_path=env["db"], secure_cookies=False))
    response = client.get(
        "/api/v1/summary",
        params={"site_id": "default", "from": FROM.isoformat(), "to": TO.isoformat()},
        headers={"Authorization": f"Bearer {env['token']}"},
    )
    assert response.status_code == 200
    assert response.json()["totals"]["requests"] == 10


def test_provider_failure_charges_and_keeps_dashboard_layer(env):
    fake = FakeProvider(fail_with=ProviderError)
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(env, fake)
    assert excinfo.value.code == "provider_unavailable"
    assert budget.lifetime_micro_usd(env["db"]) > 0


def test_exhausted_budget_blocks_with_english_error(env):
    env["settings"].llm_daily_limit_usd = 0.0
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(env, FakeProvider(script=_scripted_summary()))
    assert excinfo.value.code == "budget_reached"
    assert "Analytics remain available" in str(excinfo.value)


def test_disabled_ai_blocks_investigation_but_not_api(env):
    env["settings"].ai_enabled = False
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(env, FakeProvider(script=_scripted_summary()))
    assert excinfo.value.code == "ai_disabled"
    from app.main import create_app

    client = TestClient(create_app(db_path=env["db"], secure_cookies=False))
    response = client.get(
        "/api/v1/summary",
        params={"site_id": "default", "from": FROM.isoformat(), "to": TO.isoformat()},
        headers={"Authorization": f"Bearer {env['token']}"},
    )
    assert response.status_code == 200


def _login(client):
    response = client.post(
        "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
    )
    assert response.status_code == 200
    return response.json()["csrf_token"]


def _chat_body():
    return {
        "question": "What claimed crawler activity is visible?",
        "site_id": "default",
        "time_from": FROM.isoformat(),
        "time_to": TO.isoformat(),
    }


def test_chat_requires_admin_session_and_csrf(env):
    from app.main import create_app

    client = TestClient(create_app(db_path=env["db"], secure_cookies=False))
    assert client.post("/api/v1/chat/ask", json=_chat_body()).status_code == 401
    csrf = _login(client)
    no_csrf = TestClient(create_app(db_path=env["db"], secure_cookies=False))
    _login(no_csrf)
    assert no_csrf.post("/api/v1/chat/ask", json=_chat_body()).status_code == 403
    assert csrf


def test_chat_rejects_analytics_bearer_tokens(env):
    from app.main import create_app

    client = TestClient(create_app(db_path=env["db"], secure_cookies=False))
    response = client.post(
        "/api/v1/chat/ask",
        json=_chat_body(),
        headers={"Authorization": f"Bearer {env['token']}"},
    )
    assert response.status_code == 401


def test_chat_disabled_returns_local_error(env, monkeypatch):
    from app.main import create_app

    monkeypatch.setenv("AI_ENABLED", "false")
    client = TestClient(create_app(db_path=env["db"], secure_cookies=False))
    csrf = _login(client)
    response = client.post("/api/v1/chat/ask", json=_chat_body(), headers={"X-CSRF-Token": csrf})
    assert response.status_code == 409
    assert response.json()["code"] == "ai_disabled"


def test_chat_without_backend_reports_unavailable(env, monkeypatch):
    from app.main import create_app

    monkeypatch.setenv("AI_ENABLED", "true")
    monkeypatch.setenv("MODEL_DATA_POLICY_VERIFIED", "true")
    monkeypatch.setenv("MODEL_ALLOW_REAL_DATA", "true")
    monkeypatch.setenv("LLM_DAILY_LIMIT_USD", "50")
    client = TestClient(create_app(db_path=env["db"], secure_cookies=False))
    csrf = _login(client)
    response = client.post("/api/v1/chat/ask", json=_chat_body(), headers={"X-CSRF-Token": csrf})
    assert response.status_code == 503
    assert response.json()["code"] == "ai_unavailable"


def test_chat_success_with_injected_fake(env, monkeypatch):
    from app.main import create_app

    fake = FakeProvider(script=_scripted_summary())
    monkeypatch.setenv("AI_ENABLED", "true")
    monkeypatch.setenv("MODEL_DATA_POLICY_VERIFIED", "true")
    monkeypatch.setenv("MODEL_ALLOW_REAL_DATA", "true")
    monkeypatch.setenv("LLM_DAILY_LIMIT_USD", "50")
    monkeypatch.setattr("app.ai.service.select_provider", lambda settings: fake)
    client = TestClient(create_app(db_path=env["db"], secure_cookies=False))
    csrf = _login(client)
    response = client.post("/api/v1/chat/ask", json=_chat_body(), headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    body = response.json()
    assert body["answer"].startswith("Claimed crawlers")
    assert len(body["evidence"]) == 2
    assert body["usage"]["tool_calls"] == 2


def test_chat_rate_limit_bounds_sessions(env, monkeypatch):
    from app.api import routes_chat
    from app.main import create_app

    monkeypatch.setenv("AI_ENABLED", "false")
    monkeypatch.setattr(routes_chat, "_chat_attempts", {})
    client = TestClient(create_app(db_path=env["db"], secure_cookies=False))
    csrf = _login(client)
    headers = {"X-CSRF-Token": csrf}
    codes = [
        client.post("/api/v1/chat/ask", json=_chat_body(), headers=headers).status_code
        for _ in range(routes_chat.CHAT_RATE_MAX + 1)
    ]
    assert codes[-1] == 429
    assert codes[0] == 409
