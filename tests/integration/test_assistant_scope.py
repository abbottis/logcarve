"""Slice A: trusted assistant scope for traffic/bot/search selectors.

Model arguments can neither omit nor widen the operator-selected scope:
every tool executes with scope-overridden selectors, unknown values fail
closed, sensitive search text is egress-blocked, and identical runs replay
exactly. The sanitized request explorer stays out of the model tool set.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.ai.providers.base import ProviderResponse, ToolCall
from app.ai.providers.fake import FakeProvider
from app.ai.service import Actor, InvestigationError, run_investigation
from app.ai.tools import definitions
from app.analytics import service as analytics_service
from app.analytics.contracts import AnalyticsFilter, TimeWindow
from app.analytics.rules import load_rules
from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user
from app.db.database import connect, writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.sources import SourceConfig
from app.web.evidence import envelope_href

NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)
FROM = datetime(2026, 10, 27, tzinfo=UTC)
TO = datetime(2026, 10, 28, tzinfo=UTC)
ROOT = Path(__file__).resolve().parent.parent.parent
HMAC_KEY = b"synthetic-test-hmac-key"
ACTOR = Actor(kind="admin", username="admin", session_id="s1")


@pytest.fixture
def senv(tmp_path, monkeypatch):
    from app.config import Settings

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes(
        (ROOT / "tests" / "fixtures" / "combined" / "nginx_combined.txt").read_bytes()
    )
    db = tmp_path / "scope.sqlite3"
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
    return {"db": db, "rules": rules, "settings": settings}


def _investigate(senv, fake, **overrides):
    params = {
        "db_path": senv["db"],
        "rules": senv["rules"],
        "settings": senv["settings"],
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


def _answer_script(*calls):
    return [
        ProviderResponse(text="", input_tokens=10, output_tokens=5, tool_calls=tuple(calls)),
        ProviderResponse(text="Scoped answer.", input_tokens=10, output_tokens=5),
    ]


def _summary_call(**arguments):
    args = {"limit": 5}
    args.update(arguments)
    return ToolCall(name="get_summary", arguments=args)


def test_selected_scope_wins_over_hostile_args(senv):
    fake = FakeProvider(
        script=_answer_script(
            _summary_call(
                traffic="all",
                bot="bot-search-google",
                method="POST",
                path_prefix="/missing",
            )
        )
    )
    result = _investigate(senv, fake, traffic="claimed_bot", bot="bot-ai-gpt")
    filters = result.evidence[0]["filters"]
    assert filters["traffic"] == "claimed_bot"
    assert filters["bot"] == "bot-ai-gpt"
    # Unselected dimensions stay open to bounded model narrowing.
    assert filters["method"] == "POST"
    assert filters["path_prefix"] == "/missing"
    assert filters["site_id"] == "default"


def test_model_narrowing_honored_when_parent_unset(senv):
    fake = FakeProvider(
        script=_answer_script(
            _summary_call(
                traffic="claimed_bot",
                bot="bot-ai-gpt",
                method="GET",
                status=200,
                path_prefix="/robots",
                referer_host="example.org",
                search="gpt",
            )
        )
    )
    result = _investigate(senv, fake)
    filters = result.evidence[0]["filters"]
    assert filters["traffic"] == "claimed_bot"
    assert filters["bot"] == "bot-ai-gpt"
    assert filters["method"] == "GET"
    assert filters["status"] == 200
    assert filters["path_prefix"] == "/robots"
    assert filters["referer_host"] == "example.org"
    assert filters["search"] == "gpt"
    conn = connect(senv["db"], read_only=True)
    try:
        filt = AnalyticsFilter(
            site_id="default",
            window=TimeWindow(time_from=FROM, time_to=TO),
            method="GET",
            status=200,
            path_prefix="/robots",
            referer_host="example.org",
            traffic="claimed_bot",
            bot="bot-ai-gpt",
            search="gpt",
        )
        expected = analytics_service.summarize(conn, filt, senv["rules"], observation_time=NOW)
    finally:
        conn.close()
    assert result.evidence[0]["result"]["totals"] == expected["totals"]


def test_omitted_selectors_fall_back_to_scope(senv):
    fake = FakeProvider(script=_answer_script(_summary_call()))
    result = _investigate(
        senv, fake, traffic="claimed_bot", bot="bot-ai-gpt", search="gpt", status_class="2xx"
    )
    filters = result.evidence[0]["filters"]
    assert filters["traffic"] == "claimed_bot"
    assert filters["bot"] == "bot-ai-gpt"
    assert filters["search"] == "gpt"
    assert filters["status_class"] == "2xx"


def test_unknown_scope_selector_rejected_before_dispatch(senv):
    fake = FakeProvider(script=_answer_script(_summary_call()))
    with pytest.raises(InvestigationError) as exc:
        _investigate(senv, fake, bot="bot-nope")
    assert exc.value.code == "invalid_request"
    with pytest.raises(InvestigationError) as exc:
        _investigate(senv, fake, bot="bot-ai-gpt", category="search_crawler")
    assert exc.value.code == "invalid_request"


def test_unknown_tool_selector_rejected_without_broadening(senv):
    fake = FakeProvider(script=_answer_script(_summary_call(bot="bot-nope")))
    with pytest.raises(InvestigationError) as exc:
        _investigate(senv, fake)
    assert exc.value.code == "tool_rejected"


def test_sensitive_search_text_is_egress_blocked(senv):
    fake = FakeProvider(script=_answer_script(_summary_call()))
    with pytest.raises(InvestigationError) as exc:
        _investigate(senv, fake, search="https://x.example/?token=secret")
    assert exc.value.code == "egress_blocked"


def test_exact_replay_of_scoped_read(senv):
    def _run():
        fake = FakeProvider(script=_answer_script(_summary_call()))
        return _investigate(senv, fake, traffic="browser_like", search="Mozilla")

    first = _run()
    second = _run()
    assert first.evidence[0]["filters"] == second.evidence[0]["filters"]
    assert first.evidence[0]["filters"]["traffic"] == "browser_like"
    assert first.evidence[0]["filters"]["search"] == "Mozilla"
    assert first.evidence[0]["result"] == second.evidence[0]["result"]


def test_tool_aggregate_equals_service_aggregate(senv):
    conn = connect(senv["db"], read_only=True)
    try:
        envelope = definitions.execute_tool(
            conn,
            senv["rules"],
            name="get_summary",
            arguments={
                "site_id": "default",
                "time_from": FROM.isoformat(),
                "time_to": TO.isoformat(),
                "traffic": "claimed_bot",
                "limit": 20,
            },
            tool_call_id="tc1",
            observation_time=NOW,
        )
        filt = AnalyticsFilter(
            site_id="default",
            window=TimeWindow(time_from=FROM, time_to=TO),
            traffic="claimed_bot",
        )
        expected = analytics_service.summarize(conn, filt, senv["rules"], observation_time=NOW)
    finally:
        conn.close()
    assert envelope["result"]["totals"] == expected["totals"]
    assert envelope["result"]["status_distribution"] == expected["status_distribution"]
    assert envelope["filters"]["traffic"] == "claimed_bot"
    assert envelope["filters"]["site_id"] == "default"


def test_request_explorer_is_not_a_model_tool():
    assert "get_requests" not in definitions.TOOL_NAMES
    with pytest.raises(definitions.ToolError):
        definitions.execute_tool(
            None, [], name="get_requests", arguments={}, tool_call_id="tc", observation_time=NOW
        )


def test_evidence_href_carries_all_selectors():
    href = envelope_href(
        "get_crawler_claims",
        {
            "site_id": "default",
            "time_from": FROM.isoformat(),
            "time_to": TO.isoformat(),
            "traffic": "claimed_bot",
            "bot": "bot-ai-gpt",
            "category": "ai_crawler",
            "provider": "OpenAI",
            "purpose": "AI Crawler",
            "status_class": "2xx",
            "search": "gpt",
            "limit": 20,
            "offset": 0,
            "bucket": "hour",
        },
        "UTC",
    )
    assert href is not None and href.startswith("/crawlers?")
    for fragment in (
        "traffic=claimed_bot",
        "bot=bot-ai-gpt",
        "category=ai_crawler",
        "provider=OpenAI",
        "purpose=AI+Crawler",
        "status_class=2xx",
        "search=gpt",
    ):
        assert fragment in href, fragment


def test_chat_route_applies_scope_over_hostile_args(senv, monkeypatch):
    from starlette.testclient import TestClient

    import app.ai.service as ai_service
    from app.main import create_app

    monkeypatch.setenv("AI_ENABLED", "true")
    monkeypatch.setenv("MODEL_DATA_POLICY_VERIFIED", "true")
    monkeypatch.setenv("MODEL_ALLOW_REAL_DATA", "true")
    monkeypatch.setenv("LLM_DAILY_LIMIT_USD", "50")

    hostile = FakeProvider(
        script=_answer_script(
            _summary_call(
                traffic="browser_like",
                bot="bot-search-google",
                search="x",
                method="POST",
                status=404,
            )
        )
    )
    monkeypatch.setattr(ai_service, "select_provider", lambda settings: hostile)
    client = TestClient(
        create_app(db_path=senv["db"], secure_cookies=False), raise_server_exceptions=False
    )
    login = client.post("/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"})
    assert login.status_code == 200
    headers = {"X-CSRF-Token": login.json()["csrf_token"]}
    response = client.post(
        "/api/v1/chat/ask",
        json={
            "question": "What claimed crawler activity is visible?",
            "site_id": "default",
            "time_from": FROM.isoformat(),
            "time_to": TO.isoformat(),
            "method": "GET",
            "traffic": "claimed_bot",
            "bot": "bot-ai-gpt",
            "search": "gpt",
        },
        headers=headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    filters = body["evidence"][0]["filters"]
    assert filters["traffic"] == "claimed_bot"
    assert filters["bot"] == "bot-ai-gpt"
    assert filters["search"] == "gpt"
    assert filters["method"] == "GET"
    assert filters["status"] == 404
    href = body["evidence"][0]["href"]
    for fragment in ("traffic=claimed_bot", "bot=bot-ai-gpt", "search=gpt", "method=GET"):
        assert fragment in href, fragment
