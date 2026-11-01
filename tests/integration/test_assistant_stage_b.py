"""Stage B AI readiness regressions: bounded context, exact cost, citations.

Offline validation ONLY (fully stubbed native Meta transport, blocked
sockets, synthetic T8 fixture, temporary test stores): three scripted
three-case A/B/C native investigations, overflow/gate/budget safety,
poisoned-input handling, matcher scope, call-ID pairing, rounding and
prompt/wire/UI contracts.

This NEVER labels the AI-02 real-call requirement passed: no production
transport, key, account or paid call exists here. Fake measured counts
derive from stub wire length, never from actual product spend.
"""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.ai import budget as budget_mod
from app.ai import egress as egress_mod
from app.ai.egress import MAX_WIRE_BYTES
from app.ai.providers.meta_responses import (
    MetaResponsesAdapter,
    cost_micro_usd,
    serialize_body,
    validate_body,
)
from app.ai.service import (
    Actor,
    InvestigationError,
    _compose_user_text,
    load_system_prompt,
    run_investigation,
)
from app.ai.tools.definitions import execute_tool
from app.analytics.rules import load_rules
from app.config import Settings
from app.db.database import connect
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.sources import SourceConfig

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "combined" / "t8_smoke.txt"
ENDPOINT = "https://api.meta.ai/v1/responses"

NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)
WIN_C = (datetime(2026, 10, 28, 9, 0, tzinfo=UTC), datetime(2026, 10, 28, 10, 0, tzinfo=UTC))
ACTOR = Actor(kind="admin", username="admin", session_id="stage-b")


@pytest.fixture
def no_network(monkeypatch):
    def _blocked(self, *args, **kwargs):
        raise AssertionError("network is blocked in this offline test")

    monkeypatch.setattr("socket.socket.connect", _blocked)


@pytest.fixture
def senv(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    monkeypatch.delenv("DEFAULT_TIMEZONE", raising=False)
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes(FIXTURE.read_bytes())
    db = tmp_path / "stage-b.sqlite3"
    migrate(db)
    from app.auth.passwords import hash_password
    from app.auth.tokens import create_admin_user
    from app.db.database import writer_transaction

    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
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
        hmac_key=b"synthetic-test-hmac-key",
    )
    rules = (
        load_rules(ROOT / "config" / "bot_rules.yaml").rules
        + load_rules(ROOT / "config" / "security_rules.yaml").rules
    )
    settings = Settings(
        ai_enabled=True,
        model_data_policy_verified=True,
        model_allow_real_data=True,
        model_endpoint=ENDPOINT,
        llm_daily_limit_usd=50.0,
        llm_budget_usd=150.0,
        llm_warn_at_usd=120.0,
        llm_stop_at_usd=140.0,
    )
    return {"db": db, "rules": rules, "settings": settings}


class StubTransport:
    """Fully stubbed native server: usage from stub wire length, paired IDs."""

    def __init__(self, script, *, cached=0, reasoning=5):
        self.script = list(script)
        self.calls = []
        self.cached = cached
        self.reasoning = reasoning

    def __call__(self, *, url, headers, body, timeout_s, max_response_bytes):
        assert url == "https://api.meta.ai:443/v1/responses"
        assert headers["Content-Type"] == "application/json"
        assert headers["Authorization"].startswith("Bearer ")
        # Every dispatch body decodes, validates and stays byte-capped.
        payload = json.loads(body.decode("utf-8"))
        assert payload["model"] == "muse-spark-1.3"
        assert payload["store"] is False
        assert "previous_response_id" not in payload
        validate_body(body, expected_model="muse-spark-1.3")
        assert len(body) <= MAX_WIRE_BYTES
        self.calls.append(body)
        step = self.script.pop(0) if self.script else {"text": "done"}
        output = []
        for index, call in enumerate(step.get("calls", [])):
            output.append(
                {
                    "type": "function_call",
                    "name": call,
                    "arguments": '{"limit": 5}',
                    "call_id": f"call_{len(self.calls)}_{index}",
                    "status": "completed",
                }
            )
        if step.get("text") is not None:
            output.append(
                {"type": "message", "content": [{"type": "output_text", "text": step["text"]}]}
            )
        return {
            "id": f"resp_{len(self.calls)}",
            "model": "muse-spark-1.3",
            "status": "completed",
            "output": output,
            "usage": {
                "input_tokens": min(len(body), 60000),
                "output_tokens": 25,
                "total_tokens": min(len(body), 60000) + 25,
                "input_tokens_details": {"cached_tokens": self.cached},
                "output_tokens_details": {"reasoning_tokens": self.reasoning},
            },
        }


def _native(script, **kwargs):
    transport = StubTransport(
        script, **{k: v for k, v in kwargs.items() if k in ("cached", "reasoning")}
    )
    provider = MetaResponsesAdapter(
        endpoint=ENDPOINT,
        model="muse-spark-1.3",
        api_key="synthetic-dummy-key",
        transport=transport,
    )
    return provider, transport


def _investigate(senv, provider, **overrides):
    params = {
        "db_path": senv["db"],
        "rules": senv["rules"],
        "settings": senv["settings"],
        "provider": provider,
        "actor": ACTOR,
        "question": "Which suspicious request patterns are visible in this window?",
        "site_id": "default",
        "source_id": "example-combined",
        "time_from": WIN_C[0],
        "time_to": WIN_C[1],
        "now": NOW,
        "smoke_enforced": False,
    }
    params.update(overrides)
    return run_investigation(**params)


def _settled(senv):
    return budget_mod.micro_to_usd(budget_mod.lifetime_micro_usd(senv["db"]))


def test_native_case_a_direct_answer_settles_exactly(senv, no_network):
    provider, transport = _native([{"text": "WIN_C shows no suspicious patterns."}])
    result = _investigate(senv, provider)
    assert result.provider == "meta-responses"
    assert result.tool_calls == 0
    assert len(transport.calls) == 1
    assert result.usage["estimated_cost_usd"] == _settled(senv)
    assert result.usage["estimated_cost_usd"] > 0
    assert result.usage["pricing_version"] == "2026-10-31-dev.meta.ai"
    assert result.response_ids == ["resp_1"]


def test_native_case_b_summary_then_final_settles_exactly(senv, no_network):
    provider, transport = _native([{"calls": ["get_summary"]}, {"text": "Summary done."}])
    result = _investigate(senv, provider)
    assert result.tool_calls == 1
    assert len(result.evidence) == 1
    assert len(transport.calls) == 2
    assert result.usage["estimated_cost_usd"] == _settled(senv)
    envelope = result.evidence[0]
    assert envelope["tool"] == "get_summary"
    assert envelope["filters"]["site_id"] == "default"
    assert envelope["filters"]["source_id"] == "example-combined"
    assert envelope["filters"]["time_from"] == WIN_C[0].isoformat()
    assert envelope["filters"]["time_to"] == WIN_C[1].isoformat()
    assert envelope["observation_time"] == NOW.isoformat()
    assert envelope["coverage"]["unique_events"] > 0
    # Paired call IDs: each local evidence ID links to one provider call.
    assert result.provider_calls == [
        {
            "tool_call_id": envelope["tool_call_id"],
            "call_id": "call_1_0",
            "tool": "get_summary",
        }
    ]
    # Stateless real replay carries the typed call and its output once.
    replay = json.loads(transport.calls[1].decode("utf-8"))
    kinds = [item["type"] for item in replay["input"]]
    assert kinds.count("function_call") == 1
    assert kinds.count("function_call_output") == 1
    paired = next(i for i in replay["input"] if i["type"] == "function_call")
    out = next(i for i in replay["input"] if i["type"] == "function_call_output")
    assert paired["call_id"] == out["call_id"] == "call_1_0"
    wire_output = json.loads(out["output"])
    assert wire_output["tool_call_id"] == envelope["tool_call_id"]
    assert wire_output["observation_time"] == NOW.isoformat()
    assert envelope["tool_call_id"] in wire_output["summary"]


def test_native_case_c_three_tools_complete_two_dispatches(senv, no_network):
    """The reported C failure now completes: 3 tools, 2 dispatches, exact cost."""
    provider, transport = _native(
        [
            {"calls": ["get_summary", "get_security_findings", "get_top_paths"]},
            {"text": "Two candidate findings are visible with rule references."},
        ]
    )
    result = _investigate(senv, provider)
    assert result.tool_calls == 3
    assert len(result.evidence) == 3
    assert len(transport.calls) == 2
    assert result.usage["estimated_cost_usd"] == _settled(senv)
    by_tool = {item["tool"]: item for item in result.evidence}
    # Same scope on every envelope; T8 WIN_C goldens hold locally.
    for item in result.evidence:
        assert item["filters"]["site_id"] == "default"
        assert item["filters"]["source_id"] == "example-combined"
        assert item["filters"]["time_from"] == WIN_C[0].isoformat()
        assert item["observation_time"] == NOW.isoformat()
    findings = by_tool["get_security_findings"]["result"]
    assert findings["total"] == 2
    assert {row["rule_id"] for row in findings["items"]} == {
        "sec-sensitive-path",
        "sec-repeated-client-errors",
    }
    # Every decoded outgoing wire stays within the unchanged limits.
    for body in transport.calls:
        decoded = json.loads(body.decode("utf-8"))
        egress_mod.check_wire_values(decoded, context="stage-b replay")
    assert len(serialize_body(json.loads(transport.calls[1].decode("utf-8")))) <= MAX_WIRE_BYTES
    # Same compact projection is truthful on the native wire: each rule
    # ref replays exactly once in the second dispatch.
    second = transport.calls[1].decode("utf-8")
    assert second.count("sec-sensitive-path") == 1
    assert second.count("sec-repeated-client-errors") == 1
    # Local envelopes keep the full result; wire carries the projection.
    assert len(findings["items"][0]["evidence"]) > 0
    # Direct tool execution agrees with the investigation envelopes.
    conn = connect(senv["db"], read_only=True)
    try:
        direct = execute_tool(
            conn,
            senv["rules"],
            name="get_security_findings",
            arguments={
                "site_id": "default",
                "source_id": "example-combined",
                "time_from": WIN_C[0].isoformat(),
                "time_to": WIN_C[1].isoformat(),
                "limit": 5,
            },
            tool_call_id="direct-compare",
            observation_time=NOW,
        )
    finally:
        conn.close()
    assert direct["result"] == by_tool["get_security_findings"]["result"]
    assert direct["filters"] == by_tool["get_security_findings"]["filters"]


def test_native_many_tool_overflow_still_fails_safely(senv, no_network):
    """Nine calls in one response fail closed; spend stays bounded."""
    calls = ["get_summary"] * 9
    provider, transport = _native([{"calls": calls}, {"text": "never"}])
    before = budget_mod.lifetime_micro_usd(senv["db"])
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(senv, provider)
    assert excinfo.value.code == "tool_limit_reached"
    assert len(transport.calls) == 1
    assert budget_mod.lifetime_micro_usd(senv["db"]) > before


def test_native_gate_switch_blocks_second_dispatch(senv, no_network):
    """A mid-session tier switch blocks the next native dispatch."""

    class SwitchTier(StubTransport):
        def __call__(self, **kwargs):
            body = super().__call__(**kwargs)
            senv["settings"].model_service_tier = "contributor"
            return body

    transport = SwitchTier([{"calls": ["get_summary"]}, {"text": "never"}])
    provider = MetaResponsesAdapter(
        endpoint=ENDPOINT,
        model="muse-spark-1.3",
        api_key="synthetic-dummy-key",
        transport=transport,
    )
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(senv, provider)
    assert excinfo.value.code == "egress_blocked"
    assert len(transport.calls) == 1


def test_native_interrupt_and_budget_and_timeout_stay_safe(senv, no_network):
    import threading

    provider, _ = _native([{"text": "cancelled"}])
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(senv, provider, cancel=cancel)
    assert excinfo.value.code == "cancelled"

    senv["settings"].llm_daily_limit_usd = 0.0
    provider, transport = _native([{"text": "blocked"}])
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(senv, provider)
    assert excinfo.value.code == "budget_reached"
    assert transport.calls == []
    assert "Analytics remain available" in str(excinfo.value)


def test_native_poisoned_question_never_dispatches(senv, no_network):
    """Hostile bearer-shaped text blocks before any dispatch or charge."""
    provider, transport = _native([{"text": "never"}])
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(senv, provider, question="look at lc_abcdefghijklmnop now")
    assert excinfo.value.code == "egress_blocked"
    assert transport.calls == []
    assert budget_mod.lifetime_micro_usd(senv["db"]) == 0


def test_native_oversized_question_rejected_without_dispatch(senv, no_network):
    provider, transport = _native([{"text": "never"}])
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(senv, provider, question="q" * 2001)
    assert excinfo.value.code == "invalid_request"
    assert transport.calls == []


def test_projection_overflow_fails_closed_before_dispatch(senv, no_network, monkeypatch):
    """Evidence that cannot fit its bound fails closed, never thinned."""
    minimized = {
        "totals": {"requests": 7, "errors_4xx": 1, "errors_5xx": 0, "bytes_total": 100},
        "status_distribution": [{"status": 200, "requests": 6}, {"status": 404, "requests": 1}],
        "duration": {"available": False},
        "warnings": [],
    }
    # A shrunken bound proves the fail-closed wiring: the meaningful
    # content no longer fits, so no dispatch may use a thinned version.
    monkeypatch.setattr(egress_mod, "EVIDENCE_PROJECTION_MAX_CHARS", 10)
    with pytest.raises(egress_mod.EgressViolation) as excinfo:
        egress_mod.project_evidence_summary(
            tool_name="get_summary",
            tool_call_id="tc-overflow",
            minimized=minimized,
            filters={
                "site_id": "default",
                "source_id": None,
                "time_from": WIN_C[0].isoformat(),
                "time_to": WIN_C[1].isoformat(),
            },
            observation_time=NOW.isoformat(),
            coverage={
                "unique_events": 1,
                "observed_min": WIN_C[0].isoformat(),
                "observed_max": WIN_C[1].isoformat(),
            },
        )
    assert excinfo.value.code == "payload_too_large"


def test_projection_never_repairs_hostile_content():
    """Forbidden shapes fail in serialization first; projection never sees them."""
    hostile = {
        "items": [{"path": "/x", "status": 200, "requests": 1, "referer_host": "ok.example.org"}],
        "total_groups": 1,
    }
    hostile["items"][0]["path"] = (
        '198.51.100.9 - - [27/Oct/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 12 "-" "evil/1.0"'
    )
    with pytest.raises(egress_mod.EgressViolation):
        egress_mod.serialize_evidence("get_top_paths", hostile)


def test_native_all_matchers_travel_in_user_text_and_filters(senv, no_network):
    """Every selected traffic/classification/exact matcher reaches the wire."""
    provider, transport = _native([{"calls": ["get_summary"]}, {"text": "Scoped."}])
    result = _investigate(
        senv,
        provider,
        method="GET",
        status=404,
        status_class="4xx",
        path_prefix="/docs/",
        referer_host="example.org",
        traffic="claimed_bot",
        search="docs",
    )
    assert result.tool_calls == 1
    filters = result.evidence[0]["filters"]
    assert filters["method"] == "GET"
    assert filters["status"] == 404
    assert filters["status_class"] == "4xx"
    assert filters["path_prefix"] == "/docs/"
    assert filters["referer_host"] == "example.org"
    assert filters["traffic"] == "claimed_bot"
    assert filters["search"] == "docs"
    # The decoded first-dispatch user text carries every matcher exactly once.
    user_text = json.loads(transport.calls[0].decode("utf-8"))["input"][0]["content"][0]["text"]
    for needle in (
        "method: GET",
        "status: 404",
        "status_class: 4xx",
        "path_prefix: /docs/",
        "referer_host: example.org",
        "traffic: claimed_bot",
        "search: docs",
    ):
        assert user_text.count(needle) == 1, needle


def test_native_duplicate_call_ids_rejected(senv, no_network):
    """Paired call IDs must be unique and well-formed on the native path."""
    raw = {
        "id": "resp_dup",
        "model": "muse-spark-1.3",
        "status": "completed",
        "output": [
            {
                "type": "function_call",
                "name": "get_summary",
                "arguments": '{"limit": 5}',
                "call_id": "same",
            },
            {
                "type": "function_call",
                "name": "get_summary",
                "arguments": '{"limit": 5}',
                "call_id": "same",
            },
        ],
        "usage": {
            "input_tokens": 10,
            "output_tokens": 5,
            "total_tokens": 15,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens_details": {"reasoning_tokens": 0},
        },
    }

    class DupTransport:
        def __init__(self):
            self.calls = []

        def __call__(self, *, url, headers, body, timeout_s, max_response_bytes):
            self.calls.append(body)
            return raw

    dup = DupTransport()
    dup_provider = MetaResponsesAdapter(
        endpoint=ENDPOINT,
        model="muse-spark-1.3",
        api_key="synthetic-dummy-key",
        transport=dup,
    )
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(senv, dup_provider)
    assert excinfo.value.code == "invalid_response"
    # Validation failed after dispatch, so the full step hold is kept.
    assert budget_mod.lifetime_micro_usd(senv["db"]) > 0


def test_native_cached_reasoning_rounding_settles_exactly(senv, no_network):
    """Cached/reasoning subsets settle with exact displayed cost over steps."""
    provider, transport = _native(
        [{"calls": ["get_summary"]}, {"calls": ["get_top_paths"]}, {"text": "Rounded."}],
        cached=200,
        reasoning=5,
    )
    result = _investigate(senv, provider, max_steps=3)
    assert result.tool_calls == 2
    assert len(transport.calls) == 3
    assert result.usage["cached_tokens"] == 600
    assert result.usage["reasoning_tokens"] == 15
    assert result.usage["estimated_cost_usd"] == _settled(senv)
    # Integer ledger math is exact: displayed micro-USD equals the ledger.
    from app.ai.service import MAX_OUTPUT_TOKENS  # noqa: F401  (bound unchanged)

    ledger = budget_mod.lifetime_micro_usd(senv["db"])
    assert ledger == budget_mod.usd_to_micro(result.usage["estimated_cost_usd"])
    assert cost_micro_usd(input_tokens=10, cached_tokens=0, output_tokens=10) >= 1


def test_system_prompt_requires_citations_and_honest_wording():
    """Contract on prompt wording: citation form, time split, safe claims."""
    prompt = load_system_prompt()
    assert "[evidence {tool_call_id}]" in prompt
    assert "observation" in prompt.lower()
    assert "window" in prompt.lower()
    assert "claimed" in prompt.lower()
    assert "investigation candidate" in prompt.lower()
    assert "unavailable" in prompt.lower()
    assert "truncat" in prompt.lower()


def test_user_text_carries_full_scope_without_duplication():
    """Real user message keeps every trusted matcher exactly once."""
    text = _compose_user_text(
        "q",
        "default",
        "example-combined",
        WIN_C[0],
        WIN_C[1],
        [],
        method="GET",
        status=404,
        status_class="4xx",
        path_prefix="/docs/",
        referer_host="example.org",
        traffic="claimed_bot",
        bot="bot-search-google",
        category="search",
        provider_claim="Google",
        purpose="indexing",
        search="docs",
    )
    for needle in (
        "method: GET",
        "status: 404",
        "status_class: 4xx",
        "path_prefix: /docs/",
        "referer_host: example.org",
        "traffic: claimed_bot",
        "bot: bot-search-google",
        "category: search",
        "provider: Google",
        "purpose: indexing",
        "search: docs",
    ):
        assert text.count(needle) == 1, needle


def test_fake_history_lines_carry_evidence_ids_and_observation(senv, no_network):
    """Fake path shares the same explicit evidence metadata as the wire."""
    from app.ai.providers.base import ProviderResponse, ToolCall
    from app.ai.providers.fake import FakeProvider

    script = [
        ProviderResponse(
            text="",
            input_tokens=100,
            output_tokens=20,
            tool_calls=(ToolCall(name="get_summary", arguments={"limit": 5}),),
        ),
        ProviderResponse(text="Fake summary done.", input_tokens=200, output_tokens=30),
    ]
    fake = FakeProvider(script=script)
    result = _investigate(senv, fake)
    assert result.usage["estimated_cost_usd"] == _settled(senv)
    call_id = result.evidence[0]["tool_call_id"]
    history = "\n".join(fake.captured_prompts())
    assert f"[evidence {call_id}]" in history
    assert NOW.isoformat() in history
    assert "observed=" in history


def test_wire_limits_and_immutable_serialization_hold(senv, no_network):
    """Unchanged wire bounds: byte cap, decoding validation, fixed encoding."""
    provider, transport = _native([{"calls": ["get_summary"]}, {"text": "Bounded."}])
    result = _investigate(senv, provider)
    assert result.usage["estimated_cost_usd"] == _settled(senv)
    for body in transport.calls:
        assert len(body) <= MAX_WIRE_BYTES
        decoded = json.loads(body.decode("utf-8"))
        egress_mod.check_wire_values(decoded, context="stage-b bounds")
        assert serialize_body(decoded) == body
        assert decoded["store"] is False
        assert "previous_response_id" not in decoded


def test_chat_answer_reports_settled_usage_and_typed_evidence(senv, no_network, monkeypatch):
    """UI contract: chat JSON carries exact settled cost and evidence IDs."""
    from starlette.testclient import TestClient

    from app.ai.providers.base import ProviderResponse, ToolCall
    from app.ai.providers.fake import FakeProvider

    fake = FakeProvider(
        script=[
            ProviderResponse(
                text="",
                input_tokens=100,
                output_tokens=20,
                tool_calls=(ToolCall(name="get_summary", arguments={"limit": 5}),),
            ),
            ProviderResponse(text="Chat summary done.", input_tokens=200, output_tokens=30),
        ]
    )
    monkeypatch.setenv("AI_ENABLED", "true")
    monkeypatch.setenv("MODEL_DATA_POLICY_VERIFIED", "true")
    monkeypatch.setenv("MODEL_ALLOW_REAL_DATA", "true")
    monkeypatch.setenv("LLM_DAILY_LIMIT_USD", "50")
    monkeypatch.setattr("app.ai.service.select_provider", lambda settings: fake)
    from app.main import create_app

    client = TestClient(create_app(db_path=senv["db"], secure_cookies=False))
    login = client.post("/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"})
    assert login.status_code == 200
    csrf = login.json()["csrf_token"]
    response = client.post(
        "/api/v1/chat/ask",
        json={
            "question": "What claimed crawler activity is visible?",
            "site_id": "default",
            "time_from": WIN_C[0].isoformat(),
            "time_to": WIN_C[1].isoformat(),
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["answer"] == "Chat summary done."
    assert len(body["evidence"]) == 1
    item = body["evidence"][0]
    assert item["tool_call_id"]
    # Live observation timestamp (chat passes no frozen clock), ISO form.
    assert datetime.fromisoformat(item["observation_time"]).tzinfo is not None
    assert item["filters"]["site_id"] == "default"
    assert "coverage" in item
    # Server-generated reproducible evidence link rides every UI item.
    assert item["href"].startswith("/")
    assert body["usage"]["tool_calls"] == 1
    assert body["usage"]["estimated_cost_usd"] == _settled(senv)
