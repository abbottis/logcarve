"""Multi-provider native investigations: all four transports end to end.

Offline ONLY (fully stubbed native transports, blocked sockets,
synthetic T8 fixture, temporary test stores with explicit runtime
grants): scripted chat -> tool -> evidence runs for Meta, OpenAI,
Gemini and Anthropic through their genuine native wire formats,
plus unknown-model rejection, mid-run binding changes, allowance
fail-closed and cross-provider budget accumulation.

This NEVER authorizes real calls: no production transport, key,
account or paid call exists here. Measured counts derive from stub
wire length, never from actual product spend.
"""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.ai import allowance as allowance_mod
from app.ai import budget as budget_mod
from app.ai import registry
from app.ai.egress import MAX_WIRE_BYTES
from app.ai.providers.anthropic_messages import AnthropicMessagesAdapter
from app.ai.providers.base import BackendUnavailable
from app.ai.providers.gemini_generate import GeminiGenerateContentAdapter
from app.ai.providers.meta_responses import MetaResponsesAdapter
from app.ai.providers.openai_responses import OpenAIResponsesAdapter
from app.ai.service import (
    HISTORY_MAX_CHARS,
    Actor,
    InvestigationError,
    run_investigation,
    select_provider,
)
from app.analytics.rules import load_rules
from app.config import Settings
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.sources import SourceConfig

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "combined" / "t8_smoke.txt"

NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)
WIN_C = (datetime(2026, 10, 28, 9, 0, tzinfo=UTC), datetime(2026, 10, 28, 10, 0, tzinfo=UTC))
ACTOR = Actor(kind="admin", username="admin", session_id="multi")

PROVIDERS = {
    "meta": ("muse-spark-1.3", "standard"),
    "openai": ("gpt-6-luna", "standard"),
    "gemini": ("gemini-3.5-flash-lite", "paid"),
    "anthropic": ("claude-haiku-5-5", "api"),
}


@pytest.fixture
def no_network(monkeypatch):
    def _blocked(self, *args, **kwargs):
        raise AssertionError("network is blocked in this offline test")

    monkeypatch.setattr("socket.socket.connect", _blocked)


@pytest.fixture
def menv(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    monkeypatch.delenv("DEFAULT_TIMEZONE", raising=False)
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes(FIXTURE.read_bytes())
    db = tmp_path / "multi.sqlite3"
    migrate(db)
    allowance_mod.grant(
        db,
        max_investigations=50,
        max_requests=500,
        max_micro_usd=budget_mod.usd_to_micro(50.0),
    )
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
    return {"db": db, "rules": rules}


def _settings(provider):
    model, tier = PROVIDERS[provider]
    return Settings(
        ai_enabled=True,
        model_provider=provider,
        model_id=model,
        model_service_tier=tier,
        model_data_policy_verified=True,
        model_allow_real_data=True,
        model_api_key="synthetic-test-key-never-sent",
        llm_daily_limit_usd=50.0,
        llm_budget_usd=150.0,
        llm_warn_at_usd=120.0,
        llm_stop_at_usd=140.0,
    )


def _scripted_transport(provider, calls, first_payload=None):
    """Native stub backend per provider; asserts exact native headers.

    ``first_payload`` optionally overrides the first-turn tool payload
    (a ``(provider, model) -> dict`` builder); later turns keep the
    shared final-text payload.
    """
    model, _ = PROVIDERS[provider]
    endpoint = registry.endpoint_for(provider, model)

    def transport(*, url, headers, body, timeout_s, max_response_bytes, max_wire_bytes=None):
        assert url == endpoint
        assert headers["Content-Type"] == "application/json"
        assert "?" not in url
        if provider in ("meta", "openai"):
            assert headers["Authorization"].startswith("Bearer ")
            payload = json.loads(body.decode("utf-8"))
            assert payload["model"] == model
            assert payload["store"] is False
            assert "previous_response_id" not in payload
            if provider == "openai":
                # Deliberate non-strict opt-out: explicit false on every
                # direct function tool (omission is not the default).
                assert payload["tools"], "openai wire must carry tools"
                for tool in payload["tools"]:
                    assert tool["strict"] is False
            else:
                # The shared catalog schemas are never mutated by the
                # OpenAI wire builder: Meta tools carry no strict key.
                for tool in payload["tools"]:
                    assert "strict" not in tool
        elif provider == "gemini":
            assert headers["x-goog-api-key"].startswith("synthetic")
            assert "Authorization" not in headers
            payload = json.loads(body.decode("utf-8"))
            assert "systemInstruction" in payload
            assert "functionDeclarations" in payload["tools"][0]
        else:
            assert headers["Authorization"].startswith("Bearer ")
            assert headers["anthropic-version"] == "2026-10-21"
            payload = json.loads(body.decode("utf-8"))
            assert payload["thinking"] == {"type": "disabled"}
        calls.append(body)
        if len(calls) == 1 and first_payload is not None:
            return first_payload(provider, model)
        return _native_payload(provider, model, body, len(calls))

    return transport


def _native_payload(provider, model, body, turn):
    if turn == 1:
        return _native_tool_payload(provider, model)
    return _native_text_payload(provider, model, "Evidence-backed answer.")


def _native_tool_payload(provider, model):
    if provider in ("meta", "openai"):
        return {
            "id": "resp_tool",
            "model": model,
            "status": "completed",
            "output": [
                {
                    "type": "function_call",
                    "name": "get_summary",
                    "arguments": '{"limit": 5}',
                    "call_id": "call_1_0",
                    "status": "completed",
                }
            ],
            "usage": {
                "input_tokens": 400,
                "output_tokens": 20,
                "total_tokens": 420,
                "input_tokens_details": {"cached_tokens": 0},
            },
        }
    if provider == "gemini":
        return {
            "responseId": "resp_tool",
            "modelVersion": model,
            "candidates": [
                {
                    "finishReason": "STOP",
                    "content": {
                        "role": "model",
                        "parts": [
                            {
                                # Native shape: thoughtSignature is a
                                # SIBLING of functionCall, and the
                                # provided id is preserved on replay.
                                "functionCall": {
                                    "name": "get_summary",
                                    "args": {"limit": 5},
                                    "id": "call_1_0",
                                },
                                "thoughtSignature": "opaque-test-sig",
                            }
                        ],
                    },
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 400,
                "candidatesTokenCount": 15,
                "thoughtsTokenCount": 5,
                "totalTokenCount": 420,
            },
        }
    return {
        "id": "msg_tool",
        "type": "message",
        "model": model,
        "role": "assistant",
        "stop_reason": "tool_use",
        "content": [
            {"type": "tool_use", "id": "toolu_1", "name": "get_summary", "input": {"limit": 5}}
        ],
        "usage": {"input_tokens": 400, "output_tokens": 20},
    }


def _native_text_payload(provider, model, text):
    if provider in ("meta", "openai"):
        return {
            "id": "resp_final",
            "model": model,
            "status": "completed",
            "output": [{"type": "message", "content": [{"type": "output_text", "text": text}]}],
            "usage": {
                "input_tokens": 600,
                "output_tokens": 20,
                "total_tokens": 620,
                "input_tokens_details": {"cached_tokens": 50},
            },
        }
    if provider == "gemini":
        return {
            "responseId": "resp_final",
            "candidates": [
                {
                    "finishReason": "STOP",
                    "content": {"role": "model", "parts": [{"text": text}]},
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 600,
                "cachedContentTokenCount": 50,
                "candidatesTokenCount": 15,
                "thoughtsTokenCount": 5,
                "totalTokenCount": 620,
            },
        }
    return {
        "id": "msg_final",
        "type": "message",
        "model": model,
        "role": "assistant",
        "stop_reason": "end_turn",
        "content": [{"type": "text", "text": text}],
        "usage": {
            "input_tokens": 550,
            "cache_creation_input_tokens": 25,
            "cache_read_input_tokens": 25,
            "output_tokens": 20,
        },
    }


def _adapter(provider, transport):
    model, _ = PROVIDERS[provider]
    endpoint = registry.endpoint_for(provider, model)
    if provider == "meta":
        return MetaResponsesAdapter(
            endpoint=endpoint, model=model, api_key="synthetic-test-key", transport=transport
        )
    if provider == "openai":
        return OpenAIResponsesAdapter(
            endpoint=endpoint, model=model, api_key="synthetic-test-key", transport=transport
        )
    if provider == "gemini":
        return GeminiGenerateContentAdapter(
            endpoint=endpoint, model=model, api_key="synthetic-test-key", transport=transport
        )
    return AnthropicMessagesAdapter(
        endpoint=endpoint, model=model, api_key="synthetic-test-key", transport=transport
    )


def _investigate(menv, provider, provider_obj, **overrides):
    params = {
        "db_path": menv["db"],
        "rules": menv["rules"],
        "settings": _settings(provider),
        "provider": provider_obj,
        "actor": ACTOR,
        "question": "Which suspicious request patterns are visible in this window?",
        "site_id": "default",
        "source_id": "example-combined",
        "time_from": WIN_C[0],
        "time_to": WIN_C[1],
        "now": NOW,
    }
    params.update(overrides)
    return run_investigation(**params)


@pytest.mark.parametrize("provider", ["meta", "openai", "gemini", "anthropic"])
def test_complete_tool_evidence_flow_per_provider(menv, no_network, provider):
    calls = []
    adapter = _adapter(provider, _scripted_transport(provider, calls))
    result = _investigate(menv, provider, adapter)
    assert result.answer_text == "Evidence-backed answer."
    assert result.tool_calls == 1
    assert len(result.evidence) == 1
    assert result.evidence[0]["tool"] == "get_summary"
    assert len(calls) == 2
    model, tier = PROVIDERS[provider]
    assert result.provider == adapter.name
    assert result.model == model
    assert result.usage["tier"] == tier
    assert result.usage["pricing_version"] == registry.entry_for(provider)["pricing_version"]
    assert len(result.response_ids) == 2
    assert result.usage["input_tokens"] > 0 and result.usage["output_tokens"] > 0


def test_gemini_signature_replays_exactly_across_turns(menv, no_network):
    calls = []
    adapter = _adapter("gemini", _scripted_transport("gemini", calls))
    result = _investigate(menv, "gemini", adapter)
    assert result.tool_calls == 1
    second = json.loads(calls[1].decode("utf-8"))
    replayed = second["contents"][1]["parts"][0]
    # Sibling position preserved exactly; never nested, never dropped.
    assert replayed["thoughtSignature"] == "opaque-test-sig"
    assert "thoughtSignature" not in replayed["functionCall"]
    # The provided FunctionCall.id is preserved and echoed by the response.
    assert replayed["functionCall"]["id"] == "call_1_0"
    echoed = second["contents"][2]["parts"][0]["functionResponse"]
    assert echoed["id"] == "call_1_0"
    # The service replays the executed scope-overridden arguments.
    assert replayed["functionCall"]["args"]["limit"] == 5
    assert replayed["functionCall"]["args"]["site_id"] == "default"


def test_select_provider_resolves_native_adapters(menv):
    assert isinstance(select_provider(_settings("meta")), MetaResponsesAdapter)
    assert isinstance(select_provider(_settings("openai")), OpenAIResponsesAdapter)
    assert isinstance(select_provider(_settings("gemini")), GeminiGenerateContentAdapter)
    assert isinstance(select_provider(_settings("anthropic")), AnthropicMessagesAdapter)
    assert select_provider(_settings("anthropic"))._workspace_id == ""


def test_select_provider_rejects_unknown_model_pair(menv):
    settings = Settings(
        ai_enabled=True,
        model_provider="meta",
        model_id="gpt-6-luna",
        model_service_tier="standard",
        model_data_policy_verified=True,
        model_allow_real_data=True,
        model_api_key="synthetic-test-key",
        llm_daily_limit_usd=50.0,
        llm_budget_usd=150.0,
        llm_warn_at_usd=120.0,
        llm_stop_at_usd=140.0,
    )
    with pytest.raises(BackendUnavailable):
        select_provider(settings)


def test_mid_run_provider_switch_fails_closed(menv, no_network):
    calls = []
    adapter = _adapter("openai", _scripted_transport("openai", calls))
    first = _settings("openai")
    second = _settings("gemini")
    seen = {"n": 0}

    def loader():
        seen["n"] += 1
        return first if seen["n"] == 1 else second

    with pytest.raises(InvestigationError) as exc:
        _investigate(menv, "openai", adapter, settings_loader=loader)
    assert exc.value.code == "egress_blocked"
    # The second provider never saw the first provider's history/secret.
    assert len(calls) == 1


def test_missing_allowance_fails_closed_without_spend(menv, no_network, tmp_path, monkeypatch):
    from app.db.database import connect as _connect

    calls = []
    adapter = _adapter("openai", _scripted_transport("openai", calls))
    # Seeded store without any runtime grant: scope and gate pass, the
    # missing grant fails the investigation before any provider bytes.
    root = tmp_path / "logs-nogrant"
    root.mkdir()
    (root / "access.log").write_bytes(FIXTURE.read_bytes())
    db = tmp_path / "nogrant.sqlite3"
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
        hmac_key=b"synthetic-test-hmac-key",
    )
    params = {
        "db_path": db,
        "rules": menv["rules"],
        "settings": _settings("openai"),
        "provider": adapter,
        "actor": ACTOR,
        "question": "Which suspicious request patterns are visible in this window?",
        "site_id": "default",
        "source_id": "example-combined",
        "time_from": WIN_C[0],
        "time_to": WIN_C[1],
        "now": NOW,
    }
    with pytest.raises(InvestigationError) as exc:
        run_investigation(**params)
    assert exc.value.code == "usage_not_authorized"
    assert calls == []
    conn = _connect(db, read_only=True)
    try:
        # Refused at investigation admission, before any per-step
        # reservation: no budget rows, no spend, no provider contact.
        assert conn.execute("SELECT COUNT(*) FROM ai_spend").fetchone()[0] == 0
    finally:
        conn.close()


def test_limits_are_global_across_provider_switches(menv, no_network):
    day = NOW.date().isoformat()
    before = budget_mod.outstanding_micro_usd(menv["db"], day=day)
    for provider in ("openai", "gemini"):
        calls = []
        result = _investigate(
            menv, provider, _adapter(provider, _scripted_transport(provider, calls))
        )
        assert result.tool_calls == 1
    after = budget_mod.outstanding_micro_usd(menv["db"], day=day)
    assert after > before
    grants = allowance_mod.status(menv["db"])
    assert grants["used_requests"] == 4
    assert grants["used_investigations"] == 2


# ---------------------------------------------------------------------------
# Native history-bypass regression (ai-history fix, 2026-11-02)
# ---------------------------------------------------------------------------

#: Six legitimate rich tools: each evidence projection is ~750-1050
#: chars on the shared fixture, so the combined text exceeds the legacy
#: HISTORY_MAX_CHARS (4000) while the typed native replay stays far
#: below MAX_WIRE_BYTES (65536). This mirrors the owner-verified live
#: failure where two rich 404/referrer reports tripped the legacy
#: history bound before the second native request.
RICH_TOOL_CALLS = (
    ("get_summary", {"limit": 100}),
    ("get_top_paths", {"limit": 50}),
    ("get_top_referrers", {"limit": 50}),
    ("get_crawler_claims", {"limit": 50}),
    ("get_security_findings", {"limit": 50}),
    ("get_error_groups", {"limit": 50}),
)


def _rich_tool_payload(provider, model):
    """First-turn native payload: six legitimate rich tool calls."""
    if provider in ("meta", "openai"):
        return {
            "id": "resp_rich",
            "model": model,
            "status": "completed",
            "output": [
                {
                    "type": "function_call",
                    "name": name,
                    "arguments": json.dumps(args, sort_keys=True),
                    "call_id": f"call_1_{index}",
                    "status": "completed",
                }
                for index, (name, args) in enumerate(RICH_TOOL_CALLS)
            ],
            "usage": {
                "input_tokens": 400,
                "output_tokens": 20,
                "total_tokens": 420,
                "input_tokens_details": {"cached_tokens": 0},
            },
        }
    if provider == "gemini":
        return {
            "responseId": "resp_rich",
            "modelVersion": model,
            "candidates": [
                {
                    "finishReason": "STOP",
                    "content": {
                        "role": "model",
                        "parts": [
                            (
                                {
                                    "functionCall": {
                                        "name": name,
                                        "args": dict(args),
                                        "id": f"call_1_{index}",
                                    },
                                    # Sibling position per native shape; the
                                    # replay requires the first part's
                                    # signature (never nested, never forged).
                                    "thoughtSignature": "opaque-test-sig",
                                }
                                if index == 0
                                else {
                                    "functionCall": {
                                        "name": name,
                                        "args": dict(args),
                                        "id": f"call_1_{index}",
                                    }
                                }
                            )
                            for index, (name, args) in enumerate(RICH_TOOL_CALLS)
                        ],
                    },
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 400,
                "candidatesTokenCount": 15,
                "thoughtsTokenCount": 5,
                "totalTokenCount": 420,
            },
        }
    return {
        "id": "msg_rich",
        "type": "message",
        "model": model,
        "role": "assistant",
        "stop_reason": "tool_use",
        "content": [
            {
                "type": "tool_use",
                "id": f"toolu_1_{index}",
                "name": name,
                "input": dict(args),
            }
            for index, (name, args) in enumerate(RICH_TOOL_CALLS)
        ],
        "usage": {"input_tokens": 400, "output_tokens": 20},
    }


def _wire_summaries(body):
    """Every replayed evidence summary carried by one native wire body."""
    payload = json.loads(body.decode("utf-8"))
    found = []

    def _walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "summary" and isinstance(value, str):
                    found.append(value)
                else:
                    _walk(value)
        elif isinstance(node, list):
            for item in node:
                _walk(item)
        elif isinstance(node, str):
            text = node.strip()
            if text.startswith("{") and '"summary"' in text:
                try:
                    _walk(json.loads(text))
                except ValueError:
                    pass

    _walk(payload)
    return found


@pytest.mark.parametrize("provider", ["meta", "openai", "gemini", "anthropic"])
def test_native_rich_history_completes_second_request(menv, no_network, provider):
    """Native paths must not trip the legacy text-history bound.

    The six rich tool results carry more than HISTORY_MAX_CHARS of
    evidence text combined, yet the actual second-turn native wire
    stays far below MAX_WIRE_BYTES. Pre-fix this raised
    output_limit_reached (history bound) before the second native
    request; post-fix the investigation completes with evidence-linked
    typed replay, bounded/sanitized bodies and an exact ledger.
    """
    calls = []
    adapter = _adapter(
        provider, _scripted_transport(provider, calls, first_payload=_rich_tool_payload)
    )
    result = _investigate(menv, provider, adapter)
    assert result.answer_text == "Evidence-backed answer."
    assert result.tool_calls == len(RICH_TOOL_CALLS)
    assert len(result.evidence) == len(RICH_TOOL_CALLS)
    # The second native request happened: the pre-fix history bound
    # would have failed the investigation before this dispatch.
    assert len(calls) == 2
    for body in calls:
        assert 0 < len(body) <= MAX_WIRE_BYTES
    # The legacy-equivalent text on the second turn exceeds the old
    # bound, proving this scenario is a genuine regression for it.
    summaries = _wire_summaries(calls[1])
    assert len(summaries) == len(RICH_TOOL_CALLS)
    assert sum(len(text) for text in summaries) > HISTORY_MAX_CHARS
    # Raw source lines never travel on the native wire.
    raw_first = FIXTURE.read_bytes().splitlines()[0]
    assert raw_first not in calls[0]
    assert raw_first not in calls[1]
    # Exact per-step ledger across both native steps (400+600 in,
    # 20+20 out for every provider under the shared scripted usage).
    assert result.usage["input_tokens"] == 1000
    assert result.usage["output_tokens"] == 40
    assert len(result.response_ids) == 2
    assert len(result.provider_calls) == len(RICH_TOOL_CALLS)
    linked = {entry["tool_call_id"] for entry in result.provider_calls}
    assert linked == {envelope["tool_call_id"] for envelope in result.evidence}
    model, tier = PROVIDERS[provider]
    assert result.provider == adapter.name
    assert result.model == model
    assert result.usage["tier"] == tier
    assert result.usage["pricing_version"] == registry.entry_for(provider)["pricing_version"]


def _oversize_tool_payload(provider, model, turn):
    """Eight rich tool calls with per-turn unique call IDs."""
    if provider in ("meta", "openai"):
        return {
            "id": f"resp_big_{turn}",
            "model": model,
            "status": "completed",
            "output": [
                {
                    "type": "function_call",
                    "name": name,
                    "arguments": json.dumps(args, sort_keys=True),
                    "call_id": f"call_{turn}_{index}",
                    "status": "completed",
                }
                for index, (name, args) in enumerate(_oversize_calls())
            ],
            "usage": {
                "input_tokens": 400,
                "output_tokens": 20,
                "total_tokens": 420,
                "input_tokens_details": {"cached_tokens": 0},
            },
        }
    raise AssertionError("oversize guard test uses the meta wire shape only")


def _oversize_calls():
    return RICH_TOOL_CALLS + (
        ("get_timeseries", {"bucket": "hour"}),
        ("get_report", {"report": "slow_endpoints", "limit": 5}),
    )


def test_native_wire_oversize_still_blocked(menv, no_network):
    """An actual oversized native wire still fails closed (meta shape).

    Enough rich turns push the replayed wire past MAX_WIRE_BYTES: the
    service must raise output_limit_reached with the prompt-bound
    message (the wire guard), never the removed legacy history bound
    and never a silent truncation. Complements the fake-history guard
    in test_assistant_corrections.py::test_aggregate_history_bound_is_safe_error.
    """
    from app.ai.providers.meta_responses import MetaResponsesAdapter

    model, _ = PROVIDERS["meta"]
    endpoint = registry.endpoint_for("meta", model)
    calls = []
    turn = {"n": 0}

    def transport(*, url, headers, body, timeout_s, max_response_bytes, max_wire_bytes=None):
        assert url == endpoint
        assert headers["Content-Type"] == "application/json"
        calls.append(body)
        turn["n"] += 1
        return _oversize_tool_payload("meta", model, turn["n"])

    adapter = MetaResponsesAdapter(
        endpoint=endpoint, model=model, api_key="synthetic-test-key", transport=transport
    )
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(menv, "meta", adapter)
    assert excinfo.value.code == "output_limit_reached"
    assert "prompt bound" in str(excinfo.value)
    assert len(calls) >= 2


def test_native_http_failure_keeps_analytics_and_caps(menv, no_network):
    """A native 503 through the real HTTP helper fails the run closed.

    The OpenAI adapter dispatches through the genuine
    ``_http.post_json`` over a fake urllib opener (no sockets, no
    network, no real key) that answers HTTP 503 once. The service
    reports ``provider_unavailable`` with no leaked holds, global caps
    stay unchanged, and a follow-up scripted investigation on the same
    store still completes with evidence — the deterministic analytics
    layer is independent of the provider outcome.
    """
    import urllib.error

    from app.ai.providers import _http

    model, _ = PROVIDERS["openai"]
    endpoint = registry.endpoint_for("openai", model)
    opener_calls = []

    class _FailingOpener:
        def open(self, request, timeout=None):
            opener_calls.append(request.full_url)
            raise urllib.error.HTTPError(request.full_url, 503, "synthetic overloaded", {}, None)

    def failing_transport(
        *, url, headers, body, timeout_s, max_response_bytes, max_wire_bytes=None
    ):
        return _http.post_json(
            url=url,
            headers=headers,
            body=body,
            timeout_s=timeout_s,
            max_response_bytes=max_response_bytes,
            max_wire_bytes=max_wire_bytes,
            opener_factory=lambda context: _FailingOpener(),
        )

    before = allowance_mod.status(menv["db"])
    adapter = OpenAIResponsesAdapter(
        endpoint=endpoint,
        model=model,
        api_key="synthetic-test-key",
        transport=failing_transport,
    )
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(menv, "openai", adapter)
    assert excinfo.value.code == "provider_unavailable"
    assert "synthetic-test-key" not in str(excinfo.value)
    # Exactly one native attempt: no automatic retries at any layer.
    assert opener_calls == [registry.endpoint_for("openai", model)]

    after = allowance_mod.status(menv["db"])
    assert after["max_investigations"] == before["max_investigations"]
    assert after["max_requests"] == before["max_requests"]
    assert after["max_micro_usd"] == before["max_micro_usd"]
    assert after["held_micro_usd"] == 0

    # Deterministic analytics and the allowance ledger still serve:
    # the same store completes a scripted follow-up with evidence.
    calls = []
    followup = _investigate(
        menv, "openai", _adapter("openai", _scripted_transport("openai", calls))
    )
    assert followup.tool_calls == 1
    assert followup.evidence, "scripted follow-up must carry evidence links"
    final = allowance_mod.status(menv["db"])
    assert final["held_micro_usd"] == 0
