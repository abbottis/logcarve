"""Anthropic Messages adapter unit tests: endpoint, pricing tiers, blocks.

Pure offline tests (mocked transport only): no key file, no network,
no provider account. Synthetic values throughout.
"""

import threading

import pytest

from app.ai.egress import MAX_WIRE_BYTES
from app.ai.providers.anthropic_messages import (
    ANTHROPIC_VERSION,
    AnthropicMessagesAdapter,
    build_dispatch_body,
    cost_micro_usd,
    parse_endpoint,
    parse_response,
    serialize_body,
    validate_body,
    validate_usage,
    validate_workspace_id,
)
from app.ai.providers.base import ProviderError, ProviderRequest

ENDPOINT = "https://api.anthropic.com/v1/messages"
MODEL = "claude-haiku-5-5"
KEY = "synthetic-test-key-never-a-real-secret"


def test_parse_endpoint_accepts_only_allowlisted():
    assert parse_endpoint(ENDPOINT) == "https://api.anthropic.com:443/v1/messages"
    for bad in (
        "",
        "http://api.anthropic.com/v1/messages",
        "https://api.anthropic.com:8443/v1/messages",
        "https://evil.example.org/v1/messages",
        "https://api.anthropic.com/v1/other",
        "https://api.anthropic.com/v1/messages?x=1",
        "https://user:pass@api.anthropic.com/v1/messages",
        "https://api.openai.com/v1/responses",
    ):
        with pytest.raises(ProviderError):
            parse_endpoint(bad)


def test_version_constant_is_pinned_migration():
    assert ANTHROPIC_VERSION == "2026-10-21"


def test_workspace_id_validation():
    assert validate_workspace_id(None) == ""
    assert validate_workspace_id("") == ""
    assert validate_workspace_id("wrkspc_abc123") == "wrkspc_abc123"
    for bad in ("has space", "a" * 129, "x\ny", "a<b", 123):
        with pytest.raises(ProviderError):
            validate_workspace_id(bad)


def test_pricing_small_and_large_tiers():
    # Small prompts (<=100k input): .10/.50/.01 per M.
    assert (
        cost_micro_usd(
            input_tokens=100_000,
            cache_creation_tokens=0,
            cache_read_tokens=0,
            output_tokens=0,
        )
        == 10_000
    )
    # Cache WRITES bill above the input rate: 5-minute writes 1.25x,
    # 1-hour writes 2x; unknown-TTL creation is priced at the 1-hour
    # rate. Reads bill at the cached rate; all buckets are disjoint.
    # 90k base + 10k unknown creation = 9000 + 2000 micro-USD.
    assert (
        cost_micro_usd(
            input_tokens=90_000,
            cache_creation_tokens=10_000,
            cache_read_tokens=0,
            output_tokens=0,
        )
        == 11_000
    )
    # 1000 unknown creation tokens cost 200 micro-USD (1-hour rate),
    # not 100: creation never bills at the plain input rate.
    assert (
        cost_micro_usd(
            input_tokens=0,
            cache_creation_tokens=1000,
            cache_read_tokens=0,
            output_tokens=0,
        )
        == 200
    )
    # Explicit 5-minute vs 1-hour breakdown: 1000 tokens each cost
    # 125 and 200 micro-USD respectively.
    assert (
        cost_micro_usd(
            input_tokens=0,
            cache_creation_tokens=0,
            cache_read_tokens=0,
            output_tokens=0,
            cache_creation_5m_tokens=1000,
        )
        == 125
    )
    assert (
        cost_micro_usd(
            input_tokens=0,
            cache_creation_tokens=0,
            cache_read_tokens=0,
            output_tokens=0,
            cache_creation_1h_tokens=1000,
        )
        == 200
    )
    assert (
        cost_micro_usd(
            input_tokens=90_000,
            cache_creation_tokens=0,
            cache_read_tokens=10_000,
            output_tokens=0,
        )
        == 9_100
    )
    # Large prompts (>100k input): .50/2.50/.05 per M, conservative.
    assert (
        cost_micro_usd(
            input_tokens=100_001,
            cache_creation_tokens=0,
            cache_read_tokens=0,
            output_tokens=0,
        )
        == 50_001
    )
    # Large-tier 1-hour creation bills at 1.00/M.
    assert (
        cost_micro_usd(
            input_tokens=100_000,
            cache_creation_tokens=0,
            cache_read_tokens=0,
            output_tokens=0,
            cache_creation_1h_tokens=10_000,
        )
        == 60_000
    )
    for bad in (-1, True):
        with pytest.raises(ProviderError):
            cost_micro_usd(
                input_tokens=bad,
                cache_creation_tokens=0,
                cache_read_tokens=0,
                output_tokens=0,
            )


def test_validate_usage_preserves_creation_and_read_details():
    usage = validate_usage(
        {
            "input_tokens": 800,
            "cache_creation_input_tokens": 100,
            "cache_read_input_tokens": 100,
            "output_tokens": 25,
        },
        max_output_tokens=2048,
        input_upper=5000,
    )
    # Total input is the disjoint sum; details are preserved, not dropped.
    # Unknown-TTL creation stays in its own bucket (1-hour pricing).
    assert usage == {
        "input_tokens": 1000,
        "output_tokens": 25,
        "cached_tokens": 100,
        "reasoning_tokens": 0,
        "cache_creation_tokens": 100,
        "cache_creation_5m_tokens": 0,
        "cache_creation_1h_tokens": 0,
    }
    with pytest.raises(ProviderError):
        validate_usage(
            {"input_tokens": 10, "output_tokens": 9999},
            max_output_tokens=2048,
            input_upper=50000,
        )


def test_validate_usage_native_nested_breakdown_example():
    # Native API example shape: aggregate at usage level, TTL split
    # nested under ``cache_creation``.
    usage = validate_usage(
        {
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_creation_input_tokens": 1000,
            "cache_creation": {
                "ephemeral_5m_input_tokens": 1000,
                "ephemeral_1h_input_tokens": 0,
            },
        },
        max_output_tokens=2048,
        input_upper=5000,
    )
    assert usage["input_tokens"] == 1000
    assert usage["cache_creation_tokens"] == 0
    assert usage["cache_creation_5m_tokens"] == 1000
    assert usage["cache_creation_1h_tokens"] == 0
    # The native 5-minute bucket bills at 1.25x: 1000 tokens cost 125
    # micro-USD, not 200 at the conservative unknown rate.
    assert (
        cost_micro_usd(
            input_tokens=0,
            cache_creation_tokens=0,
            cache_read_tokens=0,
            output_tokens=0,
            cache_creation_5m_tokens=usage["cache_creation_5m_tokens"],
            cache_creation_1h_tokens=usage["cache_creation_1h_tokens"],
        )
        == 125
    )


def test_validate_usage_breakdown_buckets_are_disjoint():
    usage = validate_usage(
        {
            "input_tokens": 700,
            "cache_creation_input_tokens": 200,
            "cache_creation": {
                "ephemeral_5m_input_tokens": 100,
                "ephemeral_1h_input_tokens": 100,
            },
            "cache_read_input_tokens": 100,
            "output_tokens": 25,
        },
        max_output_tokens=2048,
        input_upper=5000,
    )
    assert usage["input_tokens"] == 1000
    assert usage["cache_creation_tokens"] == 0
    assert usage["cache_creation_5m_tokens"] == 100
    assert usage["cache_creation_1h_tokens"] == 100
    # A total alongside a breakdown must equal the breakdown sum,
    # otherwise the report is rejected instead of double-counted.
    with pytest.raises(ProviderError):
        validate_usage(
            {
                "input_tokens": 700,
                "cache_creation_input_tokens": 150,
                "cache_creation": {
                    "ephemeral_5m_input_tokens": 100,
                    "ephemeral_1h_input_tokens": 100,
                },
                "cache_read_input_tokens": 100,
                "output_tokens": 25,
            },
            max_output_tokens=2048,
            input_upper=5000,
        )
    # The invented top-level breakdown fields are not native and are
    # rejected even when their sum matches the aggregate.
    with pytest.raises(ProviderError):
        validate_usage(
            {
                "input_tokens": 700,
                "cache_creation_input_tokens": 200,
                "cache_creation_5m_input_tokens": 100,
                "cache_creation_1h_input_tokens": 100,
                "cache_read_input_tokens": 100,
                "output_tokens": 25,
            },
            max_output_tokens=2048,
            input_upper=5000,
        )
    # Malformed breakdowns fail closed: null counts, wrong types,
    # negative counts, unexpected keys and non-object breakdowns.
    for bad_breakdown in (
        {"ephemeral_5m_input_tokens": None, "ephemeral_1h_input_tokens": 0},
        {"ephemeral_5m_input_tokens": "100", "ephemeral_1h_input_tokens": 0},
        {"ephemeral_5m_input_tokens": True, "ephemeral_1h_input_tokens": 0},
        {"ephemeral_5m_input_tokens": -1, "ephemeral_1h_input_tokens": 0},
        {
            "ephemeral_5m_input_tokens": 100,
            "ephemeral_1h_input_tokens": 100,
            "ephemeral_2h_input_tokens": 50,
        },
        [100, 100],
        "100",
    ):
        with pytest.raises(ProviderError):
            validate_usage(
                {
                    "input_tokens": 700,
                    "cache_creation_input_tokens": 200,
                    "cache_creation": bad_breakdown,
                    "cache_read_input_tokens": 100,
                    "output_tokens": 25,
                },
                max_output_tokens=2048,
                input_upper=5000,
            )
    # A null breakdown means unknown TTL: the aggregate stays
    # conservative at the 1-hour rate instead of failing.
    null_usage = validate_usage(
        {
            "input_tokens": 700,
            "cache_creation_input_tokens": 200,
            "cache_creation": None,
            "cache_read_input_tokens": 100,
            "output_tokens": 25,
        },
        max_output_tokens=2048,
        input_upper=5000,
    )
    assert null_usage["cache_creation_tokens"] == 200
    assert null_usage["cache_creation_5m_tokens"] == 0
    assert null_usage["cache_creation_1h_tokens"] == 0


def _tools():
    return [
        {
            "type": "function",
            "name": "get_summary",
            "description": "Bounded read-only analytics read: get_summary.",
            "parameters": {"type": "object", "properties": {}},
        }
    ]


def test_dispatch_body_native_stateless_thinking_disabled():
    body = build_dispatch_body(
        model=MODEL,
        max_output_tokens=2048,
        instructions="sys",
        user_text="What crawlers are visible?",
        exchanges=[
            {
                "calls": [
                    {
                        "call_id": "toolu_1",
                        "name": "get_summary",
                        "arguments": {"limit": 5},
                        "metadata": {},
                    }
                ],
                "outputs": [
                    {
                        "call_id": "toolu_1",
                        "name": "get_summary",
                        "evidence": {
                            "tool_call_id": "abc-tc1",
                            "tool": "get_summary",
                            "observation_time": "2026-10-28T10:00:00+00:00",
                            "summary": "evidence summary",
                        },
                    }
                ],
            }
        ],
        tools=_tools(),
    )
    assert body["model"] == MODEL
    assert body["thinking"] == {"type": "disabled"}
    assert "stream" not in body
    assert body["tools"] == [
        {
            "name": "get_summary",
            "description": "Bounded read-only analytics read: get_summary.",
            "input_schema": {"type": "object", "properties": {}},
        }
    ]
    assert body["system"] == [{"type": "text", "text": "sys"}]
    roles = [item["role"] for item in body["messages"]]
    assert roles == ["user", "assistant", "user"]
    tool_use = body["messages"][1]["content"][0]
    assert tool_use == {
        "type": "tool_use",
        "id": "toolu_1",
        "name": "get_summary",
        "input": {"limit": 5},
    }
    tool_result = body["messages"][2]["content"][0]
    assert tool_result["type"] == "tool_result"
    assert tool_result["tool_use_id"] == "toolu_1"
    wire = serialize_body(body)
    assert len(wire) <= MAX_WIRE_BYTES
    validate_body(wire, expected_model=MODEL)
    with pytest.raises(ProviderError):
        validate_body(wire, expected_model="gpt-6-luna")


def test_parse_response_tool_then_answer():
    payload = {
        "id": "msg_1",
        "type": "message",
        "model": MODEL,
        "role": "assistant",
        "stop_reason": "tool_use",
        "content": [
            {"type": "tool_use", "id": "toolu_1", "name": "get_summary", "input": {"limit": 5}},
            {"type": "text", "text": "checking"},
        ],
        "usage": {
            "input_tokens": 400,
            "cache_creation_input_tokens": 50,
            "cache_read_input_tokens": 50,
            "output_tokens": 20,
        },
    }
    response = parse_response(
        payload, expected_model=MODEL, max_output_tokens=2048, input_upper=5000
    )
    assert response.text == "checking"
    assert [(c.name, c.call_id) for c in response.tool_calls] == [("get_summary", "toolu_1")]
    assert response.input_tokens == 500
    assert response.usage["cache_creation_tokens"] == 50


def test_parse_response_rejects_truncated_refused_and_unknown_blocks():
    usage = {"input_tokens": 10, "output_tokens": 1}
    base = {
        "id": "msg_1",
        "type": "message",
        "model": MODEL,
        "content": [{"type": "text", "text": "x"}],
        "usage": usage,
    }
    for reason in ("max_tokens", "refusal", "stop_sequence", None):
        with pytest.raises(ProviderError):
            parse_response(
                dict(base, stop_reason=reason),
                expected_model=MODEL,
                max_output_tokens=2048,
                input_upper=5000,
            )
    with pytest.raises(ProviderError):
        parse_response(
            dict(
                base,
                stop_reason="end_turn",
                content=[{"type": "server_tool_use", "id": "x", "name": "web_search"}],
            ),
            expected_model=MODEL,
            max_output_tokens=2048,
            input_upper=5000,
        )
    with pytest.raises(ProviderError):
        parse_response(
            dict(base, stop_reason="end_turn", model="claude-haiku-4-5"),
            expected_model=MODEL,
            max_output_tokens=2048,
            input_upper=5000,
        )


def test_adapter_headers_and_optional_workspace():
    seen = {}

    def transport(*, url, headers, body, timeout_s, max_response_bytes, max_wire_bytes):
        seen.update(url=url, headers=dict(headers))
        assert url == "https://api.anthropic.com:443/v1/messages"
        assert headers["Authorization"] == f"Bearer {KEY}"
        assert headers["anthropic-version"] == "2026-10-21"
        assert headers["Content-Type"] == "application/json"
        assert "?" not in url
        return {
            "id": "msg_9",
            "type": "message",
            "model": MODEL,
            "role": "assistant",
            "stop_reason": "end_turn",
            "content": [{"type": "text", "text": "hi"}],
            "usage": {"input_tokens": 10, "output_tokens": 2},
        }

    adapter = AnthropicMessagesAdapter(
        endpoint=ENDPOINT,
        model=MODEL,
        api_key=KEY,
        workspace_id="wrkspc_abc123",
        transport=transport,
    )
    wire = serialize_body(
        build_dispatch_body(
            model=MODEL,
            max_output_tokens=2048,
            instructions="sys",
            user_text="hi",
            exchanges=[],
            tools=_tools(),
        )
    )
    response = adapter.complete(
        ProviderRequest(prompt_text="hi", max_output_tokens=2048, body=wire),
        cancel=threading.Event(),
    )
    assert response.text == "hi"
    assert seen["headers"]["anthropic-workspace-id"] == "wrkspc_abc123"

    plain = AnthropicMessagesAdapter(endpoint=ENDPOINT, model=MODEL, api_key=KEY)
    assert plain._workspace_id == ""
