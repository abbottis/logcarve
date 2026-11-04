"""Anthropic Messages adapter unit tests: endpoint, pricing tiers, blocks.

Pure offline tests (mocked transport only): no key file, no network,
no provider account. Synthetic values throughout.
"""

import json
import threading

import pytest

from app.ai.egress import MAX_WIRE_BYTES
from app.ai.providers.anthropic_messages import (
    ANTHROPIC_VERSION,
    SERVICE_TIER,
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
MODEL = "claude-sonnet-5-5"
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


def test_pricing_flat_sonnet_rate_no_haiku_tier():
    # Sonnet 5.5 flat rate (NO 100k tier): 2.00/M in, 10.00/M out,
    # 0.10/M cached read, 2.50/M 5m write, 4.00/M 1h write.
    assert (
        cost_micro_usd(
            input_tokens=100_000,
            cache_creation_tokens=0,
            cache_read_tokens=0,
            output_tokens=0,
        )
        == 200_000
    )
    # Large prompts use the SAME rate: 100001 base tokens cost
    # 200002 micro-USD, not a larger-prompt rate.
    assert (
        cost_micro_usd(
            input_tokens=100_001,
            cache_creation_tokens=0,
            cache_read_tokens=0,
            output_tokens=0,
        )
        == 200_002
    )
    # Cache WRITES bill above the input rate: 5-minute writes 2.50/M,
    # 1-hour writes 4.00/M; unknown-TTL creation is priced at the
    # 1-hour rate. Reads bill at the cached rate; all buckets are
    # disjoint. 90k base + 10k unknown creation = 180000 + 40000.
    assert (
        cost_micro_usd(
            input_tokens=90_000,
            cache_creation_tokens=10_000,
            cache_read_tokens=0,
            output_tokens=0,
        )
        == 220_000
    )
    # 1000 unknown creation tokens cost 4000 micro-USD (1-hour rate),
    # not 2000: creation never bills at the plain input rate.
    assert (
        cost_micro_usd(
            input_tokens=0,
            cache_creation_tokens=1000,
            cache_read_tokens=0,
            output_tokens=0,
        )
        == 4_000
    )
    # Explicit 5-minute vs 1-hour breakdown: 1000 tokens each cost
    # 2500 and 4000 micro-USD respectively.
    assert (
        cost_micro_usd(
            input_tokens=0,
            cache_creation_tokens=0,
            cache_read_tokens=0,
            output_tokens=0,
            cache_creation_5m_tokens=1000,
        )
        == 2_500
    )
    assert (
        cost_micro_usd(
            input_tokens=0,
            cache_creation_tokens=0,
            cache_read_tokens=0,
            output_tokens=0,
            cache_creation_1h_tokens=1000,
        )
        == 4_000
    )
    # Reads bill at the cached rate: 90k base + 10k read =
    # 180000 + 1000 micro-USD.
    assert (
        cost_micro_usd(
            input_tokens=90_000,
            cache_creation_tokens=0,
            cache_read_tokens=10_000,
            output_tokens=0,
        )
        == 181_000
    )
    # Large prompts use the same flat rate (no tier): 100k base +
    # 10k 1-hour creation = 200000 + 40000 micro-USD.
    assert (
        cost_micro_usd(
            input_tokens=100_000,
            cache_creation_tokens=0,
            cache_read_tokens=0,
            output_tokens=0,
            cache_creation_1h_tokens=10_000,
        )
        == 240_000
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
    # The native 5-minute bucket bills at its own rate: 1000 tokens
    # cost 2500 micro-USD, not 4000 at the conservative unknown rate.
    assert (
        cost_micro_usd(
            input_tokens=0,
            cache_creation_tokens=0,
            cache_read_tokens=0,
            output_tokens=0,
            cache_creation_5m_tokens=usage["cache_creation_5m_tokens"],
            cache_creation_1h_tokens=usage["cache_creation_1h_tokens"],
        )
        == 2_500
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


def test_dispatch_body_native_stateless_between_tools():
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
    # ``disabled`` returns 400: the product pins between_tools with a
    # fixed cheap effort for the whole run.
    assert body["thinking"] == {"type": "between_tools"}
    assert body["output_config"] == {"effort": "low"}
    assert "stream" not in body
    for forbidden in ("tool_choice", "temperature", "top_p", "top_k"):
        assert forbidden not in body
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
        validate_body(wire, expected_model="gpt-6.1-terra")


def test_validate_body_rejects_disabled_thinking_and_effort_changes():
    body = build_dispatch_body(
        model=MODEL,
        max_output_tokens=2048,
        instructions="sys",
        user_text="hi",
        exchanges=[],
        tools=_tools(),
    )

    def _encode(mutated):
        return json.dumps(mutated, sort_keys=True, separators=(",", ":")).encode("utf-8")

    for thinking in ({"type": "disabled"}, {"type": "between_tools", "budget_tokens": 100}, None):
        mutated = json.loads(json.dumps(body))
        if thinking is None:
            del mutated["thinking"]
        else:
            mutated["thinking"] = thinking
        with pytest.raises(ProviderError):
            validate_body(_encode(mutated), expected_model=MODEL)
    for effort in (None, "medium", "high", "max"):
        mutated = json.loads(json.dumps(body))
        if effort is None:
            del mutated["output_config"]
        else:
            mutated["output_config"] = {"effort": effort}
        with pytest.raises(ProviderError):
            validate_body(_encode(mutated), expected_model=MODEL)
    for forbidden in ("tool_choice", "temperature", "top_p", "top_k"):
        mutated = json.loads(json.dumps(body))
        mutated[forbidden] = {"any": {"forced": True}} if forbidden == "tool_choice" else 1
        with pytest.raises(ProviderError):
            validate_body(_encode(mutated), expected_model=MODEL)


def test_thinking_blocks_replay_verbatim_in_original_order():
    import json as _json

    from app.ai.providers.anthropic_messages import ASSISTANT_CONTENT_KEY

    thinking = {"type": "thinking", "thinking": "checking now", "signature": "sig-abc"}
    redacted = {"type": "redacted_thinking", "data": "enc-xyz"}
    original = [
        thinking,
        {"type": "tool_use", "id": "toolu_1", "name": "get_summary", "input": {}},
        redacted,
        {"type": "tool_use", "id": "toolu_2", "name": "get_summary", "input": {}},
    ]
    payload = {
        "id": "msg_7",
        "type": "message",
        "model": MODEL,
        "role": "assistant",
        "stop_reason": "tool_use",
        "content": [dict(b) for b in original],
        "usage": {"input_tokens": 100, "output_tokens": 10},
    }
    response = parse_response(
        payload, expected_model=MODEL, max_output_tokens=2048, input_upper=5000
    )
    # Thinking text never enters the answer text.
    assert response.text == ""
    assert [c.call_id for c in response.tool_calls] == ["toolu_1", "toolu_2"]
    first_meta = dict(response.tool_calls[0].metadata)
    assert set(first_meta.keys()) == {ASSISTANT_CONTENT_KEY}
    assert dict(response.tool_calls[1].metadata) == {}
    assert _json.loads(first_meta[ASSISTANT_CONTENT_KEY]) == original
    # The next dispatch replays the exact blocks in original order,
    # even when executed scopes override arguments.
    body = build_dispatch_body(
        model=MODEL,
        max_output_tokens=2048,
        instructions="sys",
        user_text="hi",
        exchanges=[
            {
                "calls": [
                    {
                        "call_id": "toolu_1",
                        "name": "get_summary",
                        "arguments": {"limit": 5, "site_id": "default"},
                        "metadata": first_meta,
                    },
                    {
                        "call_id": "toolu_2",
                        "name": "get_summary",
                        "arguments": {"limit": 5, "site_id": "default"},
                        "metadata": {},
                    },
                ],
                "outputs": [],
            }
        ],
        tools=_tools(),
    )
    assistant = body["messages"][1]["content"]
    assert assistant == original
    validate_body(serialize_body(body), expected_model=MODEL)


def test_exact_content_preserves_text_and_original_inputs():
    import json as _json

    from app.ai.providers.anthropic_messages import ASSISTANT_CONTENT_KEY

    original = [
        {"type": "text", "text": "Synthetic public progress note."},
        {"type": "thinking", "thinking": "Synthetic progress", "signature": "synthetic-signature"},
        {"type": "tool_use", "id": "call_1", "name": "get_summary", "input": {"limit": 5}},
    ]
    payload = {
        "id": "msg_probe",
        "type": "message",
        "model": MODEL,
        "role": "assistant",
        "stop_reason": "tool_use",
        "content": [dict(b) for b in original],
        "usage": {"input_tokens": 100, "output_tokens": 10},
    }
    response = parse_response(
        payload, expected_model=MODEL, max_output_tokens=2048, input_upper=5000
    )
    assert response.text == "Synthetic public progress note."
    assert [c.call_id for c in response.tool_calls] == ["call_1"]
    meta = dict(response.tool_calls[0].metadata)
    assert _json.loads(meta[ASSISTANT_CONTENT_KEY]) == original
    # Rebuild with the normal service exchange (scope-overridden args):
    # replay must keep the exact original prefix, not the override.
    body = build_dispatch_body(
        model=MODEL,
        max_output_tokens=2048,
        instructions="sys",
        user_text="hi",
        exchanges=[
            {
                "calls": [
                    {
                        "call_id": "call_1",
                        "name": "get_summary",
                        "arguments": {"limit": 5, "site_id": "default"},
                        "metadata": meta,
                    }
                ],
                "outputs": [],
            }
        ],
        tools=_tools(),
    )
    assistant = body["messages"][1]["content"]
    assert [b["type"] for b in assistant] == ["text", "thinking", "tool_use"]
    assert assistant == original
    assert assistant[2]["input"] == {"limit": 5}
    validate_body(serialize_body(body), expected_model=MODEL)


def test_exact_content_mixed_and_second_round_stays_identical():
    import json as _json

    from app.ai.providers.anthropic_messages import ASSISTANT_CONTENT_KEY

    first_turn = [
        {"type": "text", "text": "note-one"},
        {"type": "thinking", "thinking": "t1", "signature": "sig-1"},
        {"type": "tool_use", "id": "toolu_1", "name": "get_summary", "input": {"limit": 5}},
        {"type": "text", "text": "note-two"},
        {"type": "thinking", "thinking": "t2", "signature": "sig-2"},
        {"type": "tool_use", "id": "toolu_2", "name": "get_summary", "input": {"limit": 5}},
        {"type": "redacted_thinking", "data": "enc-1"},
    ]
    # A trailing redacted block after the last tool_use is part of the
    # same turn: the parser keeps it inside the same exact blob, so a
    # second signed round replays the whole first prefix identically.
    second_turn = [
        {"type": "thinking", "thinking": "t3", "signature": "sig-3"},
        {"type": "tool_use", "id": "toolu_3", "name": "get_summary", "input": {"limit": 5}},
    ]
    first_payload = {
        "id": "msg_r1",
        "type": "message",
        "model": MODEL,
        "role": "assistant",
        "stop_reason": "tool_use",
        "content": [dict(b) for b in first_turn],
        "usage": {"input_tokens": 100, "output_tokens": 10},
    }
    second_payload = {
        "id": "msg_r2",
        "type": "message",
        "model": MODEL,
        "role": "assistant",
        "stop_reason": "tool_use",
        "content": [dict(b) for b in second_turn],
        "usage": {"input_tokens": 100, "output_tokens": 10},
    }
    first = parse_response(
        first_payload, expected_model=MODEL, max_output_tokens=2048, input_upper=5000
    )
    second = parse_response(
        second_payload, expected_model=MODEL, max_output_tokens=2048, input_upper=5000
    )
    first_meta = dict(first.tool_calls[0].metadata)
    second_meta = dict(second.tool_calls[0].metadata)
    body = build_dispatch_body(
        model=MODEL,
        max_output_tokens=2048,
        instructions="sys",
        user_text="hi",
        exchanges=[
            {
                "calls": [
                    {
                        "call_id": "toolu_1",
                        "name": "get_summary",
                        "arguments": {"limit": 5, "site_id": "default"},
                        "metadata": first_meta,
                    },
                    {
                        "call_id": "toolu_2",
                        "name": "get_summary",
                        "arguments": {"limit": 5, "site_id": "default"},
                        "metadata": {},
                    },
                ],
                "outputs": [
                    {"call_id": "toolu_1", "name": "get_summary", "evidence": {}},
                    {"call_id": "toolu_2", "name": "get_summary", "evidence": {}},
                ],
            },
            {
                "calls": [
                    {
                        "call_id": "toolu_3",
                        "name": "get_summary",
                        "arguments": {"limit": 5, "site_id": "default"},
                        "metadata": second_meta,
                    }
                ],
                "outputs": [],
            },
        ],
        tools=_tools(),
    )
    assert body["messages"][1]["content"] == first_turn
    assert body["messages"][3]["content"] == second_turn
    assert _json.loads(first_meta[ASSISTANT_CONTENT_KEY]) == first_turn
    validate_body(serialize_body(body), expected_model=MODEL)


def test_thinking_replay_rejects_forged_or_unknown_metadata():
    import json as _json

    from app.ai.providers.anthropic_messages import ASSISTANT_CONTENT_KEY

    forged = {
        ASSISTANT_CONTENT_KEY: _json.dumps(
            [{"type": "thinking", "thinking": "x", "signature": "y", "extra": 1}]
        )
    }
    with pytest.raises(ProviderError):
        build_dispatch_body(
            model=MODEL,
            max_output_tokens=2048,
            instructions="sys",
            user_text="hi",
            exchanges=[
                {
                    "calls": [
                        {
                            "call_id": "toolu_1",
                            "name": "get_summary",
                            "arguments": {},
                            "metadata": forged,
                        }
                    ],
                    "outputs": [],
                }
            ],
            tools=_tools(),
        )
    unknown = {
        ASSISTANT_CONTENT_KEY: _json.dumps(
            [{"type": "thinking", "thinking": "x", "signature": "y"}]
        ),
        "provider_note": "hello",
    }
    legacy = {
        "anthropic_thinking_before": _json.dumps(
            [{"type": "thinking", "thinking": "x", "signature": "y"}]
        )
    }
    with pytest.raises(ProviderError):
        build_dispatch_body(
            model=MODEL,
            max_output_tokens=2048,
            instructions="sys",
            user_text="hi",
            exchanges=[
                {
                    "calls": [
                        {
                            "call_id": "toolu_1",
                            "name": "get_summary",
                            "arguments": {},
                            "metadata": unknown,
                        }
                    ],
                    "outputs": [],
                }
            ],
            tools=_tools(),
        )
    with pytest.raises(ProviderError):
        build_dispatch_body(
            model=MODEL,
            max_output_tokens=2048,
            instructions="sys",
            user_text="hi",
            exchanges=[
                {
                    "calls": [
                        {
                            "call_id": "toolu_1",
                            "name": "get_summary",
                            "arguments": {},
                            "metadata": legacy,
                        }
                    ],
                    "outputs": [],
                }
            ],
            tools=_tools(),
        )
    # Mismatched call binding, misplaced blob, and oversized metadata
    # all fail closed.
    good = _json.dumps(
        [
            {"type": "text", "text": "note"},
            {"type": "tool_use", "id": "toolu_1", "name": "get_summary", "input": {}},
        ]
    )
    for bad_meta in (
        {ASSISTANT_CONTENT_KEY: good, "extra": "x"},
        {ASSISTANT_CONTENT_KEY: "not-json"},
    ):
        with pytest.raises(ProviderError):
            build_dispatch_body(
                model=MODEL,
                max_output_tokens=2048,
                instructions="sys",
                user_text="hi",
                exchanges=[
                    {
                        "calls": [
                            {
                                "call_id": "toolu_1",
                                "name": "get_summary",
                                "arguments": {},
                                "metadata": bad_meta,
                            }
                        ],
                        "outputs": [],
                    }
                ],
                tools=_tools(),
            )
    # Oversized replay blobs fail closed at the egress boundary before
    # the dispatch decode runs.
    from app.ai.egress import EgressViolation

    with pytest.raises((ProviderError, EgressViolation)):
        build_dispatch_body(
            model=MODEL,
            max_output_tokens=2048,
            instructions="sys",
            user_text="hi",
            exchanges=[
                {
                    "calls": [
                        {
                            "call_id": "toolu_1",
                            "name": "get_summary",
                            "arguments": {},
                            "metadata": {ASSISTANT_CONTENT_KEY: "x" * 65537},
                        }
                    ],
                    "outputs": [],
                }
            ],
            tools=_tools(),
        )
    with pytest.raises(ProviderError):
        build_dispatch_body(
            model=MODEL,
            max_output_tokens=2048,
            instructions="sys",
            user_text="hi",
            exchanges=[
                {
                    "calls": [
                        {
                            "call_id": "toolu_1",
                            "name": "get_summary",
                            "arguments": {},
                            "metadata": {},
                        },
                        {
                            "call_id": "toolu_2",
                            "name": "get_summary",
                            "arguments": {},
                            "metadata": {ASSISTANT_CONTENT_KEY: good},
                        },
                    ],
                    "outputs": [],
                }
            ],
            tools=_tools(),
        )


def test_parse_response_rejects_malformed_thinking_blocks():
    usage = {"input_tokens": 10, "output_tokens": 1}
    base = {
        "id": "msg_1",
        "type": "message",
        "model": MODEL,
        "stop_reason": "tool_use",
        "content": [],
        "usage": usage,
    }
    for bad_block in (
        {"type": "thinking", "thinking": "x"},
        {"type": "thinking", "thinking": "", "signature": "y"},
        {"type": "thinking", "thinking": "x", "signature": "y", "extra": 1},
        {"type": "redacted_thinking", "data": ""},
        {"type": "redacted_thinking"},
    ):
        with pytest.raises(ProviderError):
            parse_response(
                dict(
                    base,
                    content=[
                        bad_block,
                        {
                            "type": "tool_use",
                            "id": "toolu_1",
                            "name": "get_summary",
                            "input": {},
                        },
                    ],
                ),
                expected_model=MODEL,
                max_output_tokens=2048,
                input_upper=5000,
            )


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


def test_dispatch_body_carries_explicit_standard_only_tier():
    assert SERVICE_TIER == "standard_only"
    body = build_dispatch_body(
        model=MODEL,
        max_output_tokens=2048,
        instructions="sys",
        user_text="hi",
        exchanges=[],
        tools=_tools(),
    )
    assert body["service_tier"] == "standard_only"
    validate_body(serialize_body(body), expected_model=MODEL)
    # Missing or auto (the documented default, which may use Priority
    # capacity) fails the dispatch check.
    for tampered in ("auto", "priority", None):
        mutated = json.loads(json.dumps(body))
        if tampered is None:
            del mutated["service_tier"]
        else:
            mutated["service_tier"] = tampered
        with pytest.raises(ProviderError):
            validate_body(
                json.dumps(mutated, sort_keys=True, separators=(",", ":")).encode("utf-8"),
                expected_model=MODEL,
            )


def test_usage_rejects_non_standard_reported_tier():
    def _usage(**extra):
        base = {"input_tokens": 10, "output_tokens": 2}
        base.update(extra)
        return base

    # Absent, null and explicit standard stay compatible.
    for tier in ("absent", None, "standard"):
        usage_in = _usage()
        if tier == "absent":
            usage_in.pop("service_tier", None)
        else:
            usage_in["service_tier"] = tier
        usage = validate_usage(usage_in, max_output_tokens=2048, input_upper=5000)
        assert usage["input_tokens"] == 10
    # Explicit priority/batch/unknown tiers fail closed instead of
    # being accounted at standard rates.
    for tier in ("priority", "batch", "auto", "unknown-tier"):
        with pytest.raises(ProviderError):
            validate_usage(_usage(service_tier=tier), max_output_tokens=2048, input_upper=5000)


def test_parse_response_rejects_priority_usage_tier():
    payload = {
        "id": "msg_1",
        "type": "message",
        "model": MODEL,
        "role": "assistant",
        "stop_reason": "end_turn",
        "content": [{"type": "text", "text": "hi"}],
        "usage": {"input_tokens": 10, "output_tokens": 2, "service_tier": "priority"},
    }
    with pytest.raises(ProviderError):
        parse_response(payload, expected_model=MODEL, max_output_tokens=2048, input_upper=5000)


def test_native_neutral_fields_preserved_exact_and_replay_identical():
    import json as _json

    from app.ai.providers.anthropic_messages import ASSISTANT_CONTENT_KEY

    original = [
        {"type": "text", "text": "Synthetic progress note.", "citations": []},
        {"type": "text", "text": "Second note.", "citations": None},
        {
            "type": "tool_use",
            "id": "toolu_1",
            "name": "get_summary",
            "input": {"limit": 5},
            "caller": {"type": "direct"},
            "toolset_name": None,
        },
    ]
    payload = {
        "id": "msg_neutral",
        "type": "message",
        "model": MODEL,
        "role": "assistant",
        "stop_reason": "tool_use",
        "content": [dict(b) for b in original],
        "usage": {"input_tokens": 100, "output_tokens": 10},
    }
    response = parse_response(
        payload, expected_model=MODEL, max_output_tokens=2048, input_upper=5000
    )
    assert response.text == "Synthetic progress note.Second note."
    assert [c.call_id for c in response.tool_calls] == ["toolu_1"]
    meta = dict(response.tool_calls[0].metadata)
    decoded = _json.loads(meta[ASSISTANT_CONTENT_KEY])
    # Null citations/toolset are dropped (never invented); the empty
    # citations list and the direct caller are preserved verbatim.
    assert decoded == [
        {"type": "text", "text": "Synthetic progress note.", "citations": []},
        {"type": "text", "text": "Second note."},
        {
            "type": "tool_use",
            "id": "toolu_1",
            "name": "get_summary",
            "input": {"limit": 5},
            "caller": {"type": "direct"},
        },
    ]
    body = build_dispatch_body(
        model=MODEL,
        max_output_tokens=2048,
        instructions="sys",
        user_text="hi",
        exchanges=[
            {
                "calls": [
                    {
                        "call_id": "toolu_1",
                        "name": "get_summary",
                        "arguments": {"limit": 5, "site_id": "default"},
                        "metadata": meta,
                    }
                ],
                "outputs": [],
            }
        ],
        tools=_tools(),
    )
    assert body["messages"][1]["content"] == decoded
    validate_body(serialize_body(body), expected_model=MODEL)


def test_native_hostile_fields_fail_closed():
    import json as _json

    from app.ai.providers.anthropic_messages import ASSISTANT_CONTENT_KEY

    usage = {"input_tokens": 10, "output_tokens": 1}

    def _payload(content):
        return {
            "id": "msg_hostile",
            "type": "message",
            "model": MODEL,
            "role": "assistant",
            "stop_reason": "tool_use",
            "content": content,
            "usage": dict(usage),
        }

    hostile_contents = [
        # Arbitrary extra field on a text block.
        [{"type": "text", "text": "x", "extra": 1}],
        # Nonempty citations content (citations feature unrequested).
        [{"type": "text", "text": "x", "citations": [{"type": "web"}]}],
        [{"type": "text", "text": "x", "citations": "none"}],
        # Server/code-execution callers are not the direct profile.
        [
            {
                "type": "tool_use",
                "id": "toolu_1",
                "name": "get_summary",
                "input": {},
                "caller": {"type": "server"},
            }
        ],
        [
            {
                "type": "tool_use",
                "id": "toolu_1",
                "name": "get_summary",
                "input": {},
                "caller": {"type": "code_execution_20260224"},
            }
        ],
        # Any non-null toolset name is a hosted-tool marker.
        [
            {
                "type": "tool_use",
                "id": "toolu_1",
                "name": "get_summary",
                "input": {},
                "toolset_name": "web_search",
            }
        ],
        # Arbitrary extra field on a tool_use block.
        [
            {
                "type": "tool_use",
                "id": "toolu_1",
                "name": "get_summary",
                "input": {},
                "extra": 1,
            }
        ],
    ]
    for content in hostile_contents:
        with pytest.raises(ProviderError):
            parse_response(
                _payload(content),
                expected_model=MODEL,
                max_output_tokens=2048,
                input_upper=5000,
            )
    # The same hostile blocks fail closed on the replay path.
    for content in hostile_contents:
        encoded = _json.dumps(content, sort_keys=True, separators=(",", ":"))
        with pytest.raises(ProviderError):
            build_dispatch_body(
                model=MODEL,
                max_output_tokens=2048,
                instructions="sys",
                user_text="hi",
                exchanges=[
                    {
                        "calls": [
                            {
                                "call_id": "toolu_1",
                                "name": "get_summary",
                                "arguments": {"limit": 5, "site_id": "default"},
                                "metadata": {ASSISTANT_CONTENT_KEY: encoded},
                            }
                        ],
                        "outputs": [],
                    }
                ],
                tools=_tools(),
            )
