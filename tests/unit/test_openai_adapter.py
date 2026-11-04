"""OpenAI Responses adapter unit tests: endpoint, pricing, protocol.

Pure offline tests (mocked transport only): no key file, no network,
no provider account. Synthetic values throughout.
"""

import json
import threading

import pytest

from app.ai.egress import MAX_WIRE_BYTES
from app.ai.providers import _http
from app.ai.providers.base import ProviderError, ProviderRequest
from app.ai.providers.openai_responses import (
    OpenAIResponsesAdapter,
    build_dispatch_body,
    cost_micro_usd,
    parse_endpoint,
    parse_response,
    serialize_body,
    validate_body,
    validate_usage,
)

ENDPOINT = "https://api.openai.com/v1/responses"
KEY = "synthetic-test-key-never-a-real-secret"


def test_parse_endpoint_accepts_only_allowlisted():
    assert parse_endpoint(ENDPOINT) == "https://api.openai.com:443/v1/responses"
    for bad in (
        "",
        "http://api.openai.com/v1/responses",
        "https://api.openai.com:8443/v1/responses",
        "https://evil.example.org/v1/responses",
        "https://api.openai.com/v1/other",
        "https://api.openai.com/v1/responses?x=1",
        "https://api.openai.com/v1/responses#frag",
        "https://user:pass@api.openai.com/v1/responses",
        "https://api.meta.ai/v1/responses",
    ):
        with pytest.raises(ProviderError):
            parse_endpoint(bad)


def test_pricing_exact_integer_rates():
    # Terra Standard: input 1.00/M, cached 0.05/M (subset),
    # cache-write 2.50/M conservative 12h (subset), output 5.00/M.
    assert cost_micro_usd(input_tokens=1_000_000, cached_tokens=0, output_tokens=0) == 1_000_000
    assert (
        cost_micro_usd(input_tokens=1_000_000, cached_tokens=1_000_000, output_tokens=0) == 50_000
    )
    assert cost_micro_usd(input_tokens=0, cached_tokens=0, output_tokens=1_000_000) == 5_000_000
    # Mixed: 700k ordinary + 200k cached + 100k write + 100k out =
    # 700000 + 10000 + 250000 + 500000 micro-USD.
    assert (
        cost_micro_usd(
            input_tokens=1_000_000,
            cached_tokens=200_000,
            output_tokens=100_000,
            cache_write_tokens=100_000,
        )
        == 1_460_000
    )
    # Writes are a subset of input: cached + write above input fails.
    with pytest.raises(ProviderError):
        cost_micro_usd(input_tokens=100, cached_tokens=60, cache_write_tokens=41, output_tokens=0)
    with pytest.raises(ProviderError):
        cost_micro_usd(input_tokens=100, cached_tokens=101, output_tokens=0)
    for bad in (-1, True):
        with pytest.raises(ProviderError):
            cost_micro_usd(input_tokens=bad, cached_tokens=0, output_tokens=0)


def test_validate_usage_subsets_and_bounds():
    usage = validate_usage(
        {
            "input_tokens": 1000,
            "output_tokens": 50,
            "total_tokens": 1050,
            "input_tokens_details": {"cached_tokens": 200, "cache_write_tokens": 100},
        },
        max_output_tokens=2048,
        input_upper=5000,
    )
    assert usage == {
        "input_tokens": 1000,
        "output_tokens": 50,
        "cached_tokens": 200,
        "cache_write_tokens": 100,
        "reasoning_tokens": 0,
    }
    # Absent details default both subsets to zero.
    plain = validate_usage(
        {"input_tokens": 100, "output_tokens": 5, "total_tokens": 105},
        max_output_tokens=2048,
        input_upper=5000,
    )
    assert plain["cached_tokens"] == 0
    assert plain["cache_write_tokens"] == 0
    with pytest.raises(ProviderError):
        validate_usage(
            {"input_tokens": 10, "output_tokens": 5, "total_tokens": 999},
            max_output_tokens=2048,
            input_upper=50000,
        )
    # cached + write above the input total fails closed (no double count).
    with pytest.raises(ProviderError):
        validate_usage(
            {
                "input_tokens": 100,
                "output_tokens": 5,
                "total_tokens": 105,
                "input_tokens_details": {"cached_tokens": 60, "cache_write_tokens": 41},
            },
            max_output_tokens=2048,
            input_upper=50000,
        )


def _tools():
    return [
        {
            "type": "function",
            "name": "get_summary",
            "description": "Bounded read-only analytics read: get_summary.",
            "parameters": {"type": "object", "properties": {}},
        }
    ]


def test_dispatch_body_is_stateless_native():
    body = build_dispatch_body(
        model="gpt-6.1-terra",
        max_output_tokens=2048,
        instructions="sys",
        user_text="What crawlers are visible?",
        exchanges=[
            {
                "calls": [
                    {"call_id": "call_1_0", "name": "get_summary", "arguments": {"limit": 5}}
                ],
                "outputs": [
                    {
                        "call_id": "call_1_0",
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
    assert body["model"] == "gpt-6.1-terra"
    assert body["store"] is False
    assert "previous_response_id" not in body
    assert body["reasoning"] == {"effort": "none"}
    kinds = [item["type"] for item in body["input"]]
    assert kinds == ["message", "function_call", "function_call_output"]
    assert "DO NOT" not in json.dumps(body)
    wire = serialize_body(body)
    assert len(wire) <= MAX_WIRE_BYTES
    validate_body(wire, expected_model="gpt-6.1-terra")
    with pytest.raises(ProviderError):
        validate_body(wire, expected_model="muse-spark-1.3")


def test_parse_response_tool_then_answer():
    payload = {
        "id": "resp_1",
        "model": "gpt-6.1-terra",
        "status": "completed",
        "output": [
            {
                "type": "function_call",
                "name": "get_summary",
                "arguments": '{"limit": 5}',
                "call_id": "call_1_0",
                "status": "completed",
            },
            {"type": "message", "content": [{"type": "output_text", "text": "done"}]},
        ],
        "usage": {
            "input_tokens": 500,
            "output_tokens": 25,
            "total_tokens": 525,
            "input_tokens_details": {"cached_tokens": 100},
        },
    }
    response = parse_response(
        payload, expected_model="gpt-6.1-terra", max_output_tokens=2048, input_upper=5000
    )
    assert response.text == "done"
    assert [call.call_id for call in response.tool_calls] == ["call_1_0"]
    assert response.usage["cached_tokens"] == 100
    assert response.response_id == "resp_1"


def test_parse_response_rejects_incomplete_and_foreign_models():
    base = {
        "id": "resp_1",
        "model": "gpt-6.1-terra",
        "status": "incomplete",
        "output": [],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
    }
    with pytest.raises(ProviderError):
        parse_response(
            base, expected_model="gpt-6.1-terra", max_output_tokens=2048, input_upper=5000
        )
    foreign = dict(base, status="completed", model="gpt-4.1-mini")
    with pytest.raises(ProviderError):
        parse_response(
            foreign, expected_model="gpt-6.1-terra", max_output_tokens=2048, input_upper=5000
        )


def test_adapter_sends_bearer_header_and_validates_binding():
    seen = {}

    def transport(*, url, headers, body, timeout_s, max_response_bytes, max_wire_bytes):
        seen.update(url=url, headers=headers)
        assert url == "https://api.openai.com:443/v1/responses"
        assert headers["Authorization"] == f"Bearer {KEY}"
        assert "x-api-key" not in {k.lower(): v for k, v in headers.items()}
        assert "?" not in url
        return {
            "id": "resp_9",
            "model": "gpt-6.1-terra",
            "status": "completed",
            "output": [{"type": "message", "content": [{"type": "output_text", "text": "hi"}]}],
            "usage": {"input_tokens": 10, "output_tokens": 2, "total_tokens": 12},
        }

    adapter = OpenAIResponsesAdapter(
        endpoint=ENDPOINT, model="gpt-6.1-terra", api_key=KEY, transport=transport
    )
    wire = serialize_body(
        build_dispatch_body(
            model="gpt-6.1-terra",
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
    with pytest.raises(ProviderError):
        adapter.check_dispatch(
            serialize_body(
                build_dispatch_body(
                    model="muse-spark-1.3",
                    max_output_tokens=2048,
                    instructions="sys",
                    user_text="hi",
                    exchanges=[],
                    tools=_tools(),
                )
            )
        )


def test_redirects_are_refused_by_shared_transport():
    import ssl

    opener = _http._default_opener(ssl.create_default_context())
    assert opener.open is not None
    handler = _http._NoRedirect()
    assert handler.redirect_request(None, None, 302, None, None, None) is None


def test_wire_tools_carry_explicit_strict_false_without_mutating_shared():
    from app.ai.tools.definitions import response_tool_definitions

    shared = response_tool_definitions()
    body = build_dispatch_body(
        model="gpt-6.1-terra",
        max_output_tokens=2048,
        instructions="sys",
        user_text="hi",
        exchanges=[],
        tools=shared,
    )
    assert body["tools"], "wire must carry the bounded tools"
    for tool in body["tools"]:
        assert tool["strict"] is False
    # The shared catalog schemas (also used by Meta/Gemini/Claude)
    # are untouched: no strict key leaks into them.
    assert all("strict" not in tool for tool in shared)
    wire = serialize_body(body)
    validate_body(wire, expected_model="gpt-6.1-terra")


def test_dispatch_body_carries_explicit_default_tier():
    from app.ai.providers.openai_responses import SERVICE_TIER

    assert SERVICE_TIER == "default"
    body = build_dispatch_body(
        model="gpt-6.1-terra",
        max_output_tokens=2048,
        instructions="sys",
        user_text="hi",
        exchanges=[],
        tools=_tools(),
    )
    assert body["service_tier"] == "default"
    validate_body(serialize_body(body), expected_model="gpt-6.1-terra")


def test_validate_body_rejects_missing_or_non_default_tier():
    body = build_dispatch_body(
        model="gpt-6.1-terra",
        max_output_tokens=2048,
        instructions="sys",
        user_text="hi",
        exchanges=[],
        tools=_tools(),
    )

    def _encode(mutated):
        return json.dumps(mutated, sort_keys=True, separators=(",", ":")).encode("utf-8")

    for tampered in ("auto", "priority", "flex", "", None):
        mutated = json.loads(json.dumps(body))
        if tampered is None:
            del mutated["service_tier"]
        else:
            mutated["service_tier"] = tampered
        with pytest.raises(ProviderError):
            validate_body(_encode(mutated), expected_model="gpt-6.1-terra")


def test_parse_response_rejects_non_default_reported_tier():
    def _payload(**extra):
        base = {
            "id": "resp_1",
            "model": "gpt-6.1-terra",
            "status": "completed",
            "output": [{"type": "message", "content": [{"type": "output_text", "text": "hi"}]}],
            "usage": {"input_tokens": 10, "output_tokens": 2, "total_tokens": 12},
        }
        base.update(extra)
        return base

    # Absent, null and explicit default stay compatible.
    for tier in ("absent", None, "default"):
        payload = _payload()
        if tier == "absent":
            payload.pop("service_tier", None)
        else:
            payload["service_tier"] = tier
        response = parse_response(
            payload, expected_model="gpt-6.1-terra", max_output_tokens=2048, input_upper=5000
        )
        assert response.text == "hi"
    # An explicitly reported non-default tier fails closed instead of
    # being accounted at standard rates.
    for tier in ("auto", "priority", "flex", "unknown-tier"):
        with pytest.raises(ProviderError):
            parse_response(
                _payload(service_tier=tier),
                expected_model="gpt-6.1-terra",
                max_output_tokens=2048,
                input_upper=5000,
            )


def test_validate_body_rejects_tampered_strict_profile():
    body = build_dispatch_body(
        model="gpt-6.1-terra",
        max_output_tokens=2048,
        instructions="sys",
        user_text="hi",
        exchanges=[],
        tools=_tools(),
    )
    wire = json.loads(serialize_body(body).decode("utf-8"))

    def _encode(mutated):
        return json.dumps(mutated, sort_keys=True, separators=(",", ":")).encode("utf-8")

    omitted = json.loads(json.dumps(wire))
    del omitted["tools"][0]["strict"]
    with pytest.raises(ProviderError):
        validate_body(_encode(omitted), expected_model="gpt-6.1-terra")
    strict_true = json.loads(json.dumps(wire))
    strict_true["tools"][0]["strict"] = True
    with pytest.raises(ProviderError):
        validate_body(_encode(strict_true), expected_model="gpt-6.1-terra")
