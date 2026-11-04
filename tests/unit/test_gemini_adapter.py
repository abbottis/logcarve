"""Gemini generateContent adapter unit tests: endpoint, pricing, signatures.

Pure offline tests (mocked transport only): no key file, no network,
no provider account. Synthetic values throughout.
"""

import json
import threading

import pytest

from app.ai.egress import MAX_WIRE_BYTES
from app.ai.providers.base import ProviderError, ProviderRequest
from app.ai.providers.gemini_generate import (
    GeminiGenerateContentAdapter,
    build_dispatch_body,
    cost_micro_usd,
    parse_endpoint,
    parse_response,
    serialize_body,
    validate_body,
    validate_usage,
)

MODEL = "gemini-3.8-flash"
ENDPOINT = (
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent"
)
KEY = "synthetic-test-key-never-a-real-secret"


def test_parse_endpoint_accepts_only_model_bound_allowlisted():
    assert parse_endpoint(ENDPOINT, expected_model=MODEL) == ENDPOINT.replace(
        "https://generativelanguage.googleapis.com",
        "https://generativelanguage.googleapis.com:443",
    )
    for bad in (
        "",
        "http://generativelanguage.googleapis.com/v1beta/models/m:generateContent",
        (
            "https://generativelanguage.googleapis.com:8443/v1beta/models/"
            "gemini-3.8-flash:generateContent"
        ),
        "https://evil.example.org/v1beta/models/gemini-3.8-flash:generateContent",
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent?key=x",
        "https://generativelanguage.googleapis.com/v1beta/models/other-model:generateContent",
    ):
        with pytest.raises(ProviderError):
            parse_endpoint(bad, expected_model=MODEL)
    # A dispatch for another model never matches this endpoint.
    with pytest.raises(ProviderError):
        parse_endpoint(
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
            expected_model=MODEL,
        )


def test_pricing_exact_integer_rates():
    # 3.8 Flash paid intro (through 2026-12-31): input .75/M,
    # cached .075/M (subset), output 3.75/M including thoughts.
    assert cost_micro_usd(input_tokens=1_000_000, cached_tokens=0, output_tokens=0) == 750_000
    assert (
        cost_micro_usd(input_tokens=1_000_000, cached_tokens=1_000_000, output_tokens=0) == 75_000
    )
    assert cost_micro_usd(input_tokens=0, cached_tokens=0, output_tokens=1_000_000) == 3_750_000
    # Mixed: 800k uncached + 200k cached + 100k out = 0.990 USD.
    assert (
        cost_micro_usd(input_tokens=1_000_000, cached_tokens=200_000, output_tokens=100_000)
        == 990_000
    )
    with pytest.raises(ProviderError):
        cost_micro_usd(input_tokens=100, cached_tokens=101, output_tokens=0)


def test_validate_usage_total_and_thinking():
    usage = validate_usage(
        {
            "promptTokenCount": 1000,
            "cachedContentTokenCount": 200,
            "candidatesTokenCount": 40,
            "thoughtsTokenCount": 10,
            "totalTokenCount": 1050,
        },
        max_output_tokens=2048,
        input_upper=5000,
    )
    # Output is candidates PLUS thoughts; cached is a subset of prompt.
    assert usage == {
        "input_tokens": 1000,
        "output_tokens": 50,
        "cached_tokens": 200,
        "reasoning_tokens": 10,
    }
    for bad in (
        {
            "promptTokenCount": 1000,
            "candidatesTokenCount": 40,
            "thoughtsTokenCount": 10,
            "totalTokenCount": 9999,
        },
        {
            "promptTokenCount": 100,
            "cachedContentTokenCount": 101,
            "candidatesTokenCount": 1,
            "totalTokenCount": 101,
        },
    ):
        with pytest.raises(ProviderError):
            validate_usage(bad, max_output_tokens=2048, input_upper=5000)


def _tools():
    return [
        {
            "type": "function",
            "name": "get_summary",
            "description": "Bounded read-only analytics read: get_summary.",
            "parameters": {"type": "object", "properties": {}},
        }
    ]


def test_dispatch_body_native_stateless_with_signature_replay():
    body = build_dispatch_body(
        model=MODEL,
        max_output_tokens=2048,
        instructions="sys",
        user_text="What crawlers are visible?",
        exchanges=[
            {
                "calls": [
                    {
                        "call_id": "call_1_0",
                        "name": "get_summary",
                        "arguments": {"limit": 5},
                        "metadata": {"thoughtSignature": "opaque-sig-1"},
                    }
                ],
                "outputs": [
                    {
                        "call_id": "call_1_0",
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
    assert body["systemInstruction"] == {"parts": [{"text": "sys"}]}
    assert body["tools"] == [
        {
            "functionDeclarations": [
                {
                    "name": "get_summary",
                    "description": "Bounded read-only analytics read: get_summary.",
                    "parametersJsonSchema": {"type": "object", "properties": {}},
                }
            ]
        }
    ]
    assert body["generationConfig"] == {
        "maxOutputTokens": 2048,
        "thinkingConfig": {"thinkingLevel": "LOW"},
    }
    roles = [item["role"] for item in body["contents"]]
    assert roles == ["user", "model", "user"]
    replayed = body["contents"][1]["parts"][0]
    # thoughtSignature is a SIBLING of functionCall, never nested inside.
    assert replayed["thoughtSignature"] == "opaque-sig-1"
    assert "thoughtSignature" not in replayed["functionCall"]
    # The provided call correlation is preserved and echoed by the response.
    assert replayed["functionCall"]["id"] == "call_1_0"
    assert replayed["functionCall"]["args"] == {"limit": 5}
    echoed = body["contents"][2]["parts"][0]["functionResponse"]
    assert echoed["id"] == "call_1_0"
    wire = serialize_body(body)
    assert len(wire) <= MAX_WIRE_BYTES
    validate_body(wire, expected_model=MODEL)


def test_dispatch_rejects_forged_signature_shapes():
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
                            "call_id": "call_1_0",
                            "name": "get_summary",
                            "arguments": {},
                            "metadata": {"thoughtSignature": 123},
                        }
                    ],
                    "outputs": [],
                }
            ],
            tools=_tools(),
        )


def test_dispatch_requires_first_call_part_signature():
    # Gemini 3 requires the first function-call part's signature per
    # step: replaying model calls without it fails closed instead of
    # dropping or forging a signature.
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
                            "call_id": "call_1_0",
                            "name": "get_summary",
                            "arguments": {},
                            "metadata": {},
                        }
                    ],
                    "outputs": [],
                }
            ],
            tools=_tools(),
        )


def test_validate_body_rejects_openapi_parameters_field():
    body = build_dispatch_body(
        model=MODEL,
        max_output_tokens=2048,
        instructions="sys",
        user_text="hi",
        exchanges=[],
        tools=_tools(),
    )
    body["tools"][0]["functionDeclarations"][0]["parameters"] = {}
    with pytest.raises(ProviderError):
        validate_body(serialize_body(body), expected_model=MODEL)


def test_validate_body_rejects_missing_or_retiered_thinking():
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

    omitted = json.loads(json.dumps(body))
    del omitted["generationConfig"]["thinkingConfig"]
    with pytest.raises(ProviderError):
        validate_body(_encode(omitted), expected_model=MODEL)
    for level in ("MINIMAL", "MEDIUM", "HIGH", ""):
        retiered = json.loads(json.dumps(body))
        retiered["generationConfig"]["thinkingConfig"] = {"thinkingLevel": level}
        with pytest.raises(ProviderError):
            validate_body(_encode(retiered), expected_model=MODEL)


def test_parse_response_tool_then_answer_with_signature():
    # Official wire shape: thoughtSignature is a SIBLING of
    # functionCall on the Part, and the provided FunctionCall.id is
    # preserved for replay correlation.
    payload = {
        "responseId": "resp_1",
        "modelVersion": MODEL,
        "candidates": [
            {
                "finishReason": "STOP",
                "content": {
                    "role": "model",
                    "parts": [
                        {
                            "functionCall": {
                                "name": "get_summary",
                                "args": {"limit": 5},
                                "id": "call_provided_7",
                            },
                            "thoughtSignature": "opaque-sig-9",
                        },
                        {"text": "partial"},
                    ],
                },
            }
        ],
        "usageMetadata": {
            "promptTokenCount": 500,
            "cachedContentTokenCount": 100,
            "candidatesTokenCount": 20,
            "thoughtsTokenCount": 5,
            "totalTokenCount": 525,
        },
    }
    response = parse_response(
        payload, expected_model=MODEL, max_output_tokens=2048, input_upper=5000
    )
    assert response.text == "partial"
    assert len(response.tool_calls) == 1
    call = response.tool_calls[0]
    assert call.name == "get_summary"
    assert call.call_id == "call_provided_7"
    assert call.metadata == {"thoughtSignature": "opaque-sig-9"}
    # Output counts candidates plus thoughts; cache stays a subset.
    assert response.input_tokens == 500
    assert response.output_tokens == 25
    assert response.usage["cached_tokens"] == 100
    assert response.usage["reasoning_tokens"] == 5


def test_parse_response_rejects_nested_signature_and_model_mismatch():
    base_usage = {
        "promptTokenCount": 10,
        "candidatesTokenCount": 1,
        "totalTokenCount": 11,
    }

    def candidate_with(part):
        return {
            "candidates": [
                {
                    "finishReason": "STOP",
                    "content": {"role": "model", "parts": [part]},
                }
            ],
            "usageMetadata": dict(base_usage),
        }

    # Nested thoughtSignature inside functionCall is not the native
    # position and is rejected.
    with pytest.raises(ProviderError):
        parse_response(
            candidate_with(
                {
                    "functionCall": {
                        "name": "get_summary",
                        "args": {},
                        "thoughtSignature": "opaque-sig-9",
                    }
                }
            ),
            expected_model=MODEL,
            max_output_tokens=2048,
            input_upper=5000,
        )
    # Provided modelVersion must match the verified model exactly:
    # mismatches and prefix-style near matches are rejected, while an
    # absent modelVersion stays accepted.
    for version in ("other-model", MODEL + "-newer", MODEL[:8]):
        bad = candidate_with({"text": "x"})
        bad["modelVersion"] = version
        with pytest.raises(ProviderError):
            parse_response(bad, expected_model=MODEL, max_output_tokens=2048, input_upper=5000)
    ok = candidate_with({"text": "x"})
    assert (
        parse_response(ok, expected_model=MODEL, max_output_tokens=2048, input_upper=5000).text
        == "x"
    )


def test_parse_response_rejects_truncated_and_refused():
    base_candidate = {
        "content": {"role": "model", "parts": [{"text": "x"}]},
    }
    usage = {
        "promptTokenCount": 10,
        "candidatesTokenCount": 1,
        "totalTokenCount": 11,
    }
    for reason in ("MAX_TOKENS", "SAFETY", "RECITATION", "OTHER", "FINISH_REASON_UNSPECIFIED"):
        with pytest.raises(ProviderError):
            parse_response(
                {
                    "candidates": [dict(base_candidate, finishReason=reason)],
                    "usageMetadata": usage,
                },
                expected_model=MODEL,
                max_output_tokens=2048,
                input_upper=5000,
            )


def test_parse_response_rejects_missing_null_empty_invalid_call_id():
    # Gemini 3 always returns a unique FunctionCall.id: a missing,
    # null, empty or otherwise invalid id fails closed instead of
    # inventing a positional substitute that could repeat across
    # turns. Exact provided IDs are still preserved (see the
    # signature test above).
    base_usage = {
        "promptTokenCount": 10,
        "candidatesTokenCount": 1,
        "totalTokenCount": 11,
    }

    def payload_with(call):
        return {
            "responseId": "resp_1",
            "modelVersion": MODEL,
            "candidates": [
                {
                    "finishReason": "STOP",
                    "content": {"role": "model", "parts": [{"functionCall": call}]},
                }
            ],
            "usageMetadata": dict(base_usage),
        }

    cases = [
        {"name": "get_summary", "args": {}},  # missing id
        {"name": "get_summary", "args": {}, "id": None},
        {"name": "get_summary", "args": {}, "id": ""},
        {"name": "get_summary", "args": {}, "id": 123},
        {"name": "get_summary", "args": {}, "id": "x" * 65},
    ]
    for call in cases:
        with pytest.raises(ProviderError):
            parse_response(
                payload_with(call),
                expected_model=MODEL,
                max_output_tokens=2048,
                input_upper=5000,
            )


def test_adapter_sends_header_key_never_url():
    seen = {}

    def transport(*, url, headers, body, timeout_s, max_response_bytes, max_wire_bytes):
        seen.update(url=url, headers=headers)
        assert url == ENDPOINT.replace(
            "https://generativelanguage.googleapis.com",
            "https://generativelanguage.googleapis.com:443",
        )
        assert headers["x-goog-api-key"] == KEY
        assert "Authorization" not in headers
        assert "?" not in url
        return {
            "responseId": "resp_9",
            "candidates": [
                {
                    "finishReason": "STOP",
                    "content": {"role": "model", "parts": [{"text": "hi"}]},
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 10,
                "candidatesTokenCount": 2,
                "totalTokenCount": 12,
            },
        }

    adapter = GeminiGenerateContentAdapter(
        endpoint=ENDPOINT, model=MODEL, api_key=KEY, transport=transport
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
    assert json.loads(json.dumps(seen["url"])) == seen["url"]
