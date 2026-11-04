"""T8 Meta Responses adapter unit tests: endpoint, pricing, protocol.

Pure offline tests (mocked transport only): no key file, no network,
no provider account. Synthetic values throughout.
"""

import json
import threading

import pytest

from app.ai.egress import MAX_WIRE_BYTES
from app.ai.providers.base import (
    BackendUnavailable,
    ProviderCancelled,
    ProviderError,
    ProviderRequest,
    ProviderResponse,
    ProviderTimeout,
)
from app.ai.providers.meta_responses import (
    MetaResponsesAdapter,
    build_dispatch_body,
    cost_micro_usd,
    parse_endpoint,
    parse_response,
    serialize_body,
    validate_usage,
)

ENDPOINT = "https://api.meta.ai/v1/responses"
KEY = "synthetic-test-key-never-a-real-secret"


def test_parse_endpoint_accepts_only_allowlisted():
    assert parse_endpoint(ENDPOINT) == "https://api.meta.ai:443/v1/responses"
    for bad in (
        "",
        "http://api.meta.ai/v1/responses",
        "https://api.meta.ai:8443/v1/responses",
        "https://evil.example.org/v1/responses",
        "https://api.meta.ai/v1/other",
        "https://api.meta.ai/v1/responses?x=1",
        "https://api.meta.ai/v1/responses#frag",
        "https://user:pass@api.meta.ai/v1/responses",
        "https://api.meta.ai.evil.org/v1/responses",
    ):
        with pytest.raises(ProviderError):
            parse_endpoint(bad)


def test_pricing_exact_integer_rates():
    assert cost_micro_usd(input_tokens=1_000_000, cached_tokens=0, output_tokens=0) == 1_250_000
    assert (
        cost_micro_usd(input_tokens=1_000_000, cached_tokens=1_000_000, output_tokens=0) == 150_000
    )
    assert cost_micro_usd(input_tokens=0, cached_tokens=0, output_tokens=1_000_000) == 4_250_000
    # Mixed: 800k uncached + 200k cached + 100k out = 1.455 USD.
    assert (
        cost_micro_usd(input_tokens=1_000_000, cached_tokens=200_000, output_tokens=100_000)
        == 1_455_000
    )
    # Cached is a subset of input, never added twice.
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
            "input_tokens_details": {"cached_tokens": 200},
            "output_tokens_details": {"reasoning_tokens": 10},
        },
        max_output_tokens=2048,
        input_upper=5000,
    )
    assert usage == {
        "input_tokens": 1000,
        "output_tokens": 50,
        "cached_tokens": 200,
        "reasoning_tokens": 10,
    }
    # Reasoning is a subset of output; cached a subset of input.
    with pytest.raises(ProviderError):
        validate_usage(
            {
                "input_tokens": 10,
                "output_tokens": 5,
                "total_tokens": 15,
                "input_tokens_details": {"cached_tokens": 11},
                "output_tokens_details": {"reasoning_tokens": 0},
            },
            max_output_tokens=2048,
            input_upper=5000,
        )
    with pytest.raises(ProviderError):
        validate_usage(
            {
                "input_tokens": 10,
                "output_tokens": 5,
                "total_tokens": 15,
                "input_tokens_details": {"cached_tokens": 0},
                "output_tokens_details": {"reasoning_tokens": 6},
            },
            max_output_tokens=2048,
            input_upper=5000,
        )
    with pytest.raises(ProviderError):
        validate_usage(
            {"input_tokens": 10, "output_tokens": 9999, "total_tokens": 10009},
            max_output_tokens=2048,
            input_upper=50000,
        )
    with pytest.raises(ProviderError):
        validate_usage(
            {"input_tokens": -1, "output_tokens": 0, "total_tokens": 0},
            max_output_tokens=2048,
            input_upper=5000,
        )
    with pytest.raises(ProviderError):
        validate_usage("not-a-dict", max_output_tokens=2048, input_upper=5000)


def _payload(**overrides):
    body = {
        "id": "resp_1",
        "model": "muse-spark-1.3",
        "status": "completed",
        "output": [
            {
                "type": "message",
                "content": [{"type": "output_text", "text": "hello"}],
            }
        ],
        "usage": {
            "input_tokens": 100,
            "output_tokens": 10,
            "total_tokens": 110,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens_details": {"reasoning_tokens": 2},
        },
    }
    body.update(overrides)
    return body


def test_parse_response_text_and_correlated_calls():
    response = parse_response(
        {
            "id": "resp_9",
            "model": "muse-spark-1.3",
            "status": "completed",
            "output": [
                {
                    "type": "function_call",
                    "name": "get_summary",
                    "arguments": '{"limit": 5}',
                    "call_id": "call_1",
                    "status": "completed",
                }
            ],
            "usage": {
                "input_tokens": 100,
                "output_tokens": 10,
                "total_tokens": 110,
                "input_tokens_details": {"cached_tokens": 0},
                "output_tokens_details": {"reasoning_tokens": 0},
            },
        },
        expected_model="muse-spark-1.3",
        max_output_tokens=2048,
        input_upper=5000,
    )
    assert response.text == ""
    assert len(response.tool_calls) == 1
    assert response.tool_calls[0].call_id == "call_1"
    assert response.tool_calls[0].arguments == {"limit": 5}
    assert response.usage["reasoning_tokens"] == 0
    assert response.response_id == "resp_9"


def test_parse_response_rejects_shapes():
    with pytest.raises(ProviderError):
        parse_response(
            _payload(output=[{"type": "mystery"}]),
            expected_model="muse-spark-1.3",
            max_output_tokens=2048,
            input_upper=5000,
        )
    with pytest.raises(ProviderError):
        parse_response(
            _payload(
                output=[
                    {"type": "function_call", "name": "x", "arguments": "nope", "call_id": "c1"}
                ]
            ),
            expected_model="muse-spark-1.3",
            max_output_tokens=2048,
            input_upper=5000,
        )
    with pytest.raises(ProviderError):
        parse_response(
            _payload(
                output=[{"type": "function_call", "name": "x", "arguments": "[]", "call_id": "c1"}]
            ),
            expected_model="muse-spark-1.3",
            max_output_tokens=2048,
            input_upper=5000,
        )
    with pytest.raises(ProviderError):
        parse_response(
            _payload(
                output=[{"type": "function_call", "name": "x", "arguments": "{}", "call_id": ""}]
            ),
            expected_model="muse-spark-1.3",
            max_output_tokens=2048,
            input_upper=5000,
        )
    with pytest.raises(ProviderError):
        parse_response(
            "nope", expected_model="muse-spark-1.3", max_output_tokens=2048, input_upper=5000
        )


def test_wire_pins_low_reasoning_profile():
    import copy

    from app.ai.providers.meta_responses import REASONING_EFFORT, validate_body

    assert REASONING_EFFORT == "low"
    body = build_dispatch_body(
        model="muse-spark-1.3",
        max_output_tokens=2048,
        instructions="sys",
        user_text="q",
        exchanges=[],
        tools=[],
    )
    assert body["reasoning"] == {"effort": "low"}
    assert body["max_output_tokens"] == 2048
    wire = serialize_body(body)
    assert b'"reasoning":{"effort":"low"}' in wire
    tampered = copy.deepcopy(body)
    tampered["reasoning"] = {"effort": "high"}
    with pytest.raises(ProviderError):
        validate_body(serialize_body(tampered), expected_model="muse-spark-1.3")


def test_parse_response_validates_id_bounds():
    import copy

    good = _payload()
    parse_response(good, expected_model="muse-spark-1.3", max_output_tokens=2048, input_upper=5000)
    missing = copy.deepcopy(good)
    del missing["id"]
    with pytest.raises(ProviderError):
        parse_response(
            missing, expected_model="muse-spark-1.3", max_output_tokens=2048, input_upper=5000
        )
    long_id = copy.deepcopy(good)
    long_id["id"] = "r" * 129
    with pytest.raises(ProviderError):
        parse_response(
            long_id, expected_model="muse-spark-1.3", max_output_tokens=2048, input_upper=5000
        )


def test_body_build_serialize_deterministic_and_stateless():
    body = build_dispatch_body(
        model="muse-spark-1.3",
        max_output_tokens=2048,
        instructions="sys",
        user_text="q",
        exchanges=[
            {
                "calls": [{"call_id": "call_1", "name": "get_summary", "arguments": {"limit": 5}}],
                "outputs": [{"call_id": "call_1", "evidence": {"items": []}}],
            }
        ],
        tools=[{"name": "get_summary"}],
    )
    assert body["store"] is False
    assert "previous_response_id" not in body
    kinds = [item["type"] for item in body["input"]]
    assert kinds == ["message", "function_call", "function_call_output"]
    assert body["input"][2]["call_id"] == "call_1"
    assert serialize_body(body) == serialize_body(json.loads(json.dumps(body)))
    assert len(serialize_body(body)) < MAX_WIRE_BYTES


def _ok_transport(captured):
    def run(*, url, headers, body, timeout_s, max_response_bytes):
        captured.append({"url": url, "headers": dict(headers), "body": body})
        return _payload()

    return run


def test_complete_posts_exact_bytes_with_bearer():
    captured: list = []
    adapter = MetaResponsesAdapter(
        endpoint=ENDPOINT, model="muse-spark-1.3", api_key=KEY, transport=_ok_transport(captured)
    )
    wire = (
        b'{"model":"muse-spark-1.3","reasoning":{"effort":"low"},'
        b'"store":false,"pad":"' + b"x" * 200 + b'"}'
    )
    response = adapter.complete(
        ProviderRequest(prompt_text="q", max_output_tokens=2048, body=wire),
        cancel=threading.Event(),
    )
    assert captured[0]["url"] == "https://api.meta.ai:443/v1/responses"
    assert captured[0]["body"] == wire
    assert captured[0]["headers"]["Authorization"] == f"Bearer {KEY}"
    assert isinstance(response, ProviderResponse)
    assert KEY not in repr(adapter) and "Bearer" not in repr(adapter)


def test_complete_honors_cancel_and_empty_body():
    adapter = MetaResponsesAdapter(
        endpoint=ENDPOINT,
        model="muse-spark-1.3",
        api_key=KEY,
        transport=_ok_transport([]),
    )
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(ProviderCancelled):
        adapter.complete(
            ProviderRequest(prompt_text="q", max_output_tokens=2048, body=b"{}"),
            cancel=cancel,
        )
    with pytest.raises(ProviderError):
        adapter.complete(
            ProviderRequest(prompt_text="q", max_output_tokens=2048, body=b""),
            cancel=threading.Event(),
        )


def test_adapter_needs_endpoint_model_and_key():
    with pytest.raises(ProviderError):
        MetaResponsesAdapter(endpoint="", model="muse-spark-1.3", api_key=KEY)
    with pytest.raises(ProviderError):
        MetaResponsesAdapter(endpoint=ENDPOINT, model="", api_key=KEY)
    with pytest.raises(ProviderError):
        MetaResponsesAdapter(endpoint=ENDPOINT, model="muse-spark-1.3", api_key="")


def test_response_tool_definitions_match_protocol():
    from app.ai.tools.definitions import TOOL_NAMES, response_tool_definitions

    catalog = response_tool_definitions()
    assert [item["name"] for item in catalog] == list(TOOL_NAMES)
    for item in catalog:
        assert item["type"] == "function"
        assert "parameters" in item and "arguments" not in item
        assert item["parameters"].get("type") == "object"


def test_parse_response_accepts_bounded_reasoning_and_validates_meta():
    import copy

    good = _payload(
        model="muse-spark-1.3",
        status="completed",
        output=[
            {"type": "reasoning", "summary": []},
            {"type": "message", "content": [{"type": "output_text", "text": "hi"}]},
        ],
    )
    response = parse_response(
        good, expected_model="muse-spark-1.3", max_output_tokens=2048, input_upper=5000
    )
    assert response.text == "hi"
    bad_status = copy.deepcopy(good)
    bad_status["status"] = "incomplete"
    with pytest.raises(ProviderError):
        parse_response(
            bad_status, expected_model="muse-spark-1.3", max_output_tokens=2048, input_upper=5000
        )
    bad_model = copy.deepcopy(good)
    bad_model["model"] = "muse-spark-1.3-contributor"
    with pytest.raises(ProviderError):
        parse_response(
            bad_model, expected_model="muse-spark-1.3", max_output_tokens=2048, input_upper=5000
        )
    bad_total = copy.deepcopy(good)
    bad_total["usage"]["total_tokens"] = 999
    with pytest.raises(ProviderError):
        parse_response(
            bad_total, expected_model="muse-spark-1.3", max_output_tokens=2048, input_upper=5000
        )
    bad_reasoning = copy.deepcopy(good)
    bad_reasoning["output"][0] = {"type": "reasoning", "summary": "not-a-list"}
    with pytest.raises(ProviderError):
        parse_response(
            bad_reasoning, expected_model="muse-spark-1.3", max_output_tokens=2048, input_upper=5000
        )


def test_validate_body_binding_rejects_before_transport():
    from app.ai.providers.meta_responses import validate_body

    good = serialize_body(
        {
            "model": "muse-spark-1.3",
            "reasoning": {"effort": "low"},
            "store": False,
            "input": [],
        }
    )
    assert validate_body(good, expected_model="muse-spark-1.3") is None
    evil = serialize_body(
        {
            "model": "muse-spark-1.3-contributor",
            "reasoning": {"effort": "low"},
            "store": False,
            "input": [],
        }
    )
    with pytest.raises(ProviderError):
        validate_body(evil, expected_model="muse-spark-1.3")
    stored = serialize_body(
        {
            "model": "muse-spark-1.3",
            "reasoning": {"effort": "low"},
            "store": True,
            "previous_response_id": "resp_1",
            "input": [],
        }
    )
    with pytest.raises(ProviderError):
        validate_body(stored, expected_model="muse-spark-1.3")


def test_native_transport_wrapper_with_stub_opener():

    from app.ai.providers import meta_responses as native

    class StubResponse:
        def __init__(self, raw, exc=None):
            self.raw = raw
            self.exc = exc
            self.read_sizes = []

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size):
            self.read_sizes.append(size)
            if self.exc is not None:
                raise self.exc
            return self.raw

    class StubOpener:
        def __init__(self, response=None, exc=None):
            self.response = response
            self.exc = exc
            self.requests = []

        def open(self, request, timeout=None):
            self.requests.append((request.full_url, timeout))
            if self.exc is not None:
                raise self.exc
            return self.response

    import ssl as ssl_mod

    # Real opener factory carries redirect refusal with real signatures.
    opener = native._default_opener(ssl_mod.create_default_context())
    assert any(isinstance(h, native._NoRedirect) for h in opener.handlers)
    # TLS context creation happens on the native path (no network here:
    # the stub opener answers with real method signatures).
    created = []
    real_ctx = ssl_mod.create_default_context
    ssl_mod.create_default_context = lambda *a, **k: created.append(True) or real_ctx()
    try:
        native._urllib_transport(
            url=ENDPOINT,
            headers={},
            body=b"{}",
            timeout_s=5.0,
            max_response_bytes=100,
            opener_factory=lambda ctx: StubOpener(StubResponse(b'{"a": 1}')),
        )
    finally:
        ssl_mod.create_default_context = real_ctx
    assert created, "native path must create a TLS context"

    stub = StubOpener(StubResponse(b"not json"))
    with pytest.raises(ProviderError):
        native._urllib_transport(
            url=ENDPOINT,
            headers={},
            body=b"{}",
            timeout_s=5.0,
            max_response_bytes=100,
            opener_factory=lambda ctx: stub,
        )
    assert stub.requests[0][0].startswith("https://") and stub.requests[0][1] == 5.0

    slow = StubOpener(StubResponse(b"", exc=TimeoutError()))
    with pytest.raises(ProviderTimeout):
        native._urllib_transport(
            url=ENDPOINT,
            headers={},
            body=b"{}",
            timeout_s=5.0,
            max_response_bytes=100,
            opener_factory=lambda ctx: slow,
        )

    big = StubOpener(StubResponse(b"x" * 200))
    with pytest.raises(ProviderError):
        native._urllib_transport(
            url=ENDPOINT,
            headers={},
            body=b"{}",
            timeout_s=5.0,
            max_response_bytes=100,
            opener_factory=lambda ctx: big,
        )
    sent_before = len(stub.requests)
    with pytest.raises(ProviderError):
        native._urllib_transport(
            url=ENDPOINT,
            headers={},
            body=b"x" * (MAX_WIRE_BYTES + 1),
            timeout_s=5.0,
            max_response_bytes=100,
            opener_factory=lambda ctx: stub,
        )
    assert len(stub.requests) == sent_before, "oversize bodies never reach the opener"


def test_build_validates_decoded_values_before_encoding():
    """R4: a fullwidth-IP matcher hidden behind JSON escapes must fail at build."""
    from app.ai.egress import EgressViolation, check_outgoing

    fullwidth_ip = "２０３.０.１１３.５"
    # Direct check blocks it; the dispatch path must too, on DECODED values
    # (the JSON-encoded body would hide it behind \\u escapes).
    with pytest.raises(EgressViolation):
        check_outgoing(fullwidth_ip, context="t")
    with pytest.raises(EgressViolation):
        build_dispatch_body(
            model="muse-spark-1.3",
            max_output_tokens=2048,
            instructions="sys",
            user_text="q",
            exchanges=[
                {
                    "calls": [
                        {
                            "call_id": "call_1",
                            "name": "get_top_paths",
                            "arguments": {"limit": 5, "path_prefix": fullwidth_ip},
                        }
                    ],
                    "outputs": [{"call_id": "call_1", "evidence": {"items": []}}],
                }
            ],
            tools=[],
        )
    # Benign decoded values still build.
    body = build_dispatch_body(
        model="muse-spark-1.3",
        max_output_tokens=2048,
        instructions="sys",
        user_text="q",
        exchanges=[],
        tools=[],
    )
    assert body["store"] is False


def test_select_provider_binds_all_or_unavailable():
    from app.ai.service import select_provider
    from app.config import Settings

    base = {
        "ai_enabled": True,
        "model_data_policy_verified": True,
        "model_allow_real_data": True,
        "llm_daily_limit_usd": 50.0,
        "llm_budget_usd": 150.0,
        "llm_warn_at_usd": 120.0,
        "llm_stop_at_usd": 140.0,
    }
    with pytest.raises(BackendUnavailable):
        select_provider(Settings(**base))  # no endpoint, no key
    with pytest.raises(BackendUnavailable):
        select_provider(Settings(**base, model_endpoint=ENDPOINT))  # no key
    with pytest.raises(BackendUnavailable):
        select_provider(Settings(**base, model_endpoint="https://evil.example.org/v1/responses"))
    adapter = select_provider(
        Settings(
            **base,
            model_endpoint=ENDPOINT,
            model_api_key="synthetic-test-key-never-a-real-secret",
        )
    )
    assert adapter.name == "meta-responses"
