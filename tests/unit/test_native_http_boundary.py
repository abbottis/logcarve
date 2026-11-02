"""Native adapters through the real shared HTTP helper (offline opener fakes).

Closes the HTTP-boundary gap: earlier adapter tests inject a scripted
``transport`` and the shared-helper test only calls
``redirect_request`` directly. Here each of the three new providers
(openai/gemini/anthropic) drives ``adapter.complete()`` through the
REAL ``_http.post_json`` with a fake urllib-level ``opener_factory``
— no sockets, no network, no real keys.

Covers per provider: success integration (exact normalized URL, TLS
context, timeout passthrough), refusal/auth/rate-limit/server errors
(401/403/429/500/503), timeout/network errors, oversize wire never
sent, oversize/malformed/non-dict answers, exactly one opener attempt
(no retries), and public errors free of key/URL/body material. One
shared test pins TLS + redirect refusal on the real opener chain.
"""

import json
import ssl
import threading
import urllib.error

import pytest

from app.ai.egress import MAX_WIRE_BYTES
from app.ai.providers import _http
from app.ai.providers import anthropic_messages as am
from app.ai.providers import gemini_generate as gg
from app.ai.providers import openai_responses as oai
from app.ai.providers.base import ProviderError, ProviderRequest, ProviderTimeout

KEY = "sk-synthetic-boundary-key-9f8e7d6c5b4a"
INSTRUCTIONS_SENTINEL = "SYNTHETIC-BOUNDARY-INSTRUCTIONS-aa55"
USER_SENTINEL = "synthetic boundary question bb66"


def _tools():
    return [
        {
            "type": "function",
            "name": "get_summary",
            "description": "Bounded read-only analytics read: get_summary.",
            "parameters": {"type": "object", "properties": {}},
        }
    ]


PROVIDERS = {
    "openai": {
        "module": oai,
        "adapter": oai.OpenAIResponsesAdapter,
        "endpoint": "https://api.openai.com/v1/responses",
        "normalized_url": "https://api.openai.com:443/v1/responses",
        "model": "gpt-6-luna",
        "payload": {
            "id": "resp_ok",
            "model": "gpt-6-luna",
            "status": "completed",
            "output": [{"type": "message", "content": [{"type": "output_text", "text": "ok"}]}],
            "usage": {"input_tokens": 10, "output_tokens": 2, "total_tokens": 12},
        },
    },
    "gemini": {
        "module": gg,
        "adapter": gg.GeminiGenerateContentAdapter,
        "endpoint": (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            "gemini-3.5-flash-lite:generateContent"
        ),
        "normalized_url": (
            "https://generativelanguage.googleapis.com:443/v1beta/models/"
            "gemini-3.5-flash-lite:generateContent"
        ),
        "model": "gemini-3.5-flash-lite",
        "payload": {
            "responseId": "resp_ok",
            "modelVersion": "gemini-3.5-flash-lite",
            "candidates": [
                {
                    "finishReason": "STOP",
                    "content": {"role": "model", "parts": [{"text": "ok"}]},
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 10,
                "candidatesTokenCount": 2,
                "totalTokenCount": 12,
            },
        },
    },
    "anthropic": {
        "module": am,
        "adapter": am.AnthropicMessagesAdapter,
        "endpoint": "https://api.anthropic.com/v1/messages",
        "normalized_url": "https://api.anthropic.com:443/v1/messages",
        "model": "claude-haiku-5-5",
        "payload": {
            "id": "msg_ok",
            "type": "message",
            "model": "claude-haiku-5-5",
            "role": "assistant",
            "stop_reason": "end_turn",
            "content": [{"type": "text", "text": "ok"}],
            "usage": {"input_tokens": 10, "output_tokens": 2},
        },
    },
}


class FakeResponse:
    """Minimal urllib response: context manager plus bounded read."""

    def __init__(self, raw: bytes):
        self._raw = raw

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, size=-1):
        if size is None or size < 0:
            return self._raw
        return self._raw[:size]


class FakeOpener:
    """Scripted opener: records attempts, then answers or raises."""

    def __init__(self, *, raw=None, exc=None):
        self._raw = raw
        self._exc = exc
        self.calls = []

    def open(self, request, timeout=None):
        self.calls.append((request.full_url, timeout, dict(request.header_items())))
        if self._exc is not None:
            raise self._exc
        return FakeResponse(self._raw)


def _wire(provider):
    cfg = PROVIDERS[provider]
    mod = cfg["module"]
    body = mod.build_dispatch_body(
        model=cfg["model"],
        max_output_tokens=64,
        instructions=INSTRUCTIONS_SENTINEL,
        user_text=USER_SENTINEL,
        exchanges=[],
        tools=_tools(),
    )
    return mod.serialize_body(body)


def _adapter(provider, opener):
    """Real adapter bound to the REAL helper over a fake opener."""
    cfg = PROVIDERS[provider]
    seen = {}

    def factory(context):
        seen["context"] = context
        return opener

    def transport(*, url, headers, body, timeout_s, max_response_bytes, max_wire_bytes):
        return _http.post_json(
            url=url,
            headers=headers,
            body=body,
            timeout_s=timeout_s,
            max_response_bytes=max_response_bytes,
            max_wire_bytes=max_wire_bytes,
            opener_factory=factory,
        )

    adapter = cfg["adapter"](
        endpoint=cfg["endpoint"], model=cfg["model"], api_key=KEY, transport=transport
    )
    return adapter, seen


def _complete(provider, opener):
    adapter, seen = _adapter(provider, opener)
    response = adapter.complete(
        ProviderRequest(prompt_text=USER_SENTINEL, max_output_tokens=64, body=_wire(provider)),
        cancel=threading.Event(),
    )
    return response, seen


def _assert_public_error(exc: ProviderError, opener: FakeOpener, cfg: dict):
    message = str(exc)
    assert KEY not in message
    assert INSTRUCTIONS_SENTINEL not in message
    assert USER_SENTINEL not in message
    assert cfg["normalized_url"] not in message
    assert cfg["endpoint"] not in message


@pytest.mark.parametrize("provider", sorted(PROVIDERS))
def test_native_success_through_real_http_helper(provider):
    cfg = PROVIDERS[provider]
    opener = FakeOpener(raw=json.dumps(cfg["payload"]).encode("utf-8"))
    response, seen = _complete(provider, opener)
    assert response.text == "ok"
    # Exactly one attempt: no retries.
    assert len(opener.calls) == 1
    url, timeout, headers = opener.calls[0]
    assert url == cfg["normalized_url"]
    assert timeout == 30.0
    lowered = {key.lower(): value for key, value in headers.items()}
    assert lowered["content-type"] == "application/json"
    assert "?" not in url
    # The real helper built a genuine TLS context for the dispatch.
    assert isinstance(seen["context"], ssl.SSLContext)


@pytest.mark.parametrize("provider", sorted(PROVIDERS))
@pytest.mark.parametrize("code", [401, 403, 429, 500, 503])
def test_refusal_and_server_errors_are_public_and_single_attempt(provider, code):
    cfg = PROVIDERS[provider]
    opener = FakeOpener(
        exc=urllib.error.HTTPError(cfg["normalized_url"], code, "refused", {}, None)
    )
    with pytest.raises(ProviderError) as excinfo:
        _complete(provider, opener)
    assert "refused" in str(excinfo.value)
    assert len(opener.calls) == 1
    _assert_public_error(excinfo.value, opener, cfg)


@pytest.mark.parametrize("provider", sorted(PROVIDERS))
@pytest.mark.parametrize(
    "exc",
    [
        urllib.error.URLError("synthetic connection refused"),
        TimeoutError("synthetic slow network"),
    ],
)
def test_timeout_and_network_errors_map_to_provider_timeout(provider, exc):
    cfg = PROVIDERS[provider]
    opener = FakeOpener(exc=exc)
    with pytest.raises(ProviderTimeout) as excinfo:
        _complete(provider, opener)
    assert len(opener.calls) == 1
    _assert_public_error(excinfo.value, opener, cfg)


@pytest.mark.parametrize("provider", sorted(PROVIDERS))
def test_oversize_wire_never_reaches_opener(provider):
    opener = FakeOpener(raw=b"{}")
    adapter, _ = _adapter(provider, opener)
    with pytest.raises(ProviderError):
        adapter.complete(
            ProviderRequest(
                prompt_text=USER_SENTINEL,
                max_output_tokens=64,
                body=b"x" * (MAX_WIRE_BYTES + 1),
            ),
            cancel=threading.Event(),
        )
    assert opener.calls == []


@pytest.mark.parametrize("provider", sorted(PROVIDERS))
def test_oversize_and_malformed_answers_rejected(provider):
    cfg = PROVIDERS[provider]
    for raw in (
        b"x" * 300000,  # oversize answer
        b"not json at all",  # malformed answer
        b"[1, 2, 3]",  # valid JSON but not an object
    ):
        opener = FakeOpener(raw=raw)
        with pytest.raises(ProviderError):
            _complete(provider, opener)
        assert len(opener.calls) == 1
    opener = FakeOpener(raw=b"not json at all")
    try:
        _complete(provider, opener)
    except ProviderError as exc:
        _assert_public_error(exc, opener, cfg)


def test_shared_opener_refuses_redirects_over_tls():
    """The real opener chain carries TLS plus redirect refusal."""
    opener = _http._default_opener(ssl.create_default_context())
    assert any(isinstance(h, _http._NoRedirect) for h in opener.handlers)
    assert any(isinstance(h, urllib.request.HTTPSHandler) for h in opener.handlers)
    handler = _http._NoRedirect()
    for code in (301, 302, 303, 307, 308):
        assert handler.redirect_request(None, None, code, None, None, None) is None
