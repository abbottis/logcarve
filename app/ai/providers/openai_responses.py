"""Real OpenAI Responses transport over stdlib HTTP.

Native ``POST https://api.openai.com/v1/responses`` with
``Authorization: Bearer`` (key in header, never in URL), ``store:
false``, explicit ``service_tier: "default"`` for standard
pricing/performance (omission would inherit the Project's configured
tier), explicit ``strict: false`` on the direct function tools
(deliberate non-strict opt-out) and explicit ``call_id`` correlation. Stateless: every turn
carries the user message plus the prior typed
``function_call``/``function_call_output`` pairs the service hands
over. No ``previous_response_id``, no replayed reasoning items, no
hosted/programmatic/shell/search tools. Reasoning effort ``none``
keeps function calling while avoiding hidden-reasoning replay.

Zero automatic retries: any transport or mapping failure surfaces to
the caller, which keeps the step hold and reports unavailable.

No network, key file or account access happens at import or in tests:
tests inject ``transport`` (or drive the pure build/parse helpers).
The product key lives only in the adapter instance built for a real
run and never enters logs, exceptions, responses or usage records.
"""

import json
import threading
from collections.abc import Callable
from urllib.parse import urlsplit

from app.ai.egress import MAX_WIRE_BYTES
from app.ai.providers import _http
from app.ai.providers.base import (
    ProviderAdapter,
    ProviderCancelled,
    ProviderError,
    ProviderRequest,
    ProviderResponse,
    ToolCall,
)

ENDPOINT_HOST = "api.openai.com"
ENDPOINT_PORT = 443
ENDPOINT_PATH = "/v1/responses"

#: Verified Luna Standard pricing, task reference 2026-11-02
#: (https://developers.openai.com/api/docs/pricing): input USD 0.10/M,
#: cached input USD 0.01/M (a SUBSET of input), output USD 0.50/M.
#: Never add cached tokens on top of the input total.
PRICING_VERSION = "2026-11-02-developers.openai.com"
PRICE_INPUT_MICRO_PER_M = 100_000
PRICE_CACHED_MICRO_PER_M = 10_000
PRICE_OUTPUT_MICRO_PER_M = 500_000
MICRO_PER_TOKEN_UNIT = 1_000_000

#: Small documented framing margin added to the exact immutable body
#: byte length for the input-token upper bound.
WIRE_FRAMING_TOKENS = 64

#: Responses function_call call_id bounds (documented 1..64 chars).
CALL_ID_MAX_LEN = 64

#: Fixed product inference profile: no reasoning effort keeps
#: investigations cheap while preserving function calling.
REASONING_EFFORT = "none"

#: Fixed processing tier: explicit ``service_tier: "default"`` uses
#: standard model pricing/performance. An omitted field would inherit
#: the Project's configured tier instead, so omission fails the
#: dispatch check. The request flag alone does not prove how the
#: provider actually processed the call; the response tier is checked
#: separately in :func:`parse_response`.
SERVICE_TIER = "default"

#: Bound on server response IDs kept in safe metadata (opaque, short).
RESPONSE_ID_MAX_LEN = 128


def parse_endpoint(raw: str) -> str:
    """Accept exactly the allowlisted endpoint; fail closed otherwise."""
    if not isinstance(raw, str) or not raw:
        raise ProviderError("The configured model endpoint is missing.")
    try:
        parts = urlsplit(raw)
    except ValueError as exc:
        raise ProviderError("The configured model endpoint is invalid.") from exc
    if parts.scheme != "https":
        raise ProviderError("The configured model endpoint must use HTTPS.")
    if parts.username or parts.password:
        raise ProviderError("The configured model endpoint must not carry credentials.")
    if parts.query or parts.fragment:
        raise ProviderError("The configured model endpoint must not carry query data.")
    if (parts.hostname or "") != ENDPOINT_HOST:
        raise ProviderError("The configured model endpoint host is not allowlisted.")
    if (parts.port or 443) != ENDPOINT_PORT:
        raise ProviderError("The configured model endpoint port is not allowlisted.")
    if parts.path != ENDPOINT_PATH:
        raise ProviderError("The configured model endpoint path is not allowlisted.")
    return f"https://{ENDPOINT_HOST}:{ENDPOINT_PORT}{ENDPOINT_PATH}"


def build_dispatch_body(
    *,
    model: str,
    max_output_tokens: int,
    instructions: str,
    user_text: str,
    exchanges: list,
    tools: list,
) -> dict:
    """Assemble the decoded wire body from already-gated values.

    Replay decision: only (a) the user message, (b) prior assistant
    ``function_call`` items this adapter produced, (c) our paired
    ``function_call_output`` items. No reasoning items, no
    ``previous_response_id``, no raw responses.

    Decoded values are egress-validated BEFORE ``arguments`` and
    ``output`` are JSON-encoded, so forbidden content cannot hide
    behind escapes.

    The direct function tools carry explicit ``strict: false``: the
    Responses API otherwise attempts strict schema normalization and
    only falls back to non-strict when needed, so omission is not a
    non-strict default. The flag is set on per-dispatch copies —
    the shared tool schemas (also used by Meta/Gemini/Claude) are
    never mutated.

    The body carries explicit ``service_tier: "default"`` for
    standard pricing/performance: omitting the field would inherit
    the Project's configured tier instead.
    """
    from app.ai.egress import check_wire_values

    check_wire_values(
        {
            "model": model,
            "instructions": instructions,
            "user_text": user_text,
            "exchanges": exchanges,
            "tools": tools,
        },
        context="provider dispatch",
    )
    if not isinstance(tools, list) or not tools:
        raise ProviderError("The provider dispatch tools are malformed.")
    wire_tools: list = []
    for tool in tools:
        if (
            not isinstance(tool, dict)
            or tool.get("type") != "function"
            or not isinstance(tool.get("name"), str)
            or not tool.get("name")
            or not isinstance(tool.get("parameters"), dict)
        ):
            raise ProviderError("The provider dispatch tools are malformed.")
        wire_tools.append({**tool, "strict": False})
    items: list = [
        {
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": user_text}],
        }
    ]
    for exchange in exchanges:
        for call in exchange.get("calls", ()):  # type: ignore[union-attr]
            items.append(
                {
                    "type": "function_call",
                    "call_id": call["call_id"],
                    "name": call["name"],
                    "arguments": json.dumps(
                        call["arguments"], sort_keys=True, separators=(",", ":")
                    ),
                }
            )
        for output in exchange.get("outputs", ()):  # type: ignore[union-attr]
            items.append(
                {
                    "type": "function_call_output",
                    "call_id": output["call_id"],
                    "output": json.dumps(output["evidence"], sort_keys=True, separators=(",", ":")),
                    "status": "completed",
                }
            )
    return {
        "model": model,
        "instructions": instructions,
        "input": items,
        "tools": wire_tools,
        "reasoning": {"effort": REASONING_EFFORT},
        "store": False,
        "service_tier": SERVICE_TIER,
        "max_output_tokens": max_output_tokens,
    }


def serialize_body(body: dict) -> bytes:
    """Immutable serialization: fixed key order and separators."""
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def validate_body(wire: bytes, *, expected_model: str) -> None:
    """Enforce immutable body/model/stateless binding before any send."""
    if not isinstance(wire, bytes) or not wire:
        raise ProviderError("The provider dispatch is malformed.")
    try:
        body = json.loads(wire.decode("utf-8"))
    except ValueError as exc:
        raise ProviderError("The provider dispatch is malformed.") from exc
    if not isinstance(body, dict):
        raise ProviderError("The provider dispatch is malformed.")
    if body.get("model") != expected_model:
        raise ProviderError("The provider dispatch model is not allowlisted.")
    if body.get("store") is not False or "previous_response_id" in body:
        raise ProviderError("The provider dispatch must be stateless.")
    if body.get("reasoning") != {"effort": REASONING_EFFORT}:
        raise ProviderError("The provider dispatch reasoning profile is not allowlisted.")
    if body.get("service_tier") != SERVICE_TIER:
        raise ProviderError("The provider dispatch processing tier is not allowlisted.")
    wire_tools = body.get("tools")
    if not isinstance(wire_tools, list) or not wire_tools:
        raise ProviderError("The provider dispatch tools are malformed.")
    for tool in wire_tools:
        if (
            not isinstance(tool, dict)
            or tool.get("type") != "function"
            or not isinstance(tool.get("name"), str)
            or not tool.get("name")
            or not isinstance(tool.get("parameters"), dict)
            or tool.get("strict") is not False
        ):
            raise ProviderError("The provider dispatch tools are malformed.")


def cost_micro_usd(*, input_tokens: int, cached_tokens: int, output_tokens: int) -> int:
    """Integer micro-USD charge; cached is a subset of input."""
    if (
        isinstance(input_tokens, bool)
        or isinstance(cached_tokens, bool)
        or isinstance(output_tokens, bool)
        or not isinstance(input_tokens, int)
        or not isinstance(cached_tokens, int)
        or not isinstance(output_tokens, int)
        or input_tokens < 0
        or cached_tokens < 0
        or output_tokens < 0
        or cached_tokens > input_tokens
    ):
        raise ProviderError("The provider usage is malformed.")
    uncached = input_tokens - cached_tokens
    total = (
        uncached * PRICE_INPUT_MICRO_PER_M
        + cached_tokens * PRICE_CACHED_MICRO_PER_M
        + output_tokens * PRICE_OUTPUT_MICRO_PER_M
    )
    return max(1, (total + MICRO_PER_TOKEN_UNIT - 1) // MICRO_PER_TOKEN_UNIT)


def validate_usage(payload: object, *, max_output_tokens: int, input_upper: int) -> dict:
    """Validate a Responses ``usage`` object into safe counts."""
    if not isinstance(payload, dict):
        raise ProviderError("The provider usage is malformed.")
    for name in ("input_tokens", "output_tokens", "total_tokens"):
        tokens = payload.get(name)
        if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 0:
            raise ProviderError("The provider usage is malformed.")
    details_in = payload.get("input_tokens_details", {})
    cached = details_in.get("cached_tokens", 0) if isinstance(details_in, dict) else None
    if isinstance(cached, bool) or not isinstance(cached, int) or cached < 0:
        raise ProviderError("The provider usage is malformed.")
    usage = {
        "input_tokens": payload["input_tokens"],
        "output_tokens": payload["output_tokens"],
        "cached_tokens": cached,
        "reasoning_tokens": 0,
    }
    if cached > usage["input_tokens"]:
        raise ProviderError("The provider usage is malformed.")
    if payload["total_tokens"] != usage["input_tokens"] + usage["output_tokens"]:
        raise ProviderError("The provider usage is malformed.")
    if usage["output_tokens"] > max_output_tokens or usage["input_tokens"] > input_upper:
        raise ProviderError("The provider usage exceeds its requested bounds.")
    return usage


#: Bound on known reasoning-item summaries kept per response; reasoning
#: content is validated for shape and ignored, never forwarded or logged.
REASONING_SUMMARY_MAX_ITEMS = 100


def parse_response(
    payload: object, *, expected_model: str, max_output_tokens: int, input_upper: int
) -> ProviderResponse:
    """Parse one Responses body into text, correlated calls and usage.

    The response ``service_tier`` reports how the call was actually
    processed and may differ from the requested tier. An absent or
    null field stays compatible with older payloads; an explicit
    non-default tier fails closed instead of being accounted at
    standard rates.
    """
    if not isinstance(payload, dict):
        raise ProviderError("The provider answer is malformed.")
    if payload.get("status") != "completed":
        raise ProviderError("The provider response is not complete.")
    if payload.get("model") != expected_model:
        raise ProviderError("The provider response model is not allowlisted.")
    reported_tier = payload.get("service_tier", None)
    if reported_tier is not None and reported_tier != SERVICE_TIER:
        raise ProviderError("The provider response processing tier is not standard.")
    response_id = payload.get("id", "")
    if not isinstance(response_id, str) or not 1 <= len(response_id) <= RESPONSE_ID_MAX_LEN:
        raise ProviderError("The provider answer is malformed.")
    output = payload.get("output")
    if not isinstance(output, list):
        raise ProviderError("The provider answer is malformed.")
    texts: list[str] = []
    calls: list[ToolCall] = []
    for item in output:
        if not isinstance(item, dict):
            raise ProviderError("The provider answer is malformed.")
        kind = item.get("type")
        if kind == "function_call":
            name = item.get("name")
            raw_args = item.get("arguments", "{}")
            call_id = item.get("call_id", "")
            if (
                not isinstance(name, str)
                or not name
                or not isinstance(raw_args, str)
                or not isinstance(call_id, str)
                or not 1 <= len(call_id) <= CALL_ID_MAX_LEN
            ):
                raise ProviderError("A provider tool call is malformed.")
            try:
                arguments = json.loads(raw_args)
            except ValueError as exc:
                raise ProviderError("A provider tool call is malformed.") from exc
            if not isinstance(arguments, dict):
                raise ProviderError("A provider tool call is malformed.")
            calls.append(ToolCall(name=name, arguments=arguments, call_id=call_id))
        elif kind == "message":
            content = item.get("content", [])
            if not isinstance(content, list):
                raise ProviderError("The provider answer is malformed.")
            for part in content:
                if not isinstance(part, dict):
                    raise ProviderError("The provider answer is malformed.")
                if part.get("type") in ("output_text", "text"):
                    text = part.get("text", "")
                    if not isinstance(text, str):
                        raise ProviderError("The provider answer is malformed.")
                    texts.append(text)
        elif kind == "reasoning":
            summary = item.get("summary", [])
            if not isinstance(summary, list) or len(summary) > REASONING_SUMMARY_MAX_ITEMS:
                raise ProviderError("The provider answer is malformed.")
        else:
            raise ProviderError("The provider answer carries an unknown item type.")
    usage = validate_usage(
        payload.get("usage"), max_output_tokens=max_output_tokens, input_upper=input_upper
    )
    return ProviderResponse(
        text="".join(texts),
        input_tokens=usage["input_tokens"],
        output_tokens=usage["output_tokens"],
        tool_calls=tuple(calls),
        usage=usage,
        response_id=response_id,
    )


class OpenAIResponsesAdapter(ProviderAdapter):
    """Real OpenAI Responses adapter (stdlib transport, zero retries)."""

    name = "openai-responses"

    def __init__(
        self,
        *,
        endpoint: str,
        model: str,
        api_key,
        timeout_s: float = 30.0,
        transport: Callable | None = None,
        max_response_bytes: int = 262144,
    ) -> None:
        self.endpoint = parse_endpoint(endpoint)
        if not isinstance(model, str) or not model:
            raise ProviderError("The configured model is missing.")
        self.model = model
        secret = api_key.get_secret_value() if hasattr(api_key, "get_secret_value") else api_key
        if not isinstance(secret, str) or not secret:
            raise ProviderError("The product key is missing.")
        self._key = secret
        self.timeout_s = timeout_s
        self._transport = transport or _http.post_json
        self.max_response_bytes = max_response_bytes

    def __repr__(self) -> str:
        return f"OpenAIResponsesAdapter(model={self.model!r}, endpoint=<allowlisted>)"

    def check_dispatch(self, body: bytes) -> None:
        """Enforce body/model/stateless binding before admission or send."""
        validate_body(body, expected_model=self.model)

    def complete(self, request: ProviderRequest, *, cancel: threading.Event) -> ProviderResponse:
        if cancel.is_set():
            raise ProviderCancelled("The investigation was cancelled.")
        body = request.body
        if not isinstance(body, bytes) or not body:
            raise ProviderError("The provider dispatch is malformed.")
        if len(body) > MAX_WIRE_BYTES:
            raise ProviderError("The provider dispatch exceeds its bound.")
        validate_body(body, expected_model=self.model)
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._key}",
        }
        payload = self._transport(
            url=self.endpoint,
            headers=headers,
            body=body,
            timeout_s=self.timeout_s,
            max_response_bytes=self.max_response_bytes,
            max_wire_bytes=MAX_WIRE_BYTES,
        )
        if cancel.is_set():
            raise ProviderCancelled("The investigation was cancelled.")
        return parse_response(
            payload,
            expected_model=self.model,
            max_output_tokens=request.max_output_tokens,
            input_upper=len(body) + WIRE_FRAMING_TOKENS,
        )
