"""Real Anthropic Claude Messages transport over stdlib HTTP.

Native ``POST https://api.anthropic.com/v1/messages`` with
``Authorization: Bearer`` (key in header, never in URL),
``anthropic-version: 2026-10-21`` and JSON content. Non-workspace
keys may carry the optional bounded ``anthropic-workspace-id`` header
when the operator configures it. Every request carries explicit
``service_tier: "standard_only"`` for standard-capacity processing
(the documented ``"auto"`` default would use Priority capacity when
available). Tools use ``{name, description,
input_schema}``; the assistant ``tool_use`` id/input replays as the
user ``tool_result`` with the matching ``tool_use_id``, preserving
order. Stateless: every turn carries the system prompt, the user
message and the prior typed tool_use/tool_result pairs the service
hands over.

Stop handling: only ``end_turn`` and ``tool_use`` complete; truncated
(``max_tokens``), refused or unsupported blocks fail closed. Thinking
is disabled where supported; no tool runs outside the app allowlist.

Total input is ``input_tokens`` + ``cache_creation_input_tokens`` +
``cache_read_input_tokens`` (these are disjoint counts): creation and
read details are preserved, never double-counted and never dropped.

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

ENDPOINT_HOST = "api.anthropic.com"
ENDPOINT_PORT = 443
ENDPOINT_PATH = "/v1/messages"

#: Required API version header (migration 2026-10-21).
ANTHROPIC_VERSION = "2026-10-21"

#: Fixed processing tier: explicit ``service_tier: "standard_only"``
#: uses only standard capacity. The documented default ``"auto"``
#: would use Priority capacity when available, so omission fails the
#: dispatch check. The request flag alone does not prove how the
#: provider actually processed the call; the response usage tier is
#: checked separately in :func:`validate_usage`.
SERVICE_TIER = "standard_only"

#: Response usage tier billed at the standard rates enforced here.
RESPONSE_STANDARD_TIER = "standard"

#: Verified Haiku 5.5 standard API pricing, task reference
#: 2026-11-02 (https://platform.claude.com/docs/en/about-claude/pricing),
#: tiered on total input tokens: small prompts (<=100k input) USD
#: 0.10/M in, 0.50/M out, 0.01/M cached; larger prompts USD 0.50/M
#: in, 2.50/M out, 0.05/M cached. Cache WRITES are billed above the
#: input rate: 5-minute writes 1.25x (USD 0.125/M small, 0.625/M
#: large), 1-hour writes 2x (USD 0.20/M small, 1.00/M large). Cache
#: creation/read counts are disjoint input components; creation of
#: unknown TTL is priced conservatively at the highest supported
#: (1-hour) rate, reads at the cached rate, so nothing is
#: undercharged.
PRICING_VERSION = "2026-11-02-platform.claude.com"
SMALL_INPUT_MAX = 100_000
PRICE_INPUT_MICRO_PER_M = 100_000
PRICE_OUTPUT_MICRO_PER_M = 500_000
PRICE_CACHED_MICRO_PER_M = 10_000
PRICE_CREATE_5M_MICRO_PER_M = 125_000
PRICE_CREATE_1H_MICRO_PER_M = 200_000
PRICE_INPUT_LARGE_MICRO_PER_M = 500_000
PRICE_OUTPUT_LARGE_MICRO_PER_M = 2_500_000
PRICE_CACHED_LARGE_MICRO_PER_M = 50_000
PRICE_CREATE_5M_LARGE_MICRO_PER_M = 625_000
PRICE_CREATE_1H_LARGE_MICRO_PER_M = 1_000_000
MICRO_PER_TOKEN_UNIT = 1_000_000

#: Conservative framing margin added to the exact immutable body byte
#: length for the input-token upper bound. Deliberately larger than
#: the byte-exact wire size: it also covers native protocol framing
#: plus hidden provider-side tool scaffolding that never appears in
#: the dispatched bytes but can enter the billed input count.
WIRE_FRAMING_TOKENS = 256

#: Messages tool_use id bounds (documented short opaque IDs).
TOOL_USE_ID_MAX_LEN = 64

#: Bound on server response IDs kept in safe metadata (opaque, short).
RESPONSE_ID_MAX_LEN = 128

#: Bound on the optional workspace ID header value.
WORKSPACE_ID_MAX_LEN = 128


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


def validate_workspace_id(raw: object) -> str:
    """Validate the optional workspace ID; empty means unset."""
    if raw is None:
        return ""
    if not isinstance(raw, str):
        raise ProviderError("The workspace ID is malformed.")
    value = raw.strip()
    if not value:
        return ""
    if len(value) > WORKSPACE_ID_MAX_LEN:
        raise ProviderError("The workspace ID is malformed.")
    if any(char.isspace() or char in "<>\"'&" for char in value):
        raise ProviderError("The workspace ID is malformed.")
    return value


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

    Replay decision: the system prompt, the user message and, in
    order, prior assistant ``tool_use`` blocks plus the paired user
    ``tool_result`` blocks the service hands over. Thinking stays
    disabled; no other history.

    The body carries explicit ``service_tier: "standard_only"`` for
    standard-capacity processing: the documented default ``"auto"``
    would use Priority capacity when available.

    Decoded values are egress-validated BEFORE evidence is
    JSON-encoded, so forbidden content cannot hide behind escapes.
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
    native_tools = []
    for tool in tools:
        if not isinstance(tool, dict):
            raise ProviderError("The provider dispatch tools are malformed.")
        name = tool.get("name")
        parameters = tool.get("parameters")
        if not isinstance(name, str) or not name or not isinstance(parameters, dict):
            raise ProviderError("The provider dispatch tools are malformed.")
        native_tools.append(
            {
                "name": name,
                "description": tool.get("description", ""),
                "input_schema": parameters,
            }
        )
    messages: list = [{"role": "user", "content": [{"type": "text", "text": user_text}]}]
    for exchange in exchanges:
        assistant_content: list = []
        user_content: list = []
        for call in exchange.get("calls", ()):  # type: ignore[union-attr]
            assistant_content.append(
                {
                    "type": "tool_use",
                    "id": call["call_id"],
                    "name": call["name"],
                    "input": call["arguments"],
                }
            )
        for output in exchange.get("outputs", ()):  # type: ignore[union-attr]
            user_content.append(
                {
                    "type": "tool_result",
                    "tool_use_id": output["call_id"],
                    "content": json.dumps(
                        output["evidence"], sort_keys=True, separators=(",", ":")
                    ),
                }
            )
        if assistant_content:
            messages.append({"role": "assistant", "content": assistant_content})
        if user_content:
            messages.append({"role": "user", "content": user_content})
    return {
        "model": model,
        "system": [{"type": "text", "text": instructions}],
        "messages": messages,
        "tools": native_tools,
        "thinking": {"type": "disabled"},
        "service_tier": SERVICE_TIER,
        "max_tokens": max_output_tokens,
    }


def serialize_body(body: dict) -> bytes:
    """Immutable serialization: fixed key order and separators."""
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def validate_body(wire: bytes, *, expected_model: str) -> None:
    """Enforce immutable model/stateless binding before any send."""
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
    if body.get("stream") is True:
        raise ProviderError("The provider dispatch must not stream.")
    if body.get("thinking") != {"type": "disabled"}:
        raise ProviderError("The provider dispatch thinking profile is not allowlisted.")
    if body.get("service_tier") != SERVICE_TIER:
        raise ProviderError("The provider dispatch processing tier is not allowlisted.")
    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        raise ProviderError("The provider dispatch is malformed.")


def cost_micro_usd(
    *,
    input_tokens: int,
    cache_creation_tokens: int,
    cache_read_tokens: int,
    output_tokens: int,
    cache_creation_5m_tokens: int = 0,
    cache_creation_1h_tokens: int = 0,
) -> int:
    """Integer micro-USD charge with tiered small/large input pricing.

    Cache creation/read counts are disjoint input components.
    ``cache_creation_tokens`` carries creation of UNKNOWN time-to-live
    and is priced conservatively at the highest supported (1-hour)
    write rate; the explicit 5-minute / 1-hour breakdown buckets use
    their own rates. Reads bill at the cached rate. Totals above
    ``SMALL_INPUT_MAX`` input tokens use the larger-prompt rates.
    """
    for tokens in (
        input_tokens,
        cache_creation_tokens,
        cache_read_tokens,
        output_tokens,
        cache_creation_5m_tokens,
        cache_creation_1h_tokens,
    ):
        if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 0:
            raise ProviderError("The provider usage is malformed.")
    created_total = cache_creation_tokens + cache_creation_5m_tokens + cache_creation_1h_tokens
    total_input = input_tokens + created_total + cache_read_tokens
    if total_input <= SMALL_INPUT_MAX:
        price_in, price_out, price_cached, price_5m, price_1h = (
            PRICE_INPUT_MICRO_PER_M,
            PRICE_OUTPUT_MICRO_PER_M,
            PRICE_CACHED_MICRO_PER_M,
            PRICE_CREATE_5M_MICRO_PER_M,
            PRICE_CREATE_1H_MICRO_PER_M,
        )
    else:
        price_in, price_out, price_cached, price_5m, price_1h = (
            PRICE_INPUT_LARGE_MICRO_PER_M,
            PRICE_OUTPUT_LARGE_MICRO_PER_M,
            PRICE_CACHED_LARGE_MICRO_PER_M,
            PRICE_CREATE_5M_LARGE_MICRO_PER_M,
            PRICE_CREATE_1H_LARGE_MICRO_PER_M,
        )
    total = (
        input_tokens * price_in
        + (cache_creation_tokens + cache_creation_1h_tokens) * price_1h
        + cache_creation_5m_tokens * price_5m
        + cache_read_tokens * price_cached
        + output_tokens * price_out
    )
    return max(1, (total + MICRO_PER_TOKEN_UNIT - 1) // MICRO_PER_TOKEN_UNIT)


def _native_breakdown_counts(breakdown: object) -> tuple[int, int]:
    """Extract native 5-minute / 1-hour creation counts.

    The native ``cache_creation`` object carries
    ``ephemeral_5m_input_tokens`` / ``ephemeral_1h_input_tokens``; both
    default to zero when absent. Null values, non-integer counts or
    unexpected keys are malformed.
    """
    if not isinstance(breakdown, dict):
        raise ProviderError("The provider usage is malformed.")
    five = breakdown.get("ephemeral_5m_input_tokens", 0)
    one_h = breakdown.get("ephemeral_1h_input_tokens", 0)
    for tokens in (five, one_h):
        if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 0:
            raise ProviderError("The provider usage is malformed.")
    for key in breakdown:
        if key not in ("ephemeral_5m_input_tokens", "ephemeral_1h_input_tokens"):
            raise ProviderError("The provider usage is malformed.")
    return five, one_h


def validate_usage(payload: object, *, max_output_tokens: int, input_upper: int) -> dict:
    """Validate a Messages ``usage`` object into safe counts.

    Accepts the aggregate ``cache_creation_input_tokens`` total plus
    the native nested ``cache_creation`` breakdown
    (``ephemeral_5m_input_tokens`` / ``ephemeral_1h_input_tokens``).
    A present breakdown must sum exactly to the aggregate total,
    otherwise the report is rejected instead of double-counted. An
    absent or null breakdown leaves the aggregate as unknown-TTL
    creation, priced conservatively at the 1-hour write rate.
    Top-level ``cache_creation_5m_input_tokens`` /
    ``cache_creation_1h_input_tokens`` fields are not native and are
    rejected.

    The native ``usage.service_tier`` is an optional
    standard/priority/batch enum: an absent or null field stays
    compatible with older payloads, an explicit ``"standard"`` is
    billed at the standard rates below, and any other explicit tier
    fails closed instead of being accounted at standard rates.
    """
    if not isinstance(payload, dict):
        raise ProviderError("The provider usage is malformed.")
    if "cache_creation_5m_input_tokens" in payload or "cache_creation_1h_input_tokens" in payload:
        raise ProviderError("The provider usage is malformed.")
    reported_tier = payload.get("service_tier", None)
    if reported_tier is not None and reported_tier != RESPONSE_STANDARD_TIER:
        raise ProviderError("The provider response processing tier is not standard.")
    base = payload.get("input_tokens")
    created = payload.get("cache_creation_input_tokens", 0)
    read = payload.get("cache_read_input_tokens", 0)
    output = payload.get("output_tokens")
    for tokens in (base, created, read, output):
        if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 0:
            raise ProviderError("The provider usage is malformed.")
    breakdown = payload.get("cache_creation")
    if breakdown is None:
        created_unknown = created
        created_5m = 0
        created_1h = 0
    else:
        created_5m, created_1h = _native_breakdown_counts(breakdown)
        if created != created_5m + created_1h:
            raise ProviderError("The provider usage is malformed.")
        created_unknown = 0
    created_total = created_unknown + created_5m + created_1h
    total_input = base + created_total + read
    usage = {
        "input_tokens": total_input,
        "output_tokens": output,
        "cached_tokens": read,
        "reasoning_tokens": 0,
        # Unknown-TTL creation stays in ``cache_creation_tokens`` and
        # is priced at the 1-hour rate; breakdown buckets are disjoint
        # from it, so the three never double-count.
        "cache_creation_tokens": created_unknown,
        "cache_creation_5m_tokens": created_5m,
        "cache_creation_1h_tokens": created_1h,
    }
    if usage["output_tokens"] > max_output_tokens or usage["input_tokens"] > input_upper:
        raise ProviderError("The provider usage exceeds its requested bounds.")
    return usage


def parse_response(
    payload: object, *, expected_model: str, max_output_tokens: int, input_upper: int
) -> ProviderResponse:
    """Parse one Messages body into text, correlated calls and usage."""
    if not isinstance(payload, dict):
        raise ProviderError("The provider answer is malformed.")
    if payload.get("type") != "message":
        raise ProviderError("The provider answer is malformed.")
    if payload.get("model") != expected_model:
        raise ProviderError("The provider response model is not allowlisted.")
    stop = payload.get("stop_reason")
    if stop not in ("end_turn", "tool_use"):
        raise ProviderError("The provider response is not complete.")
    response_id = payload.get("id", "")
    if not isinstance(response_id, str) or not 1 <= len(response_id) <= RESPONSE_ID_MAX_LEN:
        raise ProviderError("The provider answer is malformed.")
    content = payload.get("content")
    if not isinstance(content, list):
        raise ProviderError("The provider answer is malformed.")
    texts: list[str] = []
    calls: list[ToolCall] = []
    for block in content:
        if not isinstance(block, dict):
            raise ProviderError("The provider answer is malformed.")
        kind = block.get("type")
        if kind == "text":
            text = block.get("text", "")
            if not isinstance(text, str):
                raise ProviderError("The provider answer is malformed.")
            texts.append(text)
        elif kind == "tool_use":
            tool_id = block.get("id", "")
            name = block.get("name")
            arguments = block.get("input", {})
            if (
                not isinstance(tool_id, str)
                or not 1 <= len(tool_id) <= TOOL_USE_ID_MAX_LEN
                or not isinstance(name, str)
                or not name
                or not isinstance(arguments, dict)
            ):
                raise ProviderError("A provider tool call is malformed.")
            calls.append(ToolCall(name=name, arguments=arguments, call_id=tool_id))
        else:
            raise ProviderError("The provider answer carries an unknown block type.")
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


class AnthropicMessagesAdapter(ProviderAdapter):
    """Real Anthropic Messages adapter (stdlib transport, zero retries)."""

    name = "anthropic-messages"

    def __init__(
        self,
        *,
        endpoint: str,
        model: str,
        api_key,
        workspace_id: str = "",
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
        self._workspace_id = validate_workspace_id(workspace_id)
        self.timeout_s = timeout_s
        self._transport = transport or _http.post_json
        self.max_response_bytes = max_response_bytes

    def __repr__(self) -> str:
        return f"AnthropicMessagesAdapter(model={self.model!r}, endpoint=<allowlisted>)"

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
            "anthropic-version": ANTHROPIC_VERSION,
        }
        if self._workspace_id:
            headers["anthropic-workspace-id"] = self._workspace_id
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
