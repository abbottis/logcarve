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
uses ``{"type": "between_tools"}`` (``disabled`` returns 400) with a
fixed cheap ``output_config`` effort; no forced ``tool_choice``,
no ``temperature``/``top_p``/``top_k``, and no tool runs outside the
app allowlist. The exact original assistant blocks (public progress
``text`` plus ``thinking``/``redacted_thinking`` plus ``tool_use``
with verbatim original inputs, in original order) the service hands
over replay verbatim on the next tool-result turn — never forged,
never reconstructed, never re-input from executed scopes, and never
shown to the UI, logs, evidence or persistent DB (public text alone
reaches the answer normally). Replay is bound to the same
provider/model with unchanged system/tools/prefix via the pinned
per-investigation binding plus the immutable dispatch check.

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

#: Verified Sonnet 5.5 standard API pricing, owner task reference
#: 2026-11-02 (https://platform.claude.com/docs/en/models/sonnet-5-5/overview):
#: single flat rate with NO 100k Haiku-style input tier — input USD
#: 2.00/M, output USD 10.00/M, cached-read USD 0.10/M, 5-minute
#: cache-write USD 2.50/M, 1-hour cache-write USD 4.00/M. Cache
#: creation/read counts are disjoint input components; creation of
#: unknown TTL is priced conservatively at the highest supported
#: (1-hour) rate, reads at the cached rate, so nothing is
#: undercharged.
PRICING_VERSION = "2026-11-02-platform.claude.com"
PRICE_INPUT_MICRO_PER_M = 2_000_000
PRICE_OUTPUT_MICRO_PER_M = 10_000_000
PRICE_CACHED_MICRO_PER_M = 100_000
PRICE_CREATE_5M_MICRO_PER_M = 2_500_000
PRICE_CREATE_1H_MICRO_PER_M = 4_000_000
MICRO_PER_TOKEN_UNIT = 1_000_000

#: Fixed cheap thinking profile: ``disabled`` returns 400, so the
#: product pins ``between_tools`` (no other thinking fields) with a
#: fixed ``output_config`` effort of ``low`` for the whole run. The
#: immutable dispatch check enforces both values exactly.
THINKING_PROFILE = {"type": "between_tools"}
EFFORT_LEVEL = "low"

#: Bounds for one replayed thinking/redacted_thinking block and for
#: the number of such blocks per response turn. Blocks replay
#: verbatim; anything larger or more numerous fails closed instead
#: of being truncated or forged.
THINKING_TEXT_MAX_CHARS = 8192
THINKING_SIGNATURE_MAX_CHARS = 8192
REDACTED_DATA_MAX_CHARS = 8192
THINKING_MAX_BLOCKS = 32

#: Replay-metadata key carrying the exact original assistant content
#: blocks for one turn (text/thinking/redacted_thinking/tool_use in
#: original order, with verbatim original tool inputs), JSON encoded
#: once on the first parsed tool_use. Unknown metadata keys fail the
#: dispatch closed; only the parser in this module ever writes this.
ASSISTANT_CONTENT_KEY = "anthropic_assistant_content"

#: Legacy partitioned thinking keys (no longer written): retained as
#: recognized-but-rejected markers so an old/forged partition fails
#: closed with the dispatch-signature error instead of passing as an
#: unknown key.
THINKING_BEFORE_KEY = "anthropic_thinking_before"
THINKING_AFTER_KEY = "anthropic_thinking_after"

#: Bounds for one public progress text block kept for exact replay.
TEXT_MAX_CHARS = 8192

#: Bound on total assistant blocks per turn (all kinds) and on the
#: JSON-encoded exact-content replay blob carried in metadata.
ASSISTANT_MAX_BLOCKS = 64
ASSISTANT_CONTENT_MAX_CHARS = 65536

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


def _checked_thinking_block(block: object) -> dict:
    """Validate one verbatim thinking/redacted_thinking block.

    Only exact documented shapes pass: ``thinking`` carries exactly
    ``type``/``thinking``/``signature``, ``redacted_thinking``
    exactly ``type``/``data`` — no extra provider fields, no
    reconstruction, no truncation. Anything else fails closed.
    """
    if not isinstance(block, dict):
        raise ProviderError("A provider thinking block is malformed.")
    kind = block.get("type")
    if kind == "thinking":
        thinking = block.get("thinking")
        signature = block.get("signature")
        if (
            set(block.keys()) != {"type", "thinking", "signature"}
            or not isinstance(thinking, str)
            or not 1 <= len(thinking) <= THINKING_TEXT_MAX_CHARS
            or not isinstance(signature, str)
            or not 1 <= len(signature) <= THINKING_SIGNATURE_MAX_CHARS
        ):
            raise ProviderError("A provider thinking block is malformed.")
        return {"type": "thinking", "thinking": thinking, "signature": signature}
    if kind == "redacted_thinking":
        data = block.get("data")
        if (
            set(block.keys()) != {"type", "data"}
            or not isinstance(data, str)
            or not 1 <= len(data) <= REDACTED_DATA_MAX_CHARS
        ):
            raise ProviderError("A provider thinking block is malformed.")
        return {"type": "redacted_thinking", "data": data}
    raise ProviderError("A provider thinking block is malformed.")


def _checked_caller(raw: object, *, missing_ok: bool = True) -> dict | None:
    """Validate the optional native ``caller`` field; fail closed.

    Only absent/``None`` or exactly ``{"type": "direct"}`` passes for
    the direct-tool profile. Server/code-execution callers and any
    other shape fail closed. Returns the preserved dict or ``None``
    when the field is absent/null (never invented).
    """
    if raw is None and missing_ok:
        return None
    if isinstance(raw, dict) and raw == {"type": "direct"}:
        return {"type": "direct"}
    raise ProviderError("The provider dispatch signature is malformed.")


def _checked_toolset_name(raw: object, *, missing_ok: bool = True) -> None:
    """Validate the optional native ``toolset_name`` field; fail closed.

    Only absent/``None`` passes for the direct-tool profile: any
    non-null toolset name is a hosted-tool marker and fails closed.
    """
    if raw is None and missing_ok:
        return
    raise ProviderError("The provider dispatch signature is malformed.")


def _checked_citations(raw: object, *, missing_ok: bool = True) -> list | None:
    """Validate the optional native text ``citations`` field; fail closed.

    Only absent/``None``/``[]`` passes (citations feature
    unrequested): any nonempty citation content fails closed.
    Returns the preserved ``[]`` or ``None`` when absent/null.
    """
    if raw is None and missing_ok:
        return None
    if isinstance(raw, list) and raw == []:
        return []
    raise ProviderError("The provider dispatch signature is malformed.")


def _checked_tool_use_block(block: dict) -> dict:
    """Validate one exact ``tool_use`` block incl. neutral native fields."""
    allowed = {"type", "id", "name", "input", "caller", "toolset_name"}
    if not set(block.keys()) <= allowed:
        raise ProviderError("The provider dispatch signature is malformed.")
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
        raise ProviderError("The provider dispatch signature is malformed.")
    checked: dict = {"type": "tool_use", "id": tool_id, "name": name, "input": arguments}
    if "caller" in block:
        caller = _checked_caller(block.get("caller"))
        if caller is not None:
            checked["caller"] = caller
    if "toolset_name" in block:
        _checked_toolset_name(block.get("toolset_name"))
    return checked


def _checked_text_block(block: object) -> dict:
    """Validate one verbatim public progress text block; fail closed."""
    if not isinstance(block, dict):
        raise ProviderError("The provider answer is malformed.")
    if not set(block.keys()) <= {"type", "text", "citations"}:
        raise ProviderError("The provider answer is malformed.")
    text = block.get("text")
    if not isinstance(text, str) or not 1 <= len(text) <= TEXT_MAX_CHARS:
        raise ProviderError("The provider answer is malformed.")
    checked: dict = {"type": "text", "text": text}
    if "citations" in block:
        try:
            citations = _checked_citations(block.get("citations"))
        except ProviderError as exc:
            raise ProviderError("The provider answer is malformed.") from exc
        if citations is not None:
            checked["citations"] = citations
    return checked


def _checked_assistant_block(block: object) -> dict:
    """Validate one exact original assistant block; fail closed."""
    if not isinstance(block, dict):
        raise ProviderError("The provider dispatch signature is malformed.")
    kind = block.get("type")
    if kind == "text":
        if not set(block.keys()) <= {"type", "text", "citations"}:
            raise ProviderError("The provider dispatch signature is malformed.")
        text = block.get("text")
        if not isinstance(text, str) or not 1 <= len(text) <= TEXT_MAX_CHARS:
            raise ProviderError("The provider dispatch signature is malformed.")
        checked: dict = {"type": "text", "text": text}
        if "citations" in block:
            citations = _checked_citations(block.get("citations"))
            if citations is not None:
                checked["citations"] = citations
        return checked
    if kind in ("thinking", "redacted_thinking"):
        return _checked_thinking_block(block)
    if kind == "tool_use":
        return _checked_tool_use_block(block)
    raise ProviderError("The provider dispatch signature is malformed.")


def _decode_assistant_content(raw: object) -> list:
    """Decode one exact original assistant content list; fail closed."""
    if not isinstance(raw, str):
        raise ProviderError("The provider dispatch signature is malformed.")
    if not 1 <= len(raw) <= ASSISTANT_CONTENT_MAX_CHARS:
        raise ProviderError("The provider dispatch signature is malformed.")
    try:
        items = json.loads(raw)
    except ValueError as exc:
        raise ProviderError("The provider dispatch signature is malformed.") from exc
    if not isinstance(items, list) or not 1 <= len(items) <= ASSISTANT_MAX_BLOCKS:
        raise ProviderError("The provider dispatch signature is malformed.")
    checked = [_checked_assistant_block(item) for item in items]
    thinking_total = sum(1 for item in checked if item["type"] in ("thinking", "redacted_thinking"))
    if thinking_total > THINKING_MAX_BLOCKS:
        raise ProviderError("The provider dispatch signature is malformed.")
    return checked


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
    order, prior assistant content plus the paired user
    ``tool_result`` blocks the service hands over. Assistant content
    replays the EXACT original blocks per turn (text/thinking/
    redacted_thinking/tool_use in original order, with verbatim
    original tool inputs) carried once on the first call's replay
    metadata. Tool execution still uses the server-overridden
    arguments; the stored originals are replay data only.
    Signatures are never forged or reconstructed: a malformed
    replay fails the dispatch closed. No other history.

    Thinking uses ``{"type": "between_tools"}`` (``disabled``
    returns 400) with a fixed cheap ``output_config`` effort for
    the whole run; no forced ``tool_choice``, no
    ``temperature``/``top_p``/``top_k``. The body carries explicit
    ``service_tier: "standard_only"`` for standard-capacity
    processing: the documented default ``"auto"`` would use
    Priority capacity when available.

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
        exchange_calls = exchange.get("calls", ())
        if not isinstance(exchange_calls, (list, tuple)):
            raise ProviderError("The provider dispatch tools are malformed.")
        for position, call in enumerate(exchange_calls):
            if not isinstance(call, dict):
                raise ProviderError("The provider dispatch tools are malformed.")
            metadata = call.get("metadata") or {}
            if not isinstance(metadata, dict):
                raise ProviderError("The provider dispatch signature is malformed.")
            for key in metadata:
                if key == ASSISTANT_CONTENT_KEY and position != 0:
                    raise ProviderError("The provider dispatch signature is malformed.")
                if key in (THINKING_BEFORE_KEY, THINKING_AFTER_KEY):
                    raise ProviderError("The provider dispatch signature is malformed.")
                if key != ASSISTANT_CONTENT_KEY:
                    raise ProviderError("The provider dispatch signature is malformed.")
        first_meta = {}
        if exchange_calls:
            first = exchange_calls[0]
            if not isinstance(first, dict):
                raise ProviderError("The provider dispatch tools are malformed.")
            first_meta = first.get("metadata") or {}
            if not isinstance(first_meta, dict):
                raise ProviderError("The provider dispatch signature is malformed.")
        if ASSISTANT_CONTENT_KEY in first_meta:
            decoded = _decode_assistant_content(first_meta[ASSISTANT_CONTENT_KEY])
            replay_tools = [b for b in decoded if b["type"] == "tool_use"]
            if len(replay_tools) != len(exchange_calls):
                raise ProviderError("The provider dispatch signature is malformed.")
            for block, call in zip(replay_tools, exchange_calls):
                if block["id"] != call.get("call_id") or block["name"] != call.get("name"):
                    raise ProviderError("The provider dispatch signature is malformed.")
            check_wire_values({"assistant_content": decoded}, context="provider dispatch")
            assistant_content = decoded
        else:
            for call in exchange_calls:
                if not isinstance(call, dict):
                    raise ProviderError("The provider dispatch tools are malformed.")
                if (call.get("metadata") or {}) != {}:
                    raise ProviderError("The provider dispatch signature is malformed.")
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
        "thinking": dict(THINKING_PROFILE),
        "output_config": {"effort": EFFORT_LEVEL},
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
    if body.get("thinking") != dict(THINKING_PROFILE):
        raise ProviderError("The provider dispatch thinking profile is not allowlisted.")
    if body.get("output_config") != {"effort": EFFORT_LEVEL}:
        raise ProviderError("The provider dispatch thinking profile is not allowlisted.")
    for forbidden in ("tool_choice", "temperature", "top_p", "top_k"):
        if forbidden in body:
            raise ProviderError("The provider dispatch tools are malformed.")
    if body.get("service_tier") != SERVICE_TIER:
        raise ProviderError("The provider dispatch processing tier is not allowlisted.")
    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        raise ProviderError("The provider dispatch is malformed.")
    thinking_total = 0
    for message in messages:
        if not isinstance(message, dict):
            raise ProviderError("The provider dispatch is malformed.")
        role = message.get("role")
        content = message.get("content")
        if role not in ("user", "assistant") or not isinstance(content, list) or not content:
            raise ProviderError("The provider dispatch is malformed.")
        if role != "assistant":
            continue
        for block in content:
            if not isinstance(block, dict):
                raise ProviderError("The provider dispatch is malformed.")
            kind = block.get("type")
            if kind == "text":
                _checked_text_block(block)
            elif kind in ("thinking", "redacted_thinking"):
                _checked_thinking_block(block)
                thinking_total += 1
                if thinking_total > THINKING_MAX_BLOCKS:
                    raise ProviderError("The provider dispatch signature is malformed.")
            elif kind == "tool_use":
                try:
                    _checked_tool_use_block(block)
                except ProviderError as exc:
                    raise ProviderError("The provider dispatch tools are malformed.") from exc
            else:
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
    """Integer micro-USD charge at the single flat Sonnet rate.

    Cache creation/read counts are disjoint input components.
    ``cache_creation_tokens`` carries creation of UNKNOWN time-to-live
    and is priced conservatively at the highest supported (1-hour)
    write rate; the explicit 5-minute / 1-hour breakdown buckets use
    their own rates. Reads bill at the cached rate. There is no
    100k input tier for this Sonnet model.
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
    total = (
        input_tokens * PRICE_INPUT_MICRO_PER_M
        + (cache_creation_tokens + cache_creation_1h_tokens) * PRICE_CREATE_1H_MICRO_PER_M
        + cache_creation_5m_tokens * PRICE_CREATE_5M_MICRO_PER_M
        + cache_read_tokens * PRICE_CACHED_MICRO_PER_M
        + output_tokens * PRICE_OUTPUT_MICRO_PER_M
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
    """Parse one Messages body into text, correlated calls and usage.

    The exact original assistant blocks (text/thinking/
    redacted_thinking/tool_use in original order, with verbatim
    original tool inputs) are JSON-encoded once on the first parsed
    ``tool_use`` under the single replay key. The next dispatch
    replays those blocks verbatim (never reconstructed, never
    reordered, never re-input from executed scopes). Thinking text
    never enters the answer text, logs, evidence or persistent DB —
    only ``text`` blocks do.
    """
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
    original: list[dict] = []
    thinking_total = 0
    if len(content) > ASSISTANT_MAX_BLOCKS:
        raise ProviderError("The provider answer is malformed.")
    for block in content:
        if not isinstance(block, dict):
            raise ProviderError("The provider answer is malformed.")
        kind = block.get("type")
        if kind == "text":
            checked = _checked_text_block(block)
            texts.append(checked["text"])
            original.append(checked)
        elif kind in ("thinking", "redacted_thinking"):
            checked = _checked_thinking_block(block)
            original.append(checked)
            thinking_total += 1
            if thinking_total > THINKING_MAX_BLOCKS:
                raise ProviderError("A provider thinking block is malformed.")
        elif kind == "tool_use":
            try:
                checked_tool = _checked_tool_use_block(block)
            except ProviderError as exc:
                raise ProviderError("A provider tool call is malformed.") from exc
            original.append(checked_tool)
            calls.append(
                ToolCall(
                    name=checked_tool["name"],
                    arguments=checked_tool["input"],
                    call_id=checked_tool["id"],
                    metadata={},
                )
            )
        else:
            raise ProviderError("The provider answer carries an unknown block type.")
    if calls:
        encoded = json.dumps(original, sort_keys=True, separators=(",", ":"))
        if not 1 <= len(encoded) <= ASSISTANT_CONTENT_MAX_CHARS:
            raise ProviderError("The provider answer is malformed.")
        first = calls[0]
        calls[0] = ToolCall(
            name=first.name,
            arguments=first.arguments,
            call_id=first.call_id,
            metadata={ASSISTANT_CONTENT_KEY: encoded},
        )
    # Thinking/text with no tool_use ends the turn: nothing to replay,
    # the blocks are dropped (never shown) rather than stored anywhere.
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
