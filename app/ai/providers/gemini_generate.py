"""Real Gemini generateContent transport over stdlib HTTP.

Native ``POST
https://generativelanguage.googleapis.com/v1beta/models/<allowlisted-model>:generateContent``
with the key in the ``x-goog-api-key`` HEADER (never in the URL),
``systemInstruction`` plus ``contents`` user/model parts and
``tools.functionDeclarations`` for the bounded read-only analytics
tools. Stateless: every turn carries the system instruction, the user
message and the prior model ``functionCall``/user ``functionResponse``
pairs the service hands over.

Thought signatures: Gemini 3 requires the exact ordered
``thoughtSignature`` parts across tool turns. The adapter preserves
the bounded opaque signature produced by the backend, ties it to the
same investigation/provider/model turn via the service exchange, and
replays it verbatim. Signatures are never reconstructed, never forged
for tests, and arbitrary provider text/unsafe metadata is rejected.

Zero automatic retries: any transport or mapping failure surfaces to
the caller, which keeps the step hold and reports unavailable.

No network, key file or account access happens at import or in tests:
tests inject ``transport`` (or drive the pure build/parse helpers).
The product key lives only in the adapter instance built for a real
run and never enters logs, exceptions, responses or usage records.
"""

import json
import re
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

ENDPOINT_HOST = "generativelanguage.googleapis.com"
ENDPOINT_PORT = 443
ENDPOINT_PATH_PREFIX = "/v1beta/models/"
ENDPOINT_PATH_SUFFIX = ":generateContent"

#: Verified Gemini 3.5 Flash-Lite Standard paid text pricing, task
#: reference 2026-11-02 (https://ai.google.dev/gemini-api/docs/pricing):
#: input USD 0.30/M, cached input USD 0.03/M (a SUBSET of input),
#: output USD 2.50/M where output = candidatesTokenCount PLUS
#: thoughtsTokenCount. Never add cached tokens on top of the input.
PRICING_VERSION = "2026-11-02-ai.google.dev"
PRICE_INPUT_MICRO_PER_M = 300_000
PRICE_CACHED_MICRO_PER_M = 30_000
PRICE_OUTPUT_MICRO_PER_M = 2_500_000
MICRO_PER_TOKEN_UNIT = 1_000_000

#: Small documented framing margin added to the exact immutable body
#: byte length for the input-token upper bound.
WIRE_FRAMING_TOKENS = 96

#: Bounds for one opaque thoughtSignature blob (Gemini 3 tool turns).
SIGNATURE_MAX_CHARS = 8192
SIGNATURE_MAX_ITEMS = 8

#: thoughtSignature is opaque base64 bytes carried on the Part: bounded
#: charset plus length, never inspected or reconstructed.
_SIGNATURE_RE = re.compile(r"[A-Za-z0-9+/=_-]+\Z")

#: Provider FunctionCall.id bounds (required server unique ID, opaque).
CALL_ID_MAX_LEN = 64


def _check_signature(signature: object) -> str:
    """Validate one opaque thoughtSignature blob; fail closed."""
    if (
        not isinstance(signature, str)
        or not 1 <= len(signature) <= SIGNATURE_MAX_CHARS
        or not _SIGNATURE_RE.match(signature)
    ):
        raise ProviderError("A provider thought signature is malformed.")
    return signature


#: Bound on server response IDs kept in safe metadata (opaque, short).
RESPONSE_ID_MAX_LEN = 128


def parse_endpoint(raw: str, *, expected_model: str) -> str:
    """Accept exactly the allowlisted model-bound endpoint; fail closed."""
    if not isinstance(raw, str) or not raw:
        raise ProviderError("The configured model endpoint is missing.")
    if not isinstance(expected_model, str) or not expected_model:
        raise ProviderError("The configured model is missing.")
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
    expected_path = f"{ENDPOINT_PATH_PREFIX}{expected_model}{ENDPOINT_PATH_SUFFIX}"
    if parts.path != expected_path:
        raise ProviderError("The configured model endpoint path is not allowlisted.")
    return f"https://{ENDPOINT_HOST}:{ENDPOINT_PORT}{expected_path}"


def _to_function_declarations(tools: list) -> list:
    """Convert Responses-style tool defs to Gemini functionDeclarations.

    Uses the documented native ``parametersJsonSchema`` field (JSON
    Schema, mutually exclusive with the narrower OpenAPI ``parameters``
    Schema): the app tool schemas carry ``additionalProperties: false``
    and nullable unions that the OpenAPI field cannot express.
    """
    declarations = []
    for tool in tools:
        if not isinstance(tool, dict):
            raise ProviderError("The provider dispatch tools are malformed.")
        name = tool.get("name")
        parameters = tool.get("parameters")
        if not isinstance(name, str) or not name or not isinstance(parameters, dict):
            raise ProviderError("The provider dispatch tools are malformed.")
        declarations.append(
            {
                "name": name,
                "description": tool.get("description", ""),
                "parametersJsonSchema": parameters,
            }
        )
    return declarations


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

    Replay decision: the system instruction, the user message and, in
    order, prior model ``functionCall`` parts plus the paired user
    ``functionResponse`` parts the service hands over. ``Part``
    ``thoughtSignature`` is a SIBLING of ``functionCall`` (never nested inside
    it): each replayed part carries its preserved opaque signature
    verbatim, in order. The provider ``FunctionCall.id``, when the
    service hands one over, is preserved, and the matching
    ``FunctionResponse.id`` echoes it. No invented signatures, no
    other history, no extra native/built-in tools.

    Gemini 3 requires the first function-call part's signature per
    step in the current turn: an exchange that replays model calls
    without that first-part signature fails closed instead of
    dropping or forging one.

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
    contents: list = [{"role": "user", "parts": [{"text": user_text}]}]
    for exchange in exchanges:
        model_parts: list = []
        user_parts: list = []
        for position, call in enumerate(exchange.get("calls", ())):  # type: ignore[union-attr]
            if not isinstance(call, dict):
                raise ProviderError("The provider dispatch tools are malformed.")
            call_id = call.get("call_id", "")
            if not isinstance(call_id, str) or not 1 <= len(call_id) <= CALL_ID_MAX_LEN:
                raise ProviderError("The provider dispatch call correlation is malformed.")
            function_call: dict = {
                "name": call["name"],
                "args": call["arguments"],
                "id": call_id,
            }
            part = {"functionCall": function_call}
            metadata = call.get("metadata") or {}
            if not isinstance(metadata, dict):
                raise ProviderError("The provider dispatch signature is malformed.")
            signature = metadata.get("thoughtSignature")
            if position == 0:
                if signature is None:
                    raise ProviderError("The provider dispatch signature is missing.")
                part["thoughtSignature"] = _check_signature(signature)
            elif signature is not None:
                part["thoughtSignature"] = _check_signature(signature)
            model_parts.append(part)
        for output in exchange.get("outputs", ()):  # type: ignore[union-attr]
            if not isinstance(output, dict):
                raise ProviderError("The provider dispatch tools are malformed.")
            output_id = output.get("call_id", "")
            if not isinstance(output_id, str) or not 1 <= len(output_id) <= CALL_ID_MAX_LEN:
                raise ProviderError("The provider dispatch call correlation is malformed.")
            user_parts.append(
                {
                    "functionResponse": {
                        "name": output["name"],
                        "response": {"output": output["evidence"]},
                        "id": output_id,
                    }
                }
            )
        if model_parts:
            contents.append({"role": "model", "parts": model_parts})
        if user_parts:
            contents.append({"role": "user", "parts": user_parts})
    return {
        "systemInstruction": {"parts": [{"text": instructions}]},
        "contents": contents,
        "tools": [{"functionDeclarations": _to_function_declarations(tools)}],
        "generationConfig": {"maxOutputTokens": max_output_tokens},
    }


def serialize_body(body: dict) -> bytes:
    """Immutable serialization: fixed key order and separators."""
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def validate_body(wire: bytes, *, expected_model: str) -> None:
    """Enforce immutable model/stateless binding before any send.

    The model itself travels in the pinned endpoint URL (validated by
    :func:`parse_endpoint`), so the body check enforces the stateless
    native shape instead: non-empty contents, exactly the
    ``functionDeclarations`` tool form with native
    ``parametersJsonSchema`` (the narrower OpenAPI ``parameters``
    field is rejected), and no extra native/built-in tool blocks.
    """
    if not isinstance(wire, bytes) or not wire:
        raise ProviderError("The provider dispatch is malformed.")
    try:
        body = json.loads(wire.decode("utf-8"))
    except ValueError as exc:
        raise ProviderError("The provider dispatch is malformed.") from exc
    if not isinstance(body, dict):
        raise ProviderError("The provider dispatch is malformed.")
    if not isinstance(expected_model, str) or not expected_model:
        raise ProviderError("The configured model is missing.")
    contents = body.get("contents")
    if not isinstance(contents, list) or not contents:
        raise ProviderError("The provider dispatch is malformed.")
    tools = body.get("tools")
    if not isinstance(tools, list) or not tools:
        raise ProviderError("The provider dispatch tools are malformed.")
    for entry in tools:
        if not isinstance(entry, dict):
            raise ProviderError("The provider dispatch tools are malformed.")
        declarations = entry.get("functionDeclarations")
        if not isinstance(declarations, list) or not declarations:
            raise ProviderError("The provider dispatch tools are malformed.")
        for declaration in declarations:
            if not isinstance(declaration, dict):
                raise ProviderError("The provider dispatch tools are malformed.")
            name = declaration.get("name")
            schema = declaration.get("parametersJsonSchema")
            if not isinstance(name, str) or not name or not isinstance(schema, dict):
                raise ProviderError("The provider dispatch tools are malformed.")
            if "parameters" in declaration:
                raise ProviderError("The provider dispatch tools are malformed.")
        for forbidden in ("codeExecution", "googleSearch", "computerUse"):
            if forbidden in entry:
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
    """Validate a ``usageMetadata`` object into safe counts.

    Output is ``candidatesTokenCount`` PLUS ``thoughtsTokenCount``;
    the total must equal prompt + candidates + thoughts exactly, and
    ``cachedContentTokenCount`` is a subset of the prompt count.
    """
    if not isinstance(payload, dict):
        raise ProviderError("The provider usage is malformed.")
    prompt = payload.get("promptTokenCount")
    candidates = payload.get("candidatesTokenCount")
    thoughts = payload.get("thoughtsTokenCount", 0)
    cached = payload.get("cachedContentTokenCount", 0)
    total = payload.get("totalTokenCount")
    for tokens in (prompt, candidates, thoughts, cached, total):
        if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 0:
            raise ProviderError("The provider usage is malformed.")
    output_tokens = candidates + thoughts
    if total != prompt + candidates + thoughts:
        raise ProviderError("The provider usage is malformed.")
    if cached > prompt:
        raise ProviderError("The provider usage is malformed.")
    usage = {
        "input_tokens": prompt,
        "output_tokens": output_tokens,
        "cached_tokens": cached,
        "reasoning_tokens": thoughts,
    }
    if usage["output_tokens"] > max_output_tokens or usage["input_tokens"] > input_upper:
        raise ProviderError("The provider usage exceeds its requested bounds.")
    return usage


def parse_response(
    payload: object, *, expected_model: str, max_output_tokens: int, input_upper: int
) -> ProviderResponse:
    """Parse one generateContent body into text, calls and usage.

    ``thoughtSignature`` is read as a SIBLING of ``functionCall`` on
    the Part (its documented native position); a signature nested
    inside ``functionCall`` is rejected as malformed. Gemini 3 always
    returns a unique ``FunctionCall.id`` with every functionCall, so a
    missing, null, empty or otherwise invalid id fails closed instead
    of inventing a positional substitute that could repeat across
    turns and never echoes a real server id. A provided id is
    preserved verbatim for replay correlation, and the matching
    ``FunctionResponse.id`` echoes it. A provided ``modelVersion``
    must equal the verified expected model exactly: mismatches
    (including prefix-style near matches) are rejected.
    """
    if not isinstance(expected_model, str) or not expected_model:
        raise ProviderError("The configured model is missing.")
    if not isinstance(payload, dict):
        raise ProviderError("The provider answer is malformed.")
    model_version = payload.get("modelVersion", "")
    if model_version not in ("", None) and (
        not isinstance(model_version, str) or model_version != expected_model
    ):
        raise ProviderError("The provider response model is not allowlisted.")
    candidates = payload.get("candidates")
    if not isinstance(candidates, list) or len(candidates) != 1:
        raise ProviderError("The provider answer is malformed.")
    candidate = candidates[0]
    if not isinstance(candidate, dict):
        raise ProviderError("The provider answer is malformed.")
    finish = candidate.get("finishReason")
    if finish != "STOP":
        raise ProviderError("The provider response is not complete.")
    content = candidate.get("content")
    if not isinstance(content, dict):
        raise ProviderError("The provider answer is malformed.")
    parts = content.get("parts")
    if not isinstance(parts, list):
        raise ProviderError("The provider answer is malformed.")
    texts: list[str] = []
    calls: list[ToolCall] = []
    signatures = 0
    for part in parts:
        if not isinstance(part, dict):
            raise ProviderError("The provider answer is malformed.")
        if "text" in part:
            text = part.get("text")
            if not isinstance(text, str):
                raise ProviderError("The provider answer is malformed.")
            texts.append(text)
        elif "functionCall" in part:
            call = part.get("functionCall")
            if not isinstance(call, dict):
                raise ProviderError("A provider tool call is malformed.")
            if "thoughtSignature" in call:
                raise ProviderError("A provider tool call is malformed.")
            name = call.get("name")
            args = call.get("args", {})
            if not isinstance(name, str) or not name or not isinstance(args, dict):
                raise ProviderError("A provider tool call is malformed.")
            provided_id = call.get("id")
            if not isinstance(provided_id, str) or not 1 <= len(provided_id) <= CALL_ID_MAX_LEN:
                raise ProviderError("A provider tool call is malformed.")
            call_id = provided_id
            metadata: dict = {}
            signature = part.get("thoughtSignature")
            if signature is not None:
                _check_signature(signature)
                signatures += 1
                if signatures > SIGNATURE_MAX_ITEMS:
                    raise ProviderError("A provider tool call is malformed.")
                metadata["thoughtSignature"] = signature
            calls.append(ToolCall(name=name, arguments=args, call_id=call_id, metadata=metadata))
        else:
            raise ProviderError("The provider answer carries an unknown part type.")
    usage = validate_usage(
        payload.get("usageMetadata"), max_output_tokens=max_output_tokens, input_upper=input_upper
    )
    response_id = payload.get("responseId", "")
    if not isinstance(response_id, str) or len(response_id) > RESPONSE_ID_MAX_LEN:
        raise ProviderError("The provider answer is malformed.")
    return ProviderResponse(
        text="".join(texts),
        input_tokens=usage["input_tokens"],
        output_tokens=usage["output_tokens"],
        tool_calls=tuple(calls),
        usage=usage,
        response_id=response_id,
    )


class GeminiGenerateContentAdapter(ProviderAdapter):
    """Real Gemini generateContent adapter (stdlib transport, zero retries)."""

    name = "gemini-generate-content"

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
        if not isinstance(model, str) or not model:
            raise ProviderError("The configured model is missing.")
        self.model = model
        self.endpoint = parse_endpoint(endpoint, expected_model=model)
        secret = api_key.get_secret_value() if hasattr(api_key, "get_secret_value") else api_key
        if not isinstance(secret, str) or not secret:
            raise ProviderError("The product key is missing.")
        self._key = secret
        self.timeout_s = timeout_s
        self._transport = transport or _http.post_json
        self.max_response_bytes = max_response_bytes

    def __repr__(self) -> str:
        return f"GeminiGenerateContentAdapter(model={self.model!r}, endpoint=<allowlisted>)"

    def check_dispatch(self, body: bytes) -> None:
        """Enforce body/model binding before admission or send."""
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
            "x-goog-api-key": self._key,
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
