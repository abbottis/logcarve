"""Minimized, fail-closed data-egress boundary (T7).

Only aggregates, rule references, time windows and sanitized evidence
may cross toward a provider. Raw log lines, original client addresses,
query secrets, credentials and tokens never leave. The boundary covers
prompts, conversation history, tool outputs, retries and replayed
context: every outgoing string is scanned, and evidence payloads are
built from an allowlisted field serializer rather than by forwarding
stored rows.

Log-derived strings (paths, User-Agents, Referer hosts) are treated as
untrusted data even when they resemble instructions or secrets.
Prompts, history and questions fail the whole transmission closed on
any forbidden shape. Inside tool evidence only, raw network-address
shapes are masked with a fixed placeholder (they are not original
client addresses, which never reach this layer); every other forbidden
shape still fails closed, so a smuggled secret or log line can never
slip through a masking gap.
"""

import ipaddress
import re

MAX_OUTGOING_CHARS = 8000

# Total serialized wire-body cap for a real Responses dispatch. Tool
# schemas alone exceed the 8k per-content bound, so the whole body is
# never scanned as one string; decoded values are validated
# individually (see check_wire_values) and the exact immutable
# serialized body is additionally bounded here.
MAX_WIRE_BYTES = 65536
# Finite bound on decoded values in one dispatch (dicts, lists and
# string leaves), so a hostile shape cannot force unbounded work.
MAX_WIRE_VALUES = 5000

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Colon-bearing tokens are validated with real address parsing, never
# with shape heuristics: compressed (`::1`, `::`), bracketed
# (`[::1]`), embedded (`::ffff:203.0.113.7`) and scoped (`fe80::1%eth0`)
# forms all parse, while ISO-8601 timestamps and bare times such as
# 12:30:00 never do. No word boundary is required at a leading colon.
_ADDRESS_TOKEN = re.compile(r"\[?[0-9a-fA-F:.]{0,64}:[0-9a-fA-F:.\%]{1,64}\]?")


def _parse_address(token: str):
    """Return an ipaddress object for a raw network-address token, else None."""
    cleaned = token.strip("[]")
    if not cleaned:
        return None
    try:
        return ipaddress.ip_address(cleaned.split("%")[0])
    except ValueError:
        return None


def _contains_address(text: str) -> bool:
    if _IPV4.search(text):
        return True
    return any(_parse_address(m.group(0)) is not None for m in _ADDRESS_TOKEN.finditer(text))


def _mask_addresses_in_text(text: str) -> str:
    masked = _IPV4.sub("[redacted-address]", text)

    def _replace(match: re.Match) -> str:
        return (
            "[redacted-address]" if _parse_address(match.group(0)) is not None else match.group(0)
        )

    return _ADDRESS_TOKEN.sub(_replace, masked)


# NCSA Combined shape: host ident user [time] "request" status bytes "referer" "agent"
_COMBINED_LINE = re.compile(r'\S+ \S+ \S+ \[[^\]]+\] "[^"]*" \d{3} \S+( "[^"]*" "[^"]*")?')
_QUERY_SECRET = re.compile(
    r"[?&](?:[^?\s&#=]{0,64})?(?:key|token|secret|password|passwd|auth|session|cookie)[^?\s&#=]{0,64}=",
    re.IGNORECASE,
)
_CREDENTIAL_ASSIGN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|bearer|authorization|cookie|set-cookie)\s*[:=]",
    re.IGNORECASE,
)
_PRODUCT_TOKEN = re.compile(r"\blc_[A-Za-z0-9_-]{8,}")
_PEM_BLOCK = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_URL_CREDENTIALS = re.compile(r"://[^/\s@]+:[^/\s@]+@")


class EgressViolation(RuntimeError):
    """An outgoing payload carries data that must never leave the boundary."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def check_outgoing(text: str, *, context: str) -> str:
    """Fail closed when text carries exfiltratable data.

    Returns the text unchanged when it is within size bounds and free of
    forbidden shapes. Raises EgressViolation otherwise; callers abort
    the provider request and never retry with the same payload.
    """
    if not isinstance(text, str):
        raise EgressViolation("non_text_payload", f"Non-text payload in {context}.")
    if len(text) > MAX_OUTGOING_CHARS:
        raise EgressViolation("payload_too_large", f"Outgoing {context} exceeds the size bound.")
    if _contains_address(text):
        raise EgressViolation(
            "raw_network_address",
            f"Outgoing {context} carries data that must not leave the server.",
        )
    for code, pattern in (
        ("raw_log_line", _COMBINED_LINE),
        ("query_secret", _QUERY_SECRET),
        ("credential_material", _CREDENTIAL_ASSIGN),
        ("credential_material", _PRODUCT_TOKEN),
        ("credential_material", _PEM_BLOCK),
        ("credential_material", _URL_CREDENTIALS),
    ):
        if pattern.search(text):
            raise EgressViolation(
                code, f"Outgoing {context} carries data that must not leave the server."
            )
    return text


def check_wire_values(value, *, context: str) -> None:
    """Fail closed when decoded outbound values carry exfiltratable data.

    Validates the DECODED actual dispatch values (protocol fields,
    typed input items, replayed evidence) instead of the escaped JSON
    serialization, so forbidden content cannot hide behind JSON
    escaping. Every string leaf crosses the existing per-content
    bounds; container shape itself is bounded by MAX_WIRE_VALUES.
    Non-string scalars (int/float/bool/None) pass; any other type
    fails closed. Returns None; callers abort the dispatch on
    EgressViolation with no retry of the same payload.
    """
    seen = 0
    stack = [value]
    while stack:
        seen += 1
        if seen > MAX_WIRE_VALUES:
            raise EgressViolation(
                "payload_too_large", f"Outgoing {context} exceeds the value bound."
            )
        current = stack.pop()
        if isinstance(current, str):
            check_outgoing(current, context=context)
        elif isinstance(current, dict):
            for key, item in current.items():
                if not isinstance(key, str):
                    raise EgressViolation("non_text_payload", f"Non-text payload key in {context}.")
                check_outgoing(key, context=context)
                stack.append(item)
        elif isinstance(current, (list, tuple)):
            stack.extend(current)
        elif current is None or isinstance(current, (bool, int, float)):
            continue
        else:
            raise EgressViolation("non_text_payload", f"Non-text payload in {context}.")


# Allowlisted evidence fields per tool result: everything else is
# dropped before serialization, so new analytics fields cannot leak
# across the boundary by accident.
_EVIDENCE_FIELDS: dict[str, frozenset[str]] = {
    "get_summary": frozenset(
        {"site_id", "time_range", "totals", "status_distribution", "duration", "warnings"}
    ),
    "get_timeseries": frozenset({"site_id", "time_range", "bucket", "buckets"}),
    "get_top_paths": frozenset({"items", "total_groups"}),
    "get_top_referrers": frozenset({"items", "total_groups"}),
    "get_crawler_claims": frozenset({"items", "total"}),
    "get_security_findings": frozenset({"items", "total"}),
    "get_error_groups": frozenset({"items", "total_groups"}),
}

_EVIDENCE_ITEM_LIMIT = 10
_EVIDENCE_TEXT_LIMIT = 200


def _scrub(value):
    if isinstance(value, str):
        masked = _mask_addresses_in_text(value[:_EVIDENCE_TEXT_LIMIT])
        return check_outgoing(masked, context="tool evidence")
    if isinstance(value, list):
        return [_scrub(item) for item in value[:_EVIDENCE_ITEM_LIMIT]]
    if isinstance(value, dict):
        return {key: _scrub(item) for key, item in value.items()}
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return check_outgoing(str(value)[:_EVIDENCE_TEXT_LIMIT], context="tool evidence")


def serialize_evidence(tool_name: str, result: dict) -> dict:
    """Project a tool result onto its allowlisted evidence fields.

    Unknown tools, unknown fields and forbidden embedded shapes all fail
    closed. Coverage and limitation notes travel separately in the
    investigation envelope, never inside provider-visible evidence.
    """
    allowed = _EVIDENCE_FIELDS.get(tool_name)
    if allowed is None:
        raise EgressViolation("unknown_tool", f"No evidence contract for {tool_name}.")
    return {key: _scrub(result[key]) for key in allowed if key in result}
