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
import json
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
    # Aggregate-only reports: every value stays a server-computed
    # aggregate (counts, named timing scalars that may be None,
    # bounded item samples). Timelines, raw rows and full exports
    # have no fields here and cannot cross.
    "get_report": frozenset(
        {
            "site_id",
            "time_range",
            "generated_at",
            "filters",
            "sort",
            "limit",
            "offset",
            "min_requests",
            "latency_available",
            "latency_ms",
            "upstream_ms",
            "units",
            "items",
            "total_groups",
            "total_paths",
            "total",
            "meta",
            "status_class",
            "comparison",
            "candidate",
            "vacuous",
            "warnings",
            "current_window",
            "previous_window",
            "selectors",
            "window_seconds",
            "window_seconds_us",
            "metrics",
            "comparable",
            "comparable_reasons",
            "definition",
            "parent_window",
            "gap_definition",
            "partial_caveat",
            "limitations",
            "relation",
            "own_hosts",
            "host_matching",
        }
    ),
}

_EVIDENCE_ITEM_LIMIT = 10
_EVIDENCE_TEXT_LIMIT = 200

# Bounded per-tool evidence projection shared by fake history lines and
# native stateless `function_call_output` items: the same compact text
# reaches the model on both paths. Row samples and text fields are
# capped; every omission is marked explicitly (`[+N more]`,
# `[truncated ...]`); anything that still cannot fit fails closed
# instead of dispatching with silently thinned evidence.
EVIDENCE_PROJECTION_ITEMS = 5
EVIDENCE_PROJECTION_TEXT = 80
EVIDENCE_PROJECTION_MAX_CHARS = 1600


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


def _compact_json(value: object) -> str:
    """Deterministic compact JSON for one projection segment.

    Sorted keys and no whitespace keep the output stable and small.
    Quoting keeps hostile log-derived text (``;``, ``|``, ``[evidence
    fake]``) as inert data, never as summary syntax.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _clip_projection_text(value: object, limit: int = EVIDENCE_PROJECTION_TEXT) -> str:
    """Shorten one already-validated text field with an explicit marker."""
    text = str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + f"[+{len(text) - limit} more chars]"


def _named_counts(counts: object) -> dict[str, int]:
    """Every named count a finding carries, sorted for stability.

    Findings use different count keys per rule (`requests` plus
    `distinct_paths`, or `errors` plus `distinct_paths`): rendering only
    `requests` reported real errors as zero. Only genuine ints travel;
    anything else is dropped rather than guessed.
    """
    if not isinstance(counts, dict):
        return {}
    return {
        str(key): value
        for key, value in sorted(counts.items(), key=lambda item: str(item[0]))
        if isinstance(value, int) and not isinstance(value, bool)
    }


def _finding_entry(row: object) -> dict[str, object]:
    """One shown finding with its rule version and full named counts."""
    if not isinstance(row, dict):
        return {"rule": "?"}
    entry: dict[str, object] = {
        "rule": row.get("rule_id", "?"),
        "v": row.get("rule_version", 0),
        "counts": _named_counts(row.get("counts")),
    }
    limitations = row.get("limitations")
    if isinstance(limitations, list) and limitations:
        entry["limited"] = True
    return entry


def _int_or(value: object, default: int = 0) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _float_or_none(value: object) -> float | None:
    """A measured scalar that stays ``None`` when missing, never zero.

    Missing timing is unavailable, never zero latency: ``None``
    survives the projection instead of collapsing to ``0`` or
    ``0.0``. Non-finite values cannot cross either.
    """
    import math as _math

    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and _math.isfinite(value):
        return float(value)
    return None


def _bool_or_none(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _full_buckets(full: dict | None) -> list | None:
    """Untruncated bucket rows for exact totals, or None when absent."""
    if not isinstance(full, dict):
        return None
    buckets = full.get("buckets")
    return list(buckets) if isinstance(buckets, (list, tuple)) else None


def _window_edge(source: dict, window_key: str, edge: str) -> str:
    """One exact window edge (ISO string) from a comparison envelope."""
    window = source.get(window_key)
    window = window if isinstance(window, dict) else {}
    edge_value = window.get(edge)
    return edge_value if isinstance(edge_value, str) else "?"


def _project_report(report: object, minimized: dict, full: dict | None) -> str:
    """Compact typed projection for one ``get_report`` value.

    Aggregates only: exact all-row totals from the untruncated
    ``full`` result (falling back to the minimized rows), bounded
    display samples from the scrubbed minimized rows, every
    remainder marked explicitly. Measured scalars keep ``None``
    when missing — never zero. Unknown reports fail closed.
    """
    source = full if isinstance(full, dict) else minimized
    if not isinstance(source, dict) or not isinstance(report, str):
        raise EgressViolation("unknown_tool", "Tool evidence is malformed.")
    if report == "performance":
        latency = source.get("latency_ms")
        latency = latency if isinstance(latency, dict) else {}
        upstream = source.get("upstream_ms")
        upstream = upstream if isinstance(upstream, dict) else {}
        cache = source.get("cache")
        cache = cache if isinstance(cache, dict) else {}
        payload = {
            "latency_available": _bool_or_none(source.get("latency_available")),
            "requests": _int_or(latency.get("total")),
            "measured": _int_or(latency.get("measured")),
            "missing": _int_or(latency.get("missing")),
            "p50_ms": _float_or_none(latency.get("p50_ms")),
            "p95_ms": _float_or_none(latency.get("p95_ms")),
            "average_ms": _float_or_none(latency.get("average_ms")),
            "upstream_measured": _int_or(upstream.get("measured")),
            "upstream_average_ms": _float_or_none(upstream.get("average_ms")),
            "cache_measured": _int_or(cache.get("cache_measured")),
            "cache_hits": _int_or(cache.get("hit_requests")),
            "hit_ratio": _float_or_none(cache.get("hit_ratio")),
        }
        return _compact_json(payload)
    if report == "slow_endpoints":
        items = minimized.get("items")
        rows = list(items) if isinstance(items, (list, tuple)) else []
        total = _int_or(source.get("total_paths"), len(rows))
        shown = [
            {
                "path": _clip_projection_text(row.get("path", "?")),
                "measured": _int_or(row.get("measured")),
                "p95_ms": _float_or_none(row.get("p95_ms")),
                "average_ms": _float_or_none(row.get("average_ms")),
            }
            for row in rows[:EVIDENCE_PROJECTION_ITEMS]
            if isinstance(row, dict)
        ]
        sort = source.get("sort")
        sort = sort if isinstance(sort, str) else "?"
        return _compact_json(
            {
                "paths": total,
                "more": max(0, total - len(shown)),
                "sort": sort,
                "sort_definition": "server avg rank; not a p95 rank",
                "top": shown,
            }
        )
    if report in ("seo_redirects", "seo_client_errors", "seo_server_errors"):
        items = minimized.get("items")
        rows = list(items) if isinstance(items, (list, tuple)) else []
        total = _int_or(source.get("total_groups"), len(rows))
        shown = [
            {
                "path": _clip_projection_text(row.get("path", "?")),
                "rule": row.get("rule_id", "?"),
                "requests": _int_or(row.get("requests")),
            }
            for row in rows[:EVIDENCE_PROJECTION_ITEMS]
            if isinstance(row, dict)
        ]
        return _compact_json({"groups": total, "more": max(0, total - len(shown)), "top": shown})
    if report == "seo_ai_only":
        items = minimized.get("items")
        rows = list(items) if isinstance(items, (list, tuple)) else []
        total = _int_or(source.get("total_paths"), len(rows))
        comparison = source.get("comparison")
        comparison = comparison if isinstance(comparison, dict) else {}
        shown = [
            {
                "path": _clip_projection_text(row.get("path", "?")),
                "ai_requests": _int_or(row.get("ai_requests")),
            }
            for row in rows[:EVIDENCE_PROJECTION_ITEMS]
            if isinstance(row, dict)
        ]
        return _compact_json(
            {
                "paths": total,
                "more": max(0, total - len(shown)),
                "top": shown,
                "universe_requests": _int_or(comparison.get("universe_requests")),
                "ai_paths": _int_or(comparison.get("ai_observed_paths")),
                "other_paths": _int_or(comparison.get("other_observed_paths")),
                "vacuous": _bool_or_none(source.get("vacuous")),
            }
        )
    if report == "referrer_404s":
        items = minimized.get("items")
        rows = list(items) if isinstance(items, (list, tuple)) else []
        total = _int_or(source.get("total_groups"), len(rows))
        shown = [
            {
                "referrer": _clip_projection_text(row.get("referer_host", "?")),
                "target": _clip_projection_text(row.get("target_path", "?")),
                "requests": _int_or(row.get("requests")),
                "internal": _bool_or_none(row.get("internal")),
            }
            for row in rows[:EVIDENCE_PROJECTION_ITEMS]
            if isinstance(row, dict)
        ]
        return _compact_json({"groups": total, "more": max(0, total - len(shown)), "top": shown})
    if report == "referrer_urls":
        # Host-only privacy boundary: local groups are distinct
        # sanitized source URLs, but the model projection carries
        # only the referer host per group. Repeated hosts are
        # host-only URL-group samples with paths withheld — never
        # whole-host aggregate totals and never complete URLs. The
        # limitation travels in the quality envelope; the short row
        # key keeps repeated samples explicit within the 1600-char
        # bound.
        items = minimized.get("items")
        rows = list(items) if isinstance(items, (list, tuple)) else []
        total = _int_or(source.get("total_groups"), len(rows))
        shown = [
            {
                "host_sample": _clip_projection_text(row.get("referer_host", "?")),
                "requests": _int_or(row.get("requests")),
                "errors": _int_or(row.get("errors")),
                "internal": _bool_or_none(row.get("internal")),
            }
            for row in rows[:EVIDENCE_PROJECTION_ITEMS]
            if isinstance(row, dict)
        ]
        return _compact_json({"groups": total, "more": max(0, total - len(shown)), "top": shown})
    if report == "journeys":
        items = minimized.get("items")
        rows = list(items) if isinstance(items, (list, tuple)) else []
        total = _int_or(source.get("total_groups"), len(rows))
        shown = [
            {
                "entry": _clip_projection_text(row.get("entry_path", "?")),
                "requests_total": _int_or(row.get("requests_total")),
                "requests_shown": _int_or(row.get("requests_shown")),
                "completeness": row.get("completeness", "?"),
            }
            for row in rows[:EVIDENCE_PROJECTION_ITEMS]
            if isinstance(row, dict)
        ]
        return _compact_json(
            {"groups": total, "more": max(0, total - len(shown)), "journeys": shown}
        )
    if report == "journey_entries":
        items = minimized.get("items")
        rows = list(items) if isinstance(items, (list, tuple)) else []
        total = _int_or(source.get("total_groups"), len(rows))
        shown = [
            {
                "entry": _clip_projection_text(row.get("entry_path", "?")),
                "journeys": _int_or(row.get("journeys")),
                "complete": _int_or(row.get("complete_journeys")),
                "partial": _int_or(row.get("partial_journeys")),
            }
            for row in rows[:EVIDENCE_PROJECTION_ITEMS]
            if isinstance(row, dict)
        ]
        return _compact_json({"groups": total, "more": max(0, total - len(shown)), "top": shown})
    if report == "countries":
        # Aggregate-only country evidence: exact per-country counts
        # with top/remainder bounds, honest lookup coverage and the
        # portable DB-IP credit. Country codes and the credit strings
        # are server-generated labels — never original addresses, raw
        # rows, keys or paths. Hostile client/country scope narrowing
        # is enforced before execution (scope wins); the projection
        # only renders the executed read.
        items = minimized.get("items")
        rows = list(items) if isinstance(items, (list, tuple)) else []
        full_items = source.get("items")
        full_rows = list(full_items) if isinstance(full_items, (list, tuple)) else rows
        geo = source.get("geo")
        geo = geo if isinstance(geo, dict) else {}
        credit = source.get("attribution")
        credit = credit if isinstance(credit, dict) else {}
        shown = [
            {
                "country": row.get("country", "?"),
                "requests": _int_or(row.get("requests")),
                "errors_4xx": _int_or(row.get("errors_4xx")),
                "errors_5xx": _int_or(row.get("errors_5xx")),
                "bytes": _int_or(row.get("bytes_total")),
            }
            for row in rows[:EVIDENCE_PROJECTION_ITEMS]
            if isinstance(row, dict)
        ]
        return _compact_json(
            {
                "countries": len(full_rows),
                "more": max(0, len(full_rows) - len(shown)),
                "top": shown,
                "with_country": _int_or(geo.get("with_country")),
                "unknown": _int_or(geo.get("unknown")),
                "unavailable": _int_or(geo.get("unavailable")),
                "legacy": _int_or(geo.get("legacy")),
                "sources": [
                    value for value in (geo.get("sources") or []) if isinstance(value, str)
                ],
                "releases": [
                    value for value in (geo.get("releases") or []) if isinstance(value, str)
                ],
                "credit": credit.get("text", "?") if isinstance(credit, dict) else "?",
            }
        )
    if report == "comparison":
        metrics = source.get("metrics")
        rows = list(metrics) if isinstance(metrics, (list, tuple)) else []
        # The per-hour rate is derivable from requests and the exact
        # windows below, so it stays out of the bounded projection;
        # the full envelope (and API/UI) keeps all seven metrics.
        shown = [
            {
                # Current and previous cross exactly (ints stay ints);
                # the absolute change is their exact difference, so only
                # the non-derivable ratio status travels alongside.
                "name": row.get("name", "?"),
                "current": row.get("current"),
                "previous": row.get("previous"),
                "status": row.get("ratio_status", "?"),
            }
            for row in rows
            if isinstance(row, dict) and row.get("name") != "requests_per_hour"
        ]
        statuses = {row.get("status", "?") for row in shown}
        payload: dict[str, object] = {
            "comparable": _bool_or_none(source.get("comparable")),
            "metrics": shown,
            "definition": "inside halves: baseline first, current second",
            "current": [
                _window_edge(source, "current_window", "time_from"),
                _window_edge(source, "current_window", "time_to"),
            ],
            "previous": [
                _window_edge(source, "previous_window", "time_from"),
                _window_edge(source, "previous_window", "time_to"),
            ],
        }
        if len(statuses) == 1:
            # Uniform verdict (e.g. every ratio limited): hoist the one
            # shared status instead of repeating it on every metric.
            only = next(iter(statuses))
            payload["status"] = only
            for row in shown:
                del row["status"]
        return _compact_json(payload)
    raise EgressViolation("unknown_tool", f"No evidence contract for {report!r}.")


def _project_result(
    tool_name: str,
    minimized: dict,
    full: dict | None = None,
    *,
    report: object = None,
) -> str:
    """Compact typed per-tool result over allowlisted minimized fields.

    Display strings always come from the validated, masked minimized
    rows; exact totals and the true bucket/group counts come from the
    untruncated `full` result when provided (falling back to the
    minimized rows for direct unit calls). Every remainder is computed
    against the true total, never against the 10-row serialized cap, so
    a sampled view can never masquerade as a complete one.
    """
    if not isinstance(minimized, dict):
        raise EgressViolation("unknown_tool", "Tool evidence is malformed.")
    if tool_name == "get_summary":
        totals = minimized.get("totals", {})
        totals = totals if isinstance(totals, dict) else {}
        statuses = minimized.get("status_distribution", [])
        rows = list(statuses) if isinstance(statuses, (list, tuple)) else []
        shown = [
            [row.get("status", "?"), _int_or(row.get("requests"))]
            for row in rows[:EVIDENCE_PROJECTION_ITEMS]
            if isinstance(row, dict)
        ]
        full_len: int | None = None
        if isinstance(full, dict) and isinstance(full.get("status_distribution"), list):
            full_len = len(full["status_distribution"])
        total_statuses = full_len if full_len is not None else len(rows)
        duration = minimized.get("duration", {})
        timing = (
            "available"
            if isinstance(duration, dict) and duration.get("available")
            else "unavailable"
        )
        payload = {
            "bytes": _int_or(totals.get("bytes_total")),
            "errors_4xx": _int_or(totals.get("errors_4xx")),
            "errors_5xx": _int_or(totals.get("errors_5xx")),
            "requests": _int_or(totals.get("requests")),
            "statuses": shown,
            "statuses_more": max(0, total_statuses - len(shown)),
            "timing": timing,
        }
        return _compact_json(payload)
    if tool_name == "get_timeseries":
        rows = _full_buckets(full)
        if rows is None:
            buckets = minimized.get("buckets", [])
            rows = list(buckets) if isinstance(buckets, (list, tuple)) else []
        valid = [row for row in rows if isinstance(row, dict)]
        total_requests = sum(_int_or(row.get("requests")) for row in valid)
        total_errors = sum(_int_or(row.get("errors")) for row in valid)
        stamps = [row.get("bucket") for row in valid if isinstance(row.get("bucket"), str)]
        sample_rows = minimized.get("buckets")
        sample = list(sample_rows) if isinstance(sample_rows, (list, tuple)) else []
        sample_ids = [
            row.get("bucket")
            for row in sample[:EVIDENCE_PROJECTION_ITEMS]
            if isinstance(row, dict) and isinstance(row.get("bucket"), str)
        ]
        payload = {
            "bucket": minimized.get("bucket", "-"),
            "buckets": len(valid),
            "errors": total_errors,
            "first": stamps[0] if stamps else "-",
            "last": stamps[-1] if stamps else "-",
            "more_buckets": max(0, len(valid) - len(sample_ids)),
            "requests": total_requests,
            "sample": sample_ids,
        }
        return _compact_json(payload)
    if tool_name == "get_top_paths":
        items = minimized.get("items")
        rows = list(items) if isinstance(items, (list, tuple)) else []
        total = _int_or(minimized.get("total_groups"), len(rows))
        if isinstance(full, dict):
            total = _int_or(full.get("total_groups"), total)
        shown = [
            {
                "path": _clip_projection_text(row.get("path", "?")),
                "requests": _int_or(row.get("requests")),
                "status": row.get("status", "?"),
            }
            for row in rows[:EVIDENCE_PROJECTION_ITEMS]
            if isinstance(row, dict)
        ]
        return _compact_json({"groups": total, "more": max(0, total - len(shown)), "top": shown})
    if tool_name == "get_top_referrers":
        items = minimized.get("items")
        rows = list(items) if isinstance(items, (list, tuple)) else []
        total = _int_or(minimized.get("total_groups"), len(rows))
        if isinstance(full, dict):
            total = _int_or(full.get("total_groups"), total)
        shown = [
            {
                "host": _clip_projection_text(row.get("referer_host", "?")),
                "requests": _int_or(row.get("requests")),
            }
            for row in rows[:EVIDENCE_PROJECTION_ITEMS]
            if isinstance(row, dict)
        ]
        return _compact_json({"groups": total, "more": max(0, total - len(shown)), "top": shown})
    if tool_name in ("get_crawler_claims", "get_security_findings"):
        items = minimized.get("items")
        rows = list(items) if isinstance(items, (list, tuple)) else []
        total = _int_or(minimized.get("total"), len(rows))
        if isinstance(full, dict):
            total = _int_or(full.get("total"), total)
        shown = [_finding_entry(row) for row in rows[:EVIDENCE_PROJECTION_ITEMS]]
        return _compact_json({"more": max(0, total - len(shown)), "items": shown, "total": total})
    if tool_name == "get_error_groups":
        items = minimized.get("items")
        rows = list(items) if isinstance(items, (list, tuple)) else []
        total = _int_or(minimized.get("total_groups"), len(rows))
        if isinstance(full, dict):
            total = _int_or(full.get("total_groups"), total)
        shown = [
            {
                "path": _clip_projection_text(row.get("path", "?")),
                "requests": _int_or(row.get("requests")),
                "status": row.get("status", "?"),
            }
            for row in rows[:EVIDENCE_PROJECTION_ITEMS]
            if isinstance(row, dict)
        ]
        return _compact_json({"groups": total, "more": max(0, total - len(shown)), "top": shown})
    if tool_name == "get_report":
        return _project_report(report, minimized, full)
    raise EgressViolation("unknown_tool", f"No evidence contract for {tool_name}.")


def _project_scope(filters: dict) -> str:
    """Exact executed scope as compact JSON with sorted keys.

    Every selected and model-narrowed filter value travels exactly —
    never clipped — so the summary replays the real read. Decoded
    scope values are egress-validated BEFORE JSON encoding so a
    forbidden shape cannot hide behind escape sequences; the complete
    encoded scope is validated again by the caller. A scope that
    cannot fit the projection bound fails the dispatch closed instead
    of sending a thinned, unreproducible one.
    """
    if not isinstance(filters, dict):
        raise EgressViolation("unknown_tool", "Tool evidence scope is malformed.")
    exact: dict[str, object] = {}
    for key in sorted(filters):
        value = filters[key]
        if isinstance(value, str):
            check_outgoing(value, context="tool evidence scope")
            exact[str(key)] = value
        elif isinstance(value, bool) or value is None:
            exact[str(key)] = value
        elif isinstance(value, (int, float)):
            import math as _math

            if isinstance(value, float) and not _math.isfinite(value):
                raise EgressViolation("unknown_tool", "Tool evidence scope is malformed.")
            exact[str(key)] = value
        else:
            raise EgressViolation("unknown_tool", "Tool evidence scope is malformed.")
    for key in exact:
        check_outgoing(str(key), context="tool evidence scope")
    return _compact_json(exact)


def project_evidence_summary(
    *,
    tool_name: str,
    tool_call_id: str,
    minimized: dict,
    filters: dict,
    observation_time: str,
    coverage: dict,
    full_result: dict | None = None,
    quality: dict | None = None,
) -> str:
    """Bounded evidence projection both model paths share.

    Built ONLY from already egress-validated values (the allowlisted
    minimized result plus server-generated envelope metadata), with
    decoded scope/metadata values validated BEFORE JSON encoding so
    forbidden shapes cannot hide behind escape sequences, then the
    complete final string is validated again — hostile content fails
    closed in `serialize_evidence` first and is never thinned into
    safety here. Exact totals come from the untruncated `full_result`
    while display strings stay on validated minimized rows. Carries the
    exact evidence ID, tool name, actual observation time, the exact
    executed scope, coverage and the compact result with explicit
    remainder markers, plus compact quality state (timing, warnings,
    import state, limitations) when provided. Raises `EgressViolation`
    when the meaningful content cannot fit the bound.
    """
    if not isinstance(minimized, dict) or not isinstance(observation_time, str):
        raise EgressViolation("unknown_tool", "Tool evidence is malformed.")
    if not isinstance(tool_call_id, str) or not tool_call_id:
        raise EgressViolation("unknown_tool", "Tool evidence ID is malformed.")
    if not isinstance(coverage, dict):
        raise EgressViolation("unknown_tool", "Tool evidence coverage is malformed.")
    if full_result is not None and not isinstance(full_result, dict):
        raise EgressViolation("unknown_tool", "Tool evidence is malformed.")
    if quality is not None and not isinstance(quality, dict):
        raise EgressViolation("unknown_tool", "Tool evidence quality is malformed.")
    coverage_payload = {
        "events": coverage.get("unique_events", "?"),
        "from": coverage.get("observed_min", "?"),
        "to": coverage.get("observed_max", "?"),
    }
    # Decoded allowlisted metadata crosses the boundary BEFORE any JSON
    # encoding or clipping, so a Combined-like scope value or poisoned
    # suffix cannot hide behind escape sequences. Result display rows
    # stay on the already-scrubbed minimized payload (masking preserved);
    # only the outgoing metadata here is validated decoded. The complete
    # encoded summary is validated again below.
    check_wire_values(
        {
            "tool": tool_name,
            "tool_call_id": tool_call_id,
            "observed": observation_time,
            "filters": filters,
            "coverage": coverage_payload,
            "quality": quality if quality is not None else {},
        },
        context="tool evidence metadata",
    )
    report = filters.get("report") if isinstance(filters, dict) else None
    summary = (
        f"[evidence {tool_call_id}] {tool_name} "
        f"result={_project_result(tool_name, minimized, full_result, report=report)} "
        f"scope={_project_scope(filters)} "
        f"observed={observation_time} "
        f"coverage={_compact_json(coverage_payload)}"
    )
    if quality:
        summary += f" quality={_compact_json(quality)}"
    if len(summary) > EVIDENCE_PROJECTION_MAX_CHARS:
        raise EgressViolation("payload_too_large", "Tool evidence exceeds its projection bound.")
    return check_outgoing(summary, context="tool evidence summary")
