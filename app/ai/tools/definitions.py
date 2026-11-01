"""Allowlisted, typed read-only analytics tools (T7).

The only actions the assistant may take: bounded reads through the
shared deterministic analytics layer. Tool names are allowlisted,
arguments are validated Pydantic models with ``extra="forbid"`` and
every execution re-checks the trusted server-side actor scope
(site existence, source membership) plus result-size bounds. There
are no SQL, shell, filesystem, URL-fetch, scan, firewall or mutation
tools, and unknown names or arguments fail closed. Results carry
traceable tool-call IDs, the applied filters, observation time and
coverage for the investigation envelope.
"""

import sqlite3
from dataclasses import asdict
from datetime import UTC, datetime

from pydantic import BaseModel, Field, ValidationError

from app.analytics import service
from app.analytics.contracts import (
    AnalyticsFilter,
    JourneyQuery,
    SlowEndpointsQuery,
    TimeWindow,
    TopPathsQuery,
    TopReferrersQuery,
)

TOOL_NAMES = (
    "get_summary",
    "get_timeseries",
    "get_top_paths",
    "get_top_referrers",
    "get_crawler_claims",
    "get_security_findings",
    "get_error_groups",
    "get_report",
)

#: Bounded aggregate reports behind the single ``get_report`` tool.
#: Timelines, raw rows and full exports are deliberately absent: the
#: assistant gets aggregates only. Comparison reads the validated
#: scope against its own server-derived previous window — models
#: never supply a historical window.
REPORT_NAMES = (
    "performance",
    "slow_endpoints",
    "seo_redirects",
    "seo_client_errors",
    "seo_server_errors",
    "seo_ai_only",
    "referrer_404s",
    "journeys",
    "journey_entries",
    "comparison",
)

_SEO_STATUS_CLASS = {
    "seo_redirects": "3xx",
    "seo_client_errors": "4xx",
    "seo_server_errors": "5xx",
}

TOOL_RESULT_LIMIT = 100


class ToolError(RuntimeError):
    """A tool request was rejected or its execution failed safely."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ToolArguments(BaseModel):
    """Validated tool arguments; unknown fields are rejected, never ignored.

    Aggregate-only selectors: tools narrow the shared deterministic
    aggregates but never return raw request rows (the sanitized explorer
    is a UI/API read, never a tool).
    """

    model_config = {"extra": "forbid"}

    site_id: str = Field(min_length=1, max_length=128)
    source_id: str | None = Field(default=None, min_length=1, max_length=128)
    time_from: datetime
    time_to: datetime
    method: str | None = Field(default=None, min_length=1, max_length=32)
    status: int | None = Field(default=None, ge=100, le=599)
    status_class: str | None = Field(default=None, pattern="^(2xx|3xx|4xx|5xx)$")
    path_prefix: str | None = Field(default=None, min_length=1, max_length=1024)
    referer_host: str | None = Field(default=None, min_length=1, max_length=253)
    traffic: str = Field(
        default="all", pattern="^(all|browser_like|claimed_bot|other_automation|unknown)$"
    )
    bot: str | None = Field(default=None, min_length=1, max_length=64)
    category: str | None = Field(default=None, min_length=1, max_length=64)
    provider: str | None = Field(default=None, min_length=1, max_length=120)
    purpose: str | None = Field(default=None, min_length=1, max_length=120)
    search: str | None = Field(default=None, min_length=1, max_length=128)
    path_exact: str | None = Field(default=None, min_length=1, max_length=1024)
    server_host: str | None = Field(default=None, min_length=1, max_length=253)
    http_version: str | None = Field(default=None, min_length=1, max_length=16)
    mime_type: str | None = Field(default=None, min_length=1, max_length=128)
    cache_status: str | None = Field(default=None, min_length=1, max_length=32)
    tls_protocol: str | None = Field(default=None, min_length=1, max_length=32)
    timing_available: bool | None = Field(default=None)
    upstream_available: bool | None = Field(default=None)
    timing_min_ms: float | None = Field(default=None, ge=0)
    timing_max_ms: float | None = Field(default=None, ge=0)
    limit: int = Field(default=20, ge=1, le=TOOL_RESULT_LIMIT)
    offset: int = Field(default=0, ge=0)
    bucket: str = Field(default="hour", pattern="^(hour|day)$")


class ReportArguments(ToolArguments):
    """Shared selectors plus one explicit aggregate report selector.

    Fixed server-side rankings and windows keep the surface small:
    slow endpoints rank by average, journeys list by request count,
    referrer 404s cover both relations with labels, and comparison
    always reads the server-derived previous window.
    """

    report: str = Field(
        pattern="^(performance|slow_endpoints|seo_redirects|seo_client_errors|seo_server_errors|seo_ai_only|referrer_404s|journeys|journey_entries|comparison)$"
    )


def _check_scope(conn: sqlite3.Connection, args: ToolArguments) -> None:
    try:
        site = conn.execute("SELECT id FROM sites WHERE id = ?", (args.site_id,)).fetchone()
        source_row = None
        if args.source_id is not None:
            source_row = conn.execute(
                "SELECT site_id FROM log_sources WHERE id = ?", (args.source_id,)
            ).fetchone()
    except (sqlite3.Error, OSError) as exc:
        raise ToolError("store_unavailable", "The data store is unavailable.") from exc
    if site is None:
        raise ToolError("forbidden_site", "The requested site is not available to this actor.")
    if args.source_id is not None and (source_row is None or source_row[0] != args.site_id):
        raise ToolError("forbidden_source", "The requested source is not available to this actor.")


def _evidence_filters(args: ToolArguments, filt: AnalyticsFilter) -> dict[str, object]:
    """Full read contract for evidence envelopes and dashboard links.

    Every optional matcher, page bound and bucket travels with the
    evidence so a link reproduces the exact read instead of silently
    dropping part of it.
    """
    filters: dict[str, object] = {
        "site_id": filt.site_id,
        "source_id": filt.source_id,
        "time_from": filt.window.time_from.isoformat(),
        "time_to": filt.window.time_to.isoformat(),
    }
    if filt.method is not None:
        filters["method"] = filt.method
    if filt.status is not None:
        filters["status"] = filt.status
    if filt.status_class is not None:
        filters["status_class"] = filt.status_class
    if filt.path_prefix is not None:
        filters["path_prefix"] = filt.path_prefix
    if filt.referer_host is not None:
        filters["referer_host"] = filt.referer_host
    filters["traffic"] = filt.traffic
    if filt.bot is not None:
        filters["bot"] = filt.bot
    if filt.category is not None:
        filters["category"] = filt.category
    if filt.provider is not None:
        filters["provider"] = filt.provider
    if filt.purpose is not None:
        filters["purpose"] = filt.purpose
    if filt.search is not None:
        filters["search"] = filt.search
    # ``is not None`` keeps selected False/0.0 travelling: a parent
    # matcher for ``timing_available=False`` or ``timing_min_ms=0``
    # is a real selection, never an omitted dimension.
    if filt.path_exact is not None:
        filters["path_exact"] = filt.path_exact
    if filt.server_host is not None:
        filters["server_host"] = filt.server_host
    if filt.http_version is not None:
        filters["http_version"] = filt.http_version
    if filt.mime_type is not None:
        filters["mime_type"] = filt.mime_type
    if filt.cache_status is not None:
        filters["cache_status"] = filt.cache_status
    if filt.tls_protocol is not None:
        filters["tls_protocol"] = filt.tls_protocol
    if filt.timing_available is not None:
        filters["timing_available"] = filt.timing_available
    if filt.upstream_available is not None:
        filters["upstream_available"] = filt.upstream_available
    if filt.timing_min_ms is not None:
        filters["timing_min_ms"] = filt.timing_min_ms
    if filt.timing_max_ms is not None:
        filters["timing_max_ms"] = filt.timing_max_ms
    filters["limit"] = filt.limit
    filters["offset"] = filt.offset
    filters["bucket"] = args.bucket
    if isinstance(args, ReportArguments):
        filters["report"] = args.report
    return filters


def _filter(args: ToolArguments) -> AnalyticsFilter:
    try:
        return AnalyticsFilter(
            site_id=args.site_id,
            source_id=args.source_id,
            window=TimeWindow(time_from=args.time_from, time_to=args.time_to),
            method=args.method,
            status=args.status,
            status_class=args.status_class,  # type: ignore[arg-type]
            path_prefix=args.path_prefix,
            path_exact=args.path_exact,
            referer_host=args.referer_host,
            traffic=args.traffic,  # type: ignore[arg-type]
            bot=args.bot,
            category=args.category,
            provider=args.provider,
            purpose=args.purpose,
            search=args.search,
            server_host=args.server_host,
            http_version=args.http_version,
            mime_type=args.mime_type,
            cache_status=args.cache_status,
            tls_protocol=args.tls_protocol,
            timing_available=args.timing_available,
            upstream_available=args.upstream_available,
            timing_min_ms=args.timing_min_ms,
            timing_max_ms=args.timing_max_ms,
            limit=args.limit,
            offset=args.offset,
        )
    except ValidationError as exc:
        raise ToolError("invalid_arguments", "Tool arguments failed validation.") from exc


def execute_tool(
    conn: sqlite3.Connection,
    rules,
    *,
    name: str,
    arguments: dict,
    tool_call_id: str,
    observation_time: datetime | None = None,
) -> dict:
    """Execute one allowlisted tool read and wrap it with traceable evidence.

    The related aggregate and coverage reads share ONE read snapshot
    (an explicit ``BEGIN`` held for the whole dispatch and released
    before returning), so a writer committing mid-read cannot split
    generations. The connection is released before any provider or
    network await: callers run the provider dispatch only after this
    returns. Corrupt stores surface as ``ToolError``; nothing leaks.
    """
    if name not in TOOL_NAMES:
        raise ToolError("unknown_tool", f"The tool {name!r} is not available.")
    if not isinstance(arguments, dict):
        raise ToolError("invalid_arguments", "Tool arguments must be an object.")
    model = ReportArguments if name == "get_report" else ToolArguments
    try:
        args = model(**arguments)
    except ValidationError as exc:
        raise ToolError("invalid_arguments", "Tool arguments failed validation.") from exc
    _check_scope(conn, args)
    observed = datetime.now(UTC) if observation_time is None else observation_time
    filt = _filter(args)
    held = not conn.in_transaction
    if held:
        try:
            conn.execute("BEGIN")
        except sqlite3.Error as exc:
            raise ToolError("store_unavailable", "The data store is unavailable.") from exc
    try:
        try:
            return _execute_validated(
                conn,
                rules,
                name=name,
                filt=filt,
                args=args,
                tool_call_id=tool_call_id,
                observed=observed,
            )
        except ValueError as exc:
            raise ToolError(
                "invalid_arguments", "Tool selectors are unknown or contradictory."
            ) from exc
    except ToolError:
        if held:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        raise
    except (sqlite3.Error, OSError) as exc:
        if held:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        raise ToolError("store_unavailable", "The data store is unavailable.") from exc
    else:
        if held:
            try:
                conn.execute("COMMIT")
            except sqlite3.Error:
                pass


def _execute_validated(conn, rules, *, name, filt, args, tool_call_id, observed) -> dict:
    if name == "get_summary":
        result = service.summarize(conn, filt, rules, observation_time=observed)
    elif name == "get_timeseries":
        result = service.timeseries(conn, filt, args.bucket, rules)  # type: ignore[arg-type]
    elif name == "get_top_paths":
        result = service.top_paths(conn, TopPathsQuery(filt=filt, sort="requests_desc"), rules)
    elif name == "get_top_referrers":
        result = service.top_referrers(conn, TopReferrersQuery(filt=filt), rules)
    elif name == "get_crawler_claims":
        findings = service.crawler_claims(conn, filt, rules, observation_time=observed)
        result = {"items": [asdict(f) for f in findings], "total": len(findings)}
    elif name == "get_security_findings":
        findings = service.security_findings(conn, filt, rules, observation_time=observed)
        result = {"items": [asdict(f) for f in findings], "total": len(findings)}
    elif name == "get_report":
        result = _execute_report(conn, rules, report=args.report, filt=filt, observed=observed)  # type: ignore[attr-defined]
    else:
        result = service.error_groups(conn, filt, rules)
    return {
        "tool_call_id": tool_call_id,
        "tool": name,
        "filters": _evidence_filters(args, filt),
        "observation_time": observed.isoformat(),
        "coverage": service.coverage_summary(conn, filt, rules),
        "result": result,
    }


def _execute_report(conn, rules, *, report: str, filt, observed) -> dict:
    """Run one bounded aggregate report on the shared deterministic layer.

    Rankings and windows are server-fixed (slow endpoints by
    average, journeys by request count, comparison against the
    server-derived previous window): models select the report, never
    a ranking, a timeline key or a historical window. Unknown
    reports fail closed here and at the schema boundary.
    """
    if report == "performance":
        return service.performance_overview(conn, filt, rules, observation_time=observed)
    if report == "slow_endpoints":
        return service.slow_endpoints(conn, SlowEndpointsQuery(filt=filt), rules)
    if report in _SEO_STATUS_CLASS:
        return service.seo_status_groups(
            conn,
            filt,
            rules,
            status_class=_SEO_STATUS_CLASS[report],  # type: ignore[arg-type]
        )
    if report == "seo_ai_only":
        if rules is None:
            raise ValueError("AI-candidate analysis needs the versioned rules")
        return service.ai_only_paths(conn, filt, rules, observation_time=observed)
    if report == "referrer_404s":
        return service.referrer_404s(conn, filt, rules)
    if report == "journeys":
        return service.journeys(conn, JourneyQuery(filt=filt), rules, observation_time=observed)
    if report == "journey_entries":
        return service.journey_entry_paths(conn, filt, rules, observation_time=observed)
    if report == "comparison":
        previous = service.previous_window_filter(filt)
        return service.compare_windows(conn, filt, previous, rules, observation_time=observed)
    raise ValueError(f"unknown report: {report!r}")


def _schema_for(name: str) -> dict:
    """Bounded argument schema per tool: reports carry the enum selector."""
    if name == "get_report":
        return ReportArguments.model_json_schema()
    return ToolArguments.model_json_schema()


def tool_definitions() -> list[dict]:
    """Provider-visible tool catalog: names and bounded argument schema only."""
    return [
        {
            "name": name,
            "description": f"Bounded read-only analytics read: {name}.",
            "arguments": _schema_for(name),
        }
        for name in TOOL_NAMES
    ]


def response_tool_definitions() -> list[dict]:
    """Responses-protocol tool catalog for the real Meta dispatch.

    The Responses API requires ``{type: "function", name, description,
    parameters}``; the legacy ``arguments`` key is never sent on the
    wire. Parameters share the validated per-tool schema, and every
    execution still revalidates arguments server-side with the
    trusted scope override.
    """
    return [
        {
            "type": "function",
            "name": name,
            "description": f"Bounded read-only analytics read: {name}.",
            "parameters": _schema_for(name),
        }
        for name in TOOL_NAMES
    ]
