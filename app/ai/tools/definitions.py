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

from app.analytics import queries, service
from app.analytics.contracts import AnalyticsFilter, TimeWindow, TopPathsQuery, TopReferrersQuery

TOOL_NAMES = (
    "get_summary",
    "get_timeseries",
    "get_top_paths",
    "get_top_referrers",
    "get_crawler_claims",
    "get_security_findings",
    "get_error_groups",
)

TOOL_RESULT_LIMIT = 100


class ToolError(RuntimeError):
    """A tool request was rejected or its execution failed safely."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ToolArguments(BaseModel):
    """Validated tool arguments; unknown fields are rejected, never ignored."""

    model_config = {"extra": "forbid"}

    site_id: str = Field(min_length=1, max_length=128)
    source_id: str | None = Field(default=None, min_length=1, max_length=128)
    time_from: datetime
    time_to: datetime
    method: str | None = Field(default=None, min_length=1, max_length=32)
    status: int | None = Field(default=None, ge=100, le=599)
    path_prefix: str | None = Field(default=None, min_length=1, max_length=1024)
    referer_host: str | None = Field(default=None, min_length=1, max_length=253)
    limit: int = Field(default=20, ge=1, le=TOOL_RESULT_LIMIT)
    offset: int = Field(default=0, ge=0)
    bucket: str = Field(default="hour", pattern="^(hour|day)$")


def _check_scope(conn: sqlite3.Connection, args: ToolArguments) -> None:
    site = conn.execute("SELECT id FROM sites WHERE id = ?", (args.site_id,)).fetchone()
    if site is None:
        raise ToolError("forbidden_site", "The requested site is not available to this actor.")
    if args.source_id is not None:
        row = conn.execute(
            "SELECT site_id FROM log_sources WHERE id = ?", (args.source_id,)
        ).fetchone()
        if row is None or row[0] != args.site_id:
            raise ToolError(
                "forbidden_source", "The requested source is not available to this actor."
            )


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
    if filt.path_prefix is not None:
        filters["path_prefix"] = filt.path_prefix
    if filt.referer_host is not None:
        filters["referer_host"] = filt.referer_host
    filters["limit"] = filt.limit
    filters["offset"] = filt.offset
    filters["bucket"] = args.bucket
    return filters


def _filter(args: ToolArguments) -> AnalyticsFilter:
    try:
        return AnalyticsFilter(
            site_id=args.site_id,
            source_id=args.source_id,
            window=TimeWindow(time_from=args.time_from, time_to=args.time_to),
            method=args.method,
            status=args.status,
            path_prefix=args.path_prefix,
            referer_host=args.referer_host,
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
    """Execute one allowlisted tool read and wrap it with traceable evidence."""
    if name not in TOOL_NAMES:
        raise ToolError("unknown_tool", f"The tool {name!r} is not available.")
    if not isinstance(arguments, dict):
        raise ToolError("invalid_arguments", "Tool arguments must be an object.")
    try:
        args = ToolArguments(**arguments)
    except ValidationError as exc:
        raise ToolError("invalid_arguments", "Tool arguments failed validation.") from exc
    _check_scope(conn, args)
    observed = datetime.now(UTC) if observation_time is None else observation_time
    filt = _filter(args)
    if name == "get_summary":
        result = service.summarize(conn, filt, observation_time=observed)
    elif name == "get_timeseries":
        result = service.timeseries(conn, filt, args.bucket)  # type: ignore[arg-type]
    elif name == "get_top_paths":
        result = service.top_paths(conn, TopPathsQuery(filt=filt, sort="requests_desc"))
    elif name == "get_top_referrers":
        result = service.top_referrers(conn, TopReferrersQuery(filt=filt))
    elif name == "get_crawler_claims":
        findings = service.crawler_claims(conn, filt, rules, observation_time=observed)
        result = {"items": [asdict(f) for f in findings], "total": len(findings)}
    elif name == "get_security_findings":
        findings = service.security_findings(conn, filt, rules, observation_time=observed)
        result = {"items": [asdict(f) for f in findings], "total": len(findings)}
    else:
        items, total = queries.error_groups(conn, filt)
        result = {"items": items, "total_groups": total}
    return {
        "tool_call_id": tool_call_id,
        "tool": name,
        "filters": _evidence_filters(args, filt),
        "observation_time": observed.isoformat(),
        "coverage": service.coverage_summary(conn, filt),
        "result": result,
    }


def tool_definitions() -> list[dict]:
    """Provider-visible tool catalog: names and bounded argument schema only."""
    schema = ToolArguments.model_json_schema()
    return [
        {
            "name": name,
            "description": f"Bounded read-only analytics read: {name}.",
            "arguments": schema,
        }
        for name in TOOL_NAMES
    ]


def response_tool_definitions() -> list[dict]:
    """Responses-protocol tool catalog for the real Meta dispatch.

    The Responses API requires ``{type: "function", name, description,
    parameters}``; the legacy ``arguments`` key is never sent on the
    wire. Parameters share the validated ToolArguments schema, and
    every execution still revalidates arguments server-side with the
    trusted scope override.
    """
    schema = ToolArguments.model_json_schema()
    return [
        {
            "type": "function",
            "name": name,
            "description": f"Bounded read-only analytics read: {name}.",
            "parameters": schema,
        }
        for name in TOOL_NAMES
    ]
