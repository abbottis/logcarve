"""Browser dashboard pages and fragments (T9-A: shell, login, Overview).

Reads run exclusively through the shared deterministic analytics
services over a read-only handle; no metric is computed here. Browser
sessions authorize these pages (``require_admin_session``); Bearer
tokens never do. The login form posts JSON to the existing
``POST /api/v1/admin/login`` endpoint, so no form parsing was added.
Every log-derived value renders through Jinja2 autoescaping.
"""

from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote, urlencode
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError

from app.analytics import queries, service
from app.analytics.contracts import (
    AnalyticsFilter,
    TimeWindow,
    TopPathsQuery,
    TopReferrersQuery,
)
from app.analytics.service import Finding
from app.api.deps import read_store, require_admin_session
from app.config import load_settings
from app.web.evidence import evidence_url as _evidence_url
from app.web.locales import t

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))

DISPLAY_TIMEZONES = ("UTC", "Europe/Berlin")
RANGE_PRESETS = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}
DEFAULT_RANGE = "7d"


def _safe_next(value: str | None) -> str:
    """Allow only absolute in-site paths.

    Rejects protocol-relative ``//host`` targets (browsers normalize
    ``/\\example.org`` the same external way, so backslashes are
    rejected too) and any control character that could smuggle
    delimiters past parsing.
    """
    if not value or not value.startswith("/"):
        return "/"
    if value.startswith("//"):
        return "/"
    if "\\" in value:
        return "/"
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        return "/"
    return value


def _redirect_to_login(request: Request) -> RedirectResponse:
    nxt = request.url.path
    if request.url.query:
        nxt += "?" + request.url.query
    # Encode the full target so filter query parameters survive login
    # instead of being parsed as part of the login URL.
    return RedirectResponse(url=f"/login?next={quote(_safe_next(nxt), safe='')}", status_code=302)


def _session_or_none(request: Request):
    session = require_admin_session(request)
    return None if isinstance(session, JSONResponse) else session


def _parse_view_params(request: Request, now: datetime, default_limit: int = 20):
    """Shared filter-bar parameters; returns (params, error_key)."""
    q = request.query_params
    site = (q.get("site") or "").strip() or None
    preset = (q.get("range") or DEFAULT_RANGE).strip()
    tz_name = (q.get("tz") or "UTC").strip()
    if tz_name not in DISPLAY_TIMEZONES:
        return None, "error.bad_params"
    try:
        tz = ZoneInfo(tz_name)
    except ZoneInfoNotFoundError:
        return None, "error.bad_params"
    if preset == "custom":
        raw_from, raw_to = (q.get("from") or "").strip(), (q.get("to") or "").strip()
        if not raw_from or not raw_to:
            return None, "error.bad_params"
        try:
            time_from = datetime.fromisoformat(raw_from)
            time_to = datetime.fromisoformat(raw_to)
        except ValueError:
            return None, "error.bad_params"
        # The filter bar labels these fields as UTC; attach UTC explicitly
        # instead of guessing. The analytics contract still rejects any
        # naive value that reaches it from elsewhere.
        if time_from.tzinfo is None:
            time_from = time_from.replace(tzinfo=UTC)
        if time_to.tzinfo is None:
            time_to = time_to.replace(tzinfo=UTC)
    elif preset in RANGE_PRESETS:
        time_to = now
        time_from = now - RANGE_PRESETS[preset]
    else:
        return None, "error.bad_params"
    try:
        window = TimeWindow(time_from=time_from, time_to=time_to)
    except ValidationError:
        return None, "error.bad_params"
    # datetime-local controls accept only `YYYY-MM-DDTHH:MM` without an
    # offset; normalize the applied window into exactly that display
    # form (explicitly UTC, as labelled) so custom values survive Apply.
    display = {
        "from": window.time_from.astimezone(UTC).strftime("%Y-%m-%dT%H:%M"),
        "to": window.time_to.astimezone(UTC).strftime("%Y-%m-%dT%H:%M"),
    }
    matchers, error = _parse_matchers(q)
    if error is not None:
        return None, error
    page, error = _parse_paging(q, default=default_limit)
    if error is not None:
        return None, error
    bucket = (q.get("bucket") or "").strip() or None
    if bucket is not None and bucket not in ("hour", "day"):
        return None, "error.bad_params"
    source = (q.get("source") or "").strip() or None
    if source is not None and (len(source) > 128 or not source.isascii()):
        return None, "error.bad_params"
    return {
        "site": site,
        "source": source,
        "range": preset,
        "tz_name": tz_name,
        "tz": tz,
        "window": window,
        "display_from": display["from"],
        "display_to": display["to"],
        "matchers": matchers,
        "limit": page["limit"],
        "offset": page["offset"],
        "bucket": bucket,
    }, None


def _parse_matchers(q) -> tuple[dict | None, str | None]:
    """Optional event matchers; every value is allowlisted server-side.

    Values are preserved EXACTLY (no case folding): analytics matchers
    are case-sensitive SQL string comparisons, so the dashboard must
    replay the same read as an assistant evidence link instead of
    silently turning one read into another.
    """
    raw_method = (q.get("method") or "").strip() or None
    if raw_method is not None and (len(raw_method) > 32 or not raw_method.isascii()):
        return None, "error.bad_params"
    raw_status = (q.get("status") or "").strip() or None
    status = None
    if raw_status is not None:
        # isdigit() admits non-ASCII digits such as ² that int()
        # rejects, so parse in a guarded block against the shared
        # contract range instead of trusting the character class.
        try:
            status = int(raw_status)
        except ValueError:
            return None, "error.bad_params"
        if not 100 <= status <= 599:
            return None, "error.bad_params"
    path_prefix = (q.get("path_prefix") or "").strip() or None
    # Length caps mirror the shared AnalyticsFilter contract exactly so a
    # value passing here can never violate it downstream. The literal
    # "*" is the asterisk-form target the parser stores verbatim for
    # "OPTIONS *"; it is LIKE-escaped downstream, so it stays data.
    if path_prefix is not None and (
        (path_prefix != "*" and not path_prefix.startswith("/"))
        or len(path_prefix) > 1024
        or "\\" in path_prefix
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in path_prefix)
    ):
        return None, "error.bad_params"
    # Verbatim: stored referrer hosts are lowercase, so a mixed-case
    # value replays honestly (usually to zero rows), never folded.
    referer_host = (q.get("referer_host") or "").strip() or None
    if referer_host is not None and len(referer_host) > 253:
        return None, "error.bad_params"
    return {
        "method": raw_method,
        "status": status,
        "path_prefix": path_prefix,
        "referer_host": referer_host,
    }, None


def _parse_paging(q, default: int = 20) -> tuple[dict | None, str | None]:
    """Bounded offset pagination shared by every data view."""
    raw_limit, raw_offset = (q.get("limit") or "").strip(), (q.get("offset") or "").strip()
    try:
        limit = int(raw_limit) if raw_limit else default
        offset = int(raw_offset) if raw_offset else 0
    except ValueError:
        return None, "error.bad_params"
    if not 1 <= limit <= 100 or offset < 0:
        return None, "error.bad_params"
    return {"limit": limit, "offset": offset}, None


def _canonical_query(params, site: str) -> dict[str, object]:
    """Shared filter set for canonical page URLs (route path excluded)."""
    query: dict[str, object] = {
        "site": site,
        "range": params["range"],
        "from": params["window"].time_from.isoformat(),
        "to": params["window"].time_to.isoformat(),
        "tz": params["tz_name"],
    }
    if params["source"] is not None:
        query["source"] = params["source"]
    for key, value in params["matchers"].items():
        if value is not None:
            query[key] = value
    query["limit"] = params["limit"]
    query["offset"] = params["offset"]
    if params["bucket"] is not None:
        query["bucket"] = params["bucket"]
    return query


def _canonical(path: str, params, site: str) -> str:
    """Canonical page URL carrying the complete applied filter set."""
    return path + "?" + urlencode(_canonical_query(params, site))


def _nav_query(params, site: str) -> str:
    """Window-level navigation state (paging and matchers stay page-local)."""
    query: dict[str, object] = {
        "site": site,
        "range": params["range"],
        "from": params["window"].time_from.isoformat(),
        "to": params["window"].time_to.isoformat(),
        "tz": params["tz_name"],
    }
    if params["source"] is not None:
        query["source"] = params["source"]
    return "?" + urlencode(query)


def _page_url(path: str, params, site: str, **overrides) -> str:
    """Canonical URL for another dashboard page with the same window."""
    query = _canonical_query(params, site)
    query.update({key: str(value) for key, value in overrides.items() if value is not None})
    return path + "?" + urlencode(query)


def _format_bucket(iso_value: str, tz: ZoneInfo, bucket: str) -> str:
    moment = datetime.fromisoformat(iso_value).astimezone(tz)
    if bucket == "hour":
        return moment.strftime("%Y-%m-%d %H:00")
    return moment.strftime("%Y-%m-%d")


def _site_or_error(conn, params) -> tuple[str | None, list | None, str | None]:
    """Resolve the requested site against the configured sites."""
    sites = conn.execute("SELECT id, name FROM sites ORDER BY id").fetchall()
    if not sites:
        return None, None, "error.unknown_site"
    site_ids = [row[0] for row in sites]
    site = params["site"] or site_ids[0]
    if site not in site_ids:
        return None, None, "error.unknown_site"
    return site, sites, None


class _InvalidFilter(Exception):
    """An intended filter-contract violation; rendered as a safe 400."""


def _checked_base_filter(params, site: str) -> AnalyticsFilter:
    """Build the window-level filter, mapping contract violations to 400.

    Only pydantic ValidationError is caught here: a value that passed
    parsing but still violates the shared AnalyticsFilter contract is
    client input, while any other exception stays a 500.
    """
    try:
        return _base_filter(params, site)
    except ValidationError as exc:
        raise _InvalidFilter from exc


def _base_filter(params, site: str) -> AnalyticsFilter:
    """Window-level event filter: matchers apply, paging never does."""
    return AnalyticsFilter(
        site_id=site,
        window=params["window"],
        source_id=params["source"],
        method=params["matchers"]["method"],
        status=params["matchers"]["status"],
        path_prefix=params["matchers"]["path_prefix"],
        referer_host=params["matchers"]["referer_host"],
        limit=100,
        offset=0,
    )


def _source_or_error(conn, site: str, source: str | None) -> str | None:
    """The requested source must belong to the selected site."""
    if source is None:
        return None
    row = conn.execute(
        "SELECT id FROM log_sources WHERE id = ? AND site_id = ?", (source, site)
    ).fetchone()
    return None if row else "error.bad_params"


def _overview_context(conn, rules, params) -> tuple[dict | None, str | None]:
    site, sites, error = _site_or_error(conn, params)
    if error is not None:
        return None, error
    error = _source_or_error(conn, site, params["source"])
    if error is not None:
        return None, error
    try:
        filt = _checked_base_filter(params, site)
    except _InvalidFilter:
        return None, "error.bad_params"
    summary = service.summarize(conn, filt)
    span = params["window"].time_to - params["window"].time_from
    bucket = params["bucket"] or ("day" if span > timedelta(hours=48) else "hour")
    series = service.timeseries(conn, filt, bucket)
    table_filt = filt.model_copy(update={"limit": params["limit"], "offset": params["offset"]})
    top_paths = service.top_paths(conn, TopPathsQuery(filt=table_filt))
    top_referrers = service.top_referrers(conn, TopReferrersQuery(filt=table_filt))
    claims = service.crawler_claims(conn, filt, rules)[:5]
    findings = service.security_findings(conn, filt, rules)[:5]
    totals = summary["totals"]
    requests = totals["requests"]
    error_share = (
        round(100.0 * (totals["errors_4xx"] + totals["errors_5xx"]) / requests, 1)
        if requests
        else None
    )
    top_claim = (
        {"title": claims[0].title, "requests": claims[0].counts["requests"]} if claims else None
    )
    timeline = [
        {
            "label": _format_bucket(b["bucket"], params["tz"], bucket),
            "requests": b["requests"],
        }
        for b in series["buckets"]
    ]
    return {
        "t": t,
        "sites": [{"id": row[0], "name": row[1]} for row in sites],
        "site": site,
        "range": params["range"],
        "tz_name": params["tz_name"],
        "display_from": params["display_from"],
        "display_to": params["display_to"],
        "window_from": filt.window.time_from.isoformat(),
        "window_to": filt.window.time_to.isoformat(),
        "canonical_url": _canonical("/", params, site),
        "nav_query": _nav_query(params, site),
        "fragment_url": "/partials/overview",
        "page_url": lambda path, **overrides: _page_url(path, params, site, **overrides),
        "evidence_url": _evidence_url,
        "matchers": {k: v for k, v in params["matchers"].items() if v is not None},
        "params_source": params["source"],
        "summary": summary,
        "totals": totals,
        "error_share": error_share,
        "top_claim": top_claim,
        "timeline": timeline,
        "status_rows": summary["status_distribution"],
        "paths": top_paths,
        "referrers": top_referrers,
        "claims": claims,
        "findings": findings,
        "bucket": bucket,
        "limit": params["limit"],
        "offset": params["offset"],
    }, None


def _error_page(request: Request, key: str, status: int) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "pages/error.html",
        {"t": t, "message": t(key)},
        status_code=status,
    )


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if _session_or_none(request) is not None:
        return RedirectResponse(url=_safe_next(request.query_params.get("next")), status_code=302)
    return templates.TemplateResponse(
        request,
        "pages/login.html",
        {"t": t, "next": _safe_next(request.query_params.get("next"))},
    )


@router.get("/", response_class=HTMLResponse)
def overview_page(request: Request):
    if _session_or_none(request) is None:
        return _redirect_to_login(request)
    params, error = _parse_view_params(request, datetime.now(UTC), default_limit=10)
    if error is not None:
        return _error_page(request, error, 400)
    with read_store(request) as conn:
        context, error = _overview_context(conn, request.app.state.rules, params)
    if error is not None:
        return _error_page(request, error, 400 if error != "error.unknown_site" else 404)
    context["request"] = request
    return templates.TemplateResponse(request, "pages/overview.html", context)


@router.get("/partials/overview", response_class=HTMLResponse)
def overview_partial(request: Request):
    if _session_or_none(request) is None:
        return HTMLResponse(
            f'<p class="alert alert-warning" role="alert">{t("auth.login.title")}</p>',
            status_code=401,
        )
    params, error = _parse_view_params(request, datetime.now(UTC), default_limit=10)
    if error is not None:
        return HTMLResponse(
            f'<p class="alert alert-error" role="alert">{t(error)}</p>', status_code=400
        )
    with read_store(request) as conn:
        context, error = _overview_context(conn, request.app.state.rules, params)
    if error is not None:
        return HTMLResponse(
            f'<p class="alert alert-error" role="alert">{t(error)}</p>', status_code=400
        )
    context["request"] = request
    # Push the canonical full-page filter URL (not the fragment
    # endpoint) so reload, back and forward land on the real page with
    # the applied filters. This header overrides hx-push-url behavior.
    response = templates.TemplateResponse(request, "partials/overview_content.html", context)
    response.headers["HX-Push-Url"] = context["canonical_url"]
    return response


def _base_context(request: Request, params, site: str, sites, path: str) -> dict:
    """Shell context shared by every data page (single filter source)."""
    filt = _checked_base_filter(params, site)
    return {
        "t": t,
        "request": request,
        "sites": [{"id": row[0], "name": row[1]} for row in sites],
        "site": site,
        "range": params["range"],
        "tz_name": params["tz_name"],
        "display_from": params["display_from"],
        "display_to": params["display_to"],
        "window_from": filt.window.time_from.isoformat(),
        "window_to": filt.window.time_to.isoformat(),
        "canonical_url": _canonical(path, params, site),
        "nav_query": _nav_query(params, site),
        "fragment_url": None,
        "page_url": lambda path, **overrides: _page_url(path, params, site, **overrides),
        "evidence_url": _evidence_url,
        "matchers": {k: v for k, v in params["matchers"].items() if v is not None},
        "params_source": params["source"],
        "limit": params["limit"],
        "offset": params["offset"],
        "filt": filt,
    }


def _finding_support_link(site: str, filt: AnalyticsFilter, finding: Finding) -> str | None:
    """Supporting-data link for one finding card, or None when no page fits.

    Findings are immutable dataclasses, so cards render from plain view
    dicts. A link is only attached when the target page actually lists the
    underlying rows: error evidence links to the error groups, everything
    else links to the overview timeline and tables. Links are supporting
    context, never labelled complete evidence.
    """
    envelope = {
        "site_id": site,
        "time_from": filt.window.time_from.isoformat(),
        "time_to": filt.window.time_to.isoformat(),
    }
    envelope.update({k: v for k, v in finding.filters.items() if v is not None})
    evidence = finding.evidence or {}
    paths = evidence.get("paths")
    has_errors = finding.counts.get("errors", 0) > 0 or any(
        isinstance(row, dict) and row.get("errors", 0) > 0 for row in paths or []
    )
    if has_errors:
        return _evidence_url("/errors", envelope)
    return _evidence_url("/", envelope)


def _finding_view(site: str, filt: AnalyticsFilter, finding: Finding) -> dict:
    """Plain view dict for one immutable finding plus its support link."""
    view = asdict(finding)
    view["link"] = _finding_support_link(site, filt, finding)
    return view


def _paging_nav(path: str, params, site: str, total: int) -> dict:
    """Bounded offset navigation state for large tables."""
    offset, limit = params["offset"], params["limit"]
    prev_url = _page_url(path, params, site, offset=max(offset - limit, 0)) if offset > 0 else None
    next_url = (
        _page_url(path, params, site, offset=offset + limit) if offset + limit < total else None
    )
    return {
        "total": total,
        "start": offset + 1 if total else 0,
        "end": min(offset + limit, total),
        "prev_url": prev_url,
        "next_url": next_url,
    }


def _data_page(request: Request, default_limit: int = 20):
    """Shared gate + params for data pages; gate is "redirect", an error key, or None."""
    if _session_or_none(request) is None:
        return None, "redirect"
    params, error = _parse_view_params(request, datetime.now(UTC), default_limit=default_limit)
    if error is not None:
        return None, error
    return params, None


def _security_context(request: Request, conn, params):
    site, sites, error = _site_or_error(conn, params)
    if error is not None:
        return None, error
    error = _source_or_error(conn, site, params["source"])
    if error is not None:
        return None, error
    try:
        context = _base_context(request, params, site, sites, "/security")
    except _InvalidFilter:
        return None, "error.bad_params"
    filt = context["filt"]
    summary = service.summarize(conn, filt)
    findings_all = service.security_findings(conn, filt, request.app.state.rules)
    offset, limit = params["offset"], params["limit"]
    items = [
        _finding_view(site, filt, finding) for finding in findings_all[offset : offset + limit]
    ]
    context.update(
        {
            "summary": summary,
            "totals": summary["totals"],
            "status_rows": [
                row
                for row in summary["status_distribution"]
                if row["status"] in (401, 403, 404, 429)
            ],
            "findings": items,
            "paging": _paging_nav("/security", params, site, len(findings_all)),
            "fragment_url": "/partials/security",
        }
    )
    return context, None


def _crawlers_context(request: Request, conn, params):
    site, sites, error = _site_or_error(conn, params)
    if error is not None:
        return None, error
    error = _source_or_error(conn, site, params["source"])
    if error is not None:
        return None, error
    try:
        context = _base_context(request, params, site, sites, "/crawlers")
    except _InvalidFilter:
        return None, "error.bad_params"
    filt = context["filt"]
    summary = service.summarize(conn, filt)
    details = service.crawler_details(conn, filt, request.app.state.rules)
    robots = queries.summary_counts(
        conn, filt.model_copy(update={"path_prefix": "/robots.txt", "limit": 100, "offset": 0})
    )
    sitemap = queries.summary_counts(
        conn, filt.model_copy(update={"path_prefix": "/sitemap.xml", "limit": 100, "offset": 0})
    )
    context.update(
        {
            "summary": summary,
            "totals": summary["totals"],
            "details": details,
            "robots_requests": robots["requests"],
            "sitemap_requests": sitemap["requests"],
            "fragment_url": "/partials/crawlers",
        }
    )
    return context, None


def _errors_context(request: Request, conn, params):
    site, sites, error = _site_or_error(conn, params)
    if error is not None:
        return None, error
    error = _source_or_error(conn, site, params["source"])
    if error is not None:
        return None, error
    try:
        context = _base_context(request, params, site, sites, "/errors")
    except _InvalidFilter:
        return None, "error.bad_params"
    filt = context["filt"]
    page_filt = filt.model_copy(update={"limit": params["limit"], "offset": params["offset"]})
    groups, total = queries.error_groups(conn, page_filt)
    summary = service.summarize(conn, filt)
    context.update(
        {
            "summary": summary,
            "totals": summary["totals"],
            "groups": groups,
            "paging": _paging_nav("/errors", params, site, total),
            "fragment_url": "/partials/errors",
        }
    )
    return context, None


ASK_STARTER_COUNT = 8


def _ask_context(request: Request, conn, params):
    site, sites, error = _site_or_error(conn, params)
    if error is not None:
        return None, error
    error = _source_or_error(conn, site, params["source"])
    if error is not None:
        return None, error
    try:
        context = _base_context(request, params, site, sites, "/ask")
    except _InvalidFilter:
        return None, "error.bad_params"
    filt = context["filt"]
    summary = service.summarize(conn, filt)
    settings = load_settings()
    starters = [
        {
            "category": t(f"ask.starter.{index}.category"),
            "label": t(f"ask.starter.{index}.label"),
            "prompt": t(f"ask.starter.{index}.prompt"),
        }
        for index in range(1, ASK_STARTER_COUNT + 1)
    ]
    context.update(
        {
            "summary": summary,
            "duration_available": summary["duration"]["available"],
            "ai_enabled": settings.ai_enabled,
            "starters": starters,
            "form_action": "/ask",
        }
    )
    return context, None


def _optional_nav_query(request: Request) -> str:
    """Shared window state for non-data pages; empty when absent/invalid.

    Settings and Data Sources are not data views, so missing or malformed
    filter parameters never 400 here — the state is simply dropped, exactly
    like a direct visit. Valid state round-trips through the side nav back
    to the data views unchanged.
    """
    params, error = _parse_view_params(request, datetime.now(UTC))
    if error is not None:
        return ""
    query: dict[str, object] = {
        "range": params["range"],
        "from": params["window"].time_from.isoformat(),
        "to": params["window"].time_to.isoformat(),
        "tz": params["tz_name"],
    }
    if params["site"] is not None:
        query["site"] = params["site"]
    if params["source"] is not None:
        query["source"] = params["source"]
    return "?" + urlencode(query)


def _settings_context(request: Request):
    settings = load_settings()
    return {
        "t": t,
        "request": request,
        "nav_query": _optional_nav_query(request),
        "app_base_url": settings.app_base_url,
        "default_timezone": settings.default_timezone,
        "retention_days": settings.retention_days,
        "external_api_enabled": settings.external_api_enabled,
        "ai_enabled": settings.ai_enabled,
        "model_provider": settings.model_provider,
        "model_id": settings.model_id,
        "model_service_tier": settings.model_service_tier,
        "llm_budget_usd": settings.llm_budget_usd,
        "llm_warn_at_usd": settings.llm_warn_at_usd,
        "llm_stop_at_usd": settings.llm_stop_at_usd,
        "llm_daily_limit_usd": settings.llm_daily_limit_usd,
        "open_model_id": settings.open_model_id,
    }


def _sources_context(request: Request, conn):
    sites = conn.execute("SELECT id, name, hostname, timezone FROM sites ORDER BY id").fetchall()
    sources = conn.execute(
        "SELECT id, site_id, server_type, format_id, path_alias, enabled"
        " FROM log_sources ORDER BY site_id, id"
    ).fetchall()
    imports = conn.execute(
        "SELECT id, source_id, file_fingerprint, lines_total, lines_accepted,"
        " lines_rejected, records_inserted, records_replayed, status, error_summary,"
        " started_at, finished_at FROM imports ORDER BY id DESC LIMIT 20"
    ).fetchall()
    return {
        "t": t,
        "request": request,
        "nav_query": _optional_nav_query(request),
        "sites": [
            {"id": row[0], "name": row[1], "hostname": row[2], "timezone": row[3]} for row in sites
        ],
        "sources": [
            {
                "id": row[0],
                "site_id": row[1],
                "server_type": row[2],
                "format_id": row[3],
                "path_alias": row[4],
                "enabled": bool(row[5]),
            }
            for row in sources
        ],
        "imports": [
            {
                "id": row[0],
                "source_id": row[1],
                "fingerprint_prefix": (row[2] or "")[:12],
                "lines_total": row[3],
                "lines_accepted": row[4],
                "lines_rejected": row[5],
                "records_inserted": row[6],
                "records_replayed": row[7],
                "status": row[8],
                "error_summary": row[9],
                "started_at": row[10],
                "finished_at": row[11],
            }
            for row in imports
        ],
    }


@router.get("/security", response_class=HTMLResponse)
def security_page(request: Request):
    params, gate = _data_page(request)
    if gate == "redirect":
        return _redirect_to_login(request)
    if gate is not None:
        return _error_page(request, gate, 400)
    with read_store(request) as conn:
        context, error = _security_context(request, conn, params)
    if error is not None:
        return _error_page(request, error, 400 if error != "error.unknown_site" else 404)
    return templates.TemplateResponse(request, "pages/security.html", context)


@router.get("/partials/security", response_class=HTMLResponse)
def security_partial(request: Request):
    if _session_or_none(request) is None:
        return HTMLResponse(
            f'<p class="alert alert-warning" role="alert">{t("auth.login.title")}</p>',
            status_code=401,
        )
    params, gate = _data_page(request)
    if gate is not None:
        return HTMLResponse(
            f'<p class="alert alert-error" role="alert">{t(gate)}</p>', status_code=400
        )
    with read_store(request) as conn:
        context, error = _security_context(request, conn, params)
    if error is not None:
        return HTMLResponse(
            f'<p class="alert alert-error" role="alert">{t(error)}</p>', status_code=400
        )
    response = templates.TemplateResponse(request, "partials/security_content.html", context)
    response.headers["HX-Push-Url"] = context["canonical_url"]
    return response


@router.get("/crawlers", response_class=HTMLResponse)
def crawlers_page(request: Request):
    params, gate = _data_page(request)
    if gate == "redirect":
        return _redirect_to_login(request)
    if gate is not None:
        return _error_page(request, gate, 400)
    with read_store(request) as conn:
        context, error = _crawlers_context(request, conn, params)
    if error is not None:
        return _error_page(request, error, 400 if error != "error.unknown_site" else 404)
    return templates.TemplateResponse(request, "pages/crawlers.html", context)


@router.get("/partials/crawlers", response_class=HTMLResponse)
def crawlers_partial(request: Request):
    if _session_or_none(request) is None:
        return HTMLResponse(
            f'<p class="alert alert-warning" role="alert">{t("auth.login.title")}</p>',
            status_code=401,
        )
    params, gate = _data_page(request)
    if gate is not None:
        return HTMLResponse(
            f'<p class="alert alert-error" role="alert">{t(gate)}</p>', status_code=400
        )
    with read_store(request) as conn:
        context, error = _crawlers_context(request, conn, params)
    if error is not None:
        return HTMLResponse(
            f'<p class="alert alert-error" role="alert">{t(error)}</p>', status_code=400
        )
    response = templates.TemplateResponse(request, "partials/crawlers_content.html", context)
    response.headers["HX-Push-Url"] = context["canonical_url"]
    return response


@router.get("/errors", response_class=HTMLResponse)
def errors_page(request: Request):
    params, gate = _data_page(request)
    if gate == "redirect":
        return _redirect_to_login(request)
    if gate is not None:
        return _error_page(request, gate, 400)
    with read_store(request) as conn:
        context, error = _errors_context(request, conn, params)
    if error is not None:
        return _error_page(request, error, 400 if error != "error.unknown_site" else 404)
    return templates.TemplateResponse(request, "pages/errors.html", context)


@router.get("/partials/errors", response_class=HTMLResponse)
def errors_partial(request: Request):
    if _session_or_none(request) is None:
        return HTMLResponse(
            f'<p class="alert alert-warning" role="alert">{t("auth.login.title")}</p>',
            status_code=401,
        )
    params, gate = _data_page(request)
    if gate is not None:
        return HTMLResponse(
            f'<p class="alert alert-error" role="alert">{t(gate)}</p>', status_code=400
        )
    with read_store(request) as conn:
        context, error = _errors_context(request, conn, params)
    if error is not None:
        return HTMLResponse(
            f'<p class="alert alert-error" role="alert">{t(error)}</p>', status_code=400
        )
    response = templates.TemplateResponse(request, "partials/errors_content.html", context)
    response.headers["HX-Push-Url"] = context["canonical_url"]
    return response


@router.get("/ask", response_class=HTMLResponse)
def ask_page(request: Request):
    params, gate = _data_page(request)
    if gate == "redirect":
        return _redirect_to_login(request)
    if gate is not None:
        return _error_page(request, gate, 400)
    with read_store(request) as conn:
        context, error = _ask_context(request, conn, params)
    if error is not None:
        return _error_page(request, error, 400 if error != "error.unknown_site" else 404)
    return templates.TemplateResponse(request, "pages/ask.html", context)


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    if _session_or_none(request) is None:
        return _redirect_to_login(request)
    context = _settings_context(request)
    return templates.TemplateResponse(request, "pages/settings.html", context)


@router.get("/data-sources", response_class=HTMLResponse)
def sources_page(request: Request):
    if _session_or_none(request) is None:
        return _redirect_to_login(request)
    with read_store(request) as conn:
        context = _sources_context(request, conn)
    return templates.TemplateResponse(request, "pages/data_sources.html", context)
