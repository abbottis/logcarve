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
from app.analytics.classification import build_classifier, resolve_selector_indexes
from app.analytics.contracts import (
    AnalyticsFilter,
    BotTableQuery,
    ExplorerQuery,
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
    status_class = (q.get("status_class") or "").strip() or None
    if status_class is not None and status_class not in ("2xx", "3xx", "4xx", "5xx"):
        return None, "error.bad_params"
    traffic = (q.get("traffic") or "").strip() or None
    if traffic is not None and traffic not in (
        "all",
        "browser_like",
        "claimed_bot",
        "other_automation",
        "unknown",
    ):
        return None, "error.bad_params"
    selectors: dict[str, object] = {}
    for name, bound in (
        ("bot", 64),
        ("category", 64),
        ("provider", 120),
        ("purpose", 120),
    ):
        value = (q.get(name) or "").strip() or None
        if value is not None and (len(value) > bound or not value.isascii()):
            return None, "error.bad_params"
        selectors[name] = value
    # Bounded LogWerk-style text search over stored sanitized fields.
    # LIKE metacharacters are escaped downstream; control characters and
    # DEL are rejected so the value always replays as plain text.
    search = (q.get("search") or "").strip() or None
    if search is not None and (
        len(search) > 128 or any(ord(char) < 0x20 or ord(char) == 0x7F for char in search)
    ):
        return None, "error.bad_params"
    return {
        "method": raw_method,
        "status": status,
        "status_class": status_class,
        "path_prefix": path_prefix,
        "referer_host": referer_host,
        "traffic": traffic,
        "search": search,
        **selectors,
    }, None


def _parse_sort(q, allowed: tuple[str, ...], default: str) -> tuple[str | None, str | None]:
    """Allowlisted sort key; unknown values reject instead of defaulting."""
    raw = (q.get("sort") or "").strip() or None
    if raw is None:
        return default, None
    if raw not in allowed:
        return None, "error.bad_params"
    return raw, None


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


#: Global event matchers that travel with every dashboard navigation
#: link, so a selected traffic/bot/method/status/search scope is never
#: silently dropped when switching pages. Only paging offsets, table
#: sorts and the timeline bucket stay page-local.
MATCHER_KEYS = (
    "method",
    "status",
    "status_class",
    "path_prefix",
    "referer_host",
    "traffic",
    "bot",
    "category",
    "provider",
    "purpose",
    "search",
)


def _matcher_query(params) -> dict[str, object]:
    """Non-empty global matchers, shared by navigation and page URLs."""
    return {
        key: params["matchers"][key]
        for key in MATCHER_KEYS
        if params["matchers"].get(key) is not None
    }


def _nav_query(params, site: str) -> str:
    """Shared navigation state: window plus every global matcher.

    Paging offsets, table sorts and the timeline bucket stay page-local:
    a new page always starts at its first page with default presentation,
    but never with a widened event scope.
    """
    query: dict[str, object] = {
        "site": site,
        "range": params["range"],
        "from": params["window"].time_from.isoformat(),
        "to": params["window"].time_to.isoformat(),
        "tz": params["tz_name"],
    }
    if params["source"] is not None:
        query["source"] = params["source"]
    query.update(_matcher_query(params))
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


def _checked_selectors(filt: AnalyticsFilter, rules) -> None:
    """Validate named selectors against the versioned rules; 400 on unknown.

    Unknown bots/providers/purposes or contradictory combinations are
    client input, so they map to the safe filter error instead of 500.
    """
    try:
        clf = build_classifier(list(rules))
        resolve_selector_indexes(
            clf,
            bot=filt.bot,
            category=filt.category,
            provider=filt.provider,
            purpose=filt.purpose,
        )
    except ValueError as exc:
        raise _InvalidFilter from exc


def _base_filter(params, site: str) -> AnalyticsFilter:
    """Window-level event filter: matchers apply, paging never does."""
    matchers = params["matchers"]
    return AnalyticsFilter(
        site_id=site,
        window=params["window"],
        source_id=params["source"],
        method=matchers["method"],
        status=matchers["status"],
        status_class=matchers.get("status_class"),
        path_prefix=matchers["path_prefix"],
        referer_host=matchers["referer_host"],
        search=matchers.get("search"),
        traffic=matchers.get("traffic") or "all",
        bot=matchers.get("bot"),
        category=matchers.get("category"),
        provider=matchers.get("provider"),
        purpose=matchers.get("purpose"),
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


def _overview_context(request, conn, rules, params) -> tuple[dict | None, str | None]:
    site, sites, error = _site_or_error(conn, params)
    if error is not None:
        return None, error
    error = _source_or_error(conn, site, params["source"])
    if error is not None:
        return None, error
    try:
        context = _base_context(request, params, site, sites, "/", rules)
    except _InvalidFilter:
        return None, "error.bad_params"
    filt = context["filt"]
    # Overview-local path sorting: query-specific sorts stay scoped to
    # their own page, so this key never collides with the crawler-table
    # or explorer `sort` on other views. Unknown values reject (400).
    paths_sort = (request.query_params.get("paths_sort") or "").strip() or "requests_desc"
    if paths_sort not in ("requests_desc", "errors_desc", "bytes_desc"):
        return None, "error.bad_params"
    summary = service.summarize(conn, filt, rules)
    span = params["window"].time_to - params["window"].time_from
    bucket = params["bucket"] or ("day" if span > timedelta(hours=48) else "hour")
    series = service.timeseries(conn, filt, bucket, rules)
    table_filt = filt.model_copy(update={"limit": params["limit"], "offset": params["offset"]})
    clients_filt = filt.model_copy(update={"limit": 10, "offset": 0})
    top_paths = service.top_paths(conn, TopPathsQuery(filt=table_filt, sort=paths_sort), rules)
    top_referrers = service.top_referrers(conn, TopReferrersQuery(filt=table_filt), rules)
    traffic = service.traffic_breakdown(conn, filt, rules)
    resources = service.resource_breakdown(conn, filt, rules)
    browsers = service.browser_breakdown(conn, filt, rules)
    try:
        heatmap = service.heatmap(conn, filt, rules, tz_name=params["tz_name"])
        heatmap_error = None
    except ValueError:
        heatmap = None
        heatmap_error = "overview.heatmap_unavailable"
    clients = service.client_top(conn, clients_filt, rules)
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
            "errors": b["errors"],
            "bytes_total": b["bytes_total"],
        }
        for b in series["buckets"]
    ]
    # Heatmap intensity levels 0-4, scaled to the busiest cell so the
    # quantitative shading stays comparable within one view. Level 0 is
    # reserved for no requests; any positive count starts at level 1
    # (ceiling scaling), so quiet cells never wear the no-request shade.
    # Levels render through external CSS classes (never inline styles) to
    # keep the style-src 'self' CSP without unsafe-inline.
    heatmap_max = 0
    heatmap_levels: list[list[int]] | None = None
    if heatmap is not None:
        heatmap_max = max((max(row) for row in heatmap["matrix"]), default=0)
        if heatmap_max > 0:
            heatmap_levels = [
                [0 if value == 0 else min(4, -(-value * 4 // heatmap_max)) for value in row]
                for row in heatmap["matrix"]
            ]
        else:
            heatmap_levels = [[0] * 24 for _ in range(7)]
    context.update(
        {
            "fragment_url": "/partials/overview",
            "summary": summary,
            "totals": totals,
            "error_share": error_share,
            "top_claim": top_claim,
            "timeline": timeline,
            "bucket": bucket,
            "paths_sort": paths_sort,
            "status_rows": summary["status_distribution"],
            "paths": top_paths,
            "referrers": top_referrers,
            "traffic": traffic,
            "resources": resources,
            "browsers": browsers,
            "heatmap": heatmap,
            "heatmap_error": heatmap_error,
            "heatmap_hours": list(range(24)),
            "heatmap_days": list(range(7)),
            "heatmap_levels": heatmap_levels,
            "heatmap_max": heatmap_max,
            "clients": clients,
            "claims": claims,
            "findings": findings,
        }
    )
    return context, None


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
        context, error = _overview_context(request, conn, request.app.state.rules, params)
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
        context, error = _overview_context(request, conn, request.app.state.rules, params)
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


def _filter_options(rules) -> dict:
    """Select options for the traffic/bot filter controls (server-built).

    Options come from the versioned rule catalog so the bar can only
    submit values the backend accepts; unknown values still 400.
    """
    bots = [rule for rule in rules if rule.ua_contains or rule.ua_regex]
    categories = sorted({rule.category for rule in bots})
    providers = sorted({rule.provider for rule in bots if rule.provider})
    purposes = sorted({rule.purpose for rule in bots if rule.purpose})
    return {
        "traffic": ["all", "browser_like", "claimed_bot", "other_automation", "unknown"],
        "status_classes": ["all", "2xx", "3xx", "4xx", "5xx"],
        "bots": [
            {
                "id": rule.id,
                "title": rule.title,
                "category": rule.category,
                "provider": rule.provider,
            }
            for rule in bots
        ],
        "categories": categories,
        "providers": providers,
        "purposes": purposes,
    }


def _base_context(request: Request, params, site: str, sites, path: str, rules=None) -> dict:
    """Shell context shared by every data page (single filter source)."""
    filt = _checked_base_filter(params, site)
    _checked_selectors(filt, rules)
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
        "filter_options": _filter_options(rules),
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


def _paging_nav(path: str, params, site: str, total: int, extra: dict | None = None) -> dict:
    """Bounded offset navigation state for large tables.

    ``extra`` carries page-local state (such as a table sort) that is
    not part of the shared window params but must survive paging.
    """
    offset, limit = params["offset"], params["limit"]
    keep = dict(extra or {})
    prev_url = (
        _page_url(path, params, site, offset=max(offset - limit, 0), **keep) if offset > 0 else None
    )
    next_url = (
        _page_url(path, params, site, offset=offset + limit, **keep)
        if offset + limit < total
        else None
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
        context = _base_context(request, params, site, sites, "/security", request.app.state.rules)
    except _InvalidFilter:
        return None, "error.bad_params"
    filt = context["filt"]
    summary = service.summarize(conn, filt, request.app.state.rules)
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
        context = _base_context(request, params, site, sites, "/crawlers", request.app.state.rules)
    except _InvalidFilter:
        return None, "error.bad_params"
    filt = context["filt"]
    summary = service.summarize(conn, filt, request.app.state.rules)
    sort, error = _parse_sort(
        request.query_params,
        ("requests_desc", "name_asc", "category_asc", "errors_desc", "bytes_desc"),
        "requests_desc",
    )
    if error is not None:
        return None, error
    page_filt = filt.model_copy(update={"limit": params["limit"], "offset": params["offset"]})
    table = service.bot_table(
        conn, BotTableQuery(filt=page_filt, sort=sort), request.app.state.rules
    )
    details = {
        item["rule_id"]: item
        for item in service.crawler_details(conn, filt, request.app.state.rules)
    }
    for row in table["items"]:
        row["detail"] = details.get(row["rule_id"])
    clf = service.classifier_for_filter(filt, request.app.state.rules)
    robots_requests = queries.scoped_path_count(conn, filt, clf, path="/robots.txt")
    sitemap_requests = queries.scoped_path_count(conn, filt, clf, path_prefix="/sitemap.xml")
    groups = service.bot_groups(conn, filt, request.app.state.rules)
    context.update(
        {
            "summary": summary,
            "totals": summary["totals"],
            "table": table,
            "groups": groups,
            "bots_sort": sort,
            "details": details,
            "robots_requests": robots_requests,
            "sitemap_requests": sitemap_requests,
            "paging": _paging_nav("/crawlers", params, site, table["total_rules"], {"sort": sort}),
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
        context = _base_context(request, params, site, sites, "/errors", request.app.state.rules)
    except _InvalidFilter:
        return None, "error.bad_params"
    filt = context["filt"]
    page_filt = filt.model_copy(update={"limit": params["limit"], "offset": params["offset"]})
    table = service.error_groups(conn, page_filt, request.app.state.rules)
    summary = service.summarize(conn, filt, request.app.state.rules)
    context.update(
        {
            "summary": summary,
            "totals": summary["totals"],
            "groups": table["items"],
            "paging": _paging_nav("/errors", params, site, table["total_groups"]),
            "fragment_url": "/partials/errors",
        }
    )
    return context, None


def _requests_context(request: Request, conn, params):
    site, sites, error = _site_or_error(conn, params)
    if error is not None:
        return None, error
    error = _source_or_error(conn, site, params["source"])
    if error is not None:
        return None, error
    try:
        context = _base_context(request, params, site, sites, "/requests", request.app.state.rules)
    except _InvalidFilter:
        return None, "error.bad_params"
    filt = context["filt"]
    sort, error = _parse_sort(request.query_params, ("newest", "oldest"), "newest")
    if error is not None:
        return None, error
    page_filt = filt.model_copy(update={"limit": params["limit"], "offset": params["offset"]})
    explorer = service.request_explorer(
        conn, ExplorerQuery(filt=page_filt, sort=sort), request.app.state.rules
    )
    summary = service.summarize(conn, filt, request.app.state.rules)
    # Display timestamps in the selected timezone; the UTC instant stays
    # in the title attribute so both instants are inspectable. Stored
    # values are UTC ISO strings; unparsable ones fall back to verbatim.
    rows = []
    for row in explorer["items"]:
        display = row["ts_utc"]
        try:
            moment = datetime.fromisoformat(str(row["ts_utc"]))
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=UTC)
            display = moment.astimezone(params["tz"]).strftime("%Y-%m-%d %H:%M %Z")
        except (ValueError, TypeError):
            pass
        rows.append({**row, "ts_display": display})
    context.update(
        {
            "summary": summary,
            "totals": summary["totals"],
            "rows": rows,
            "explorer_sort": sort,
            "paging": _paging_nav(
                "/requests", params, site, explorer["total_rows"], {"sort": sort}
            ),
            "fragment_url": "/partials/requests",
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
        context = _base_context(request, params, site, sites, "/ask", request.app.state.rules)
    except _InvalidFilter:
        return None, "error.bad_params"
    filt = context["filt"]
    summary = service.summarize(conn, filt, request.app.state.rules)
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
    query.update(_matcher_query(params))
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


@router.get("/requests", response_class=HTMLResponse)
def requests_page(request: Request):
    params, gate = _data_page(request)
    if gate == "redirect":
        return _redirect_to_login(request)
    if gate is not None:
        return _error_page(request, gate, 400)
    with read_store(request) as conn:
        context, error = _requests_context(request, conn, params)
    if error is not None:
        return _error_page(request, error, 400 if error != "error.unknown_site" else 404)
    return templates.TemplateResponse(request, "pages/requests.html", context)


@router.get("/partials/requests", response_class=HTMLResponse)
def requests_partial(request: Request):
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
        context, error = _requests_context(request, conn, params)
    if error is not None:
        return HTMLResponse(
            f'<p class="alert alert-error" role="alert">{t(error)}</p>', status_code=400
        )
    response = templates.TemplateResponse(request, "partials/requests_content.html", context)
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
