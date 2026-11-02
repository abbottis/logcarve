"""Browser dashboard pages and fragments (T9-A: shell, login, Overview).

Reads run exclusively through the shared deterministic analytics
services over a read-only handle; no metric is computed here. Browser
sessions authorize these pages (``require_admin_session``); Bearer
tokens never do. The login form posts JSON to the existing
``POST /api/v1/admin/login`` endpoint, so no form parsing was added.
Every log-derived value renders through Jinja2 autoescaping.
"""

import math
import re
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
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
    JourneyIdQuery,
    JourneyQuery,
    SlowEndpointsQuery,
    TimeWindow,
    TopPathsQuery,
    TopReferrersQuery,
)
from app.analytics.service import Finding
from app.api.deps import read_store, require_admin_session
from app.config import load_settings
from app.db import private as private_store
from app.web import private_ip as private_view
from app.web.evidence import evidence_url as _evidence_url
from app.web.locales import t
from app.web.timezones import (
    display_options,
    format_offset_suffix,
    resolve_default_timezone,
    resolve_request_timezone,
)

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))
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


def _configured_default_from(settings) -> str | None:
    """Validated configured default timezone, or None when unusable.

    Settings stay the authority; any load/validation failure falls back
    to UTC downstream instead of breaking the filter parse. An absent
    `DEFAULT_TIMEZONE` environment value counts as unconfigured (None)
    so the resolver's reliable regional server `TZ` fallback stays
    reachable; only an explicitly configured value wins over `TZ`.
    """
    if "default_timezone" not in settings.model_fields_set:
        # Not explicitly configured (neither environment nor `.env`):
        # leave the default absent so the resolver's reliable regional
        # server `TZ` fallback stays reachable in real routing.
        return None
    candidate = settings.default_timezone
    return candidate if isinstance(candidate, str) and candidate else None


def _configured_default() -> str | None:
    """Configured default from live settings, or None when unusable."""
    try:
        settings = load_settings()
    except (ValidationError, OSError, ValueError):
        return None
    return _configured_default_from(settings)


def _effective_default(settings=None) -> str:
    """One resolved default for ordering, selection fallback and Settings.

    An explicitly configured default wins; otherwise the trusted
    regional server `TZ` applies; anything unusable names `UTC`. The
    same value orders the option list and labels the Settings display
    so the two can never disagree. An explicit `tz` URL value still
    wins for the selected display zone without changing this default.
    """
    if settings is None:
        try:
            settings = load_settings()
        except (ValidationError, OSError, ValueError):
            return resolve_default_timezone(None)
    return resolve_default_timezone(_configured_default_from(settings))


def _parse_view_params(request: Request, now: datetime, default_limit: int = 20):
    """Shared filter-bar parameters; returns (params, error_key)."""
    q = request.query_params
    site = (q.get("site") or "").strip() or None
    preset = (q.get("range") or DEFAULT_RANGE).strip()
    # Explicit valid `tz` wins; a blank value falls back to the validated
    # configured default (never a guessed host location). Unknown zones
    # fail safely without touching the filesystem.
    tz_name = resolve_request_timezone(q.get("tz"), _configured_default())
    if tz_name is None:
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
    # Exact client equality: ONE stable HMAC pseudonym (64 lowercase
    # hex), never an original address. Unknown pseudonyms replay
    # honestly (usually to zero rows), never fuzzy.
    client = (q.get("client") or "").strip().lower() or None
    if client is not None and (
        len(client) != 64 or any(char not in "0123456789abcdef" for char in client)
    ):
        return None, "error.bad_params"
    enriched, error = _parse_enrichment_matchers(q)
    if error is not None:
        return None, error
    return {
        "method": raw_method,
        "status": status,
        "status_class": status_class,
        "path_prefix": path_prefix,
        "referer_host": referer_host,
        "traffic": traffic,
        "search": search,
        "client": client,
        **selectors,
        **enriched,
    }, None


def _clean_text(value: str | None, *, limit: int) -> str | None:
    """Trimmed ASCII text without controls, or None when blank.

    Returns the sentinel ``""`` (empty string) when the value is
    present but invalid, so callers map it to ``error.bad_params``.
    """
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    if len(text) > limit or not text.isascii():
        return ""
    if "\\" in text or any(ord(char) < 0x20 or ord(char) == 0x7F for char in text):
        return ""
    return text


def _parse_enrichment_matchers(q) -> tuple[dict | None, str | None]:
    """T2 measured-enrichment selectors shared by every data view (PAR-03).

    Every value is validated against the same rules as the shared
    :class:`AnalyticsFilter` contract (equality matchers replayed as
    bound parameters downstream), so a value passing here can never
    violate it. Unknown or contradictory values reject with
    ``error.bad_params`` instead of silently widening.
    """
    path_exact = _clean_text(q.get("path_exact"), limit=1024)
    if path_exact == "" or (
        path_exact is not None and (not path_exact.startswith("/") or "\x00" in path_exact)
    ):
        return None, "error.bad_params"
    server_host = _clean_text(q.get("server_host"), limit=253)
    if server_host == "" or (server_host is not None and " " in server_host):
        return None, "error.bad_params"
    if server_host is not None:
        # Stored hosts are lowercase; the contract folds the same way,
        # so fold here to keep the URL replay honest.
        server_host = server_host.lower()
        if not server_host or "\x00" in server_host:
            return None, "error.bad_params"
    http_version = _clean_text(q.get("http_version"), limit=16)
    if http_version is not None and not re.match(r"^HTTP/\d+(\.\d+)?$", http_version):
        return None, "error.bad_params"
    mime_type = _clean_text(q.get("mime_type"), limit=128)
    if mime_type is not None:
        media = mime_type.split(";", 1)[0].strip().lower()
        if not re.match(r"^[^/\s;]{1,64}/[^;\s]{1,64}$", media):
            return None, "error.bad_params"
        mime_type = media
    cache_status = _clean_text(q.get("cache_status"), limit=32)
    if cache_status is not None:
        cache_status = cache_status.upper()
        if not re.match(r"^[A-Z_]{1,32}$", cache_status):
            return None, "error.bad_params"
    tls_protocol = _clean_text(q.get("tls_protocol"), limit=32)
    if tls_protocol is not None and not re.match(r"^[A-Za-z0-9._-]{1,32}$", tls_protocol):
        return None, "error.bad_params"
    availability: dict[str, object] = {}
    for key in ("timing_available", "upstream_available"):
        raw = (q.get(key) or "").strip().lower() or None
        if raw is None:
            availability[key] = None
        elif raw == "yes":
            availability[key] = True
        elif raw == "no":
            availability[key] = False
        else:
            return None, "error.bad_params"
    bounds: dict[str, object] = {}
    for key in ("timing_min_ms", "timing_max_ms"):
        raw = (q.get(key) or "").strip() or None
        if raw is None:
            bounds[key] = None
            continue
        try:
            number = float(raw)
        except ValueError:
            return None, "error.bad_params"
        if not math.isfinite(number) or number < 0:
            return None, "error.bad_params"
        bounds[key] = number
    if (
        bounds["timing_min_ms"] is not None
        and bounds["timing_max_ms"] is not None
        and bounds["timing_min_ms"] > bounds["timing_max_ms"]
    ):
        return None, "error.bad_params"
    return {
        "path_exact": path_exact,
        "server_host": server_host,
        "http_version": http_version,
        "mime_type": mime_type,
        "cache_status": cache_status,
        "tls_protocol": tls_protocol,
        **availability,
        **bounds,
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
    """Bounded offset pagination shared by every data view.

    Offsets stay inside the SQLite signed-64-bit binding range so a
    huge offset rejects as bad params instead of surfacing an
    ``OverflowError``/plain-500 from the driver.
    """
    raw_limit, raw_offset = (q.get("limit") or "").strip(), (q.get("offset") or "").strip()
    try:
        limit = int(raw_limit) if raw_limit else default
        offset = int(raw_offset) if raw_offset else 0
    except ValueError:
        return None, "error.bad_params"
    if not 1 <= limit <= 100 or not 0 <= offset <= 2**63 - 1:
        return None, "error.bad_params"
    return {"limit": limit, "offset": offset}, None


def _matcher_url_value(value: object) -> object:
    """URL spelling for a matcher value: booleans ride as yes/no.

    The filter bar parses ``timing_available``/``upstream_available``
    from ``yes``/``no``; serializing Python ``True`` here would emit
    ``True`` and fail the round-trip parse, silently dropping the
    matcher on reload, back/forward and htmx pushes.
    """
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return value


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
            query[key] = _matcher_url_value(value)
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
    "path_exact",
    "referer_host",
    "traffic",
    "client",
    "bot",
    "category",
    "provider",
    "purpose",
    "search",
    "server_host",
    "http_version",
    "mime_type",
    "cache_status",
    "tls_protocol",
    "timing_available",
    "upstream_available",
    "timing_min_ms",
    "timing_max_ms",
)


def _matcher_query(params) -> dict[str, object]:
    """Non-empty global matchers, shared by navigation and page URLs."""
    return {
        key: _matcher_url_value(params["matchers"][key])
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


def _quick_url(path: str, params, site: str, drop: tuple[str, ...] = (), **set_values) -> str:
    """Preset quick-view URL: same site/source/window, paging reset.

    Only the stated matcher changes: conflicting keys in ``drop`` are
    removed explicitly (e.g. a status quick view drops any status class
    instead of stacking a contradiction), ``set_values`` apply, and the
    offset restarts at the first page. Anything contradictory that
    remains is still rejected by the normal filter validation.
    """
    query = _canonical_query(params, site)
    for key in drop:
        query.pop(key, None)
    query.update({key: str(value) for key, value in set_values.items() if value is not None})
    query["offset"] = 0
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
        path_exact=matchers.get("path_exact"),
        referer_host=matchers["referer_host"],
        search=matchers.get("search"),
        client=matchers.get("client"),
        traffic=matchers.get("traffic") or "all",
        bot=matchers.get("bot"),
        category=matchers.get("category"),
        provider=matchers.get("provider"),
        purpose=matchers.get("purpose"),
        server_host=matchers.get("server_host"),
        http_version=matchers.get("http_version"),
        mime_type=matchers.get("mime_type"),
        cache_status=matchers.get("cache_status"),
        tls_protocol=matchers.get("tls_protocol"),
        timing_available=matchers.get("timing_available"),
        upstream_available=matchers.get("upstream_available"),
        timing_min_ms=matchers.get("timing_min_ms"),
        timing_max_ms=matchers.get("timing_max_ms"),
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
        {
            "title": display_bot_title(claims[0].title),
            "requests": claims[0].counts["requests"],
        }
        if claims
        else None
    )
    _attach_observed_options(conn, context, filt, rules)
    quick_views = [
        {
            "label": t("quick.404"),
            "url": _quick_url("/errors", params, site, ("status", "status_class"), status=404),
        },
        {
            "label": t("quick.5xx"),
            "url": _quick_url(
                "/errors", params, site, ("status", "status_class"), status_class="5xx"
            ),
        },
        {
            "label": t("quick.bots"),
            "url": _quick_url(
                "/crawlers",
                params,
                site,
                ("traffic", "bot", "category", "provider", "purpose"),
                traffic="claimed_bot",
            ),
        },
        {
            "label": t("quick.humans"),
            "url": _quick_url(
                "/requests",
                params,
                site,
                ("traffic", "bot", "category", "provider", "purpose"),
                traffic="browser_like",
            ),
        },
        {
            # "Largest responses" sorts individual requests by known bytes
            # (Requests bytes_desc), not the aggregated per-path byte sums
            # on this page, so the metric stays exact per response.
            "label": t("quick.largest"),
            "url": _quick_url("/requests", params, site, (), sort="bytes_desc"),
        },
    ]
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
            "quick_views": quick_views,
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
    # Overview-local paths sort rides the canonical URL, never cross-page nav.
    context["canonical_url"] = _page_url("/", params, site, paths_sort=paths_sort)
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
    context["oob_notice"] = True
    response = templates.TemplateResponse(request, "partials/overview_content.html", context)
    response.headers["HX-Push-Url"] = context["canonical_url"]
    return response


def display_bot_title(title: str) -> str:
    """Presentation name for a bot rule: one leading claim prefix dropped.

    Rule IDs, versions, meanings and stored data are untouched; only the
    human label loses the repeated ``Claimed `` prefix. Matching is a
    strict leading prefix so paths, agents or data are never rewritten.
    """
    if isinstance(title, str) and title.startswith("Claimed "):
        return title[len("Claimed ") :]
    return title


def category_label(value: str | None) -> str:
    """Human display label for a catalog category; API values unchanged."""
    if value is None:
        return t("provider.unspecified")
    label = t(f"category.{value}")
    if label != f"category.{value}":
        return label
    return str(value).replace("_", " ").title()


def provider_label(value: str | None) -> str:
    """Human display label for a provider; ``None`` reads as Unspecified."""
    if value is None:
        return t("provider.unspecified")
    return value


def purpose_label(value: str | None) -> str:
    """Human display label for a purpose; ``None`` reads as Unspecified."""
    if value is None:
        return t("purpose.unspecified")
    return value


def status_label(code: int) -> str:
    """Human status label: standard phrase or an honest unregistered note."""
    try:
        return f"{code} · {HTTPStatus(code).phrase}"
    except ValueError:
        return t("status.unregistered", code=code)


def status_phrase(code: int) -> str:
    """Registered reason phrase for a status; honest fallback for unknowns."""
    try:
        return HTTPStatus(code).phrase
    except ValueError:
        return "unregistered"


def human_bytes(value: int | None) -> str:
    """Readable byte size (B/KiB/MiB/...); unknown stays an em dash."""
    if value is None:
        return "—"
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(size) < 1024 or unit == "TiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"


#: Standard methods offered first; observed extras append after these.
STANDARD_METHODS = ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]


def _standard_statuses() -> list[dict[str, object]]:
    """Every standard HTTP status code with its registered phrase."""
    return [
        {"value": status.value, "label": f"{status.value} · {status.phrase}"}
        for status in sorted(HTTPStatus, key=lambda s: s.value)
    ]


def _filter_options(rules) -> dict:
    """Select options for the traffic/bot filter controls (server-built).

    Options come from the versioned rule catalog so the bar can only
    submit values the backend accepts; unknown values still 400.
    Method/status controls additionally offer observed scope values
    (attached per request); option values stay exact API contract
    values while labels read human-friendly.
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
                "display_title": display_bot_title(rule.title),
                "category": rule.category,
                "provider": rule.provider,
            }
            for rule in bots
        ],
        "categories": categories,
        "providers": providers,
        "purposes": purposes,
        "methods": list(STANDARD_METHODS),
        "statuses": _standard_statuses(),
    }


def _attach_observed_options(conn, context: dict, filt, rules) -> None:
    """Attach observed method/status values to the shared filter options.

    Observed values come from two bounded, parameterized, scope-aware
    queries (window/site/source plus non-method/status matchers, no
    N+1): dropdowns offer standards plus anything actually seen, and a
    currently selected valid value is retained even when unobserved.
    """
    clf = service.classifier_for_filter(filt, rules)
    observed_methods = queries.distinct_methods(conn, filt, clf)
    methods = list(STANDARD_METHODS)
    for method in sorted(set(observed_methods)):
        if method not in methods:
            methods.append(method)
    if filt.method is not None and filt.method not in methods:
        methods.append(filt.method)
    observed_statuses = queries.distinct_statuses(conn, filt, clf)
    standard_values = [entry["value"] for entry in context["filter_options"]["statuses"]]
    statuses = [entry for entry in context["filter_options"]["statuses"]]
    for code in sorted(set(observed_statuses)):
        if code not in standard_values:
            statuses.append({"value": code, "label": status_label(code)})
            standard_values.append(code)
    if filt.status is not None and filt.status not in standard_values:
        statuses.append({"value": filt.status, "label": status_label(filt.status)})
    context["filter_options"]["methods"] = methods
    context["filter_options"]["statuses"] = sorted(statuses, key=lambda e: e["value"])


def _active_filter_display(matchers: dict, rules=None) -> list[dict[str, str]]:
    """Human-readable active-filter pairs; submitted values unchanged.

    IDs, paths, methods and search text render verbatim; catalog-backed
    selectors render their display labels (plain bot names, spaced
    categories, status phrases). Unknown bot IDs fall back to the raw
    value instead of hiding the active filter.
    """
    titles: dict[str, str] = {}
    if rules:
        for rule in rules:
            if rule.ua_contains or rule.ua_regex:
                titles[rule.id] = display_bot_title(rule.title)
    items = []
    for key, value in matchers.items():
        shown = value
        if key == "traffic":
            shown = t(f"traffic.{value}")
        elif key == "category":
            shown = category_label(value)
        elif key == "provider":
            shown = provider_label(value)
        elif key == "purpose":
            shown = purpose_label(value)
        elif key == "bot":
            shown = titles.get(value, value)
        elif key == "status":
            try:
                shown = status_label(int(value))
            except (TypeError, ValueError):
                shown = value
        elif key in ("timing_available", "upstream_available"):
            shown = t("filter.timing_with") if value is True else t("filter.timing_without")
        elif key in ("timing_min_ms", "timing_max_ms"):
            try:
                shown = f"{float(value):g} ms"
            except (TypeError, ValueError):
                shown = value
        items.append({"key": key, "value": shown})
    return items


def _base_context(request: Request, params, site: str, sites, path: str, rules=None) -> dict:
    """Shell context shared by every data page (single filter source)."""
    filt = _checked_base_filter(params, site)
    _checked_selectors(filt, rules)
    window_start = filt.window.time_from
    return {
        "t": t,
        "display_bot": display_bot_title,
        "category_label": category_label,
        "provider_label": provider_label,
        "purpose_label": purpose_label,
        "status_label": status_label,
        "human_bytes": human_bytes,
        "request": request,
        "sites": [{"id": row[0], "name": row[1]} for row in sites],
        "site": site,
        "range": params["range"],
        "tz_name": params["tz_name"],
        # Offsets are always labelled at the applied window start, never
        # the review date, with an explicit DST caveat in the template.
        "tz_offset": format_offset_suffix(params["tz_name"], window_start),
        "window_start_date": window_start.astimezone(UTC).strftime("%Y-%m-%d"),
        # One effective default everywhere: option order, selection
        # fallback and the Settings display can never disagree. Full
        # pages render the notice from the filter bar only; data
        # partials opt into the out-of-band notice via `oob_notice`.
        "display_timezones": display_options(_effective_default(), window_start),
        "oob_notice": False,
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
        "active_filters": _active_filter_display(
            {k: v for k, v in params["matchers"].items() if v is not None}, rules
        ),
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
    underlying rows: error evidence links to the error groups, offender
    evidence links to the Requests explorer scoped to that client
    pseudonym, conflicting-identity evidence links to the crawler claims,
    and anything else links to the Requests explorer in the shared scope.
    Links are supporting context, never labelled complete evidence; the
    overview is never used as a fallback now that proper pages exist.
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
    client_pseudonym = evidence.get("client_pseudonym")
    if isinstance(client_pseudonym, str) and client_pseudonym:
        return _evidence_url("/requests", {**envelope, "client": client_pseudonym})
    if evidence.get("agents"):
        return _evidence_url("/crawlers", envelope)
    return _evidence_url("/requests", envelope)


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
    _attach_observed_options(conn, context, filt, request.app.state.rules)
    chart_rows = []
    for view in items:
        counts = view.get("counts") if isinstance(view, dict) else None
        total = 0
        if isinstance(counts, dict):
            total = int(counts.get("requests", counts.get("errors", 0) or 0))
        label = str(view.get("title", "")) if isinstance(view, dict) else ""
        evidence = view.get("evidence") if isinstance(view, dict) else None
        client = evidence.get("client_pseudonym") if isinstance(evidence, dict) else None
        if isinstance(client, str) and client:
            label = f"{label} · {client[:12]}…"
        chart_rows.append({"label": label, "requests": total})
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
            "chart_rows": chart_rows,
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
    _attach_observed_options(conn, context, filt, request.app.state.rules)
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
            "canonical_url": _page_url("/crawlers", params, site, sort=sort),
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
    _attach_observed_options(conn, context, filt, request.app.state.rules)
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


#: Allowlisted slow-endpoint rankings for the Performance page. Every
#: option maps to one fixed server ORDER BY over the whole filtered
#: scope (never a page-only reorder); ties break deterministically.
SLOW_SORTS = ("avg_desc", "p95_desc", "requests_desc", "max_desc")

#: Allowlisted SEO report views for the SEO page (page-local, like a
#: sort: never part of the shared navigation scope).
SEO_VIEWS = ("redirects", "client_errors", "server_errors", "ai_only")

#: Allowlisted referrer-relation selector for the Referrers page
#: (page-local SQL narrowing with matching totals).
REFERRER_RELATIONS = ("all", "internal", "external")

#: Allowlisted Referrers views: ``all`` is the sanitized source-URL
#: overview (every stored referrer, any status); ``broken`` is the
#: referrer-path -> 404-target report. Page-local, like a sort: never
#: part of the shared navigation scope.
REFERRER_VIEWS = ("all", "broken")


def _performance_context(request: Request, conn, params):
    site, sites, error = _site_or_error(conn, params)
    if error is not None:
        return None, error
    error = _source_or_error(conn, site, params["source"])
    if error is not None:
        return None, error
    try:
        context = _base_context(
            request, params, site, sites, "/performance", request.app.state.rules
        )
    except _InvalidFilter:
        return None, "error.bad_params"
    filt = context["filt"]
    slow_sort, error = _parse_sort(request.query_params, SLOW_SORTS, "avg_desc")
    if error is not None:
        return None, error
    page_filt = filt.model_copy(update={"limit": params["limit"], "offset": params["offset"]})
    try:
        overview = service.performance_overview(conn, filt, request.app.state.rules)
        slow = service.slow_endpoints(
            conn, SlowEndpointsQuery(filt=page_filt, sort=slow_sort), request.app.state.rules
        )
    except ValueError:
        return None, "error.bad_params"
    summary = service.summarize(conn, filt, request.app.state.rules)
    _attach_observed_options(conn, context, filt, request.app.state.rules)
    context.update(
        {
            "summary": summary,
            "totals": summary["totals"],
            "overview": overview,
            "latency": overview["latency_ms"],
            "latency_available": overview["latency_available"],
            "upstream": overview["upstream_ms"],
            "cache": overview["cache"],
            "mime": overview["mime_vs_resource"],
            "versions": overview["http_versions"],
            "protocols": overview["tls_protocols"],
            "hosts": overview["logged_hosts"],
            "percentile_definition": overview["percentile_definition"],
            "slow": slow,
            "slow_items": slow["items"],
            "slow_sort": slow_sort,
            "paging": _paging_nav(
                "/performance", params, site, slow["total_paths"], {"sort": slow_sort}
            ),
            "fragment_url": "/partials/performance",
        }
    )
    # Page-local sort rides the canonical URL (native GET, htmx push,
    # reload) but never the shared cross-page navigation scope.
    context["canonical_url"] = _page_url("/performance", params, site, sort=slow_sort)
    return context, None


def _seo_context(request: Request, conn, params):
    site, sites, error = _site_or_error(conn, params)
    if error is not None:
        return None, error
    error = _source_or_error(conn, site, params["source"])
    if error is not None:
        return None, error
    try:
        context = _base_context(request, params, site, sites, "/seo", request.app.state.rules)
    except _InvalidFilter:
        return None, "error.bad_params"
    filt = context["filt"]
    raw_view = (request.query_params.get("view") or "").strip() or "client_errors"
    if raw_view not in SEO_VIEWS:
        return None, "error.bad_params"
    page_filt = filt.model_copy(update={"limit": params["limit"], "offset": params["offset"]})
    groups: dict[str, object] | None = None
    ai_only: dict[str, object] | None = None
    try:
        if raw_view == "ai_only":
            ai_only = service.ai_only_paths(conn, page_filt, request.app.state.rules)
        else:
            status_class = {"redirects": "3xx", "client_errors": "4xx", "server_errors": "5xx"}[
                raw_view
            ]
            groups = service.seo_status_groups(
                conn,
                page_filt,
                request.app.state.rules,
                status_class=status_class,  # type: ignore[arg-type]
            )
    except ValueError:
        return None, "error.bad_params"
    summary = service.summarize(conn, filt, request.app.state.rules)
    _attach_observed_options(conn, context, filt, request.app.state.rules)
    bot_rules = {
        rule.id: rule for rule in request.app.state.rules if rule.ua_contains or rule.ua_regex
    }
    bot_titles = {rule_id: display_bot_title(rule.title) for rule_id, rule in bot_rules.items()}
    total = (
        groups["total_groups"]
        if isinstance(groups, dict)
        else (ai_only["total_paths"] if isinstance(ai_only, dict) else 0)
    )
    context.update(
        {
            "summary": summary,
            "totals": summary["totals"],
            "seo_view": raw_view,
            "groups": groups,
            "ai_only": ai_only,
            "bot_titles": bot_titles,
            "paging": _paging_nav("/seo", params, site, int(total), {"view": raw_view}),
            "fragment_url": "/partials/seo",
        }
    )
    context["canonical_url"] = _page_url("/seo", params, site, view=raw_view)
    return context, None


def _referrers_context(request: Request, conn, params):
    site, sites, error = _site_or_error(conn, params)
    if error is not None:
        return None, error
    error = _source_or_error(conn, site, params["source"])
    if error is not None:
        return None, error
    try:
        context = _base_context(request, params, site, sites, "/referrers", request.app.state.rules)
    except _InvalidFilter:
        return None, "error.bad_params"
    filt = context["filt"]
    raw_relation = (request.query_params.get("relation") or "").strip() or "all"
    if raw_relation not in REFERRER_RELATIONS:
        return None, "error.bad_params"
    raw_view = (request.query_params.get("view") or "").strip() or "all"
    if raw_view not in REFERRER_VIEWS:
        return None, "error.bad_params"
    page_filt = filt.model_copy(update={"limit": params["limit"], "offset": params["offset"]})
    try:
        if raw_view == "broken":
            report = service.referrer_404s(
                conn,
                page_filt,
                request.app.state.rules,
                relation=raw_relation,  # type: ignore[arg-type]
            )
            all_report = None
        else:
            all_report = service.referrer_urls(
                conn,
                page_filt,
                request.app.state.rules,
                relation=raw_relation,  # type: ignore[arg-type]
            )
            report = None
    except ValueError:
        return None, "error.bad_params"
    summary = service.summarize(conn, filt, request.app.state.rules)
    _attach_observed_options(conn, context, filt, request.app.state.rules)
    active = report if report is not None else all_report
    assert isinstance(active, dict)
    items = []
    for row in active["items"]:  # type: ignore[union-attr]
        assert isinstance(row, dict)
        scheme, host, ref_path = (
            row.get("referer_scheme"),
            row.get("referer_host"),
            row.get("referer_path"),
        )
        if scheme and host:
            full = f"{scheme}://{host}{ref_path or ''}"
        else:
            full = str(host or ref_path or "")
        link = private_view.safe_referrer_url(scheme, host, ref_path)
        items.append({**row, "referrer": full, "referrer_link": link})
    extra = {"relation": raw_relation, "view": raw_view}
    context.update(
        {
            "summary": summary,
            "totals": summary["totals"],
            "report": report,
            "all_report": all_report,
            "targets": items,
            "sources": items if all_report is not None else [],
            "relation": raw_relation,
            "referrer_view": raw_view,
            "paging": _paging_nav("/referrers", params, site, int(active["total_groups"]), extra),  # type: ignore[arg-type]
            "fragment_url": "/partials/referrers",
        }
    )
    context["canonical_url"] = _page_url(
        "/referrers", params, site, relation=raw_relation, view=raw_view
    )
    return context, None


#: Allowlisted journey views for the Journeys page: the ranked journey
#: list (with a sort and a minimum-requests floor) and the entry-path
#: aggregation over the same eligible journeys. Page-local, like a
#: sort: never part of the shared navigation scope.
JOURNEY_VIEWS = ("journeys", "entries")

#: Allowlisted journey rankings. Every option maps to one fixed server
#: ORDER BY over the whole filtered scope (never a page-only reorder);
#: ties break deterministically by stable journey ID.
JOURNEY_SORTS = ("requests_desc", "start_asc", "start_desc", "duration_desc")


def _parse_min_requests(q) -> tuple[int | None, str | None]:
    """Allowlisted minimum-requests floor; unknown values reject."""
    raw = (q.get("min_requests") or "").strip() or None
    if raw is None:
        return 1, None
    try:
        value = int(raw)
    except ValueError:
        return None, "error.bad_params"
    if not 1 <= value <= 1000:
        return None, "error.bad_params"
    return value, None


def _journeys_context(request: Request, conn, params):
    site, sites, error = _site_or_error(conn, params)
    if error is not None:
        return None, error
    error = _source_or_error(conn, site, params["source"])
    if error is not None:
        return None, error
    try:
        context = _base_context(request, params, site, sites, "/journeys", request.app.state.rules)
    except _InvalidFilter:
        return None, "error.bad_params"
    filt = context["filt"]
    query_params = request.query_params
    raw_view = (query_params.get("view") or "").strip() or "journeys"
    if raw_view not in JOURNEY_VIEWS:
        return None, "error.bad_params"
    journey_sort, error = _parse_sort(query_params, JOURNEY_SORTS, "requests_desc")
    if error is not None:
        return None, error
    min_requests, error = _parse_min_requests(query_params)
    if error is not None:
        return None, error
    assert journey_sort is not None and min_requests is not None
    page_filt = filt.model_copy(update={"limit": params["limit"], "offset": params["offset"]})
    try:
        journeys_report = service.journeys(
            conn,
            JourneyQuery(filt=page_filt, sort=journey_sort, min_requests=min_requests),  # type: ignore[arg-type]
            request.app.state.rules,
        )
        entries_report = service.journey_entry_paths(
            conn, page_filt, request.app.state.rules, min_requests=min_requests
        )
    except ValueError:
        return None, "error.bad_params"
    # Opaque journey timeline detail: all three list-issued selectors
    # must travel together (never a guessed User-Agent from a
    # truncated display field and never a raw address in the URL).
    detail = None
    detail_error = None
    raw_journey_id = (query_params.get("journey_id") or "").strip() or None
    raw_client = (query_params.get("journey_client") or "").strip() or None
    raw_start = (query_params.get("journey_start") or "").strip() or None
    detail_selectors = [
        value for value in (raw_journey_id, raw_client, raw_start) if value is not None
    ]
    if detail_selectors:
        if raw_journey_id is None or raw_client is None or raw_start is None:
            return None, "error.bad_params"
        try:
            start = datetime.fromisoformat(raw_start)
            if start.tzinfo is None:
                return None, "error.bad_params"
            detail = service.journey_timeline_by_id(
                conn,
                JourneyIdQuery(
                    filt=page_filt,
                    client_pseudonym=raw_client,
                    journey_start=start,
                    journey_id=raw_journey_id,
                ),
                request.app.state.rules,
            )
        except ValueError:
            return None, "error.bad_params"
        except KeyError:
            detail = None
            detail_error = "journeys.detail_not_found"
    summary = service.summarize(conn, filt, request.app.state.rules)
    _attach_observed_options(conn, context, filt, request.app.state.rules)
    view_total = (
        int(journeys_report["total_groups"])
        if raw_view == "journeys"
        else int(entries_report["total_groups"])
    )
    extra: dict[str, object] = {
        "view": raw_view,
        "sort": journey_sort,
        "min_requests": min_requests,
    }
    if raw_journey_id is not None:
        extra.update(
            {
                "journey_id": raw_journey_id,
                "journey_client": raw_client,
                "journey_start": raw_start,
            }
        )
    context.update(
        {
            "summary": summary,
            "totals": summary["totals"],
            "journey_view": raw_view,
            "journey_sort": journey_sort,
            "min_requests": min_requests,
            "journeys": journeys_report,
            "journey_items": journeys_report["items"],
            "entries": entries_report,
            "entry_items": entries_report["items"],
            "detail": detail,
            "detail_error": detail_error,
            "paging": _paging_nav("/journeys", params, site, view_total, extra),
            "fragment_url": "/partials/journeys",
        }
    )
    context["canonical_url"] = _page_url("/journeys", params, site, **extra)
    return context, None


#: Allowlisted explorer sorts for the Requests page, in front-column
#: order (Action is never sortable; Access is a derived display).
EXPLORER_SORTS = (
    "newest",
    "oldest",
    "time_asc",
    "time_desc",
    "client_asc",
    "client_desc",
    "method_asc",
    "method_desc",
    "path_asc",
    "path_desc",
    "status_asc",
    "status_desc",
    "bytes_asc",
    "bytes_desc",
)

#: Sortable Requests columns: (key, default sort when the column is
#: not current). The Time group keeps the legacy ``newest``/``oldest``
#: values alongside the explicit ``time_*`` pair; every other column
#: toggles its ascending/descending pair.
_EXPLORER_SORT_COLUMNS: tuple[tuple[str, str], ...] = (
    ("client", "client_asc"),
    ("time", "newest"),
    ("method", "method_asc"),
    ("path", "path_asc"),
    ("status", "status_asc"),
    ("bytes", "bytes_desc"),
)


def _sort_headers(page_url_fn, current: str, tz_name: str) -> list[dict[str, object]]:
    """Header view models for the sortable Requests columns.

    Each header carries its label, current direction (for ``aria-sort``
    and the visible marker), and the toggle link that keeps the full
    filter scope while resetting the offset to the first page.
    """
    labels = {
        "client": t("requests.client"),
        "time": t("requests.time_in", tz=tz_name),
        "method": t("table.method"),
        "path": t("table.path"),
        "status": t("table.status"),
        "bytes": t("table.bytes"),
    }
    headers = []
    for key, default in _EXPLORER_SORT_COLUMNS:
        if key == "time":
            members = {"newest", "oldest", "time_asc", "time_desc"}
            active = current in members
            if current in ("newest", "time_desc"):
                nxt = "oldest" if current == "newest" else "time_asc"
                direction: str | None = "descending"
            elif current in ("oldest", "time_asc"):
                nxt = "newest" if current == "oldest" else "time_desc"
                direction = "ascending"
            else:
                nxt, direction = default, None
        else:
            asc, desc = f"{key}_asc", f"{key}_desc"
            active = current in (asc, desc)
            if not active:
                nxt, direction = default, None
            elif current == asc:
                nxt, direction = desc, "ascending"
            else:
                nxt, direction = asc, "descending"
        headers.append(
            {
                "key": key,
                "label": labels[key],
                "active": active,
                "direction": direction,
                "direction_label": (
                    t("requests.sorted_asc")
                    if direction == "ascending"
                    else (t("requests.sorted_desc") if direction == "descending" else "")
                ),
                "next_sort": nxt,
                "href": page_url_fn("/requests", sort=nxt, offset=0),
            }
        )
    return headers


def _requests_context(request: Request, conn, params, ip_search_error: str | None = None):
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
    sort, error = _parse_sort(request.query_params, EXPLORER_SORTS, "newest")
    if error is not None:
        return None, error
    page_filt = filt.model_copy(update={"limit": params["limit"], "offset": params["offset"]})
    # The page rows and their private originals resolve inside this same
    # read snapshot: the internal request id binds each displayed row to
    # its own encrypted original by primary key (never by
    # timestamp/path/pseudonym or ordinal), so identical adjacent rows
    # and concurrent writer commits cannot cross-pair events. IDs stay
    # internal: they never reach API/exports/tools/errors.
    clf = service.classifier_for_filter(filt, request.app.state.rules)
    assert clf is not None
    paired, total_rows = queries.request_rows_with_ids(
        conn, ExplorerQuery(filt=page_filt, sort=sort), clf
    )
    display_state = private_store.resolve_display_state(conn)
    key, key_code = private_view.key_status(conn)
    private_rows = private_view.attach_private(
        conn, paired, key=key, key_code=key_code, state=display_state
    )
    summary = service.summarize(conn, filt, request.app.state.rules)
    _attach_observed_options(conn, context, filt, request.app.state.rules)
    # Named-bot metadata for the per-row details panel comes from the
    # versioned in-memory catalog (no per-row query); stored values stay
    # exact while labels read human-friendly.
    bot_rules = {
        rule.id: rule for rule in request.app.state.rules if rule.ua_contains or rule.ua_regex
    }
    # Display timestamps in the selected timezone; the UTC instant stays
    # in the title attribute so both instants are inspectable. Stored
    # values are UTC ISO strings; unparsable ones fall back to verbatim.
    rows = []
    for index, row in enumerate(private_rows):
        display = str(row["ts_utc"])
        offset = params["tz_name"]
        try:
            moment = datetime.fromisoformat(str(row["ts_utc"]))
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=UTC)
            display = moment.astimezone(params["tz"]).strftime("%Y-%m-%d %H:%M %Z")
            offset = format_offset_suffix(params["tz_name"], moment)
        except (ValueError, TypeError, OverflowError, OSError):
            pass
        rule_meta = None
        if row["rule_id"] is not None:
            rule = bot_rules.get(str(row["rule_id"]))
            if rule is not None:
                rule_meta = {
                    "id": rule.id,
                    "version": rule.version,
                    "title": display_bot_title(rule.title),
                    "meaning": rule.meaning,
                    "category": category_label(rule.category),
                    "provider": provider_label(rule.provider),
                    "purpose": purpose_label(rule.purpose),
                    "provider_raw": rule.provider,
                    "purpose_raw": rule.purpose,
                }
        rows.append(
            {
                **row,
                "ts_display": display,
                "ts_offset": offset,
                "status_phrase": status_phrase(int(row["status"])),
                "rule_meta": rule_meta,
                "detail_id": f"req-detail-{params['offset'] + index}",
                # Sanitized absolute referrer link (http/https only) or
                # None: templates render plain text otherwise, never a
                # dangerous scheme or a secret-bearing value.
                "referrer_url": private_view.safe_referrer_url(
                    row.get("referer_scheme"), row.get("referer_host"), row.get("referer_path")
                ),
            }
        )
    # Full-result download links preserve the applied window, every
    # matcher, the explorer sort and the display timezone; the reviewed
    # session export streams pseudonyms only in every IP mode.
    export_base = "/export/requests" + _nav_query(params, site)
    session = _session_or_none(request)
    csrf_token = session.csrf_token if session is not None else ""
    if display_state.get("corrupt"):
        ip_banner = "privacy.ip_corrupt"
    elif display_state.get("mode") != private_store.IP_DISPLAY_PSEUDONYM_ONLY and key is None:
        # Never render the raw ``private_unavailable:*`` store code: the
        # central catalog holds no such locale key, so it would print
        # verbatim internal codes. Map to fixed English guidance.
        ip_banner = private_view.banner_key(key_code)
    else:
        ip_banner = None
    context.update(
        {
            "summary": summary,
            "totals": summary["totals"],
            "rows": rows,
            "explorer_sort": sort,
            "sort_headers": _sort_headers(
                lambda path, **overrides: _page_url(path, params, site, **overrides),
                sort,
                params["tz_name"],
            ),
            "paging": _paging_nav("/requests", params, site, total_rows, {"sort": sort}),
            "fragment_url": "/partials/requests",
            "canonical_url": _page_url("/requests", params, site, sort=sort),
            # The exact-IP search POST rebuilds its redirect from this
            # action's query string, so the current allowlisted explorer
            # sort travels here. Page-local sort stays out of the shared
            # navigation query used by every other link.
            "ip_search_action": "/requests/ip-search" + _nav_query(params, site) + f"&sort={sort}",
            "ip_mode": display_state.get("mode"),
            "ip_corrupt": bool(display_state.get("corrupt")),
            "ip_key_configured": key is not None,
            "ip_banner": ip_banner,
            "ip_search_error": ip_search_error,
            "csrf_token": csrf_token,
            "export_csv_url": f"{export_base}&format=csv&sort={sort}",
            "export_json_url": f"{export_base}&format=json&sort={sort}",
        }
    )
    return context, None


ASK_STARTER_COUNT = 9


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
    _attach_observed_options(conn, context, filt, request.app.state.rules)
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


def _settings_context(request: Request, conn, settings_error: str | None = None):
    settings = load_settings()
    display_state = private_store.resolve_display_state(conn)
    key, _ = private_view.key_status(conn)
    session = _session_or_none(request)
    return {
        "t": t,
        "request": request,
        "nav_query": _optional_nav_query(request),
        "app_base_url": settings.app_base_url,
        # The same resolved effective default that orders the filter-bar
        # options: configured value wins, otherwise the trusted regional
        # server TZ, otherwise UTC. Never the raw "UTC" placeholder while
        # routing actually falls back to a regional zone.
        "default_timezone": _effective_default(settings),
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
        "ip_mode": display_state.get("mode"),
        "ip_v4_hidden": display_state.get("v4_hidden"),
        "ip_v6_hidden": display_state.get("v6_hidden"),
        "ip_corrupt": bool(display_state.get("corrupt")),
        "ip_key_configured": key is not None,
        "settings_error": settings_error,
        "csrf_token": session.csrf_token if session is not None else "",
    }


#: Documented small cap for the two admin HTML form bodies (IP
#: display settings and the exact-IP search). Bodies stream through
#: ``request.stream()`` and reject above this size BEFORE buffering or
#: parsing the full body — including absent, false or lying
#: Content-Length and chunked transfer (a declared length alone is
#: never trusted). The dashboard posts plain forms (no file inputs),
#: so ``application/x-www-form-urlencoded`` bodies parse without any
#: extra dependency; no multipart/upload path is added.
FORM_BODY_MAX_BYTES = 16 * 1024
#: Bounded field policy for those forms: at most this many pairs,
#: keys/values length-capped, duplicates rejected, strict UTF-8 and
#: strict percent-escapes (a ``%`` not followed by two hex digits is
#: malformed). Violations fail closed with a fixed 400; oversize
#: fails closed with a fixed 413. No input is ever reflected.
FORM_MAX_FIELDS = 50
FORM_MAX_KEY_CHARS = 128
FORM_MAX_VALUE_CHARS = 4096

_HEX_DIGITS = frozenset("0123456789ABCDEFabcdef")


async def _read_bounded_form(request: Request) -> tuple[dict[str, str], str]:
    """Stream one urlencoded form under the documented byte cap.

    Returns ``(fields, status)`` with status ``"ok"``, ``"too_large"``
    or ``"malformed"``. Stops consuming the receive channel as soon as
    the streamed total exceeds the cap, so oversized remainders never
    enter the app buffer; declared Content-Length alone is never
    trusted. Malformed covers wrong content type, undecodable bytes,
    malformed pairs, duplicate keys and bound violations — callers
    treat it as empty fields and continue to the normal CSRF check
    (bad body plus bad header stays a safe 403), while ``"too_large"``
    answers a fixed 413.
    """
    from urllib.parse import unquote_plus

    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded":
        return {}, "malformed"
    total = 0
    chunks: list[bytes] = []
    async for chunk in request.stream():
        total += len(chunk)
        if total > FORM_BODY_MAX_BYTES:
            # Over the cap: stop reading here; the remaining chunks
            # are never consumed into the app buffer.
            return {}, "too_large"
        if chunk:
            chunks.append(chunk)
    raw = b"".join(chunks)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return {}, "malformed"
    if not text:
        return {}, "ok"
    pairs = text.split("&")
    if len(pairs) > FORM_MAX_FIELDS:
        return {}, "malformed"
    fields: dict[str, str] = {}
    for pair in pairs:
        if "=" in pair:
            raw_key, raw_value = pair.split("=", 1)
        else:
            raw_key, raw_value = pair, ""
        for segment in (raw_key, raw_value):
            index = 0
            while True:
                mark = segment.find("%", index)
                if mark == -1:
                    break
                if len(segment) < mark + 3 or (
                    segment[mark + 1] not in _HEX_DIGITS or segment[mark + 2] not in _HEX_DIGITS
                ):
                    return {}, "malformed"
                index = mark + 3
        try:
            key = unquote_plus(raw_key, encoding="utf-8", errors="strict")
            value = unquote_plus(raw_value, encoding="utf-8", errors="strict")
        except (UnicodeDecodeError, ValueError):
            return {}, "malformed"
        if len(key) > FORM_MAX_KEY_CHARS or len(value) > FORM_MAX_VALUE_CHARS:
            return {}, "malformed"
        if key in fields:
            # Unambiguous duplicate policy: repeated keys reject
            # instead of silently keeping first or last.
            return {}, "malformed"
        fields[key] = value
    return fields, "ok"


def _valid_csrf_field(presented: object, expected: object) -> bool:
    """Constant-time CSRF check for form-field tokens; fail-closed.

    The header path uses :func:`app.api.deps.require_csrf`; HTML forms
    on this slice post the same per-session token as a field instead.
    Non-string, empty, non-ASCII or mismatched values all fail closed
    without raising (``compare_digest`` raises ``TypeError`` on
    non-ASCII ``str``).
    """
    import hmac as _hmac

    if not isinstance(presented, str) or not presented:
        return False
    if not isinstance(expected, str) or not expected:
        return False
    try:
        return _hmac.compare_digest(presented, expected)
    except (TypeError, ValueError, AttributeError):
        return False


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
    context["oob_notice"] = True
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
    context["oob_notice"] = True
    response = templates.TemplateResponse(request, "partials/crawlers_content.html", context)
    response.headers["HX-Push-Url"] = context["canonical_url"]
    return response


@router.get("/performance", response_class=HTMLResponse)
def performance_page(request: Request):
    params, gate = _data_page(request)
    if gate == "redirect":
        return _redirect_to_login(request)
    if gate is not None:
        return _error_page(request, gate, 400)
    with read_store(request) as conn:
        context, error = _performance_context(request, conn, params)
    if error is not None:
        return _error_page(request, error, 400 if error != "error.unknown_site" else 404)
    return templates.TemplateResponse(request, "pages/performance.html", context)


@router.get("/partials/performance", response_class=HTMLResponse)
def performance_partial(request: Request):
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
        context, error = _performance_context(request, conn, params)
    if error is not None:
        return HTMLResponse(
            f'<p class="alert alert-error" role="alert">{t(error)}</p>', status_code=400
        )
    context["oob_notice"] = True
    response = templates.TemplateResponse(request, "partials/performance_content.html", context)
    response.headers["HX-Push-Url"] = context["canonical_url"]
    return response


@router.get("/seo", response_class=HTMLResponse)
def seo_page(request: Request):
    params, gate = _data_page(request)
    if gate == "redirect":
        return _redirect_to_login(request)
    if gate is not None:
        return _error_page(request, gate, 400)
    with read_store(request) as conn:
        context, error = _seo_context(request, conn, params)
    if error is not None:
        return _error_page(request, error, 400 if error != "error.unknown_site" else 404)
    return templates.TemplateResponse(request, "pages/seo.html", context)


@router.get("/partials/seo", response_class=HTMLResponse)
def seo_partial(request: Request):
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
        context, error = _seo_context(request, conn, params)
    if error is not None:
        return HTMLResponse(
            f'<p class="alert alert-error" role="alert">{t(error)}</p>', status_code=400
        )
    context["oob_notice"] = True
    response = templates.TemplateResponse(request, "partials/seo_content.html", context)
    response.headers["HX-Push-Url"] = context["canonical_url"]
    return response


@router.get("/referrers", response_class=HTMLResponse)
def referrers_page(request: Request):
    params, gate = _data_page(request)
    if gate == "redirect":
        return _redirect_to_login(request)
    if gate is not None:
        return _error_page(request, gate, 400)
    with read_store(request) as conn:
        context, error = _referrers_context(request, conn, params)
    if error is not None:
        return _error_page(request, error, 400 if error != "error.unknown_site" else 404)
    return templates.TemplateResponse(request, "pages/referrers.html", context)


@router.get("/partials/referrers", response_class=HTMLResponse)
def referrers_partial(request: Request):
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
        context, error = _referrers_context(request, conn, params)
    if error is not None:
        return HTMLResponse(
            f'<p class="alert alert-error" role="alert">{t(error)}</p>', status_code=400
        )
    context["oob_notice"] = True
    response = templates.TemplateResponse(request, "partials/referrers_content.html", context)
    response.headers["HX-Push-Url"] = context["canonical_url"]
    return response


@router.get("/journeys", response_class=HTMLResponse)
def journeys_page(request: Request):
    params, gate = _data_page(request)
    if gate == "redirect":
        return _redirect_to_login(request)
    if gate is not None:
        return _error_page(request, gate, 400)
    with read_store(request) as conn:
        context, error = _journeys_context(request, conn, params)
    if error is not None:
        return _error_page(request, error, 400 if error != "error.unknown_site" else 404)
    return templates.TemplateResponse(request, "pages/journeys.html", context)


@router.get("/partials/journeys", response_class=HTMLResponse)
def journeys_partial(request: Request):
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
        context, error = _journeys_context(request, conn, params)
    if error is not None:
        return HTMLResponse(
            f'<p class="alert alert-error" role="alert">{t(error)}</p>', status_code=400
        )
    context["oob_notice"] = True
    response = templates.TemplateResponse(request, "partials/journeys_content.html", context)
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
    context["oob_notice"] = True
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
    context["oob_notice"] = True
    response = templates.TemplateResponse(request, "partials/requests_content.html", context)
    response.headers["HX-Push-Url"] = context["canonical_url"]
    return response


@router.get("/export/requests")
def export_requests_download(request: Request):
    """Session-authenticated full-result CSV/JSON download (thin entry).

    No Bearer token is accepted here and no credential is read from
    the query string; the admin session authorizes the download while
    the shared export builder enforces the same site/source/window
    contract, allowlisted columns, privacy label and row cap as the
    Bearer API. No export UI is added yet (T4).
    """
    from app.api import routes_export

    params, gate = _data_page(request)
    if gate == "redirect":
        return _redirect_to_login(request)
    if gate is not None:
        return _error_page(request, gate, 400)
    raw_format = (request.query_params.get("format") or "csv").strip().lower()
    if raw_format not in ("csv", "json"):
        return _error_page(request, "error.bad_params", 400)
    sort, error = _parse_sort(request.query_params, EXPLORER_SORTS, "oldest")
    if error is not None:
        return _error_page(request, error, 400)
    with read_store(request) as conn:
        site, sites, error = _site_or_error(conn, params)
        if error is not None:
            return _error_page(request, error, 400 if error != "error.unknown_site" else 404)
        error = _source_or_error(conn, site, params["source"])
        if error is not None:
            return _error_page(request, error, 400 if error != "error.unknown_site" else 404)
        try:
            context = _base_context(
                request, params, site, sites, "/export/requests", request.app.state.rules
            )
        except _InvalidFilter:
            return _error_page(request, "error.bad_params", 400)
        filt = context["filt"]
    prepared, failure = routes_export.prepare_session_export(
        filt=filt,
        rules=request.app.state.rules,
        sort=sort,
        export_format=raw_format,
        db_path=request.app.state.db_path,
        display_timezone=params["tz_name"],
    )
    if failure == "invalid":
        return _error_page(request, "error.bad_params", 400)
    if isinstance(failure, tuple):
        return HTMLResponse(
            f'<p class="alert alert-error" role="alert">{t("error.export_too_large")}</p>',
            status_code=413,
        )
    assert prepared is not None
    filename = routes_export.safe_filename(
        filt.site_id, filt.window.time_from, filt.window.time_to, raw_format
    )
    return routes_export.export_response(prepared, filename)


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
    with read_store(request) as conn:
        context = _settings_context(request, conn)
    return templates.TemplateResponse(request, "pages/settings.html", context)


@router.post("/settings/ip-display", response_class=HTMLResponse)
async def settings_ip_display_update(request: Request):
    """Persist the private original-IP display preference (T4a, PAR-02).

    Local-admin session only (Bearer [REDACTED] never authorize this);
    CSRF is accepted as the per-session header or as the form field of
    the same token. Only the display mode and the validated hidden
    octet/hextet counts are stored — never a key, never an address.
    Filter/window state rides the action query string and returns via a
    303 redirect, so mode changes never widen or drop the scope.
    """
    session = _session_or_none(request)
    if session is None:
        return _error_page(request, "error.auth_required", 401)
    from app.api.deps import require_csrf

    request_id = request.state.request_id
    header_ok = require_csrf(request, session, request_id) is None
    # Auth first, then the streamed bounded body: oversize rejects with
    # a fixed 413 before buffering or parsing; malformed behaves like
    # an empty form so a bad body plus a bad token stays a safe 403.
    body, form_status = await _read_bounded_form(request)
    if form_status == "too_large":
        with read_store(request) as conn:
            context = _settings_context(request, conn, "error.form_too_large")
        return templates.TemplateResponse(request, "pages/settings.html", context, status_code=413)
    field_token = body.get("csrf_token")
    if not header_ok and not _valid_csrf_field(field_token, session.csrf_token):
        return _error_page(request, "error.csrf_required", 403)
    raw_mode = body.get("ip_mode")
    mode = raw_mode.strip() if isinstance(raw_mode, str) else ""
    try:
        v4_hidden = int(str(body.get("ip_v4_hidden", "")).strip())
        v6_hidden = int(str(body.get("ip_v6_hidden", "")).strip())
    except (TypeError, ValueError):
        with read_store(request) as conn:
            context = _settings_context(request, conn, "error.bad_params")
        return templates.TemplateResponse(request, "pages/settings.html", context, status_code=400)
    if mode not in private_store.IP_DISPLAY_MODES:
        with read_store(request) as conn:
            context = _settings_context(request, conn, "error.bad_params")
        return templates.TemplateResponse(request, "pages/settings.html", context, status_code=400)
    # Validate the return state BEFORE writing: only the allowlisted
    # window/filter/TZ set survives into the redirect, and malformed
    # state rejects without copying any raw query value. The path is
    # fixed (never from input), so only safe local targets arise.
    nav_params, nav_error = _parse_view_params(request, datetime.now(UTC))
    if nav_error is not None:
        with read_store(request) as conn:
            context = _settings_context(request, conn, "error.bad_params")
        return templates.TemplateResponse(request, "pages/settings.html", context, status_code=400)
    from app.db.database import writer_transaction

    try:
        with writer_transaction(request.app.state.db_path) as conn:
            private_store.set_ip_display_mode(conn, mode)
            private_store.set_ip_hidden_counts(conn, v4_hidden, v6_hidden)
    except ValueError:
        with read_store(request) as conn:
            context = _settings_context(request, conn, "error.bad_params")
        return templates.TemplateResponse(request, "pages/settings.html", context, status_code=400)
    # Return target rebuilt from the validated state above — never from
    # raw query text — so only safe local filter/window/TZ state
    # survives and unknown values cannot leak into the redirect.
    return_target: dict[str, object] = {
        "range": nav_params["range"],
        "from": nav_params["window"].time_from.isoformat(),
        "to": nav_params["window"].time_to.isoformat(),
        "tz": nav_params["tz_name"],
    }
    if nav_params["site"] is not None:
        return_target["site"] = nav_params["site"]
    if nav_params["source"] is not None:
        return_target["source"] = nav_params["source"]
    return_target.update(_matcher_query(nav_params))
    return RedirectResponse(url="/settings?" + urlencode(return_target), status_code=303)


@router.post("/requests/ip-search", response_class=HTMLResponse)
async def requests_ip_search(request: Request):
    """Exact original-address lookup for the local admin (T4a, PAR-02).

    Session + CSRF POST only. The entered address is validated
    transiently (IPv4/IPv6, bounded body, exact source spelling kept
    for the legacy HMAC input) and translated server-side to the safe
    stable pseudonym: the 303 redirect carries only the pseudonym as
    the shared exact ``client`` selector — never the general text
    search (which intentionally also matches path, User-Agent and
    referrer) and never the original address. The current window,
    every other matcher, the independent text search, the limit, the
    timezone and the source survive; the page offset resets
    deliberately for the new search while the allowlisted explorer
    sort is preserved. The entered address is never echoed into
    HTML, attributes, errors, redirects, URLs, history, bookmarks,
    logs or model state, and the form re-renders empty. Invalid input
    re-renders with a fixed localized error. Bearer [REDACTED] never
    authorize this; the external API gains no raw-IP path.
    """
    session = _session_or_none(request)
    if session is None:
        return _error_page(request, "error.auth_required", 401)
    from app.api.deps import require_csrf

    request_id = request.state.request_id
    header_ok = require_csrf(request, session, request_id) is None
    # Auth first, then the streamed bounded body: oversize rejects with
    # a fixed 413 before buffering or parsing; malformed behaves like
    # an empty form so a bad body plus a bad token stays a safe 403.
    body, form_status = await _read_bounded_form(request)
    if form_status == "too_large":
        return await _requests_ip_search_error(request, "error.form_too_large", status=413)
    field_token = body.get("csrf_token")
    if not header_ok and not _valid_csrf_field(field_token, session.csrf_token):
        return _error_page(request, "error.csrf_required", 403)
    raw_ip = body.get("ip")
    candidate = raw_ip.strip() if isinstance(raw_ip, str) else ""
    if not candidate or len(candidate) > 1024:
        return await _requests_ip_search_error(request, "privacy.ip_search_invalid")
    from app.ingestion.combined import validate_original_ip

    if validate_original_ip(candidate) is None:
        return await _requests_ip_search_error(request, "privacy.ip_search_invalid")
    try:
        hmac_key = load_settings().hmac_key.get_secret_value().encode("utf-8")
    except (ValueError, AttributeError):
        return await _requests_ip_search_error(request, "privacy.ip_search_invalid")
    if not hmac_key:
        return await _requests_ip_search_error(request, "privacy.ip_search_invalid")
    from app.ingestion.combined import pseudonymize_client

    pseudonym = pseudonymize_client(candidate, hmac_key)
    # Rebuild the redirect from the posted action query: same window,
    # site, source, timezone, matchers (including an independent text
    # search) and limit survive; only the exact ``client`` selector
    # becomes the safe pseudonym (the raw address never leaves the
    # POST body, which is discarded after this translation). The page
    # offset resets deliberately for the new search while the
    # allowlisted explorer sort is preserved.
    params, error = _parse_view_params(request, datetime.now(UTC))
    if error is not None:
        return _error_page(request, error, 400)
    sort, sort_error = _parse_sort(request.query_params, EXPLORER_SORTS, "newest")
    if sort_error is not None:
        return _error_page(request, sort_error, 400)
    target: dict[str, object] = {
        "site": params["site"] or "",
        "range": params["range"],
        "from": params["window"].time_from.isoformat(),
        "to": params["window"].time_to.isoformat(),
        "tz": params["tz_name"],
    }
    if params["source"] is not None:
        target["source"] = params["source"]
    for key in MATCHER_KEYS:
        if key == "client":
            continue
        value = params["matchers"].get(key)
        if value is not None:
            target[key] = _matcher_url_value(value)
    target["client"] = pseudonym
    target["limit"] = params["limit"]
    target["offset"] = 0
    target["sort"] = sort
    return RedirectResponse(url="/requests?" + urlencode(target), status_code=303)


async def _requests_ip_search_error(
    request: Request, message_key: str, status: int = 400
) -> HTMLResponse:
    """Re-render the Requests page with a fixed search error.

    The entered address is never reflected: the message carries no
    input value and the form renders empty. Oversized bodies use 413.
    """
    params, error = _parse_view_params(request, datetime.now(UTC))
    if error is not None:
        return _error_page(request, error, 400)
    with read_store(request) as conn:
        site, _sites, site_error = _site_or_error(conn, params)
        if site_error is not None:
            return _error_page(
                request, site_error, 400 if site_error != "error.unknown_site" else 404
            )
        source_error = _source_or_error(conn, site or "", params["source"])
        if source_error is not None:
            return _error_page(request, source_error, 400)
        context, context_error = _requests_context(
            request, conn, params, ip_search_error=message_key
        )
    if context_error is not None:
        return _error_page(
            request, context_error, 400 if context_error != "error.unknown_site" else 404
        )
    context["request"] = request
    return templates.TemplateResponse(request, "pages/requests.html", context, status_code=status)


@router.get("/data-sources", response_class=HTMLResponse)
def sources_page(request: Request):
    if _session_or_none(request) is None:
        return _redirect_to_login(request)
    with read_store(request) as conn:
        context = _sources_context(request, conn)
    return templates.TemplateResponse(request, "pages/data_sources.html", context)


def _help_context(request: Request) -> dict:
    """Session-gated Help context; bearer tokens never open this UI.

    Reuses the optional shared filter/window state so active navigation
    survives a Help visit, exactly like Settings and Data Sources.
    """
    return {
        "t": t,
        "request": request,
        "nav_query": _optional_nav_query(request),
        "verify_url": (
            "https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests"
        ),
    }


@router.get("/help", response_class=HTMLResponse)
def help_page(request: Request):
    if _session_or_none(request) is None:
        return _redirect_to_login(request)
    return templates.TemplateResponse(request, "pages/help.html", _help_context(request))
