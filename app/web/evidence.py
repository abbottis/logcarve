"""Server-generated dashboard evidence links (single trusted formatter).

Every assistant tool read maps to exactly one dashboard page through the
fixed ``TOOL_PAGE_MAP`` below; :func:`evidence_url` rebuilds the full
read (site, source, window, matchers, paging, bucket) as a plain URL.
Both the browser dashboard and the authenticated chat boundary use this
module, so links never come from model text or divergent client logic.
Unknown tool names yield no link.

Comparison evidence replays the ACTUAL executed halves: the model
``comparison`` report compares equal halves INSIDE the selected parent
window, so its link carries the executed current half as the page
window and the executed baseline half as explicit baseline values on
``/comparison``. The parent window is never mapped as current with a
previous-window default (that would widen the read and display
different counts).
"""

from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

TOOL_PAGE_MAP = {
    "get_summary": "/",
    "get_timeseries": "/",
    "get_top_paths": "/",
    "get_top_referrers": "/",
    "get_crawler_claims": "/crawlers",
    "get_security_findings": "/security",
    "get_error_groups": "/errors",
    "get_report": "/",
}

#: Report pages for the aggregate-only ``get_report`` tool. Every
#: report maps to the dashboard page that reproduces its exact read,
#: including page-local selectors (SEO view, slow-endpoint sort,
#: referrer view/relation, journey view/sort/min-requests, explicit
#: comparison baseline halves).
REPORT_PAGE_MAP = {
    "performance": "/performance",
    "slow_endpoints": "/performance",
    "seo_redirects": "/seo",
    "seo_client_errors": "/seo",
    "seo_server_errors": "/seo",
    "seo_ai_only": "/seo",
    "referrer_404s": "/referrers",
    "referrer_urls": "/referrers",
    "journeys": "/journeys",
    "journey_entries": "/journeys",
    "comparison": "/comparison",
}

#: Page-local selectors per report, applied on top of the shared global
#: filters so a replayed URL returns the executed report counts. The
#: slow-endpoint report ranks by server average; the referrer-404
#: report links explicitly to the broken view (the default view is
#: the all-URL overview) with the executed relation.
REPORT_PAGE_EXTRAS: dict[str, dict[str, object]] = {
    "slow_endpoints": {"sort": "avg_desc"},
    "seo_redirects": {"view": "redirects"},
    "seo_client_errors": {"view": "client_errors"},
    "seo_server_errors": {"view": "server_errors"},
    "seo_ai_only": {"view": "ai_only"},
    "referrer_404s": {"view": "broken", "relation": "all"},
    "referrer_urls": {"view": "all", "relation": "all"},
    "journeys": {"view": "journeys", "sort": "requests_desc", "min_requests": 1},
    "journey_entries": {"view": "entries", "min_requests": 1},
}


def evidence_url(page_path: str, envelope_filters: dict, tz_name: str = "UTC") -> str:
    """Dashboard link reproducing one assistant tool read.

    Every envelope key maps to the matching page parameter; nothing is
    dropped. The envelope is server-typed, the route map is fixed, and
    values are URL-encoded — model text never becomes markup here.
    """
    query: dict[str, object] = {
        "site": envelope_filters.get("site_id", ""),
        "range": "custom",
        "from": envelope_filters.get("time_from", ""),
        "to": envelope_filters.get("time_to", ""),
        "tz": tz_name,
    }
    if envelope_filters.get("source_id") is not None:
        query["source"] = envelope_filters["source_id"]
    for key in (
        "method",
        "status",
        "status_class",
        "path_prefix",
        "path_exact",
        "referer_host",
        "search",
        "client",
        "traffic",
        "bot",
        "category",
        "provider",
        "purpose",
        "server_host",
        "http_version",
        "mime_type",
        "cache_status",
        "tls_protocol",
        "timing_available",
        "upstream_available",
        "timing_min_ms",
        "timing_max_ms",
        "report",
        "limit",
        "offset",
        "bucket",
        # Explicit comparison baselines: only the comparison page
        # reads these; every other page ignores unknown parameters.
        "baseline",
        "baseline_from",
        "baseline_to",
    ):
        value = envelope_filters.get(key)
        if value is None:
            continue
        # The filter bar parses availability matchers from ``yes``/``no``;
        # serializing Python ``True`` would emit ``True`` and silently
        # drop the matcher on reload, breaking evidence-link replay.
        if value is True:
            value = "yes"
        elif value is False:
            value = "no"
        query[key] = value
    report = envelope_filters.get("report")
    if isinstance(report, str):
        for key, value in REPORT_PAGE_EXTRAS.get(report, {}).items():
            query[key] = value
    return page_path + "?" + urlencode(query)


def _comparison_halves(
    time_from: object, time_to: object
) -> tuple[datetime, datetime, datetime] | None:
    """Executed inside-halves of a model comparison parent window.

    Mirrors :func:`app.analytics.service.split_trusted_window_filter`
    exactly (integer-microsecond arithmetic, even positive length):
    returns ``(parent_from, mid, parent_to)`` where the baseline half
    is ``[parent_from, mid)`` and the current half is ``[mid,
    parent_to)``. Returns ``None`` when the parent cannot split, so
    the caller links honestly without inventing a baseline.
    """
    try:
        start = datetime.fromisoformat(str(time_from))
        end = datetime.fromisoformat(str(time_to))
    except (ValueError, TypeError):
        return None
    if start.tzinfo is None:
        start = start.replace(tzinfo=UTC)
    if end.tzinfo is None:
        end = end.replace(tzinfo=UTC)
    delta = end - start
    total_us = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
    if total_us < 2 or total_us % 2 != 0:
        return None
    mid = start + timedelta(microseconds=total_us // 2)
    return start, mid, end


def comparison_evidence_url(envelope_filters: dict, tz_name: str = "UTC") -> str:
    """Evidence link for a model ``comparison`` report: the executed halves.

    The page window carries the executed CURRENT half (second half)
    and ``baseline_from``/``baseline_to`` carry the executed BASELINE
    half (first half) with the same selectors, so click/replay shows
    the exact tool counts. When the parent cannot split evenly, the
    link carries only the parent window with NO baseline default: the
    page then prompts for an explicit baseline instead of displaying
    different counts under a widened default.
    """
    halves = _comparison_halves(envelope_filters.get("time_from"), envelope_filters.get("time_to"))
    if halves is None:
        return evidence_url("/comparison", envelope_filters, tz_name)
    parent_from, mid, parent_to = halves
    scoped = dict(envelope_filters)
    scoped["time_from"] = mid.isoformat()
    scoped["time_to"] = parent_to.isoformat()
    scoped["baseline_from"] = parent_from.isoformat()
    scoped["baseline_to"] = mid.isoformat()
    return evidence_url("/comparison", scoped, tz_name)


def envelope_href(tool_name: object, envelope_filters: dict, tz_name: str = "UTC") -> str | None:
    """Server-generated evidence link for one tool envelope, if allowlisted."""
    page_path = TOOL_PAGE_MAP.get(tool_name) if isinstance(tool_name, str) else None
    if page_path is None:
        return None
    if not isinstance(envelope_filters, dict):
        return None
    if tool_name == "get_report":
        report = envelope_filters.get("report")
        if report == "comparison":
            return comparison_evidence_url(envelope_filters, tz_name)
        page_path = REPORT_PAGE_MAP.get(report) if isinstance(report, str) else None
        if page_path is None:
            # Tool-level default: the envelope always carries a valid
            # report, but the tool itself stays linkable without one.
            page_path = TOOL_PAGE_MAP["get_report"]
    return evidence_url(page_path, envelope_filters, tz_name)
