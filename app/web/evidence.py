"""Server-generated dashboard evidence links (single trusted formatter).

Every assistant tool read maps to exactly one dashboard page through the
fixed ``TOOL_PAGE_MAP`` below; :func:`evidence_url` rebuilds the full
read (site, source, window, matchers, paging, bucket) as a plain URL.
Both the browser dashboard and the authenticated chat boundary use this
module, so links never come from model text or divergent client logic.
Unknown tool names yield no link.
"""

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
#: report maps to the closest existing dashboard page (full report
#: pages arrive with T4): performance, slow-endpoint, comparison and
#: journey aggregates reproduce on the overview, SEO errors on the
#: error groups page, AI-candidate paths with the crawler claims.
REPORT_PAGE_MAP = {
    "performance": "/",
    "slow_endpoints": "/",
    "seo_redirects": "/errors",
    "seo_client_errors": "/errors",
    "seo_server_errors": "/errors",
    "seo_ai_only": "/crawlers",
    "referrer_404s": "/",
    "journeys": "/",
    "journey_entries": "/",
    "comparison": "/",
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
    return page_path + "?" + urlencode(query)


def envelope_href(tool_name: object, envelope_filters: dict, tz_name: str = "UTC") -> str | None:
    """Server-generated evidence link for one tool envelope, if allowlisted."""
    page_path = TOOL_PAGE_MAP.get(tool_name) if isinstance(tool_name, str) else None
    if page_path is None:
        return None
    if not isinstance(envelope_filters, dict):
        return None
    if tool_name == "get_report":
        report = envelope_filters.get("report")
        page_path = REPORT_PAGE_MAP.get(report) if isinstance(report, str) else None
        if page_path is None:
            # Tool-level default: the envelope always carries a valid
            # report, but the tool itself stays linkable without one.
            page_path = TOOL_PAGE_MAP["get_report"]
    return evidence_url(page_path, envelope_filters, tz_name)
