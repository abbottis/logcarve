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
    for key in ("method", "status", "path_prefix", "referer_host", "limit", "offset", "bucket"):
        if envelope_filters.get(key) is not None:
            query[key] = envelope_filters[key]
    return page_path + "?" + urlencode(query)


def envelope_href(tool_name: object, envelope_filters: dict, tz_name: str = "UTC") -> str | None:
    """Server-generated evidence link for one tool envelope, if allowlisted."""
    page_path = TOOL_PAGE_MAP.get(tool_name) if isinstance(tool_name, str) else None
    if page_path is None:
        return None
    if not isinstance(envelope_filters, dict):
        return None
    return evidence_url(page_path, envelope_filters, tz_name)
