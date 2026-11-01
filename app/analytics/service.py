"""Shared deterministic analytics services (T4).

The single consumer entry for the future dashboard, REST API and
internal assistant tools: equal filters always yield equal results.
Findings are derived on read without any model: every finding carries
its rule ID/version, evidence references, filters, requested window,
observation time, supporting counts, actual coverage and limitations.
No people, sessions, indexing, rankings, conversions or verified
attacks are ever inferred.
"""

import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.analytics import queries
from app.analytics.classification import Classifier, build_classifier
from app.analytics.contracts import (
    AnalyticsFilter,
    BotTableQuery,
    BucketSize,
    ExplorerQuery,
    TopPathsQuery,
    TopReferrersQuery,
)
from app.analytics.rules import Rule

LIMITATIONS_LOGS = [
    "access logs alone cannot prove traffic completeness: coverage describes observed events, not proven source coverage",
    "missing timing is unavailable, never zero: no latency averages or percentiles are fabricated",
]

LIMITATIONS_BOT = [
    "a User-Agent match proves a claimed identity only, never a verified crawler",
]

LIMITATIONS_SECURITY = [
    "security matches are investigation candidates, never proof of compromise or attribution",
]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    rule_version: int
    category: str
    title: str
    severity: str
    meaning: str
    window: dict[str, str]
    filters: dict[str, object]
    observation_time: str
    counts: dict[str, int]
    evidence: dict[str, object]
    coverage_summary: dict[str, object]
    limitations: list[str] = field(default_factory=list)


def _window_dict(filt: AnalyticsFilter) -> dict[str, str]:
    return {
        "time_from": filt.window.time_from.isoformat(),
        "time_to": filt.window.time_to.isoformat(),
    }


def _filter_dict(filt: AnalyticsFilter) -> dict[str, object]:
    return {
        "site_id": filt.site_id,
        "source_id": filt.source_id,
        "method": filt.method,
        "status": filt.status,
        "status_class": filt.status_class,
        "path_prefix": filt.path_prefix,
        "referer_host": filt.referer_host,
        "search": filt.search,
        "traffic": filt.traffic,
        "bot": filt.bot,
        "category": filt.category,
        "provider": filt.provider,
        "purpose": filt.purpose,
    }


def _needs_classifier(filt: AnalyticsFilter) -> bool:
    return (
        filt.traffic != "all"
        or filt.bot is not None
        or filt.category is not None
        or filt.provider is not None
        or filt.purpose is not None
    )


def _classifier_for(filt: AnalyticsFilter, rules: list[Rule] | None) -> Classifier | None:
    """Versioned classifier for selector filters; None when unneeded.

    Raises ``ValueError`` when selectors are set without the versioned
    rules so callers reject instead of silently widening.
    """
    if rules is None:
        if _needs_classifier(filt):
            raise ValueError("traffic/bot selectors need the versioned rule classifier")
        return None
    return build_classifier(list(rules))


def coverage_summary(
    conn: sqlite3.Connection, filt: AnalyticsFilter, rules: list[Rule] | None = None
) -> dict[str, object]:
    cov = queries.coverage(conn, filt, _classifier_for(filt, rules))
    return {
        "unique_events": cov["unique_events"],
        "observed_min": cov["observed_min"],
        "observed_max": cov["observed_max"],
        "sources": cov["sources"],
        "import_attempts": cov["import_attempts"],
        "imports": [
            {
                "import_id": i["import_id"],
                "status": i["status"],
                "error_summary": i["error_summary"],
            }
            for i in cov["imports"]  # type: ignore[union-attr]
        ],
    }


def _warnings(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    clf: Classifier | None,
    truncated: bool = False,
) -> list[str]:
    cov = queries.coverage(conn, filt, clf)
    notes = []
    for imp in cov["imports"]:  # type: ignore[union-attr]
        if imp["status"] == "running":
            notes.append(f"import {imp['import_id']} still running: data may be partial")
        elif imp["status"] == "failed":
            notes.append(
                f"import {imp['import_id']} failed: committed batches kept, resume to complete"
            )
        if imp["error_summary"] and "source_changed" in imp["error_summary"]:
            notes.append(f"import {imp['import_id']}: source changed during import")
    if truncated:
        notes.append("distinct-value scan hit its bound: rare values may be missing")
    return notes


def summarize(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    rules: list[Rule] | None = None,
    *,
    observation_time: datetime | None = None,
) -> dict[str, object]:
    """Totals, error shares, duration availability, coverage and quality."""
    clf = _classifier_for(filt, rules)
    counts = queries.summary_counts(conn, filt, clf)
    measured = _has_durations(conn, filt, clf)
    duration: dict[str, object] = (
        {"available": True, "measured": measured}
        if measured
        else {"available": False, "measured": 0, "reason": "combined_sources_have_no_timing"}
    )
    cov = queries.coverage(conn, filt, clf)
    observed = datetime.now(UTC) if observation_time is None else observation_time
    return {
        "site_id": filt.site_id,
        "time_range": _window_dict(filt),
        "generated_at": observed.isoformat(),
        "filters": _filter_dict(filt),
        "totals": counts,
        "status_distribution": queries.status_distribution(conn, filt, clf),
        "duration": duration,
        "coverage": {
            "unique_events": cov["unique_events"],
            "observed_min": cov["observed_min"],
            "observed_max": cov["observed_max"],
            "sources": cov["sources"],
        },
        "data_quality": {
            "import_attempts": cov["import_attempts"],
            "imports": [
                {
                    "import_id": i["import_id"],
                    "status": i["status"],
                    "error_summary": i["error_summary"],
                }
                for i in cov["imports"]  # type: ignore[union-attr]
            ],
        },
        "warnings": _warnings(conn, filt, clf),
        "limitations": LIMITATIONS_LOGS,
    }


def _has_durations(conn: sqlite3.Connection, filt: AnalyticsFilter, clf: Classifier | None) -> int:
    return queries.count_measured_durations(conn, filt, clf)


def timeseries(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    bucket: BucketSize,
    rules: list[Rule] | None = None,
) -> dict[str, object]:
    """UTC buckets across the whole window, including empty buckets."""
    clf = _classifier_for(filt, rules)
    return {
        "site_id": filt.site_id,
        "time_range": _window_dict(filt),
        "bucket": bucket,
        "buckets": queries.time_buckets(conn, filt, bucket, clf),
        "coverage": coverage_summary(conn, filt, rules),
    }


def top_paths(
    conn: sqlite3.Connection, query: TopPathsQuery, rules: list[Rule] | None = None
) -> dict[str, object]:
    clf = _classifier_for(query.filt, rules)
    items, total = queries.top_paths(conn, query, clf)
    return {
        "items": items,
        "total_groups": total,
        "limit": query.filt.limit,
        "offset": query.filt.offset,
        "coverage": coverage_summary(conn, query.filt, rules),
    }


def top_referrers(
    conn: sqlite3.Connection, query: TopReferrersQuery, rules: list[Rule] | None = None
) -> dict[str, object]:
    clf = _classifier_for(query.filt, rules)
    items, total = queries.top_referrers(conn, query, clf)
    return {
        "items": items,
        "total_groups": total,
        "limit": query.filt.limit,
        "offset": query.filt.offset,
        "coverage": coverage_summary(conn, query.filt, rules),
    }


def crawler_claims(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    rules: list[Rule],
    *,
    observation_time: datetime | None = None,
) -> list[Finding]:
    """Claimed crawler activity per bot rule; claims, never verified identities.

    Counts are exact GROUP BY results over the ordered match expression,
    so they stay correct beyond any distinct-agent bound: no distinct-UA
    sampling is used for totals. Agent evidence stays a bounded,
    explicitly counted sample.
    """
    observed = datetime.now(UTC) if observation_time is None else observation_time
    clf = _classifier_for(filt, rules)
    assert clf is not None
    rows = {row["index"]: row for row in queries.bot_index_rows(conn, filt, clf)}
    coverage = coverage_summary(conn, filt, rules)
    findings = []
    for index, rule in enumerate(clf.rules):
        stats = rows.get(index)
        if stats is None or stats["requests"] == 0:
            continue
        sample = queries.bot_sample_agents(conn, filt, clf, index, limit=10)
        findings.append(
            Finding(
                rule_id=rule.id,
                rule_version=rule.version,
                category=rule.category,
                title=rule.title,
                severity=rule.severity,
                meaning=rule.meaning,
                window=_window_dict(filt),
                filters=_filter_dict(filt),
                observation_time=observed.isoformat(),
                counts={
                    "requests": int(stats["requests"]),
                    "distinct_agents": int(stats["distinct_agents"]),
                },
                evidence={
                    "agents": sample,
                    "agents_shown": len(sample),
                    "agents_total": int(stats["distinct_agents"]),
                },
                coverage_summary=coverage,
                limitations=[*LIMITATIONS_BOT, *LIMITATIONS_LOGS],
            )
        )
    return sorted(findings, key=lambda f: (-f.counts["requests"], f.rule_id))


def crawler_details(
    conn: sqlite3.Connection, filt: AnalyticsFilter, rules: list[Rule]
) -> list[dict[str, object]]:
    """Per-family crawler evidence for the dashboard/API read path.

    Built from the same exact per-index aggregates and versioned rules as
    :func:`crawler_claims`; agent sets stay server-side. Families are
    claimed bot matches, never verified identities. ``*_truncated`` flags
    stay for template compatibility and are always False: nothing is
    sampled for totals anymore.
    """
    clf = _classifier_for(filt, rules)
    assert clf is not None
    rows = {row["index"]: row for row in queries.bot_index_rows(conn, filt, clf)}
    details: list[dict[str, object]] = []
    for index, rule in enumerate(clf.rules):
        stats = rows.get(index)
        if stats is None or stats["requests"] == 0:
            continue
        sample = queries.bot_sample_agents(conn, filt, clf, index, limit=10)
        top_paths = queries.bot_top_paths(conn, filt, clf, index, limit=10)
        not_found = queries.bot_top_paths(conn, filt, clf, index, status=404, limit=10)
        details.append(
            {
                "rule_id": rule.id,
                "rule_version": rule.version,
                "category": rule.category,
                "title": rule.title,
                "severity": rule.severity,
                "meaning": rule.meaning,
                "requests": int(stats["requests"]),
                "distinct_agents": int(stats["distinct_agents"]),
                "agents_truncated": False,
                "agents_shown": len(sample),
                "agents_total": int(stats["distinct_agents"]),
                "top_agents": [entry["user_agent"] for entry in sample],
                "top_paths": top_paths,
                "not_found": not_found,
                "paths_truncated": False,
                "paths_agent_cap": None,
                "limitations": [*LIMITATIONS_BOT, *LIMITATIONS_LOGS],
            }
        )
    details.sort(key=lambda item: (-int(item["requests"]), str(item["rule_id"])))
    return details


def security_findings(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    rules: list[Rule],
    *,
    observation_time: datetime | None = None,
) -> list[Finding]:
    """Deterministic security investigation candidates with rule references."""
    observed = datetime.now(UTC) if observation_time is None else observation_time
    clf = _classifier_for(filt, rules)
    coverage = coverage_summary(conn, filt, rules)
    findings: list[Finding] = []
    path_rows, paths_truncated = queries.distinct_paths(conn, filt, clf)
    for rule in rules:
        if rule.path_contains:
            matched = [(p, c, e) for p, c, e in path_rows if rule.matches_path(p)]
            if matched:
                total = sum(c for _, c, _ in matched)
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_version=rule.version,
                        category=rule.category,
                        title=rule.title,
                        severity=rule.severity,
                        meaning=rule.meaning,
                        window=_window_dict(filt),
                        filters=_filter_dict(filt),
                        observation_time=observed.isoformat(),
                        counts={"requests": total, "distinct_paths": len(matched)},
                        evidence={
                            "paths": [
                                {"path": p, "requests": c, "errors": e} for p, c, e in matched[:20]
                            ],
                            "paths_shown": min(20, len(matched)),
                            "paths_total": len(matched),
                        },
                        coverage_summary=coverage,
                        limitations=[*LIMITATIONS_SECURITY, *LIMITATIONS_LOGS],
                    )
                )
        if rule.min_client_errors is not None:
            for candidate in queries.repeated_client_errors(
                conn, filt, min_errors=rule.min_client_errors, classifier=clf
            ):
                sample_paths = queries.sample_paths_for_client(
                    conn,
                    filt,
                    client_pseudonym=str(candidate["client_pseudonym"]),
                    classifier=clf,
                )
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_version=rule.version,
                        category=rule.category,
                        title=rule.title,
                        severity=rule.severity,
                        meaning=rule.meaning,
                        window=_window_dict(filt),
                        filters=_filter_dict(filt),
                        observation_time=observed.isoformat(),
                        counts={
                            "errors": candidate["errors"],
                            "distinct_paths": candidate["paths"],
                        },
                        evidence={
                            "client_pseudonym": candidate["client_pseudonym"],
                            "sample_paths": sample_paths,
                            "sample_paths_shown": len(sample_paths),
                            "sample_paths_total": candidate["paths"],
                        },
                        coverage_summary=coverage,
                        limitations=[*LIMITATIONS_SECURITY, *LIMITATIONS_LOGS],
                    )
                )
    if paths_truncated:
        findings.append(
            Finding(
                rule_id="scan-truncated",
                rule_version=1,
                category="unknown",
                title="Path scan hit its bound",
                severity="info",
                meaning="distinct-value scan truncated; rare paths may be missing",
                window=_window_dict(filt),
                filters=_filter_dict(filt),
                observation_time=observed.isoformat(),
                counts={"requests": 0, "distinct_paths": 0},
                evidence={},
                coverage_summary=coverage,
                limitations=[*LIMITATIONS_SECURITY],
            )
        )
    return sorted(
        findings,
        key=lambda f: (-(f.counts.get("requests", 0) + f.counts.get("errors", 0)), f.rule_id),
    )


#: All traffic buckets in stable order; missing buckets are zero-filled so
#: totals sum exactly and dashboards never branch on absent keys.
TRAFFIC_BUCKETS = ("all", "browser_like", "claimed_bot", "other_automation", "unknown")


def traffic_breakdown(
    conn: sqlite3.Connection, filt: AnalyticsFilter, rules: list[Rule]
) -> dict[str, object]:
    """Exact per-traffic totals under the active filters, zero-filled."""
    clf = _classifier_for(filt, rules)
    assert clf is not None
    rows = {row["traffic"]: row for row in queries.traffic_breakdown(conn, filt, clf)}
    buckets = []
    for bucket in TRAFFIC_BUCKETS[1:]:
        row = rows.get(bucket)
        buckets.append(
            {
                "traffic": bucket,
                "requests": int(row["requests"]) if row else 0,
                "errors_4xx": int(row["errors_4xx"]) if row else 0,
                "errors_5xx": int(row["errors_5xx"]) if row else 0,
                "bytes_total": int(row["bytes_total"]) if row else 0,
            }
        )
    return {
        "site_id": filt.site_id,
        "time_range": _window_dict(filt),
        "filters": _filter_dict(filt),
        "buckets": buckets,
        "coverage": coverage_summary(conn, filt, rules),
        "limitations": [*LIMITATIONS_BOT, *LIMITATIONS_LOGS],
    }


_BOT_TABLE_ORDER = {
    "requests_desc": lambda e: (-e["requests"], e["rule_id"]),
    "name_asc": lambda e: (e["title"].lower(), e["rule_id"]),
    "category_asc": lambda e: (e["category"], e["rule_id"]),
    "errors_desc": lambda e: (-(e["errors_4xx"] + e["errors_5xx"]), -e["requests"], e["rule_id"]),
    "bytes_desc": lambda e: (-e["bytes_total"], -e["requests"], e["rule_id"]),
}


def error_groups(
    conn: sqlite3.Connection, filt: AnalyticsFilter, rules: list[Rule] | None = None
) -> dict[str, object]:
    """Error groups by path/status with referrer breadth, under filters."""
    clf = _classifier_for(filt, rules)
    items, total = queries.error_groups(conn, filt, clf)
    return {
        "items": items,
        "total_groups": total,
        "limit": filt.limit,
        "offset": filt.offset,
        "coverage": coverage_summary(conn, filt, rules),
    }


def bot_table(
    conn: sqlite3.Connection, query: BotTableQuery, rules: list[Rule]
) -> dict[str, object]:
    """Named-bot table: exact per-rule aggregates, allowlisted sort, paging."""
    filt = query.filt
    clf = _classifier_for(filt, rules)
    assert clf is not None
    rows = {row["index"]: row for row in queries.bot_index_rows(conn, filt, clf)}
    entries = []
    for index, rule in enumerate(clf.rules):
        stats = rows.get(index)
        if stats is None or stats["requests"] == 0:
            continue
        entries.append(
            {
                "rule_id": rule.id,
                "rule_version": rule.version,
                "category": rule.category,
                "title": rule.title,
                "meaning": rule.meaning,
                "provider": rule.provider,
                "purpose": rule.purpose,
                "traffic": clf.traffic[index],
                "requests": int(stats["requests"]),
                "errors_4xx": int(stats["errors_4xx"]),
                "errors_5xx": int(stats["errors_5xx"]),
                "bytes_total": int(stats["bytes_total"]),
                "distinct_agents": int(stats["distinct_agents"]),
                "distinct_paths": int(stats["distinct_paths"]),
            }
        )
    entries.sort(key=_BOT_TABLE_ORDER[query.sort])
    total = len(entries)
    page = entries[filt.offset : filt.offset + filt.limit]
    return {
        "site_id": filt.site_id,
        "time_range": _window_dict(filt),
        "filters": _filter_dict(filt),
        "sort": query.sort,
        "items": page,
        "total_rules": total,
        "limit": filt.limit,
        "offset": filt.offset,
        "coverage": coverage_summary(conn, filt, rules),
        "limitations": [*LIMITATIONS_BOT, *LIMITATIONS_LOGS],
    }


def bot_detail(
    conn: sqlite3.Connection, filt: AnalyticsFilter, rules: list[Rule], rule_id: str
) -> dict[str, object]:
    """One named bot: exact totals, top paths/404s, robots/sitemap, samples.

    Raises ``KeyError`` for an unknown rule id or a rule with no rows in
    scope (callers map to 404) and ``ValueError`` for contradictory
    selectors (callers map to 400). A path rule id never overrides an
    active named-bot filter: conflicting selectors reject instead of
    returning another bot's counts under this rule's metadata.
    """
    clf = _classifier_for(filt, rules)
    assert clf is not None
    if rule_id not in clf.rule_ids:
        raise KeyError(f"unknown bot: {rule_id}")
    if filt.bot is not None and filt.bot != rule_id:
        raise ValueError(f"path rule {rule_id} conflicts with bot selector {filt.bot}")
    index = clf.rule_ids.index(rule_id)
    rule = clf.rules[index]
    narrowed = filt.model_copy(update={"bot": rule_id, "limit": 100, "offset": 0})
    stats = queries.bot_rule_stats(conn, narrowed, clf, index)
    if stats["requests"] == 0:
        raise KeyError(f"bot has no rows in scope: {rule_id}")
    return {
        "rule_id": rule.id,
        "rule_version": rule.version,
        "category": rule.category,
        "title": rule.title,
        "meaning": rule.meaning,
        "provider": rule.provider,
        "purpose": rule.purpose,
        "traffic": clf.traffic[index],
        "filters": _filter_dict(filt),
        "window": _window_dict(filt),
        "counts": stats,
        "top_paths": queries.bot_top_paths(conn, narrowed, clf, index, limit=10),
        "not_found": queries.bot_top_paths(conn, narrowed, clf, index, status=404, limit=10),
        "robots_requests": queries.scoped_path_count(conn, narrowed, clf, path="/robots.txt"),
        "sitemap_requests": queries.scoped_path_count(conn, narrowed, clf, path_prefix="/sitemap"),
        "sample_agents": queries.bot_sample_agents(conn, narrowed, clf, index, limit=10),
        "coverage": coverage_summary(conn, filt, rules),
        "limitations": [*LIMITATIONS_BOT, *LIMITATIONS_LOGS],
    }


def request_explorer(
    conn: sqlite3.Connection, query: ExplorerQuery, rules: list[Rule]
) -> dict[str, object]:
    """Sanitized paginated request rows for the dashboard/API explorer."""
    clf = _classifier_for(query.filt, rules)
    assert clf is not None
    items, total = queries.request_rows(conn, query, clf)
    return {
        "site_id": query.filt.site_id,
        "time_range": _window_dict(query.filt),
        "filters": _filter_dict(query.filt),
        "sort": query.sort,
        "items": items,
        "total_rows": total,
        "limit": query.filt.limit,
        "offset": query.filt.offset,
        "coverage": coverage_summary(conn, query.filt, rules),
        "limitations": [*LIMITATIONS_BOT, *LIMITATIONS_LOGS],
    }


def resource_breakdown(
    conn: sqlite3.Connection, filt: AnalyticsFilter, rules: list[Rule] | None = None
) -> dict[str, object]:
    """Requests/errors/bytes by path-based resource kind (documented heuristic)."""
    clf = _classifier_for(filt, rules)
    return {
        "site_id": filt.site_id,
        "time_range": _window_dict(filt),
        "filters": _filter_dict(filt),
        "items": queries.resource_breakdown(conn, filt, clf),
        "coverage": coverage_summary(conn, filt, rules),
        "limitations": [*LIMITATIONS_LOGS],
    }


def browser_breakdown(
    conn: sqlite3.Connection, filt: AnalyticsFilter, rules: list[Rule]
) -> dict[str, object]:
    """Claimed browser family/OS shares over browser-like rows (claim labels)."""
    clf = _classifier_for(filt, rules)
    assert clf is not None
    parts = queries.browser_breakdown(conn, filt, clf)
    return {
        "site_id": filt.site_id,
        "time_range": _window_dict(filt),
        "filters": _filter_dict(filt),
        "families": parts["families"],
        "systems": parts["systems"],
        "coverage": coverage_summary(conn, filt, rules),
        "limitations": [
            "browser family and OS come from User-Agent heuristics on browser-like rows only",
            *LIMITATIONS_BOT,
            *LIMITATIONS_LOGS,
        ],
    }


def heatmap(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    rules: list[Rule] | None = None,
    *,
    tz_name: str = "UTC",
) -> dict[str, object]:
    """Weekday/hour request matrix for one display timezone.

    SQL aggregates per UTC hour; this function converts the bounded bucket
    list with zoneinfo. Genuine overlaps (e.g. the Europe/Berlin
    fall-back, where two UTC hours share one local date+hour) merge into
    one cell; ordinary repetition of a weekday across weeks never counts
    as a merge. Zones with a fractional-hour offset anywhere in the window
    are rejected: a UTC-hour bucket would straddle two local hours there.
    Raises ``ValueError`` for unknown or fractional-offset timezones.
    """
    try:
        tz = ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"unknown timezone: {tz_name}") from exc
    clf = _classifier_for(filt, rules)
    buckets = queries.heatmap_utc_hours(conn, filt, clf)
    matrix = [[0] * 24 for _ in range(7)]
    seen_local: dict[tuple[str, int], int] = {}
    for bucket in buckets:
        start = datetime.strptime(str(bucket["hour"]), "%Y-%m-%dT%H").replace(tzinfo=UTC)
        local = start.astimezone(tz)
        offset = local.utcoffset()
        if offset is None or offset % timedelta(hours=1) != timedelta(0):
            raise ValueError(f"fractional-offset timezone unsupported: {tz_name}")
        matrix[local.isoweekday() - 1][local.hour] += int(bucket["requests"])
        key = (local.date().isoformat(), local.hour)
        seen_local[key] = seen_local.get(key, 0) + 1
    dst_merges = sum(count - 1 for count in seen_local.values() if count > 1)
    return {
        "site_id": filt.site_id,
        "time_range": _window_dict(filt),
        "filters": _filter_dict(filt),
        "timezone": tz_name,
        "matrix": matrix,
        "utc_buckets": len(buckets),
        "dst_merges": dst_merges,
        "coverage": coverage_summary(conn, filt, rules),
        "limitations": [
            "local date+hour cells merge repeated UTC hours across DST transitions; counts stay exact",
            *LIMITATIONS_LOGS,
        ],
    }


def client_top(
    conn: sqlite3.Connection, filt: AnalyticsFilter, rules: list[Rule] | None = None
) -> dict[str, object]:
    """Top pseudonymized clients with aggregates; addresses never exposed."""
    clf = _classifier_for(filt, rules)
    items, total = queries.client_top(conn, filt, clf)
    return {
        "site_id": filt.site_id,
        "time_range": _window_dict(filt),
        "filters": _filter_dict(filt),
        "items": items,
        "total_clients": total,
        "limit": filt.limit,
        "offset": filt.offset,
        "coverage": coverage_summary(conn, filt, rules),
        "limitations": [*LIMITATIONS_LOGS],
    }
