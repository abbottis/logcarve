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
from datetime import UTC, datetime

from app.analytics import queries
from app.analytics.contracts import AnalyticsFilter, BucketSize, TopPathsQuery, TopReferrersQuery
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
        "path_prefix": filt.path_prefix,
        "referer_host": filt.referer_host,
    }


def coverage_summary(conn: sqlite3.Connection, filt: AnalyticsFilter) -> dict[str, object]:
    cov = queries.coverage(conn, filt)
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
    conn: sqlite3.Connection, filt: AnalyticsFilter, truncated: bool = False
) -> list[str]:
    cov = queries.coverage(conn, filt)
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
    conn: sqlite3.Connection, filt: AnalyticsFilter, *, observation_time: datetime | None = None
) -> dict[str, object]:
    """Totals, error shares, duration availability, coverage and quality."""
    counts = queries.summary_counts(conn, filt)
    measured = _has_durations(conn, filt)
    duration: dict[str, object] = (
        {"available": True, "measured": measured}
        if measured
        else {"available": False, "measured": 0, "reason": "combined_sources_have_no_timing"}
    )
    cov = queries.coverage(conn, filt)
    observed = datetime.now(UTC) if observation_time is None else observation_time
    return {
        "site_id": filt.site_id,
        "time_range": _window_dict(filt),
        "generated_at": observed.isoformat(),
        "filters": _filter_dict(filt),
        "totals": counts,
        "status_distribution": queries.status_distribution(conn, filt),
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
        "warnings": _warnings(conn, filt),
        "limitations": LIMITATIONS_LOGS,
    }


def _has_durations(conn: sqlite3.Connection, filt: AnalyticsFilter) -> int:
    return queries.count_measured_durations(conn, filt)


def timeseries(
    conn: sqlite3.Connection, filt: AnalyticsFilter, bucket: BucketSize
) -> dict[str, object]:
    """UTC buckets across the whole window, including empty buckets."""
    return {
        "site_id": filt.site_id,
        "time_range": _window_dict(filt),
        "bucket": bucket,
        "buckets": queries.time_buckets(conn, filt, bucket),
        "coverage": coverage_summary(conn, filt),
    }


def top_paths(conn: sqlite3.Connection, query: TopPathsQuery) -> dict[str, object]:
    items, total = queries.top_paths(conn, query)
    return {
        "items": items,
        "total_groups": total,
        "limit": query.filt.limit,
        "offset": query.filt.offset,
        "coverage": coverage_summary(conn, query.filt),
    }


def top_referrers(conn: sqlite3.Connection, query: TopReferrersQuery) -> dict[str, object]:
    items, total = queries.top_referrers(conn, query)
    return {
        "items": items,
        "total_groups": total,
        "limit": query.filt.limit,
        "offset": query.filt.offset,
        "coverage": coverage_summary(conn, query.filt),
    }


def crawler_claims(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    rules: list[Rule],
    *,
    observation_time: datetime | None = None,
) -> list[Finding]:
    """Claimed crawler activity per bot rule; claims, never verified identities."""
    observed = datetime.now(UTC) if observation_time is None else observation_time
    pairs, truncated = queries.distinct_user_agents(conn, filt)
    coverage = coverage_summary(conn, filt)
    findings = []
    for rule in rules:
        if not rule.ua_contains:
            continue
        matched = [(ua, count) for ua, count in pairs if rule.matches_ua(ua)]
        if not matched:
            continue
        total = sum(count for _, count in matched)
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
                counts={"requests": total, "distinct_agents": len(matched)},
                evidence={
                    "agents": [
                        {"user_agent": ua[:200], "requests": count} for ua, count in matched[:10]
                    ],
                    "agents_shown": min(10, len(matched)),
                    "agents_total": len(matched),
                },
                coverage_summary=coverage,
                limitations=[*LIMITATIONS_BOT, *LIMITATIONS_LOGS],
            )
        )
    if truncated:
        findings.append(
            Finding(
                rule_id="scan-truncated",
                rule_version=1,
                category="unknown",
                title="Agent scan hit its bound",
                severity="info",
                meaning="distinct-value scan truncated; rare agents may be missing",
                window=_window_dict(filt),
                filters=_filter_dict(filt),
                observation_time=observed.isoformat(),
                counts={"requests": 0, "distinct_agents": 0},
                evidence={},
                coverage_summary=coverage,
                limitations=[*LIMITATIONS_BOT],
            )
        )
    return sorted(findings, key=lambda f: (-f.counts["requests"], f.rule_id))


def crawler_details(
    conn: sqlite3.Connection, filt: AnalyticsFilter, rules: list[Rule]
) -> list[dict[str, object]]:
    """Per-family crawler evidence for the dashboard/API read path.

    Built from the same bounded scan and versioned rules as
    :func:`crawler_claims`; agent sets stay server-side. Families are
    claimed bot matches, never verified identities.
    """
    agents, truncated = queries.distinct_user_agents(conn, filt)
    details: list[dict[str, object]] = []
    for rule in rules:
        if not rule.ua_contains:
            continue
        matched = [ua for ua, _ in agents if rule.matches_ua(ua)]
        if not matched:
            continue
        matched_set = set(matched)
        requests = sum(count for ua, count in agents if ua in matched_set)
        top_paths, paths_truncated = queries.paths_for_agents(conn, filt, matched, limit=10)
        not_found, _ = queries.paths_for_agents(conn, filt, matched, status=404, limit=10)
        details.append(
            {
                "rule_id": rule.id,
                "rule_version": rule.version,
                "category": rule.category,
                "title": rule.title,
                "severity": rule.severity,
                "meaning": rule.meaning,
                "requests": requests,
                "distinct_agents": len(matched),
                "agents_truncated": truncated,
                "agents_shown": min(10, len(matched)),
                "agents_total": len(matched),
                "top_agents": matched[:10],
                "top_paths": top_paths,
                "not_found": not_found,
                "paths_truncated": paths_truncated,
                "paths_agent_cap": queries.PATHS_FOR_AGENTS_CAP,
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
    coverage = coverage_summary(conn, filt)
    findings: list[Finding] = []
    path_rows, paths_truncated = queries.distinct_paths(conn, filt)
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
                conn, filt, min_errors=rule.min_client_errors
            ):
                sample_paths = queries.sample_paths_for_client(
                    conn, filt, client_pseudonym=str(candidate["client_pseudonym"])
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
