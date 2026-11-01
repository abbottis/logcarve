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

from app.analytics import conflict, queries
from app.analytics.classification import Classifier, build_classifier
from app.analytics.contracts import (
    AnalyticsFilter,
    BotTableQuery,
    BucketSize,
    ExplorerQuery,
    JourneyIdQuery,
    JourneyQuery,
    JourneyTimelineQuery,
    SlowEndpointsQuery,
    TimeWindow,
    TopPathsQuery,
    TopReferrersQuery,
)
from app.analytics.rules import Rule
from app.ingestion.combined import _REJECTION_REASONS

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


def _window_micros(filt: AnalyticsFilter) -> int:
    """Exact validated-window length in integer microseconds.

    Timedelta fields (never the lossy ``total_seconds()`` float) so
    sub-second windows keep every microsecond and multi-day windows
    lose nothing to float rounding. Callers derive display seconds
    as ``micros / 1_000_000`` and carry the integer alongside.
    """
    delta = filt.window.time_to - filt.window.time_from
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def _filter_dict(filt: AnalyticsFilter) -> dict[str, object]:
    return {
        "site_id": filt.site_id,
        "source_id": filt.source_id,
        "method": filt.method,
        "status": filt.status,
        "status_class": filt.status_class,
        "path_prefix": filt.path_prefix,
        "path_exact": filt.path_exact,
        "referer_host": filt.referer_host,
        "search": filt.search,
        "traffic": filt.traffic,
        "bot": filt.bot,
        "category": filt.category,
        "provider": filt.provider,
        "purpose": filt.purpose,
        "server_host": filt.server_host,
        "http_version": filt.http_version,
        "mime_type": filt.mime_type,
        "cache_status": filt.cache_status,
        "tls_protocol": filt.tls_protocol,
        "timing_available": filt.timing_available,
        "upstream_available": filt.upstream_available,
        "timing_min_ms": filt.timing_min_ms,
        "timing_max_ms": filt.timing_max_ms,
    }


def _needs_classifier(filt: AnalyticsFilter) -> bool:
    return (
        filt.traffic != "all"
        or filt.bot is not None
        or filt.category is not None
        or filt.provider is not None
        or filt.purpose is not None
    )


def classifier_for_filter(filt: AnalyticsFilter, rules: list[Rule] | None) -> Classifier | None:
    """Public read-only classifier for dashboard query composition."""
    return _classifier_for(filt, rules)


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
    measured = queries.count_measured_request_timing(conn, filt, clf)
    legacy = queries.count_measured_durations(conn, filt, clf)
    if measured:
        duration: dict[str, object] = {"available": True, "measured": measured}
        if legacy:
            duration["legacy_measured"] = legacy
    elif legacy:
        duration = {
            "available": False,
            "measured": 0,
            "reason": "legacy_duration_only:no_measured_request_timing",
            "legacy_measured": legacy,
        }
    else:
        duration = {
            "available": False,
            "measured": 0,
            "reason": "no_measured_request_timing",
        }
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
        narrowed = filt.model_copy(update={"bot": rule.id, "limit": 100, "offset": 0})
        details.append(
            {
                "rule_id": rule.id,
                "rule_version": rule.version,
                "category": rule.category,
                "title": rule.title,
                "severity": rule.severity,
                "meaning": rule.meaning,
                "provider": rule.provider,
                "purpose": rule.purpose,
                "traffic": clf.traffic[index],
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
                "robots_requests": queries.scoped_path_count(
                    conn, narrowed, clf, path="/robots.txt"
                ),
                "sitemap_requests": queries.scoped_path_count(
                    conn, narrowed, clf, path_prefix="/sitemap"
                ),
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
    """Deterministic security investigation candidates with rule references.

    Includes the conservative conflicting-bot-identity candidate when the
    selected scope contains one: exact all-row totals (no UA sampling
    cap) with a bounded, explicitly labelled agent sample. Every other
    rule counts ALL matching rows exactly in SQL no matter how many
    distinct paths exist; only samples are bounded, with
    shown/total/truncated fields. Tempo evidence carries the window
    as float ``window_seconds`` with the exact integer-microsecond
    ``window_seconds_us`` companion (sub-second windows keep a
    precise rate instead of a truncated 0/None). No DNS, HTTP,
    GeoIP, unmasking or bot removal is ever performed; absence of a
    candidate never proves the traffic genuine.
    """
    observed = datetime.now(UTC) if observation_time is None else observation_time
    clf = _classifier_for(filt, rules)
    coverage = coverage_summary(conn, filt, rules)
    findings: list[Finding] = []
    conflict_rule = next(
        (rule for rule in rules if rule.id == conflict.CONFLICT_RULE_ID),
        None,
    )
    if conflict_rule is not None:
        totals = queries.conflict_counts(conn, filt, clf)
        if totals["requests"] > 0:
            sample, agents_total = queries.conflict_sample_agents(conn, filt, clf, limit=10)
            findings.append(
                Finding(
                    rule_id=conflict_rule.id,
                    rule_version=conflict_rule.version,
                    category=conflict_rule.category,
                    title=conflict_rule.title,
                    severity=conflict_rule.severity,
                    meaning=conflict_rule.meaning,
                    window=_window_dict(filt),
                    filters=_filter_dict(filt),
                    observation_time=observed.isoformat(),
                    counts={
                        "requests": totals["requests"],
                        "distinct_agents": totals["distinct_agents"],
                    },
                    evidence={
                        "agents": sample,
                        "agents_shown": len(sample),
                        "agents_total": agents_total,
                    },
                    coverage_summary=coverage,
                    limitations=[*LIMITATIONS_SECURITY, *LIMITATIONS_BOT, *LIMITATIONS_LOGS],
                )
            )
    for rule in rules:
        if rule.conflicting_identities:
            continue
        has_threshold = (
            rule.min_client_errors is not None
            or rule.min_client_requests is not None
            or rule.min_client_distinct_paths is not None
        )
        if has_threshold:
            offenders, offenders_total = queries.security_offenders(conn, filt, rule, clf)
            truncated = offenders_total > len(offenders)
            # Precise positive denominator: float seconds for the rate
            # plus the exact integer-microsecond companion (a sub-second
            # window no longer truncates to 0 with a None rate).
            window_us = _window_micros(filt)
            window_seconds = window_us / 1_000_000
            for offender in offenders:
                # The legacy 4xx rule keeps its exact historic shape:
                # every counted row is a stored 4xx, so the count reads
                # ``errors``; narrowed rate rules count ``requests``.
                if rule.min_client_errors is not None:
                    counts = {
                        "errors": offender["hits"],
                        "distinct_paths": offender["distinct_paths"],
                    }
                    avg_numerator = "stored 4xx errors"
                else:
                    counts = {
                        "requests": offender["hits"],
                        "distinct_paths": offender["distinct_paths"],
                    }
                    avg_numerator = "rule-matching requests"
                sample_total = offender["sample_groups_total"]
                assert isinstance(sample_total, int)
                sequence = offender["path_sequence"]
                assert isinstance(sequence, list)
                sequence_total = offender["path_sequence_total"]
                assert isinstance(sequence_total, int)
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
                        counts=counts,
                        evidence={
                            "client_pseudonym": offender["client_pseudonym"],
                            "sample_paths": offender["sample_paths"],
                            "sample_paths_shown": len(offender["sample_paths"]),
                            # Exact (path, status) groups in the
                            # sample scope — never the distinct-path
                            # count, which understates groups once one
                            # path carries several statuses.
                            "sample_paths_total": sample_total,
                            "sample_paths_truncated": sample_total > len(offender["sample_paths"]),
                            "sample_distinct_paths": offender["sample_distinct_paths"],
                            "sample_scope_requests": offender["sample_scope_requests"],
                            "offenders_shown": len(offenders),
                            "offenders_total": offenders_total,
                            "offenders_truncated": truncated,
                            # Honest tempo: a cumulative average over
                            # the explicit window plus the peak
                            # whole-UTC-minute burst. The average
                            # spreads every counted row; only the
                            # peak shows concentration.
                            "window_seconds": window_seconds,
                            "window_seconds_us": window_us,
                            "avg_requests_per_minute": offender["hits"] / window_seconds * 60.0
                            if window_seconds
                            else None,
                            "avg_numerator": avg_numerator,
                            "peak_minute_requests": offender["peak_minute_requests"],
                            "peak_minute": offender["peak_minute"],
                            "peak_minute_scope": offender["peak_minute_scope"],
                            "peak_minute_numerator": offender["peak_minute_numerator"],
                            "peak_minute_interval": offender["peak_minute_interval"],
                            "peak_minute_partial": offender["peak_minute_partial"],
                            "tempo_note": (
                                "average spreads the full validated window; "
                                "window_seconds is float seconds (exact "
                                "window_seconds_us alongside) so sub-second "
                                "windows keep a precise rate; "
                                "peak counts the busiest whole UTC minute "
                                "(fractional rows fall into their truncated "
                                "minute) over the SAME rule-matching numerator "
                                "(peak_minute_scope/numerator); the historic "
                                "all-status path/sequence context is separate "
                                "and never compared as identical traffic; a "
                                "partial edge bucket is a lower-bound count "
                                "over peak_minute_interval"
                            ),
                            # Bounded chronological evidence: the first
                            # ordered (ts, path, status) rows with
                            # exact inter-row gaps; totals stay exact.
                            "path_sequence": sequence,
                            "path_sequence_shown": len(sequence),
                            "path_sequence_total": sequence_total,
                            "path_sequence_truncated": sequence_total > len(sequence),
                            "sequence_note": (
                                "chronological sample ordered by stored UTC "
                                "instant then row id (ties keep id order); "
                                "gap_prev_s is whole seconds floored from "
                                "exact epoch microseconds; the sample scope "
                                "matches sample_paths (rule-narrowed, or "
                                "all-status for the legacy 4xx rule)"
                            ),
                        },
                        coverage_summary=coverage,
                        limitations=[*LIMITATIONS_SECURITY, *LIMITATIONS_LOGS],
                    )
                )
        elif rule.path_contains or rule.status_in:
            totals = queries.security_rule_totals(conn, filt, rule, clf)
            if totals["requests"] == 0:
                continue
            sample, groups_total = queries.security_rule_sample(conn, filt, rule, clf)
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
                        "requests": totals["requests"],
                        "distinct_paths": totals["distinct_paths"],
                    },
                    evidence={
                        "paths": sample,
                        "paths_shown": len(sample),
                        "paths_total": groups_total,
                        "paths_truncated": groups_total > len(sample),
                    },
                    coverage_summary=coverage,
                    limitations=[*LIMITATIONS_SECURITY, *LIMITATIONS_LOGS],
                )
            )
    return sorted(
        findings,
        key=lambda f: (-(f.counts.get("requests", 0) + f.counts.get("errors", 0)), f.rule_id),
    )


LIMITATIONS_JOURNEYS = [
    (
        "request journeys are technical groupings of stored requests by HMAC client pseudonym "
        "and sanitized User-Agent with a 30-minute inactivity split: never visitors, people, "
        "browser sessions or clicks"
    ),
    "a gap of exactly 1800 seconds continues a journey; only a strictly longer gap starts a new one",
    (
        "filters hide rows but never invent journey starts: boundaries come from the unfiltered "
        "site/source event stream"
    ),
    (
        "window edges are asymmetric: a first-of-key journey is partial only when "
        "start - window_from < 1800s, but a last-of-key journey is partial when "
        "window_to - end <= 1800s (an unseen event exactly on the excluded edge "
        "would still continue it); flagged partial, never resolved by reading "
        "outside the authorized window"
    ),
]


def journeys(
    conn: sqlite3.Connection,
    query: JourneyQuery,
    rules: list[Rule] | None = None,
    *,
    observation_time: datetime | None = None,
) -> dict[str, object]:
    """Paginated technical request journeys (never visitors or sessions).

    Grouping key is the HMAC client pseudonym plus the sanitized
    User-Agent (a UA change starts a new key, never a continuation);
    boundaries derive from the authorized site/source event stream
    BEFORE the caller's content matchers. Each row carries the
    unfiltered total with the filtered shown count, a stable journey
    ID, the base-scope entry path and explicit edge flags.
    """
    clf = _classifier_for(query.filt, rules)
    observed = datetime.now(UTC) if observation_time is None else observation_time
    items, total = queries.journey_list(conn, query, clf)
    return {
        "site_id": query.filt.site_id,
        "time_range": _window_dict(query.filt),
        "generated_at": observed.isoformat(),
        "filters": _filter_dict(query.filt),
        "gap_definition": (
            f"new journey when the gap to the previous event of the same "
            f"(client pseudonym, sanitized User-Agent) key strictly exceeds "
            f"{queries.JOURNEY_GAP_SECONDS} seconds; exactly "
            f"{queries.JOURNEY_GAP_SECONDS} seconds continues the journey"
        ),
        "sort": query.sort,
        "min_requests": query.min_requests,
        "items": items,
        "total_groups": total,
        "limit": query.filt.limit,
        "offset": query.filt.offset,
        "coverage": coverage_summary(conn, query.filt, rules),
        "limitations": [*LIMITATIONS_JOURNEYS, *LIMITATIONS_LOGS],
    }


def journey_timeline(
    conn: sqlite3.Connection,
    query: JourneyTimelineQuery,
    rules: list[Rule] | None = None,
) -> dict[str, object]:
    """Bounded chronological timeline for one journey key.

    Raises ``KeyError`` for an unknown journey and ``ValueError`` for
    contradictory selectors (via the shared classifier). No plaintext
    address or tracking cookie is exposed; agents render truncated at
    200 characters with an explicit flag.
    """
    clf = _classifier_for(query.filt, rules)
    result = queries.journey_timeline(conn, query, clf)
    return {
        "site_id": query.filt.site_id,
        "time_range": _window_dict(query.filt),
        "filters": _filter_dict(query.filt),
        **result,
        "coverage": coverage_summary(conn, query.filt, rules),
        "limitations": [*LIMITATIONS_JOURNEYS, *LIMITATIONS_LOGS],
    }


def journey_timeline_by_id(
    conn: sqlite3.Connection,
    query: JourneyIdQuery,
    rules: list[Rule] | None = None,
) -> dict[str, object]:
    """Bounded timeline for one opaque journey ID listed by :func:`journeys`.

    Resolves the grouping key strictly inside the validated
    site/source/window scope — callers pass the listed
    ``client_pseudonym``/``started_at``/``journey_id`` and never guess
    a full User-Agent from a truncated display field. Raises
    ``KeyError`` for an ID with no exact in-scope match.
    """
    clf = _classifier_for(query.filt, rules)
    result = queries.journey_timeline_by_id(
        conn,
        query.filt,
        client_pseudonym=query.client_pseudonym,
        journey_start=query.journey_start,
        journey_id=query.journey_id,
        classifier=clf,
    )
    return {
        "site_id": query.filt.site_id,
        "time_range": _window_dict(query.filt),
        "filters": _filter_dict(query.filt),
        **result,
        "resolved_via": "journey_id",
        "coverage": coverage_summary(conn, query.filt, rules),
        "limitations": [*LIMITATIONS_JOURNEYS, *LIMITATIONS_LOGS],
    }


def journey_entry_paths(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    rules: list[Rule] | None = None,
    *,
    min_requests: int = 1,
    observation_time: datetime | None = None,
) -> dict[str, object]:
    """Entry-path aggregation from eligible complete/partial journeys.

    The entry is each journey's base-scope first request, so filters
    cannot move entries. Complete and window-edge partial journeys
    aggregate together with both shares reported; the partial share
    carries the outside-window caveat, never a confident total.
    """
    clf = _classifier_for(filt, rules)
    observed = datetime.now(UTC) if observation_time is None else observation_time
    items, total = queries.journey_entry_paths(conn, filt, clf, min_requests=min_requests)
    return {
        "site_id": filt.site_id,
        "time_range": _window_dict(filt),
        "generated_at": observed.isoformat(),
        "filters": _filter_dict(filt),
        "min_requests": min_requests,
        "items": items,
        "total_groups": total,
        "limit": filt.limit,
        "offset": filt.offset,
        "partial_caveat": (
            "partial journeys may start or end outside the window: their entry "
            "is the first observed request, not proven to be the true first"
        ),
        "coverage": coverage_summary(conn, filt, rules),
        "limitations": [*LIMITATIONS_JOURNEYS, *LIMITATIONS_LOGS],
    }


EXPORT_SCHEMA_VERSION = "export/1"

#: Explicit privacy label carried by every full-result export (and its
#: CSV headers): stable HMAC pseudonyms only — never original IPs, raw
#: lines, query values, keys, exception text or stored diagnostics,
#: even when an admin display mode is full.
EXPORT_PRIVACY_LABEL = (
    "pseudonymized: stable HMAC client pseudonyms only; "
    "no original client IPs, raw log lines, query values, keys, "
    "exception text or stored diagnostics"
)


def export_metadata(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    rules: list[Rule] | None = None,
    *,
    row_count: int,
    sort: str = "oldest",
    display_timezone: str = "UTC",
    observation_time: datetime | None = None,
) -> dict[str, object]:
    """Metadata envelope for a full-result CSV/JSON export.

    Carries schema/version, site/source scope, the full validated
    filter set, UTC window, display timezone, selected sort,
    generation time, exact row count, coverage and import quality
    WITHOUT any free-text diagnostics (only import ``id``/``status``
    travel — never ``error_summary``), plus the explicit privacy
    label. Rows stay UTC; ``display_timezone`` records only the
    validated display zone the caller selected, and ``sort`` the
    allowlisted row order. The row payload itself comes from the
    allowlisted :data:`queries.EXPORT_COLUMNS` under the SAME read
    snapshot. No paging limit/offset leaks in: exports always cover
    the full filtered result.
    """
    clf = _classifier_for(filt, rules)
    observed = datetime.now(UTC) if observation_time is None else observation_time
    cov = queries.coverage(conn, filt, clf)
    attempts = cov["import_attempts"]
    assert isinstance(attempts, dict)
    imports = cov["imports"]
    assert isinstance(imports, list)
    return {
        "schema_version": EXPORT_SCHEMA_VERSION,
        "site_id": filt.site_id,
        "source_id": filt.source_id,
        "time_range": _window_dict(filt),
        "display_timezone": display_timezone,
        "sort": sort,
        "generated_at": observed.isoformat(),
        "filters": _filter_dict(filt),
        "row_count": row_count,
        "coverage": {
            "unique_events": cov["unique_events"],
            "observed_min": cov["observed_min"],
            "observed_max": cov["observed_max"],
            "sources": cov["sources"],
        },
        "data_quality": {
            "line_totals": {
                "lines_total": attempts["lines_total"],
                "lines_accepted": attempts["lines_accepted"],
                "lines_rejected": attempts["lines_rejected"],
                "records_replayed": attempts["records_replayed"],
            },
            "imports": [
                {"import_id": imp["import_id"], "status": imp["status"]}
                for imp in imports  # type: ignore[union-attr]
            ],
        },
        "privacy": EXPORT_PRIVACY_LABEL,
        "limitations": LIMITATIONS_LOGS,
    }


def rejected_lines(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    rules: list[Rule] | None = None,
    *,
    observation_time: datetime | None = None,
) -> dict[str, object]:
    """Line-level rejected accounting, explicitly NOT event findings.

    Rejected source lines never became stored events, so they can
    never appear as findings, paths, clients or evidence rows. This
    report carries only per-import line totals plus the allowlisted
    pre-discard reason-code vocabulary (codes only, never raw bytes,
    addresses or query values). Origin-observed malformed requests
    (stored status 400) stay event-level under the security rules;
    parser-rejected lines stay here.
    """
    clf = _classifier_for(filt, rules)
    observed = datetime.now(UTC) if observation_time is None else observation_time
    cov = queries.coverage(conn, filt, clf)
    attempts = cov["import_attempts"]
    assert isinstance(attempts, dict)
    return {
        "site_id": filt.site_id,
        "time_range": _window_dict(filt),
        "generated_at": observed.isoformat(),
        "filters": _filter_dict(filt),
        "line_totals": {
            "lines_total": attempts["lines_total"],
            "lines_accepted": attempts["lines_accepted"],
            "lines_rejected": attempts["lines_rejected"],
            "records_replayed": attempts["records_replayed"],
        },
        "imports": [
            {
                "import_id": imp["import_id"],
                "status": imp["status"],
                "lines_total": imp["lines_total"],
                "lines_accepted": imp["lines_accepted"],
                "lines_rejected": imp["lines_rejected"],
                "error_summary": imp["error_summary"],
            }
            for imp in cov["imports"]  # type: ignore[union-attr]
        ],
        "reason_codes": sorted(_REJECTION_REASONS),
        "line_vs_event": (
            "rejected lines are source bytes the parser refused before any "
            "event existed: they are counted here at line level only and "
            "never described as persisted events, paths, clients or evidence"
        ),
        "coverage": coverage_summary(conn, filt, rules),
        "limitations": [*LIMITATIONS_SECURITY, *LIMITATIONS_LOGS],
    }


def previous_window_filter(filt: AnalyticsFilter) -> AnalyticsFilter:
    """Immediately preceding equal-length window, same scope/selectors.

    Only the window slides back by exactly its own duration; every
    other selector (site, source, matchers) is preserved so the
    comparison never widens the authorized scope.

    NOTE: this helper is for the EXPLICIT deterministic API/UI
    comparison, where the caller supplies and authorizes both
    windows. The model assistant must NOT use it: an untrusted
    model report selector would otherwise read outside the trusted
    investigation interval. Model comparison uses
    :func:`split_trusted_window_filter` (both halves inside the
    selected window) instead.
    """
    duration = filt.window.time_to - filt.window.time_from
    return filt.model_copy(
        update={
            "window": TimeWindow(
                time_from=filt.window.time_from - duration,
                time_to=filt.window.time_from,
            ),
            "limit": 1,
            "offset": 0,
        }
    )


def split_trusted_window_filter(
    filt: AnalyticsFilter,
) -> tuple[AnalyticsFilter, AnalyticsFilter]:
    """Split the selected trusted window into equal inside halves.

    Returns ``(current, previous)`` where ``previous`` is the first
    half ``[time_from, mid)`` and ``current`` is the second half
    ``[mid, time_to)`` with ``mid = time_from + duration / 2``. Both
    halves stay strictly inside the selected trusted interval, so a
    model-selected ``comparison`` report never reads outside it. All
    other selectors (site, source, matchers) and paging are preserved
    on both sides so the comparison never widens or narrows the
    authorized population. The total window must span a positive even
    number of microseconds (real investigation windows do); anything
    else raises ``ValueError`` and the tool fails closed.
    """
    total_us = _window_micros(filt)
    if total_us < 2 or total_us % 2 != 0:
        raise ValueError("trusted window cannot be split into equal halves")
    half = timedelta(microseconds=total_us // 2)
    mid = filt.window.time_from + half
    previous = filt.model_copy(
        update={"window": TimeWindow(time_from=filt.window.time_from, time_to=mid)}
    )
    current = filt.model_copy(
        update={"window": TimeWindow(time_from=mid, time_to=filt.window.time_to)}
    )
    return current, previous


def _comparison_metric(
    name: str,
    current: int | float,  # noqa: PYI041 - int must survive for Pydantic/JSON exactness
    previous: int | float,  # noqa: PYI041 - int must survive for Pydantic/JSON exactness
    *,
    coverage_ok: bool,
    current_empty: bool,
    previous_empty: bool,
) -> dict[str, object]:
    """One current-vs-previous metric with honest ratio handling.

    Raw integer counts (and their absolute change, computed in
    integer arithmetic when both sides are integers) stay exact end
    to end — never through a lossy ``float`` — so SQLite int64
    values above 2**53 survive. Ratios need observed coverage on
    BOTH sides: a
    limited import state, an empty current window, or two empty
    windows all yield ``insufficient_coverage`` (an empty current
    window is never a confident -100%). Only a covered nonempty
    current window against a covered zero baseline yields
    ``zero_baseline`` (exact change, ratio unavailable, never
    infinite).
    """
    change: int | float = current - previous
    if not coverage_ok:
        return {
            "name": name,
            "current": current,
            "previous": previous,
            "absolute_change": change,
            "ratio": None,
            "percent": None,
            "ratio_status": "insufficient_coverage",
            "note": "coverage is limited (running/failed imports): no confident ratio",
        }
    if current_empty or previous_empty:
        if not current_empty and previous == 0:
            return {
                "name": name,
                "current": current,
                "previous": previous,
                "absolute_change": change,
                "ratio": None,
                "percent": None,
                "ratio_status": "zero_baseline",
                "note": "baseline is zero: change is exact, ratio is unavailable (never infinite)",
            }
        if current_empty and not previous_empty:
            note = "current window holds no observed requests: no confident ratio"
        elif previous_empty and not current_empty:
            note = "baseline window holds no observed requests: no confident ratio"
        else:
            note = "neither window holds observed requests: no confident ratio"
        return {
            "name": name,
            "current": current,
            "previous": previous,
            "absolute_change": change,
            "ratio": None,
            "percent": None,
            "ratio_status": "insufficient_coverage",
            "note": note,
        }
    if previous == 0:
        return {
            "name": name,
            "current": current,
            "previous": previous,
            "absolute_change": change,
            "ratio": None,
            "percent": None,
            "ratio_status": "zero_baseline",
            "note": "baseline is zero: change is exact, ratio is unavailable (never infinite)",
        }
    ratio = current / previous
    return {
        "name": name,
        "current": current,
        "previous": previous,
        "absolute_change": change,
        "ratio": ratio,
        "percent": (ratio - 1.0) * 100.0,
        "ratio_status": "ok",
        "note": "",
    }


#: Selector fields that must match between comparison windows. Only
#: the validated windows and paging (limit/offset) may differ; any
#: other mismatch (method, status, metadata, traffic/bot selectors)
#: raises instead of comparing different populations silently.
_COMPARISON_SELECTORS = (
    "method",
    "status",
    "status_class",
    "path_prefix",
    "path_exact",
    "referer_host",
    "search",
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
)


def _comparison_selectors(filt: AnalyticsFilter) -> dict[str, object]:
    return {name: getattr(filt, name) for name in _COMPARISON_SELECTORS}


def compare_windows(
    conn: sqlite3.Connection,
    current: AnalyticsFilter,
    previous: AnalyticsFilter,
    rules: list[Rule] | None = None,
    *,
    observation_time: datetime | None = None,
) -> dict[str, object]:
    """Current-vs-explicit/previous equal-length window comparison.

    Both filters must share site and source scope, span exactly
    equal durations, and carry identical selectors: anything else
    raises ``ValueError`` instead of widening or comparing different
    populations. Only the validated windows and paging may differ;
    both selector sets travel in the output so the comparison is
    auditable. Each side reports its own coverage range, raw counts,
    absolute change and ratio/percentage. A covered zero baseline
    yields an exact change with an unavailable ratio (never
    divide-by-zero or infinite); limited coverage (running/failed
    imports on either side) or absent observed requests on EITHER
    side marks every ratio unavailable rather than a confident
    spike — an empty current window is never a -100% finding.
    Observed min/max bound observed events only: one event never
    proves full-window coverage. Only the two validated windows are
    read. The shared window length travels as float
    ``window_seconds`` with the exact integer-microsecond
    ``window_seconds_us`` companion, consistent with the ISO window
    pair (no conflicting truncation).
    """
    if current.site_id != previous.site_id or current.source_id != previous.source_id:
        raise ValueError("comparison windows must share site and source scope")
    current_duration = current.window.time_to - current.window.time_from
    previous_duration = previous.window.time_to - previous.window.time_from
    if current_duration != previous_duration:
        raise ValueError("comparison windows must have exactly equal length")
    if current_duration <= timedelta(0):
        raise ValueError("comparison windows must have positive length")
    current_selectors = _comparison_selectors(current)
    previous_selectors = _comparison_selectors(previous)
    if current_selectors != previous_selectors:
        mismatch = next(
            name
            for name in _COMPARISON_SELECTORS
            if current_selectors[name] != previous_selectors[name]
        )
        raise ValueError(
            "comparison windows must carry identical selectors aside from the "
            f"validated windows/paging (mismatch: {mismatch})"
        )
    observed = datetime.now(UTC) if observation_time is None else observation_time
    sides: dict[str, dict[str, object]] = {}
    for name, filt in (("current", current), ("previous", previous)):
        clf = _classifier_for(filt, rules)
        counts = queries.summary_counts(conn, filt, clf)
        traffic = {row["traffic"]: row for row in queries.traffic_breakdown(conn, filt, clf)}
        cov = queries.coverage(conn, filt, clf)
        imports = cov["imports"]
        assert isinstance(imports, list)
        limited = any(imp["status"] not in ("completed",) for imp in imports)  # type: ignore[union-attr]
        hours = current_duration.total_seconds() / 3600.0
        sides[name] = {
            "counts": counts,
            "claimed_bot": int(traffic.get("claimed_bot", {}).get("requests", 0)),
            "automation": int(traffic.get("other_automation", {}).get("requests", 0)),
            "requests_per_hour": counts["requests"] / hours if hours else None,
            "coverage": {
                "unique_events": cov["unique_events"],
                "observed_min": cov["observed_min"],
                "observed_max": cov["observed_max"],
                "sources": cov["sources"],
                "import_attempts": cov["import_attempts"],
                "coverage_limited": limited,
            },
        }
    cur, prev = sides["current"], sides["previous"]
    assert isinstance(cur["coverage"], dict) and isinstance(prev["coverage"], dict)
    coverage_ok = not (cur["coverage"]["coverage_limited"] or prev["coverage"]["coverage_limited"])
    cur_counts = cur["counts"]
    prev_counts = prev["counts"]
    assert isinstance(cur_counts, dict) and isinstance(prev_counts, dict)
    current_empty = int(cur_counts["requests"]) == 0
    previous_empty = int(prev_counts["requests"]) == 0
    flags = {
        "coverage_ok": coverage_ok,
        "current_empty": current_empty,
        "previous_empty": previous_empty,
    }
    metrics = [
        _comparison_metric("requests", cur_counts["requests"], prev_counts["requests"], **flags),
        _comparison_metric(
            "errors_4xx", cur_counts["errors_4xx"], prev_counts["errors_4xx"], **flags
        ),
        _comparison_metric(
            "errors_5xx", cur_counts["errors_5xx"], prev_counts["errors_5xx"], **flags
        ),
        _comparison_metric(
            "bytes_total", cur_counts["bytes_total"], prev_counts["bytes_total"], **flags
        ),
        _comparison_metric(
            "claimed_bot_requests",
            int(cur["claimed_bot"]),
            int(prev["claimed_bot"]),
            **flags,
        ),
        _comparison_metric(
            "automation_requests",
            int(cur["automation"]),
            int(prev["automation"]),
            **flags,
        ),
    ]
    assert isinstance(cur["requests_per_hour"], (int, float))
    assert prev["requests_per_hour"] is None or isinstance(prev["requests_per_hour"], (int, float))
    metrics.append(
        _comparison_metric(
            "requests_per_hour",
            float(cur["requests_per_hour"]),
            float(prev["requests_per_hour"] or 0.0),
            **flags,
        )
    )
    comparable = coverage_ok and not current_empty and not previous_empty
    reasons = []
    if not coverage_ok:
        reasons.append("coverage limited by running/failed imports on at least one side")
    if current_empty and not previous_empty:
        reasons.append("current window holds no requests: ratios unavailable")
    if previous_empty and not current_empty:
        reasons.append("baseline window holds no requests: ratios unavailable")
    if current_empty and previous_empty:
        reasons.append("neither window holds observed requests: ratios unavailable")
    return {
        "site_id": current.site_id,
        "source_id": current.source_id,
        "current_window": _window_dict(current),
        "previous_window": _window_dict(previous),
        "selectors": current_selectors,
        "filters": {"current": _filter_dict(current), "previous": _filter_dict(previous)},
        "window_seconds": _window_micros(current) / 1_000_000,
        "window_seconds_us": _window_micros(current),
        "generated_at": observed.isoformat(),
        "metrics": metrics,
        "coverage": {"current": cur["coverage"], "previous": prev["coverage"]},
        "comparable": comparable,
        "comparable_reasons": reasons,
        "limitations": [
            "each side covers only its own validated window: no hidden widening",
            "selectors match aside from the validated windows/paging: both sets travel above",
            (
                "observed_min/observed_max bound observed events only: one event never proves "
                "full-window coverage and unseen gaps stay unknown"
            ),
            (
                "ratios are unavailable on zero baselines, empty windows or limited coverage, "
                "never infinite and never a confident -100% from an empty window"
            ),
            *LIMITATIONS_BOT,
            *LIMITATIONS_LOGS,
        ],
    }


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
    entries = _bot_entries(conn, filt, rules)
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


def _bot_entries(
    conn: sqlite3.Connection, filt: AnalyticsFilter, rules: list[Rule]
) -> list[dict[str, object]]:
    """Exact per-rule aggregates over the FULL filtered scope, no paging.

    Shared by :func:`bot_table` (which sorts/pages the same list) and
    :func:`bot_groups` (which aggregates it), so grouped shares always
    agree with the table totals regardless of page limit/offset.
    """
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
    return entries


def bot_groups(
    conn: sqlite3.Connection, filt: AnalyticsFilter, rules: list[Rule]
) -> dict[str, object]:
    """Claimed-bot aggregates grouped by category/provider/purpose.

    Grouped from the same exact full-scope per-rule entries as the bot
    table, so shares stay correct beyond any table page limit/offset.
    Provider/purpose remain configured claims from the versioned rule
    catalog, never proof of training use or verified identity.
    """
    entries = _bot_entries(conn, filt, rules)
    groups: dict[str, dict[str, dict[str, object]]] = {
        "categories": {},
        "providers": {},
        "purposes": {},
    }
    for entry in entries:
        keyed = (
            ("categories", entry["category"]),
            ("providers", entry["provider"] or "unclaimed"),
            ("purposes", entry["purpose"] or "unclaimed"),
        )
        for dimension, name in keyed:
            bucket = groups[dimension].setdefault(
                name,
                {
                    "name": name,
                    "requests": 0,
                    "errors_4xx": 0,
                    "errors_5xx": 0,
                    "bytes_total": 0,
                    "rules": 0,
                },
            )
            bucket["requests"] = int(bucket["requests"]) + entry["requests"]
            bucket["errors_4xx"] = int(bucket["errors_4xx"]) + entry["errors_4xx"]
            bucket["errors_5xx"] = int(bucket["errors_5xx"]) + entry["errors_5xx"]
            bucket["bytes_total"] = int(bucket["bytes_total"]) + entry["bytes_total"]
            bucket["rules"] = int(bucket["rules"]) + 1
    ranked = {
        dimension: sorted(buckets.values(), key=lambda b: (-int(b["requests"]), str(b["name"])))
        for dimension, buckets in groups.items()
    }
    return {
        "site_id": filt.site_id,
        "time_range": _window_dict(filt),
        "filters": _filter_dict(filt),
        "categories": ranked["categories"],
        "providers": ranked["providers"],
        "purposes": ranked["purposes"],
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
    """Sanitized paginated request rows for the dashboard/API explorer.

    One allowlisted server sort (legacy ``newest``/``oldest`` kept);
    rows carry the 200-char agent sample with a truncation flag and a
    derived conflicting-identity boolean. No raw lines, original IPs,
    query values or full agents are exposed.
    """
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


LIMITATIONS_PERFORMANCE = [
    "zero is a valid measured latency; missing timing is unavailable, never zero",
    "upstream totals aggregate all logged legs; a partial multi-leg timing leaves the total unavailable",
    "status 304 is normal cache validation, not crawl waste",
]

LIMITATIONS_SEO = [
    "AI-only means observed for configured AI-bot categories and not for other traffic in the same scope: absence elsewhere is observed absence, never proof of absence",
    "a User-Agent match proves a claimed identity only, never a verified crawler",
    "bot activity proves nothing about indexing, training use or search ranking",
]


def performance_overview(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    rules: list[Rule] | None = None,
    *,
    observation_time: datetime | None = None,
) -> dict[str, object]:
    """Measured latency, upstream, cache, MIME, version, TLS and host view.

    One deterministic entry for the future dashboard, REST API and
    bounded tools: equal filters always yield equal results. All values
    are exact all-row aggregates over the filtered scope; missing data
    stays ``None``/``Unknown`` and legacy Combined scopes honestly
    report ``latency_available: False``. Original IPs never participate:
    only HMAC pseudonyms and sanitized enrichment columns are read.
    """
    clf = _classifier_for(filt, rules)
    observed = datetime.now(UTC) if observation_time is None else observation_time
    latency = queries.timing_stats(conn, filt, clf, "request_time_ms")
    upstream = queries.timing_stats(conn, filt, clf, "upstream_time_ms")
    cache = queries.cache_distribution(conn, filt, clf)
    versions, versions_total, versions_page = queries.version_distribution(conn, filt, clf)
    tls, tls_total, tls_page = queries.tls_distribution(conn, filt, clf)
    hosts, hosts_total, hosts_page = queries.host_distribution(conn, filt, clf)
    mime = queries.mime_resource_breakdown(conn, filt, clf)
    warnings: list[str] = [
        *(str(w) for w in latency["warnings"]),  # type: ignore[union-attr]
        *(str(w) for w in upstream["warnings"]),  # type: ignore[union-attr]
        *_warnings(conn, filt, clf),
    ]
    return {
        "site_id": filt.site_id,
        "time_range": _window_dict(filt),
        "generated_at": observed.isoformat(),
        "filters": _filter_dict(filt),
        "latency_available": int(latency["measured"]) > 0,  # type: ignore[arg-type]
        "latency_ms": latency,
        "upstream_ms": upstream,
        "units": "milliseconds",
        "percentile_definition": (
            "linear interpolation over ascending measured values v[0..n-1] "
            "(missing excluded): rank r = q*(n-1), "
            "v[floor(r)] + (v[ceil(r)] - v[floor(r)]) * (r - floor(r))"
        ),
        "cache": cache,
        "mime_vs_resource": mime,
        "http_versions": {"items": versions, "total": versions_total, **versions_page},
        "tls_protocols": {"items": tls, "total": tls_total, **tls_page},
        "logged_hosts": {"items": hosts, "total": hosts_total, **hosts_page},
        "coverage": coverage_summary(conn, filt, rules),
        "warnings": warnings,
        "limitations": [*LIMITATIONS_PERFORMANCE, *LIMITATIONS_LOGS],
    }


def slow_endpoints(
    conn: sqlite3.Connection, query: SlowEndpointsQuery, rules: list[Rule] | None = None
) -> dict[str, object]:
    """Slow measured endpoints with counts and per-path percentiles."""
    clf = _classifier_for(query.filt, rules)
    items, total, meta = queries.slow_endpoints(conn, query, clf)
    return {
        "site_id": query.filt.site_id,
        "time_range": _window_dict(query.filt),
        "filters": _filter_dict(query.filt),
        "sort": query.sort,
        "items": items,
        "total_paths": total,
        "meta": meta,
        "limit": query.filt.limit,
        "offset": query.filt.offset,
        "units": "milliseconds",
        "coverage": coverage_summary(conn, query.filt, rules),
        "limitations": [*LIMITATIONS_PERFORMANCE, *LIMITATIONS_LOGS],
    }


def seo_status_groups(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    rules: list[Rule],
    *,
    status_class: str = "4xx",
) -> dict[str, object]:
    """Bot redirects/client/server errors grouped by path and rule.

    ``status_class`` is one of ``3xx`` (bot redirects), ``4xx`` (client
    errors) or ``5xx`` (server errors). Every row attributes to exactly
    one configured rule/provider via the ordered classifier; groups
    carry exact counts/bytes plus drilldown selectors. Claims only:
    no indexing, training-use or ranking inference.
    """
    if status_class not in ("3xx", "4xx", "5xx"):
        raise ValueError(f"unknown status class: {status_class!r}")
    clf = _classifier_for(filt, rules)
    assert clf is not None
    items, total = queries.seo_status_by_bot_path(conn, filt, clf, status_class=status_class)
    return {
        "site_id": filt.site_id,
        "time_range": _window_dict(filt),
        "filters": _filter_dict(filt),
        "status_class": status_class,
        "items": items,
        "total_groups": total,
        "limit": filt.limit,
        "offset": filt.offset,
        "coverage": coverage_summary(conn, filt, rules),
        "limitations": [*LIMITATIONS_SEO, *LIMITATIONS_LOGS],
    }


def ai_only_paths(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    rules: list[Rule],
    *,
    observation_time: datetime | None = None,
) -> dict[str, object]:
    """Paths observed only for the selected AI candidates (with caveat).

    The candidate side preserves the caller's bot/category/provider/
    purpose/traffic selectors; only the comparison universe widens by
    dropping them (removed names reported under
    ``comparison.selectors_removed``). Both scopes carry their own
    filters and coverage: ``candidate`` for the selected AI-candidate
    scope, ``comparison`` for the widened universe. A universe with no
    non-AI traffic is flagged ``vacuous``, never hidden. Selectors that
    cannot hold AI-candidate rows raise ``ValueError`` instead of being
    silently ignored. No indexing, training-use or SEO-rank claim is
    ever made.
    """
    clf = _classifier_for(filt, rules)
    assert clf is not None
    observed = datetime.now(UTC) if observation_time is None else observation_time
    result = queries.ai_only_paths(conn, filt, clf)
    comparison_filter = result.pop("comparison_filter")
    assert isinstance(comparison_filter, AnalyticsFilter)
    comparison = dict(result["comparison"])  # type: ignore[union-attr]
    comparison["filters"] = _filter_dict(comparison_filter)
    comparison["coverage"] = coverage_summary(conn, comparison_filter, rules)
    return {
        "site_id": filt.site_id,
        "time_range": _window_dict(filt),
        "generated_at": observed.isoformat(),
        "filters": _filter_dict(filt),
        **result,
        "candidate": {
            "filters": _filter_dict(filt),
            "coverage": coverage_summary(conn, filt, rules),
        },
        "comparison": comparison,
        "coverage": coverage_summary(conn, filt, rules),
        "limitations": [*LIMITATIONS_SEO, *LIMITATIONS_LOGS],
    }


def referrer_404s(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    rules: list[Rule] | None = None,
    *,
    relation: queries.ReferrerRelation = "all",
) -> dict[str, object]:
    """Referrer-path -> target-404 report over sanitized fields.

    Covers internal AND external referrers together (every row carries
    an ``internal`` label); pass ``relation="internal"``/``"external"``
    to narrow in SQL with matching totals instead of filtering a fetched
    page in Python. The configured own domain/aliases (site hostname
    plus stored source aliases) separate internal from external
    referrers; only the sanitized scheme+host+path travels (no query
    values, userinfo, secrets or clickable dangerous schemes).
    Ordinary host-level referrer reports stay unchanged.
    """
    clf = _classifier_for(filt, rules)
    own_hosts = queries.own_hosts_for_scope(conn, filt)
    items, total = queries.referrer_404_targets(
        conn, filt, clf, own_hosts=own_hosts, relation=relation
    )
    return {
        "site_id": filt.site_id,
        "time_range": _window_dict(filt),
        "filters": _filter_dict(filt),
        "own_hosts": sorted(own_hosts),
        "relation": relation,
        "host_matching": (
            "lowercase hostname equality; ports, userinfo and query values are never stored; "
            "IDN compares in stored encoded form; only http/https schemes are stored"
        ),
        "items": items,
        "total_groups": total,
        "limit": filt.limit,
        "offset": filt.offset,
        "coverage": coverage_summary(conn, filt, rules),
        "limitations": [*LIMITATIONS_SEO, *LIMITATIONS_LOGS],
    }
