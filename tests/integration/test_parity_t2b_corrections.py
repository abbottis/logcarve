"""Parity T2b correction tests (probes A-H, before T3).

Small independently hand-counted synthetic fixtures (never the
immutable shared fixtures, never real logs). Each probe pins the
corrected definition against the frozen-commit behavior documented
in the task: asymmetric window edges, metadata filters on journeys,
constant batched offender reads with honest group totals, >=400
error semantics, strict comparison selectors with empty-side
honesty, genuine burst/sequence evidence, microsecond precision and
opaque journey-ID resolution.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.analytics import queries, service
from app.analytics.contracts import (
    AnalyticsFilter,
    JourneyIdQuery,
    JourneyQuery,
    JourneyTimelineQuery,
    TimeWindow,
)
from app.analytics.rules import Rule, load_rules
from app.db.database import connect
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.combined import pseudonymize_client
from app.ingestion.sources import SourceConfig

ROOT = Path(__file__).resolve().parent.parent.parent
BOT_RULES = load_rules(ROOT / "config" / "bot_rules.yaml").rules
HMAC_KEY = b"parity-t2b-correction-key"
NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC)
UA = "CorrectUA/1.0"


def _line(ip: str, ts: str, path: str, status: int, ua: str = UA, size: int = 100) -> str:
    return f'{ip} - - [{ts} +0000] "GET {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def _import_lines(tmp_path, lines: bytes, site: str, source: str):
    root = tmp_path / "logs"
    root.mkdir(exist_ok=True)
    (root / "c.log").write_bytes(lines)
    db = tmp_path / f"{source}.sqlite3"
    migrate(db)
    imported = run_import(
        db,
        source=SourceConfig(
            source_id=source,
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="c.log",
        ),
        site_id=site,
        site_name="T2bC",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="c.log",
        hmac_key=HMAC_KEY,
    )
    assert imported.status == "completed"
    return db


def _filt(site: str, wf: datetime, wt: datetime, **overrides) -> AnalyticsFilter:
    base: dict = {"site_id": site, "window": TimeWindow(time_from=wf, time_to=wt)}
    base.update(overrides)
    return AnalyticsFilter(**base)


def _pseudo(ip: str) -> str:
    return pseudonymize_client(ip, HMAC_KEY)


def _insert_request(conn, ts: str, path: str, status: int, client: str, **cols) -> None:
    """Direct synthetic row insert reusing the imported scope rows."""
    scope = conn.execute(
        "SELECT imports.id, log_sources.site_id, log_sources.id, imports.file_fingerprint"
        " FROM imports JOIN log_sources ON log_sources.id = imports.source_id LIMIT 1"
    ).fetchone()
    assert scope is not None
    offset = conn.execute("SELECT COALESCE(MAX(byte_offset), 0) + 1 FROM requests").fetchone()[0]
    conn.execute(
        "INSERT INTO requests (import_id, site_id, source_id, file_fingerprint,"
        " byte_offset, line_number, ts_utc, method, path, status, bytes,"
        " referer_host, user_agent, client_pseudonym,"
        " server_host, http_version, mime_type, cache_status, tls_protocol,"
        " request_time_ms, upstream_time_ms)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, 'GET', ?, ?, 100,"
        " NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            scope[0],
            scope[1],
            scope[2],
            scope[3],
            offset,
            offset,
            ts,
            path,
            status,
            cols.get("user_agent", UA),
            client,
            cols.get("server_host"),
            cols.get("http_version"),
            cols.get("mime_type"),
            cols.get("cache_status"),
            cols.get("tls_protocol"),
            cols.get("request_time_ms"),
            cols.get("upstream_time_ms"),
        ),
    )


# ---------------------------------------------------------------------------
# A. asymmetric window edges with an expanded-window control
# ---------------------------------------------------------------------------


def test_t2b_right_edge_equality_expanded_control(tmp_path):
    """An end exactly 1800s before the edge is right-partial (proven by control)."""
    site, source = "site-t2bc-a", "t2bc-a-source"
    window = (datetime(2026, 10, 27, 9, 0, tzinfo=UTC), datetime(2026, 10, 27, 10, 30, tzinfo=UTC))
    narrow = _import_lines(
        tmp_path,
        (
            "\n".join(
                [
                    _line("198.51.100.1", "27/Oct/2026:09:30:00", "/a", 200),
                    _line("198.51.100.1", "27/Oct/2026:10:00:00", "/b", 200),
                ]
            )
            + "\n"
        ).encode(),
        site,
        source,
    )
    conn = connect(narrow, read_only=True)
    try:
        result = service.journeys(
            conn, JourneyQuery(filt=_filt(site, *window)), None, observation_time=NOW
        )
    finally:
        conn.close()
    assert result["total_groups"] == 1
    only = result["items"][0]
    assert (only["requests_total"], only["entry_path"]) == (2, "/a")
    # The gap rule continues at exactly 1800s, so an unseen request on
    # the excluded 10:30 edge could continue this journey: partial.
    assert only["right_truncated"] is True
    # ... while the left edge at exactly the gap is complete: an
    # excluded predecessor would stand strictly before 09:00, so its
    # gap would strictly exceed the limit. Asymmetry in one row.
    assert only["left_truncated"] is False
    assert only["completeness"] == "partial-right"

    # Expanded-window synthetic control: the same key with a real event
    # exactly on the old right edge continues the SAME journey.
    wide = _import_lines(
        tmp_path,
        (
            "\n".join(
                [
                    _line("198.51.100.1", "27/Oct/2026:09:30:00", "/a", 200),
                    _line("198.51.100.1", "27/Oct/2026:10:00:00", "/b", 200),
                    _line("198.51.100.1", "27/Oct/2026:10:30:00", "/edge", 200),
                ]
            )
            + "\n"
        ).encode(),
        site,
        source + "-wide",
    )
    conn = connect(wide, read_only=True)
    try:
        expanded = service.journeys(
            conn,
            JourneyQuery(filt=_filt(site, window[0], datetime(2026, 10, 27, 11, 0, tzinfo=UTC))),
            None,
        )
    finally:
        conn.close()
    assert expanded["total_groups"] == 1
    assert expanded["items"][0]["requests_total"] == 3
    assert expanded["items"][0]["journey_id"] == only["journey_id"]
    assert expanded["items"][0]["ended_at"] == "2026-10-27T10:30:00+00:00"


def test_t2b_left_edge_exact_gap_is_complete(tmp_path):
    """Left edge at exactly the gap is provably complete (asymmetry)."""
    site, source = "site-t2bc-a2", "t2bc-a2-source"
    db = _import_lines(
        tmp_path,
        (_line("198.51.100.1", "27/Oct/2026:09:30:00", "/solo", 200) + "\n").encode(),
        site,
        source,
    )
    conn = connect(db, read_only=True)
    try:
        result = service.journeys(
            conn,
            JourneyQuery(
                filt=_filt(
                    site,
                    datetime(2026, 10, 27, 9, 0, tzinfo=UTC),
                    datetime(2026, 10, 27, 12, 0, tzinfo=UTC),
                )
            ),
            None,
        )
    finally:
        conn.close()
    assert result["total_groups"] == 1
    only = result["items"][0]
    # start - from == 1800 exactly: an excluded predecessor would stand
    # strictly before 09:00, so its gap would strictly exceed the limit.
    assert only["left_truncated"] is False
    # end far from the right edge: complete on both sides.
    assert only["right_truncated"] is False
    assert only["completeness"] == "complete"


# ---------------------------------------------------------------------------
# B. every metadata filter on list, timeline and entries
# ---------------------------------------------------------------------------


def _metadata_db(tmp_path):
    site, source = "site-t2bc-b", "t2bc-b-source"
    db = _import_lines(
        tmp_path,
        (
            "\n".join(
                [
                    _line("198.51.100.1", "27/Oct/2026:10:00:00", "/m1", 200),
                    _line("198.51.100.1", "27/Oct/2026:10:05:00", "/m2", 404),
                    _line("198.51.100.1", "27/Oct/2026:10:10:00", "/m3", 200),
                    _line("198.51.100.1", "27/Oct/2026:10:15:00", "/m4", 500),
                ]
            )
            + "\n"
        ).encode(),
        site,
        source,
    )
    holder = connect(db)
    try:
        holder.execute(
            "UPDATE requests SET server_host = 'h1.example', http_version = 'HTTP/1.1',"
            " mime_type = 'text/html', cache_status = 'HIT', tls_protocol = 'TLSv1.3',"
            " request_time_ms = 5.0, upstream_time_ms = 2.0 WHERE path = '/m1'"
        )
        holder.execute(
            "UPDATE requests SET server_host = 'h2.example', http_version = 'HTTP/2',"
            " mime_type = 'application/json', cache_status = 'MISS',"
            " tls_protocol = 'TLSv1.2', request_time_ms = 50.0,"
            " upstream_time_ms = NULL WHERE path IN ('/m2', '/m3', '/m4')"
        )
        holder.commit()
    finally:
        holder.close()
    return db, site


_B_WINDOW = (datetime(2026, 10, 27, 9, 0, tzinfo=UTC), datetime(2026, 10, 27, 12, 0, tzinfo=UTC))

_B_FILTERS = [
    ({"server_host": "h1.example"}, 1),
    ({"http_version": "HTTP/1.1"}, 1),
    ({"mime_type": "text/html"}, 1),
    ({"cache_status": "HIT"}, 1),
    ({"tls_protocol": "TLSv1.3"}, 1),
    ({"timing_available": True}, 4),
    ({"timing_available": False}, 0),
    ({"upstream_available": True}, 1),
    ({"upstream_available": False}, 3),
    ({"timing_min_ms": 10.0}, 3),
    ({"timing_max_ms": 10.0}, 1),
    ({"path_exact": "/m2"}, 1),
    ({"method": "GET"}, 4),
    ({"status": 200}, 2),
    ({"status_class": "5xx"}, 1),
    ({"path_prefix": "/m"}, 4),
    ({"search": "m3"}, 1),
]


def test_t2b_journey_metadata_filters_narrow_without_new_starts(tmp_path):
    """All metadata filters apply on list/timeline/entries; starts never move."""
    db, site = _metadata_db(tmp_path)
    conn = connect(db, read_only=True)
    try:
        plain = service.journeys(
            conn, JourneyQuery(filt=_filt(site, *_B_WINDOW)), None, observation_time=NOW
        )
    finally:
        conn.close()
    assert plain["total_groups"] == 1
    journey = plain["items"][0]
    assert journey["requests_total"] == 4
    pseudo = journey["client_pseudonym"]
    start = datetime.fromisoformat(journey["started_at"])

    conn = connect(db, read_only=True)
    try:
        for kwargs, shown in _B_FILTERS:
            filt = _filt(site, *_B_WINDOW, **kwargs)
            narrowed = service.journeys(conn, JourneyQuery(filt=filt), None)
            # Boundaries still derive before matchers: the same journey
            # with the same ID/start/entry however the filter hides
            # rows (a zero shown count falls below min_requests).
            assert narrowed["total_groups"] == (1 if shown else 0), kwargs
            if shown:
                row = narrowed["items"][0]
                assert row["journey_id"] == journey["journey_id"], kwargs
                assert row["started_at"] == journey["started_at"], kwargs
                assert row["entry_path"] == "/m1", kwargs
                assert row["requests_total"] == 4, kwargs
                assert row["requests_shown"] == shown, kwargs
            # Timeline resolves the same journey under the same filter
            # even when the filter hides every row.
            timeline = service.journey_timeline(
                conn,
                JourneyTimelineQuery(
                    filt=filt,
                    client_pseudonym=pseudo,
                    user_agent=UA,
                    journey_start=start,
                ),
                None,
            )
            assert timeline["requests_shown"] == shown, kwargs
            assert timeline["shown"] == shown, kwargs
            assert timeline["journey_id"] == journey["journey_id"], kwargs
            # Entry aggregation agrees: one eligible journey, same entry.
            entries = service.journey_entry_paths(conn, filt, None)
            assert entries["total_groups"] == (1 if shown else 0), kwargs
            if shown:
                assert entries["items"][0]["entry_path"] == "/m1", kwargs
    finally:
        conn.close()


def test_t2b_journey_metadata_filter_not_silently_ignored(tmp_path):
    """A metadata filter matching nothing yields zero journeys, not everything."""
    db, site = _metadata_db(tmp_path)
    conn = connect(db, read_only=True)
    try:
        empty = service.journeys(
            conn, JourneyQuery(filt=_filt(site, *_B_WINDOW, server_host="absent.example")), None
        )
        assert empty["total_groups"] == 0
        assert empty["items"] == []
        entries = service.journey_entry_paths(
            conn, _filt(site, *_B_WINDOW, cache_status="NOPE"), None
        )
        assert entries["total_groups"] == 0
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# C. constant batched offender reads with honest group totals
# ---------------------------------------------------------------------------

_C_WINDOW = (datetime(2026, 10, 27, 9, 0, tzinfo=UTC), datetime(2026, 10, 27, 12, 0, tzinfo=UTC))


def _legacy_rule(threshold: int = 1) -> Rule:
    return Rule(
        id="sec-repeated-client-errors",
        version=1,
        category="repeated_client_errors",
        title="t",
        meaning="m",
        min_client_errors=threshold,
    )


def _count_selects(conn, func):
    stmts: list[str] = []
    conn.set_trace_callback(stmts.append)
    try:
        result = func()
    finally:
        conn.set_trace_callback(None)
    selects = sum(1 for stmt in stmts if stmt.strip().upper().startswith("SELECT"))
    return result, selects


def test_t2b_offender_selects_constant_for_1_vs_100_clients(tmp_path):
    """One offender costs the same SELECTs as 100 shown offenders."""
    site, source = "site-t2bc-c", "t2bc-c-source"
    lines = []
    lines.append(_line("198.51.100.1", "27/Oct/2026:10:00:00", "/solo", 404))
    for i in range(100):
        lines.append(_line(f"198.51.100.{10 + i}", "27/Oct/2026:10:01:00", "/crowd", 404))
    db = _import_lines(tmp_path, ("\n".join(lines) + "\n").encode(), site, source)
    filt = _filt(site, *_C_WINDOW)
    rule = _legacy_rule()
    conn = connect(db, read_only=True)
    try:
        (_, total), n_all = _count_selects(
            conn, lambda: queries.security_offenders(conn, filt, rule, None)
        )
        assert total == 101
        single_filt = _filt(site, *_C_WINDOW, search="/solo")
        (_, single_total), n_one = _count_selects(
            conn, lambda: queries.security_offenders(conn, single_filt, rule, None)
        )
        assert single_total == 1
    finally:
        conn.close()
    assert (n_all, n_one) == (6, 6)


def test_t2b_offender_groups_vs_paths_with_multiple_statuses(tmp_path):
    """One path with three statuses is 3 groups over 1 path; shown <= total."""
    site, source = "site-t2bc-c2", "t2bc-c2-source"
    db = _import_lines(
        tmp_path,
        (
            "\n".join(
                [
                    _line("198.51.100.1", "27/Oct/2026:10:00:00", "/multi", 200),
                    _line("198.51.100.1", "27/Oct/2026:10:01:00", "/multi", 404),
                    _line("198.51.100.1", "27/Oct/2026:10:02:00", "/multi", 500),
                    _line("198.51.100.1", "27/Oct/2026:10:03:00", "/other", 404),
                ]
            )
            + "\n"
        ).encode(),
        site,
        source,
    )
    filt = _filt(site, *_C_WINDOW)
    conn = connect(db, read_only=True)
    try:
        # Narrowed rule: sample scope equals the matching scope.
        rule = Rule(
            id="sec-probe-breadth-x",
            version=1,
            category="sensitive_path",
            title="t",
            meaning="m",
            path_contains=["/multi", "/other"],
            min_client_requests=1,
        )
        (offenders, total) = queries.security_offenders(conn, filt, rule, None)
        assert total == 1
        only = offenders[0]
        assert (only["hits"], only["distinct_paths"]) == (4, 2)
        assert only["sample_groups_total"] == 4  # 3 statuses on /multi + /other
        assert only["sample_distinct_paths"] == 2
        assert only["sample_scope_requests"] == 4
        assert len(only["sample_paths"]) <= only["sample_groups_total"]
        # Legacy rule: selection counts 4xx only, the sample keeps its
        # historic all-status scope with exact group totals there.
        (legacy, legacy_total) = queries.security_offenders(conn, filt, _legacy_rule(), None)
        assert legacy_total == 1
        legacy_only = legacy[0]
        assert legacy_only["hits"] == 2  # the two 4xx rows only
        assert legacy_only["sample_groups_total"] == 4  # all-status groups
        assert legacy_only["sample_scope_requests"] == 4
        assert legacy_only["sample_distinct_paths"] == 2
        assert len(legacy_only["sample_paths"]) <= legacy_only["sample_groups_total"]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# D. >=400 error semantics with honest overlapping rules
# ---------------------------------------------------------------------------


def test_t2b_sample_errors_count_4xx_and_5xx(tmp_path):
    """200/304 show 0 errors; 401/403/500 all count, split reported."""
    site, source = "site-t2bc-d", "t2bc-d-source"
    db = _import_lines(
        tmp_path,
        (
            "\n".join(
                [
                    _line("198.51.100.1", "27/Oct/2026:10:00:00", "/ok", 200),
                    _line("198.51.100.1", "27/Oct/2026:10:01:00", "/ok", 304),
                    _line("198.51.100.1", "27/Oct/2026:10:02:00", "/auth", 401),
                    _line("198.51.100.1", "27/Oct/2026:10:03:00", "/auth", 403),
                    _line("198.51.100.1", "27/Oct/2026:10:04:00", "/env", 500),
                    _line("198.51.100.1", "27/Oct/2026:10:05:00", "/env", 500),
                ]
            )
            + "\n"
        ).encode(),
        site,
        source,
    )
    filt = _filt(site, *_C_WINDOW)
    rule = Rule(
        id="sec-probe-x",
        version=1,
        category="sensitive_path",
        title="t",
        meaning="m",
        path_contains=["/ok", "/auth", "/env"],
    )
    conn = connect(db, read_only=True)
    try:
        sample, total = queries.security_rule_sample(conn, filt, rule, None)
    finally:
        conn.close()
    assert total == 5  # (path, status) groups: /ok has two statuses
    by_key = {(row["path"], row["status"]): row for row in sample}
    assert by_key[("/ok", 200)]["errors"] == 0
    assert by_key[("/ok", 304)]["errors"] == 0
    assert by_key[("/auth", 401)]["errors"] == 1
    assert by_key[("/auth", 403)]["errors"] == 1
    assert by_key[("/env", 500)]["errors"] == 2
    assert by_key[("/env", 500)]["errors_5xx"] == 2
    assert by_key[("/env", 500)]["errors_4xx"] == 0
    assert by_key[("/auth", 401)]["errors_4xx"] == 1


def test_t2b_overlapping_rules_stay_honest(tmp_path):
    """Two rules matching the same rows each report fully; no unique-event claim."""
    site, source = "site-t2bc-d2", "t2bc-d2-source"
    db = _import_lines(
        tmp_path,
        (
            "\n".join(
                [
                    _line("198.51.100.1", "27/Oct/2026:10:00:00", "/shared", 404),
                    _line("198.51.100.1", "27/Oct/2026:10:01:00", "/shared", 404),
                    _line("198.51.100.1", "27/Oct/2026:10:02:00", "/solo", 500),
                ]
            )
            + "\n"
        ).encode(),
        site,
        source,
    )
    filt = _filt(site, *_C_WINDOW)
    rule_a = Rule(
        id="rule-a",
        version=1,
        category="sensitive_path",
        title="t",
        meaning="m",
        path_contains=["/shared"],
    )
    rule_b = Rule(
        id="rule-b",
        version=1,
        category="sensitive_path",
        title="t",
        meaning="m",
        path_contains=["/shared", "/solo"],
    )
    conn = connect(db, read_only=True)
    try:
        totals_a = queries.security_rule_totals(conn, filt, rule_a, None)
        totals_b = queries.security_rule_totals(conn, filt, rule_b, None)
        coverage = queries.coverage(conn, filt, None)
    finally:
        conn.close()
    # Each rule counts its own matches exactly; the shared rows appear
    # in both (per-rule scope, never a deduplicated unique claim).
    assert totals_a == {"requests": 2, "distinct_paths": 1}
    assert totals_b == {"requests": 3, "distinct_paths": 2}
    assert coverage["unique_events"] == 3
    assert totals_a["requests"] + totals_b["requests"] == 5  # overlap counted twice, honestly


# ---------------------------------------------------------------------------
# E. strict selectors, per-side metadata, empty-side honesty
# ---------------------------------------------------------------------------

_E_PREV = (datetime(2026, 10, 27, 9, 0, tzinfo=UTC), datetime(2026, 10, 27, 10, 0, tzinfo=UTC))
_E_CUR = (datetime(2026, 10, 27, 10, 0, tzinfo=UTC), datetime(2026, 10, 27, 11, 0, tzinfo=UTC))
_E_EMPTY = (datetime(2026, 10, 27, 8, 0, tzinfo=UTC), datetime(2026, 10, 27, 9, 0, tzinfo=UTC))


def _compare_db(tmp_path):
    site, source = "site-t2bc-e", "t2bc-e-source"
    db = _import_lines(
        tmp_path,
        (
            "\n".join(
                [
                    _line("198.51.100.1", "27/Oct/2026:09:10:00", "/a", 200),
                    _line("198.51.100.1", "27/Oct/2026:10:10:00", "/a", 200),
                    _line("198.51.100.1", "27/Oct/2026:10:11:00", "/a", 404),
                ]
            )
            + "\n"
        ).encode(),
        site,
        source,
    )
    return db, site


def _metric(result, name):
    return next(m for m in result["metrics"] if m["name"] == name)


def test_t2b_compare_empty_current_is_unavailable(tmp_path):
    """An empty current window never reports a confident -100% ratio."""
    db, site = _compare_db(tmp_path)
    conn = connect(db, read_only=True)
    try:
        result = service.compare_windows(
            conn, _filt(site, *_E_EMPTY), _filt(site, *_E_PREV), BOT_RULES, observation_time=NOW
        )
    finally:
        conn.close()
    assert result["comparable"] is False
    requests = _metric(result, "requests")
    assert (requests["current"], requests["previous"]) == (0, 1)
    assert requests["absolute_change"] == -1  # exact over observed rows
    assert requests["ratio"] is None
    assert requests["percent"] is None
    assert requests["ratio_status"] == "insufficient_coverage"
    assert "current window holds no" in requests["note"]
    assert any("current window holds no" in reason for reason in result["comparable_reasons"])
    # Both filter sets travel with the comparison.
    assert result["filters"]["current"]["site_id"] == site
    assert result["filters"]["previous"]["site_id"] == site
    assert result["current_window"]["time_from"] == _E_EMPTY[0].isoformat()


def test_t2b_compare_both_empty_is_unavailable(tmp_path):
    db, site = _compare_db(tmp_path)
    conn = connect(db, read_only=True)
    try:
        result = service.compare_windows(
            conn,
            _filt(site, *_E_EMPTY),
            _filt(
                site,
                datetime(2026, 10, 27, 7, 0, tzinfo=UTC),
                datetime(2026, 10, 27, 8, 0, tzinfo=UTC),
            ),
            BOT_RULES,
        )
    finally:
        conn.close()
    assert result["comparable"] is False
    requests = _metric(result, "requests")
    assert (requests["current"], requests["previous"]) == (0, 0)
    assert requests["ratio_status"] == "insufficient_coverage"
    assert requests["absolute_change"] == 0
    assert any("neither window" in reason for reason in result["comparable_reasons"])


def test_t2b_compare_empty_previous_keeps_zero_baseline(tmp_path):
    """Covered nonempty current vs empty baseline: exact change, no ratio."""
    db, site = _compare_db(tmp_path)
    conn = connect(db, read_only=True)
    try:
        result = service.compare_windows(
            conn, _filt(site, *_E_PREV), _filt(site, *_E_EMPTY), BOT_RULES
        )
    finally:
        conn.close()
    requests = _metric(result, "requests")
    assert (requests["current"], requests["previous"]) == (1, 0)
    assert requests["absolute_change"] == 1
    assert requests["ratio"] is None
    assert requests["ratio_status"] == "zero_baseline"
    assert result["comparable"] is False


def test_t2b_compare_running_import_is_unavailable(tmp_path):
    db, site = _compare_db(tmp_path)
    holder = connect(db)
    try:
        holder.execute("UPDATE imports SET status = 'running'")
        holder.commit()
    finally:
        holder.close()
    conn = connect(db, read_only=True)
    try:
        result = service.compare_windows(
            conn, _filt(site, *_E_CUR), _filt(site, *_E_PREV), BOT_RULES
        )
    finally:
        conn.close()
    assert result["comparable"] is False
    for metric in result["metrics"]:
        assert metric["ratio"] is None
        assert metric["ratio_status"] == "insufficient_coverage"
        assert metric["absolute_change"] == metric["current"] - metric["previous"]


def test_t2b_compare_rejects_selector_mismatch(tmp_path):
    """GET vs POST (or any other selector) never compares silently."""
    db, site = _compare_db(tmp_path)
    conn = connect(db, read_only=True)
    try:
        base_kwargs = [
            {"method": "POST"},
            {"status": 404},
            {"path_prefix": "/nope"},
            {"server_host": "other.example"},
            {"timing_available": True},
        ]
        for kwargs in base_kwargs:
            with pytest.raises(ValueError, match="selectors"):
                service.compare_windows(
                    conn,
                    _filt(site, *_E_CUR, method="GET"),
                    _filt(site, *_E_PREV, **kwargs),
                    BOT_RULES,
                )
        # Windows and paging may differ: identical selectors compare.
        current = _filt(site, *_E_CUR, limit=10, offset=5)
        previous = service.previous_window_filter(_filt(site, *_E_CUR, limit=10, offset=5))
        result = service.compare_windows(conn, current, previous, BOT_RULES)
        assert result["comparable"] is True
        assert result["selectors"]["method"] is None
        assert _metric(result, "requests")["ratio_status"] == "ok"
        assert "observed events only" in " ".join(result["limitations"])
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# F. genuine burst evidence and chronological sequences
# ---------------------------------------------------------------------------

_F_WINDOW = (datetime(2026, 10, 27, 10, 0, tzinfo=UTC), datetime(2026, 10, 27, 11, 0, tzinfo=UTC))


def _rate_rule() -> Rule:
    return Rule(
        id="sec-rate-x",
        version=1,
        category="repeated_client_errors",
        title="t",
        meaning="m",
        min_client_requests=6,
    )


def _tempo_db(tmp_path):
    site, source = "site-t2bc-f", "t2bc-f-source"
    lines = []
    # Spread client: 6 requests across 6 distinct minutes.
    for minute in range(6):
        lines.append(_line("198.51.100.21", f"27/Oct/2026:10:{minute:02d}:00", "/spread", 404))
    # Concentrated client: the same 6 requests inside one minute.
    for second in range(6):
        lines.append(_line("198.51.100.22", f"27/Oct/2026:10:00:{second:02d}", "/burst", 404))
    # Outside-window control: must never leak into totals or sequences.
    lines.append(_line("198.51.100.22", "27/Oct/2026:09:59:59", "/burst", 404))
    db = _import_lines(tmp_path, ("\n".join(lines) + "\n").encode(), site, source)
    return db, site


def test_t2b_tempo_spread_vs_concentrated(tmp_path):
    """Same cumulative count, different peaks: burst evidence separates them."""
    db, site = _tempo_db(tmp_path)
    filt = _filt(site, *_F_WINDOW)
    conn = connect(db, read_only=True)
    try:
        findings = service.security_findings(conn, filt, [_rate_rule()], observation_time=NOW)
    finally:
        conn.close()
    assert len(findings) == 2
    by_client = {f.evidence["client_pseudonym"]: f for f in findings}
    spread = by_client[_pseudo("198.51.100.21")]
    burst = by_client[_pseudo("198.51.100.22")]
    # Cumulative counts agree exactly (6 in-window rows each)...
    assert spread.counts == {"requests": 6, "distinct_paths": 1}
    assert burst.counts == {"requests": 6, "distinct_paths": 1}
    # ... the window denominator is explicit and the averages agree ...
    assert spread.evidence["window_seconds"] == 3600
    assert spread.evidence["avg_requests_per_minute"] == 6 / 3600 * 60
    assert burst.evidence["avg_requests_per_minute"] == 6 / 3600 * 60
    # ... but the whole-minute peaks differ: 1 spread out, 6 at once.
    assert spread.evidence["peak_minute_requests"] == 1
    assert burst.evidence["peak_minute_requests"] == 6
    assert burst.evidence["peak_minute"] == "2026-10-27T10:00"
    assert "average spreads" in burst.evidence["tempo_note"]
    # Chronological sequences carry exact totals with inter-row gaps.
    assert [row["path"] for row in burst.evidence["path_sequence"]] == ["/burst"] * 6
    assert burst.evidence["path_sequence_total"] == 6
    assert burst.evidence["path_sequence_truncated"] is False
    assert burst.evidence["path_sequence"][0]["gap_prev_s"] is None
    assert burst.evidence["path_sequence"][1]["gap_prev_s"] == 1
    spread_gaps = [row["gap_prev_s"] for row in spread.evidence["path_sequence"][1:]]
    assert spread_gaps == [60] * 5
    # The 09:59:59 control stays outside the window everywhere.
    assert all(
        row["ts_utc"] >= "2026-10-27T10:00:00+00:00" for row in burst.evidence["path_sequence"]
    )


def test_t2b_sequence_bounded_with_exact_totals_and_benign_rows(tmp_path):
    """15 rows yield a 10-row ordered sample with exact totals; benign rows stay."""
    site, source = "site-t2bc-f2", "t2bc-f2-source"
    lines = []
    for i in range(15):
        lines.append(_line("198.51.100.31", f"27/Oct/2026:10:00:{i:02d}", f"/seq-{i:02d}", 404))
    lines.append(_line("198.51.100.31", "27/Oct/2026:10:01:00", "/benign", 200))
    db = _import_lines(tmp_path, ("\n".join(lines) + "\n").encode(), site, source)
    filt = _filt(site, *_F_WINDOW)
    conn = connect(db, read_only=True)
    try:
        # Legacy all-status scope: benign rows appear in the sequence.
        (offenders, total) = queries.security_offenders(conn, filt, _legacy_rule(), None)
        assert total == 1
        only = offenders[0]
        assert only["hits"] == 15
        assert only["path_sequence_total"] == 16
        assert len(only["path_sequence"]) == 10
        assert [row["path"] for row in only["path_sequence"]] == [
            f"/seq-{i:02d}" for i in range(10)
        ]
        assert [row["status"] for row in only["path_sequence"]] == [404] * 10
        # Identical-minute ties keep row-id order with 1s gaps.
        assert only["path_sequence"][1]["gap_prev_s"] == 1
    finally:
        conn.close()
    conn = connect(db, read_only=True)
    try:
        findings = service.security_findings(conn, filt, [_legacy_rule()], observation_time=NOW)
    finally:
        conn.close()
    assert len(findings) == 1
    evidence = findings[0].evidence
    assert evidence["path_sequence_total"] == 16
    assert evidence["path_sequence_shown"] == 10
    assert evidence["path_sequence_truncated"] is True
    assert evidence["sample_scope_requests"] == 16
    assert evidence["sample_paths_total"] == 16
    assert evidence["sample_paths_truncated"] is True
    assert evidence["peak_minute_requests"] == 15  # fifteen rows share minute 10:00
    assert "chronological sample" in evidence["sequence_note"]


# ---------------------------------------------------------------------------
# G. microsecond-precise grouping, edges and offsets
# ---------------------------------------------------------------------------


def test_t2b_epoch_micros_exact_and_offset_normalized(tmp_path):
    """Integer epoch microseconds: fractions kept, offsets exact, naive rejected."""
    assert queries.epoch_micros("2026-10-27T10:00:00+00:00") == 1793095200 * 1_000_000
    assert queries.epoch_micros("2026-10-27T10:00:00.000001+00:00") == (1793095200 * 1_000_000 + 1)
    # Positive and negative offsets normalize to the same instant.
    assert (
        queries.epoch_micros("2026-10-27T12:00:00+02:00")
        == queries.epoch_micros("2026-10-27T10:00:00+00:00")
        == queries.epoch_micros("2026-10-27T02:00:00-08:00")
    )
    with pytest.raises(ValueError):
        queries.epoch_micros("2026-10-27T10:00:00")
    # The SQLite scalar agrees on a live connection.
    db = _import_lines(
        tmp_path,
        (_line("198.51.100.1", "27/Oct/2026:10:00:00", "/a", 200) + "\n").encode(),
        "site-t2bc-g0",
        "t2bc-g0-source",
    )
    conn = connect(db, read_only=True)
    try:
        row = conn.execute(
            "SELECT epoch_micros('2026-10-27T10:00:00.000001+00:00')"
            " - epoch_micros('2026-10-27T10:00:00+00:00')"
        ).fetchone()
    finally:
        conn.close()
    assert row[0] == 1


def test_t2b_gap_boundary_microsecond_precision(tmp_path):
    """1800.000000s continues, 1800.000001s splits; identical instants share."""
    site, source = "site-t2bc-g", "t2bc-g-source"
    db = _import_lines(
        tmp_path,
        (_line("198.51.100.1", "27/Oct/2026:10:00:00", "/seed", 200) + "\n").encode(),
        site,
        source,
    )
    client = _pseudo("198.51.100.1")
    holder = connect(db)
    try:
        holder.execute("DELETE FROM requests")
        # Pair 1: exactly 1800.000000s apart -> one journey.
        _insert_request(holder, "2026-10-27T10:00:00+00:00", "/exact-a", 200, client)
        _insert_request(holder, "2026-10-27T10:30:00+00:00", "/exact-b", 200, client)
        # Pair 2: 1800.000001s after 12:00 -> two journeys; plus an
        # identical-instant twin sharing the second journey.
        _insert_request(holder, "2026-10-27T12:00:00+00:00", "/plus-a", 200, client)
        _insert_request(holder, "2026-10-27T12:30:00.000001+00:00", "/plus-b", 200, client)
        _insert_request(holder, "2026-10-27T12:30:00.000001+00:00", "/plus-twin", 200, client)
        holder.commit()
    finally:
        holder.close()
    window = (datetime(2026, 10, 27, 9, 0, tzinfo=UTC), datetime(2026, 10, 27, 13, 0, tzinfo=UTC))
    conn = connect(db, read_only=True)
    try:
        result = service.journeys(conn, JourneyQuery(filt=_filt(site, *window)), None)
    finally:
        conn.close()
    assert result["total_groups"] == 3
    by_entry = {item["entry_path"]: item for item in result["items"]}
    assert by_entry["/exact-a"]["requests_total"] == 2
    assert by_entry["/plus-a"]["requests_total"] == 1
    assert by_entry["/plus-b"]["requests_total"] == 2
    assert by_entry["/plus-b"]["duration_s"] == 0  # sub-second journey, floored honestly


def test_t2b_edge_flags_microsecond_precision(tmp_path):
    """+/-1us around the edges flips the flags exactly (one journey each)."""
    site, source = "site-t2bc-g2", "t2bc-g2-source"
    db = _import_lines(
        tmp_path,
        (_line("198.51.100.1", "27/Oct/2026:10:00:00", "/seed", 200) + "\n").encode(),
        site,
        source,
    )
    holder = connect(db)
    try:
        holder.execute("DELETE FROM requests")
        # Left: 1us inside the gap is partial, 1us past it is complete.
        _insert_request(
            holder, "2026-10-27T09:29:59.999999+00:00", "/left-in", 200, _pseudo("198.51.100.11")
        )
        _insert_request(
            holder, "2026-10-27T09:30:00.000001+00:00", "/left-out", 200, _pseudo("198.51.100.12")
        )
        # Right: ending 1800.000001s before the edge is complete.
        _insert_request(
            holder, "2026-10-27T10:59:59.999999+00:00", "/right-out", 200, _pseudo("198.51.100.13")
        )
        holder.commit()
    finally:
        holder.close()
    window = (
        datetime(2026, 10, 27, 9, 0, tzinfo=UTC),
        datetime(2026, 10, 27, 11, 30, tzinfo=UTC),
    )
    conn = connect(db, read_only=True)
    try:
        result = service.journeys(conn, JourneyQuery(filt=_filt(site, *window)), None)
    finally:
        conn.close()
    assert result["total_groups"] == 3
    by_entry = {item["entry_path"]: item for item in result["items"]}
    assert by_entry["/left-in"]["left_truncated"] is True
    assert by_entry["/left-out"]["left_truncated"] is False
    assert by_entry["/right-out"]["right_truncated"] is False
    assert by_entry["/right-out"]["completeness"] == "complete"


# ---------------------------------------------------------------------------
# H. opaque journey-ID resolution without guessing the User-Agent
# ---------------------------------------------------------------------------

_H_WINDOW = (datetime(2026, 10, 27, 9, 0, tzinfo=UTC), datetime(2026, 10, 27, 12, 0, tzinfo=UTC))
_LONG_UA = "LongAgent/9.9 " + "x" * 500


def _id_db(tmp_path):
    site, source = "site-t2bc-h", "t2bc-h-source"
    db = _import_lines(
        tmp_path,
        (
            "\n".join(
                [
                    _line(
                        "198.51.100.1", "27/Oct/2026:10:00:00", "/ua1-entry", 200, "AgentOne/1.0"
                    ),
                    _line("198.51.100.1", "27/Oct/2026:10:01:00", "/ua1-next", 200, "AgentOne/1.0"),
                    _line(
                        "198.51.100.1", "27/Oct/2026:10:00:00", "/ua2-entry", 200, "AgentTwo/2.0"
                    ),
                    _line(
                        "198.51.100.1",
                        "27/Oct/2026:10:05:00",
                        "/long-entry",
                        200,
                        _LONG_UA,
                    ),
                    # "-" stores a NULL agent for the second client.
                    _line("198.51.100.2", "27/Oct/2026:10:00:00", "/null-entry", 200, "-"),
                ]
            )
            + "\n"
        ).encode(),
        site,
        source,
    )
    holder = connect(db)
    try:
        # An empty-string agent beside the NULL agent: distinct keys.
        _insert_request(
            holder,
            "2026-10-27T10:00:00+00:00",
            "/empty-entry",
            200,
            _pseudo("198.51.100.2"),
            user_agent="",
        )
        holder.commit()
    finally:
        holder.close()
    return db, site


def test_t2b_journey_id_roundtrip_matches_direct_timeline(tmp_path):
    """Every listed ID resolves to the identical timeline, no UA guessing."""
    db, site = _id_db(tmp_path)
    filt = _filt(site, *_H_WINDOW)
    conn = connect(db, read_only=True)
    try:
        listed = service.journeys(conn, JourneyQuery(filt=filt), None)
        # AgentOne, AgentTwo, long agent, NULL agent, empty-string agent.
        assert listed["total_groups"] == 5
        for item in listed["items"]:
            start = datetime.fromisoformat(item["started_at"])
            by_id = service.journey_timeline_by_id(
                conn,
                JourneyIdQuery(
                    filt=filt,
                    client_pseudonym=item["client_pseudonym"],
                    journey_start=start,
                    journey_id=item["journey_id"],
                ),
                None,
            )
            agent, _ = queries.journey_key_for_id(
                conn,
                filt,
                client_pseudonym=item["client_pseudonym"],
                journey_start=start,
                journey_id=item["journey_id"],
            )
            direct = service.journey_timeline(
                conn,
                JourneyTimelineQuery(
                    filt=filt,
                    client_pseudonym=item["client_pseudonym"],
                    user_agent=agent,
                    journey_start=start,
                ),
                None,
            )
            assert by_id["journey_id"] == item["journey_id"] == direct["journey_id"]
            assert by_id["items"] == direct["items"]
            assert by_id["resolved_via"] == "journey_id"
            # No original address leaks through the resolution path.
            assert "198.51.100" not in str(by_id["items"])
            assert "198.51.100" not in by_id["journey_id"]
    finally:
        conn.close()


def test_t2b_journey_id_distinguishes_same_start_keys(tmp_path):
    """Same client + same start + different agents (incl None vs '') resolve apart."""
    db, site = _id_db(tmp_path)
    filt = _filt(site, *_H_WINDOW)
    conn = connect(db, read_only=True)
    try:
        listed = service.journeys(conn, JourneyQuery(filt=filt), None)
        same_start = [
            item
            for item in listed["items"]
            if item["started_at"] == "2026-10-27T10:00:00+00:00"
            and item["client_pseudonym"] == _pseudo("198.51.100.1")
        ]
        assert len(same_start) == 2  # AgentOne vs AgentTwo, same instant
        ids = {item["journey_id"] for item in same_start}
        assert len(ids) == 2
        entries = set()
        for item in same_start:
            resolved = service.journey_timeline_by_id(
                conn,
                JourneyIdQuery(
                    filt=filt,
                    client_pseudonym=item["client_pseudonym"],
                    journey_start=datetime.fromisoformat(item["started_at"]),
                    journey_id=item["journey_id"],
                ),
                None,
            )
            entries.add(resolved["entry_path"])
        assert entries == {"/ua1-entry", "/ua2-entry"}
        # Offset spelling of the same instant resolves too.
        shifted = service.journey_timeline_by_id(
            conn,
            JourneyIdQuery(
                filt=filt,
                client_pseudonym=same_start[0]["client_pseudonym"],
                journey_start=datetime.fromisoformat("2026-10-27T12:00:00+02:00"),
                journey_id=same_start[0]["journey_id"],
            ),
            None,
        )
        assert shifted["entry_path"] == same_start[0]["entry_path"]
        # NULL versus empty-string agents for the second client resolve apart.
        null_item = next(i for i in listed["items"] if i["entry_path"] == "/null-entry")
        empty_item = next(i for i in listed["items"] if i["entry_path"] == "/empty-entry")
        assert null_item["journey_id"] != empty_item["journey_id"]
        for item in (null_item, empty_item):
            resolved = service.journey_timeline_by_id(
                conn,
                JourneyIdQuery(
                    filt=filt,
                    client_pseudonym=item["client_pseudonym"],
                    journey_start=datetime.fromisoformat(item["started_at"]),
                    journey_id=item["journey_id"],
                ),
                None,
            )
            assert resolved["entry_path"] == item["entry_path"]
    finally:
        conn.close()


def test_t2b_journey_id_rejects_unknown_and_out_of_scope(tmp_path):
    """Tampered IDs and narrower windows raise KeyError; no widening, no IP."""
    db, site = _id_db(tmp_path)
    filt = _filt(site, *_H_WINDOW)
    conn = connect(db, read_only=True)
    try:
        listed = service.journeys(conn, JourneyQuery(filt=filt), None)
        item = next(i for i in listed["items"] if i["entry_path"] == "/ua1-entry")
        bad_id = ("0" if item["journey_id"][0] != "0" else "1") + item["journey_id"][1:]
        with pytest.raises(KeyError):
            service.journey_timeline_by_id(
                conn,
                JourneyIdQuery(
                    filt=filt,
                    client_pseudonym=item["client_pseudonym"],
                    journey_start=datetime.fromisoformat(item["started_at"]),
                    journey_id=bad_id,
                ),
                None,
            )
        # A window starting after the journey holds no match: the
        # resolver never widens history to find it.
        narrow_filt = _filt(
            site,
            datetime(2026, 10, 27, 11, 0, tzinfo=UTC),
            datetime(2026, 10, 27, 12, 0, tzinfo=UTC),
        )
        with pytest.raises(KeyError):
            service.journey_timeline_by_id(
                conn,
                JourneyIdQuery(
                    filt=narrow_filt,
                    client_pseudonym=item["client_pseudonym"],
                    journey_start=datetime.fromisoformat(item["started_at"]),
                    journey_id=item["journey_id"],
                ),
                None,
            )
    finally:
        conn.close()
