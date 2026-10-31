"""T4 analytics tests: hand-calculated expectations over a fixed dataset.

21 synthetic Combined lines with independently derived UTC instants,
totals, buckets, claims and findings. Every number below was computed
by hand from the lines, not from the implementation.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.analytics import service
from app.analytics.contracts import AnalyticsFilter, TimeWindow, TopPathsQuery, TopReferrersQuery
from app.analytics.rules import load_rules
from app.db.backup import backup_database, restore_database
from app.db.database import connect
from app.db.importer import run_import
from app.ingestion.sources import SourceConfig

ROOT = Path(__file__).resolve().parent.parent.parent
HMAC_KEY = b"synthetic-test-hmac-key"
NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)
BOT_RULES = load_rules(ROOT / "config" / "bot_rules.yaml").rules
SEC_RULES = load_rules(ROOT / "config" / "security_rules.yaml").rules

LINES = [
    '203.0.113.10 - - [27/Oct/2026:10:00:00 +0100] "GET / HTTP/1.1" 200 100 "https://example.org/" "Mozilla/5.0"',
    '203.0.113.11 - - [27/Oct/2026:10:05:00 +0100] "GET / HTTP/1.1" 200 120 "https://example.org/" "Mozilla/5.0"',
    '203.0.113.12 - - [27/Oct/2026:10:10:00 +0100] "GET /about HTTP/1.1" 200 80 "-" "Mozilla/5.0"',
    '203.0.113.13 - - [27/Oct/2026:10:15:00 +0100] "GET /missing-page HTTP/1.1" 404 153 "https://example.org/old" "ExampleCrawler/1.0"',
    '203.0.113.14 - - [27/Oct/2026:10:20:00 +0100] "POST /api/events HTTP/2" 201 300 "-" "curl/8.0"',
    '203.0.113.15 - - [27/Oct/2026:10:25:00 +0100] "GET /.env HTTP/1.1" 404 50 "-" "Mozilla/5.0"',
    '203.0.113.16 - - [27/Oct/2026:10:30:00 +0100] "GET /.env HTTP/1.1" 404 50 "-" "Mozilla/5.0"',
    '203.0.113.17 - - [27/Oct/2026:10:35:00 +0100] "GET /wp-admin/ HTTP/1.1" 404 60 "-" "Mozilla/5.0"',
    '203.0.113.50 - - [27/Oct/2026:10:40:00 +0100] "GET /n1 HTTP/1.1" 404 10 "-" "test/1.0"',
    '203.0.113.50 - - [27/Oct/2026:10:41:00 +0100] "GET /n2 HTTP/1.1" 404 10 "-" "test/1.0"',
    '203.0.113.50 - - [27/Oct/2026:10:42:00 +0100] "GET /n3 HTTP/1.1" 404 10 "-" "test/1.0"',
    '203.0.113.50 - - [27/Oct/2026:10:43:00 +0100] "GET /n4 HTTP/1.1" 404 10 "-" "test/1.0"',
    '203.0.113.50 - - [27/Oct/2026:10:44:00 +0100] "GET /n5 HTTP/1.1" 404 10 "-" "test/1.0"',
    '203.0.113.20 - - [27/Oct/2026:11:00:00 +0100] "GET /style.css HTTP/1.1" 200 500 "-" "Googlebot/2.1"',
    '203.0.113.21 - - [27/Oct/2026:11:05:00 +0100] "GET /robots.txt HTTP/1.1" 200 60 "-" "GPTBot/1.0"',
    '203.0.113.22 - - [27/Oct/2026:05:05:00 -0400] "GET /equiv HTTP/1.1" 200 70 "-" "Mozilla/5.0"',
    '203.0.113.23 - - [27/Oct/2026:11:10:00 +0100] "GET /search?q=logcarve HTTP/1.1" 200 90 "-" "Mozilla/5.0"',
    '203.0.113.24 - - [27/Oct/2026:11:15:00 +0100] "GET /boom HTTP/1.1" 500 70 "-" "Mozilla/5.0"',
    '203.0.113.25 - - [27/Oct/2026:11:20:00 +0100] "GET /empty HTTP/1.1" 204 - "-" "Bingbot/2.0"',
    '203.0.113.26 - - [27/Oct/2026:11:25:00 +0100] "GET /x HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
    '203.0.113.27 - - [27/Oct/2026:11:26:00 +0100] "GET /x HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
]

WINDOW = TimeWindow(
    time_from=datetime(2026, 10, 27, 9, 0, 0, tzinfo=UTC),
    time_to=datetime(2026, 10, 27, 11, 0, 0, tzinfo=UTC),
)


@pytest.fixture
def analytics_db(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_text("\n".join(LINES) + "\n", encoding="utf-8")
    db = tmp_path / "analytics.sqlite3"
    run_import(
        db,
        source=SourceConfig(
            source_id="example-combined",
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="access.log",
        ),
        site_id="default",
        site_name="Example site",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="access.log",
        hmac_key=HMAC_KEY,
    )
    return db


def _filt(**overrides):
    base = {"site_id": "default", "window": WINDOW}
    base.update(overrides)
    return AnalyticsFilter(**base)


def _conn(db):
    return connect(db, read_only=True)


def test_summary_totals_and_missing_measurements(analytics_db):
    conn = _conn(analytics_db)
    try:
        summary = service.summarize(conn, _filt(), observation_time=NOW)
    finally:
        conn.close()
    assert summary["totals"] == {
        "requests": 21,
        "errors_4xx": 9,
        "errors_5xx": 1,
        "bytes_total": 1773,
        "bytes_measured": 20,
    }
    assert summary["status_distribution"] == [
        {"status": 200, "requests": 9},
        {"status": 201, "requests": 1},
        {"status": 204, "requests": 1},
        {"status": 404, "requests": 9},
        {"status": 500, "requests": 1},
    ]
    assert summary["duration"] == {
        "available": False,
        "measured": 0,
        "reason": "combined_sources_have_no_timing",
    }
    assert "average" not in summary["duration"] and "p50" not in summary["duration"]
    assert summary["generated_at"] == NOW.isoformat()


def test_top_paths_ties_and_pagination(analytics_db):
    conn = _conn(analytics_db)
    try:
        page1 = service.top_paths(conn, TopPathsQuery(filt=_filt(limit=2)))
        page2 = service.top_paths(conn, TopPathsQuery(filt=_filt(limit=2, offset=2)))
        errors = service.top_paths(conn, TopPathsQuery(filt=_filt(limit=2), sort="errors_desc"))
    finally:
        conn.close()
    assert page1["total_groups"] == 18
    assert [(i["path"], i["requests"]) for i in page1["items"]] == [("/", 2), ("/.env", 2)]
    assert [(i["path"], i["requests"]) for i in page2["items"]] == [("/x", 2), ("/about", 1)]
    assert errors["items"][0] == {"path": "/.env", "method": "GET", "requests": 2, "errors": 2}
    assert errors["items"][1]["path"] == "/boom"


def test_top_referrers_minimized(analytics_db):
    conn = _conn(analytics_db)
    try:
        result = service.top_referrers(conn, TopReferrersQuery(filt=_filt()))
    finally:
        conn.close()
    assert result["total_groups"] == 1
    assert result["items"] == [{"referer_host": "example.org", "requests": 3, "paths": 2}]


def test_hour_buckets_empty_windows_and_equivalent_instants(analytics_db):
    conn = _conn(analytics_db)
    try:
        result = service.timeseries(conn, _filt(), "hour")
        days = service.timeseries(conn, _filt(), "day")
        rows = (
            connect(analytics_db, read_only=True)
            .execute("SELECT ts_utc FROM requests WHERE path IN ('/', '/equiv') ORDER BY ts_utc")
            .fetchall()
        )
    finally:
        conn.close()
    by_bucket = {b["bucket"]: b for b in result["buckets"]}
    assert by_bucket["2026-10-27T09:00:00+00:00"] == {
        "bucket": "2026-10-27T09:00:00+00:00",
        "requests": 14,
        "errors": 9,
    }
    assert by_bucket["2026-10-27T10:00:00+00:00"] == {
        "bucket": "2026-10-27T10:00:00+00:00",
        "requests": 7,
        "errors": 1,
    }
    assert all(
        b["requests"] == 0 for b in result["buckets"] if b["bucket"] < "2026-10-27T09:00:00+00:00"
    )
    assert days["buckets"] == [
        {"bucket": "2026-10-27T00:00:00+00:00", "requests": 21, "errors": 10}
    ]
    assert [r[0] for r in rows] == [
        "2026-10-27T09:00:00+00:00",
        "2026-10-27T09:05:00+00:00",
        "2026-10-27T09:05:00+00:00",
    ]


def test_window_boundaries_and_empty_window(analytics_db):
    conn = _conn(analytics_db)
    try:
        edge = service.summarize(
            conn,
            _filt(
                window=TimeWindow(
                    time_from=datetime(2026, 10, 27, 9, 0, 0, tzinfo=UTC),
                    time_to=datetime(2026, 10, 27, 9, 5, 0, tzinfo=UTC),
                )
            ),
        )
        empty = service.summarize(
            conn,
            _filt(
                window=TimeWindow(
                    time_from=datetime(2026, 10, 28, tzinfo=UTC),
                    time_to=datetime(2026, 10, 29, tzinfo=UTC),
                )
            ),
        )
    finally:
        conn.close()
    assert edge["totals"]["requests"] == 1  # only the 09:00:00 instant; 09:05:00 is excluded
    assert edge["coverage"]["observed_min"] == "2026-10-27T09:00:00+00:00"
    assert empty["totals"]["requests"] == 0
    assert empty["coverage"]["observed_min"] is None
    assert empty["coverage"]["unique_events"] == 0


def test_crawler_claims_are_claims_not_identities(analytics_db):
    conn = _conn(analytics_db)
    try:
        claims = service.crawler_claims(conn, _filt(), BOT_RULES, observation_time=NOW)
        empty = service.crawler_claims(
            conn,
            _filt(
                window=TimeWindow(
                    time_from=datetime(2026, 10, 28, tzinfo=UTC),
                    time_to=datetime(2026, 10, 29, tzinfo=UTC),
                )
            ),
            BOT_RULES,
        )
    finally:
        conn.close()
    by_rule = {f.rule_id: f for f in claims}
    assert set(by_rule) == {"bot-search-google", "bot-ai-gpt", "bot-search-bing"}
    assert by_rule["bot-search-google"].counts == {"requests": 1, "distinct_agents": 1}
    for finding in claims:
        assert finding.rule_version == 1
        assert "not verified" in finding.meaning
        assert any("claimed identity only" in limit for limit in finding.limitations)
        assert finding.observation_time == NOW.isoformat()
        assert finding.window == {
            "time_from": "2026-10-27T09:00:00+00:00",
            "time_to": "2026-10-27T11:00:00+00:00",
        }
        assert finding.coverage_summary["unique_events"] == 21
    assert empty == []


def test_security_findings_with_evidence_and_limits(analytics_db):
    conn = _conn(analytics_db)
    try:
        findings = service.security_findings(conn, _filt(), SEC_RULES, observation_time=NOW)
    finally:
        conn.close()
    by_rule = {f.rule_id: f for f in findings}
    assert set(by_rule) == {"sec-sensitive-path", "sec-repeated-client-errors"}
    sensitive = by_rule["sec-sensitive-path"]
    assert sensitive.counts == {"requests": 3, "distinct_paths": 2}
    assert {p["path"] for p in sensitive.evidence["paths"]} == {"/.env", "/wp-admin/"}
    assert sensitive.severity == "candidate"
    assert any("investigation candidate" in limit for limit in sensitive.limitations)
    repeated = by_rule["sec-repeated-client-errors"]
    assert repeated.counts["errors"] == 5
    assert {p["path"] for p in repeated.evidence["sample_paths"]} == {
        "/n1",
        "/n2",
        "/n3",
        "/n4",
        "/n5",
    }
    assert repeated.coverage_summary["unique_events"] == 21


def test_coverage_never_double_counts_replays(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_text("\n".join(LINES) + "\n", encoding="utf-8")
    db = tmp_path / "replay.sqlite3"
    kwargs = {
        "source": SourceConfig(
            source_id="example-combined",
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="access.log",
        ),
        "site_id": "default",
        "site_name": "Example site",
        "site_hostname": "example.org",
        "server_type": "nginx",
        "path_alias": "access.log",
        "hmac_key": HMAC_KEY,
    }
    run_import(db, **kwargs)
    second = run_import(db, **kwargs)
    assert (second.records_inserted, second.records_replayed) == (0, 21)
    conn = _conn(db)
    try:
        summary = service.summarize(conn, _filt(), observation_time=NOW)
    finally:
        conn.close()
    assert summary["coverage"]["unique_events"] == 21
    assert summary["data_quality"]["import_attempts"] == {
        "lines_total": 42,
        "lines_accepted": 42,
        "lines_rejected": 0,
        "records_replayed": 21,
    }


def test_failed_import_is_flagged_provisional(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_text("\n".join(LINES) + "\n", encoding="utf-8")
    db = tmp_path / "failed.sqlite3"

    def crash_after_first_batch(index: int) -> None:
        if index == 1:
            raise RuntimeError("simulated crash")

    with pytest.raises(RuntimeError, match="simulated crash"):
        run_import(
            db,
            source=SourceConfig(
                source_id="example-combined",
                format_id="nginx_combined",
                allowed_root=root,
                relative_path="access.log",
            ),
            site_id="default",
            site_name="Example site",
            site_hostname="example.org",
            server_type="nginx",
            path_alias="access.log",
            hmac_key=HMAC_KEY,
            batch_size=10,
            after_batch=crash_after_first_batch,
        )
    conn = _conn(db)
    try:
        summary = service.summarize(conn, _filt(), observation_time=NOW)
    finally:
        conn.close()
    assert summary["coverage"]["unique_events"] == 10
    assert any("failed" in note for note in summary["warnings"])
    assert summary["data_quality"]["imports"][0]["status"] == "failed"


def test_backup_restore_equivalence(analytics_db, tmp_path):
    backup = backup_database(analytics_db, tmp_path / "snap.sqlite3")
    restored = restore_database(backup, tmp_path / "isolated" / "restored.sqlite3")
    for db in (analytics_db, restored):
        conn = _conn(db)
        try:
            summary = service.summarize(conn, _filt(), observation_time=NOW)
        finally:
            conn.close()
        assert summary["totals"]["requests"] == 21
        assert summary["coverage"]["unique_events"] == 21
    assert restored != analytics_db
