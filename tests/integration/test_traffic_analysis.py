"""Slice A: traffic classification, bot tables, explorer and panels.

30 hand-authored synthetic Combined lines with independently derived UTC
instants and totals. Every number below was computed by hand from the
lines, not from the implementation. Timestamps use +0100, so 10:00 local
is 09:00 UTC.
"""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.analytics import service
from app.analytics.classification import build_classifier, classify_one
from app.analytics.contracts import (
    AnalyticsFilter,
    BotTableQuery,
    ExplorerQuery,
    TimeWindow,
    TopPathsQuery,
)
from app.analytics.queries import traffic_case_sql
from app.analytics.rules import load_rules
from app.db.database import connect
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.sources import SourceConfig

ROOT = Path(__file__).resolve().parent.parent.parent
HMAC_KEY = b"synthetic-test-hmac-key"

LINES = [
    # browser_like: 13 rows (12 + query-stripping probe).
    '203.0.113.1 - - [27/Oct/2026:10:00:00 +0100] "GET / HTTP/1.1" 200 100 "https://example.org/" "Mozilla/5.0"',
    '203.0.113.1 - - [27/Oct/2026:10:10:00 +0100] "GET /style.css HTTP/1.1" 200 500 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"',
    '203.0.113.2 - - [27/Oct/2026:10:20:00 +0100] "GET /app.js HTTP/1.1" 200 300 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15"',
    '203.0.113.3 - - [27/Oct/2026:10:30:00 +0100] "GET /img/logo.png HTTP/1.1" 200 1200 "-" "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/604.1"',
    '203.0.113.4 - - [27/Oct/2026:11:00:00 +0100] "GET /fonts/x.woff2 HTTP/1.1" 200 800 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0"',
    '203.0.113.5 - - [27/Oct/2026:11:10:00 +0100] "GET /movie.mp4 HTTP/1.1" 200 5000 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/120.0"',
    '203.0.113.6 - - [27/Oct/2026:11:20:00 +0100] "GET /doc/manual.pdf HTTP/1.1" 200 900 "-" "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1)"',
    '203.0.113.7 - - [27/Oct/2026:11:30:00 +0100] "GET /data.json HTTP/1.1" 200 60 "-" "Mozilla/5.0"',
    '203.0.113.8 - - [27/Oct/2026:11:40:00 +0100] "GET /page HTTP/1.1" 200 70 "-" "Mozilla/5.0"',
    '203.0.113.9 - - [27/Oct/2026:11:50:00 +0100] "GET /other.xyz HTTP/1.1" 200 40 "-" "Mozilla/5.0"',
    '203.0.113.10 - - [27/Oct/2026:12:00:00 +0100] "POST /api/events HTTP/1.1" 201 300 "-" "Mozilla/5.0"',
    '203.0.113.11 - - [27/Oct/2026:12:10:00 +0100] "GET /boom HTTP/1.1" 500 70 "-" "Mozilla/5.0"',
    '203.0.113.40 - - [27/Oct/2026:10:45:00 +0100] "GET /search?q=logcarve HTTP/1.1" 200 90 "-" "Mozilla/5.0"',
    # claimed_bot: 8 rows.
    '203.0.113.20 - - [27/Oct/2026:10:05:00 +0100] "GET / HTTP/1.1" 200 100 "-" "Googlebot/2.1"',
    '203.0.113.21 - - [27/Oct/2026:10:06:00 +0100] "GET /robots.txt HTTP/1.1" 200 60 "-" "Googlebot/2.1"',
    '203.0.113.22 - - [27/Oct/2026:10:15:00 +0100] "GET /robots.txt HTTP/1.1" 200 60 "-" "Mozilla/5.0 GPTBot/1.0"',
    '203.0.113.23 - - [27/Oct/2026:10:16:00 +0100] "GET /sitemap.xml HTTP/1.1" 200 90 "-" "GPTBot/1.0"',
    '203.0.113.24 - - [27/Oct/2026:10:17:00 +0100] "GET /missing HTTP/1.1" 404 50 "-" "GPTBot/1.0"',
    '203.0.113.25 - - [27/Oct/2026:10:25:00 +0100] "GET /sitemap.xml HTTP/1.1" 200 90 "-" "Bingbot/2.0"',
    '203.0.113.26 - - [27/Oct/2026:10:26:00 +0100] "GET /empty HTTP/1.1" 204 - "-" "Bingbot/2.0"',
    '203.0.113.38 - - [27/Oct/2026:10:43:00 +0100] "GET /old HTTP/1.1" 301 20 "https://example.com/in" "Bingbot-test Googlebot/2.1"',
    # other_automation: 6 rows.
    '203.0.113.30 - - [27/Oct/2026:10:35:00 +0100] "POST /api/events HTTP/1.1" 201 300 "-" "curl/8.0"',
    '203.0.113.31 - - [27/Oct/2026:10:36:00 +0100] "GET / HTTP/1.1" 200 100 "-" "UptimeRobot/2.0"',
    '203.0.113.32 - - [27/Oct/2026:10:37:00 +0100] "GET /wp-admin/ HTTP/1.1" 404 60 "-" "SomeBot/1.0"',
    '203.0.113.33 - - [27/Oct/2026:10:38:00 +0100] "GET /.env HTTP/1.1" 404 50 "-" "ExampleCrawler/1.0"',
    '203.0.113.34 - - [27/Oct/2026:10:39:00 +0100] "GET /n8n-hook HTTP/1.1" 200 20 "-" "n8n/1.0"',
    '203.0.113.35 - - [27/Oct/2026:10:40:00 +0100] "GET / HTTP/1.1" 404 10 "-" "masscan/1.3"',
    # unknown: 3 rows (boundary UA, malicious UA, missing UA).
    '203.0.113.36 - - [27/Oct/2026:10:41:00 +0100] "GET /.env HTTP/1.1" 404 50 "-" "somen8nthing/1.0"',
    '203.0.113.37 - - [27/Oct/2026:10:42:00 +0100] "GET /.env HTTP/1.1" 404 50 "-" "<script>alert(1)</script>"',
    '203.0.113.39 - - [27/Oct/2026:10:44:00 +0100] "GET /null-ua HTTP/1.1" 200 30 "-" "-"',
]

WINDOW = TimeWindow(
    time_from=datetime(2026, 10, 27, 9, 0, 0, tzinfo=UTC),
    time_to=datetime(2026, 10, 28, 9, 0, 0, tzinfo=UTC),
)

VECTORS = {
    item["ua"]: item
    for item in json.loads(
        (ROOT / "tests" / "fixtures" / "expected" / "ua_vectors.json").read_text(encoding="utf-8")
    )["vectors"]
}


@pytest.fixture
def traffic_db(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_text("\n".join(LINES) + "\n", encoding="utf-8")
    db = tmp_path / "traffic.sqlite3"
    migrate(db)
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


@pytest.fixture(scope="module")
def rules():
    return load_rules(ROOT / "config" / "bot_rules.yaml").rules


def _filt(**overrides):
    base = {"site_id": "default", "window": WINDOW}
    base.update(overrides)
    return AnalyticsFilter(**base)


def test_sql_and_python_classifiers_agree_on_every_fixture_row(traffic_db, rules):
    clf = build_classifier(rules)
    conn = connect(traffic_db, read_only=True)
    try:
        rows = conn.execute("SELECT user_agent FROM requests").fetchall()
    finally:
        conn.close()
    assert len(rows) == 30
    for (stored,) in rows:
        index, traffic = classify_one(stored, clf)
        if stored is None:
            assert (index, traffic) == (None, "unknown")
            continue
        assert stored in VECTORS, stored
        expected_rule = VECTORS[stored]["rule"]
        expected_traffic = VECTORS[stored]["traffic"]
        got_rule = clf.rule_ids[index] if index is not None and index != clf.browser_index else None
        assert got_rule == expected_rule, stored
        assert traffic == expected_traffic, stored
        # SQL scalar agrees with the Python mirror on the same row.
        conn = connect(traffic_db, read_only=True)
        try:
            [[sql_index]] = conn.execute(
                "SELECT classify_ua(?, ?) WHERE 1 = 1", [stored, clf.spec]
            ).fetchall()
            case, params = traffic_case_sql(clf)
            [[sql_traffic]] = conn.execute(
                f"SELECT {case} FROM requests WHERE user_agent IS ? LIMIT 1",
                [*params, stored],
            ).fetchall()
        finally:
            conn.close()
        assert sql_index == index, stored
        assert sql_traffic == traffic, stored


def test_traffic_breakdown_sums_exactly_with_zero_filled_buckets(traffic_db, rules):
    conn = connect(traffic_db, read_only=True)
    try:
        result = service.traffic_breakdown(conn, _filt(), rules)
    finally:
        conn.close()
    by_bucket = {b["traffic"]: b for b in result["buckets"]}
    assert [b["traffic"] for b in result["buckets"]] == [
        "browser_like",
        "claimed_bot",
        "other_automation",
        "unknown",
    ]
    assert by_bucket["browser_like"] == {
        "traffic": "browser_like",
        "requests": 13,
        "errors_4xx": 0,
        "errors_5xx": 1,
        "bytes_total": 9430,
    }
    assert by_bucket["claimed_bot"]["requests"] == 8
    assert by_bucket["claimed_bot"]["errors_4xx"] == 1
    assert by_bucket["claimed_bot"]["errors_5xx"] == 0
    assert by_bucket["claimed_bot"]["bytes_total"] == 470
    assert by_bucket["other_automation"]["requests"] == 6
    assert by_bucket["other_automation"]["errors_4xx"] == 3
    assert by_bucket["other_automation"]["bytes_total"] == 540
    assert by_bucket["unknown"]["requests"] == 3
    assert by_bucket["unknown"]["errors_4xx"] == 2
    assert by_bucket["unknown"]["bytes_total"] == 130
    total = sum(b["requests"] for b in result["buckets"])
    assert total == result["coverage"]["unique_events"] == 30


def test_traffic_filter_changes_every_count(traffic_db, rules):
    conn = connect(traffic_db, read_only=True)
    try:
        summary = service.summarize(conn, _filt(traffic="claimed_bot"), rules)
        paths = service.top_paths(conn, TopPathsQuery(filt=_filt(traffic="claimed_bot")), rules)
    finally:
        conn.close()
    assert summary["totals"]["requests"] == 8
    assert paths["total_groups"] == 6
    assert {row["path"] for row in paths["items"]} == {
        "/",
        "/robots.txt",
        "/sitemap.xml",
        "/missing",
        "/empty",
        "/old",
    }


def test_bot_table_sorts_and_pages_deterministically(traffic_db, rules):
    conn = connect(traffic_db, read_only=True)
    try:
        table = service.bot_table(conn, BotTableQuery(filt=_filt()), rules)
    finally:
        conn.close()
    assert table["total_rules"] == 8
    by_id = {row["rule_id"]: row for row in table["items"]}
    assert set(by_id) == {
        "bot-search-google",
        "bot-ai-gpt",
        "bot-search-bing",
        "bot-auto-curl",
        "bot-mon-uptimerobot",
        "bot-suspected-generic",
        "bot-auto-n8n",
        "bot-auto-masscan",
    }
    assert by_id["bot-search-google"]["requests"] == 3
    assert by_id["bot-search-google"]["distinct_agents"] == 2
    assert by_id["bot-ai-gpt"]["requests"] == 3
    assert by_id["bot-search-bing"]["requests"] == 2
    assert by_id["bot-ai-gpt"]["provider"] == "OpenAI"
    assert by_id["bot-ai-gpt"]["purpose"] == "AI Crawler"
    assert by_id["bot-suspected-generic"]["requests"] == 2
    assert by_id["bot-mon-uptimerobot"]["traffic"] == "other_automation"
    # Default sort: requests desc with rule-id tie-breaks.
    assert [row["rule_id"] for row in table["items"]] == [
        "bot-ai-gpt",
        "bot-search-google",
        "bot-search-bing",
        "bot-suspected-generic",
        "bot-auto-curl",
        "bot-auto-masscan",
        "bot-auto-n8n",
        "bot-mon-uptimerobot",
    ]
    conn = connect(traffic_db, read_only=True)
    try:
        names = service.bot_table(conn, BotTableQuery(filt=_filt(), sort="name_asc"), rules)[
            "items"
        ]
        page = service.bot_table(conn, BotTableQuery(filt=_filt(limit=3, offset=3)), rules)
    finally:
        conn.close()
    assert [row["rule_id"] for row in names[:2]] == [
        "bot-search-bing",
        "bot-auto-curl",
    ]
    assert [row["rule_id"] for row in page["items"]] == [
        "bot-suspected-generic",
        "bot-auto-curl",
        "bot-auto-masscan",
    ]
    assert page["total_rules"] == 8


def test_bot_detail_counts_paths_robots_sitemap(traffic_db, rules):
    filt = _filt()
    conn = connect(traffic_db, read_only=True)
    try:
        detail = service.bot_detail(conn, filt, rules, "bot-ai-gpt")
    finally:
        conn.close()
    assert detail["counts"] == {
        "requests": 3,
        "errors_4xx": 1,
        "errors_5xx": 0,
        "bytes_total": 200,
        "distinct_agents": 2,
    }
    assert detail["top_paths"] == [
        {"path": "/missing", "status": 404, "requests": 1},
        {"path": "/robots.txt", "status": 200, "requests": 1},
        {"path": "/sitemap.xml", "status": 200, "requests": 1},
    ]
    assert detail["not_found"] == [{"path": "/missing", "status": 404, "requests": 1}]
    assert detail["robots_requests"] == 1
    assert detail["sitemap_requests"] == 1
    assert {entry["user_agent"] for entry in detail["sample_agents"]} == {
        "Mozilla/5.0 GPTBot/1.0",
        "GPTBot/1.0",
    }


def test_bot_detail_rejects_conflicting_path_selector(traffic_db, rules):
    conn = connect(traffic_db, read_only=True)
    try:
        with pytest.raises(ValueError):
            service.bot_detail(conn, _filt(bot="bot-ai-gpt"), rules, "bot-search-google")
        with pytest.raises(KeyError):
            service.bot_detail(conn, _filt(), rules, "bot-nope")
    finally:
        conn.close()


def test_explorer_newest_oldest_search_and_sanitization(traffic_db, rules):
    conn = connect(traffic_db, read_only=True)
    try:
        newest = service.request_explorer(conn, ExplorerQuery(filt=_filt(limit=2)), rules)
        oldest = service.request_explorer(
            conn, ExplorerQuery(filt=_filt(limit=1), sort="oldest"), rules
        )
        ua_search = service.request_explorer(conn, ExplorerQuery(filt=_filt(search="gpt")), rules)
        path_search = service.request_explorer(
            conn, ExplorerQuery(filt=_filt(search="robots")), rules
        )
        referrer_search = service.request_explorer(
            conn, ExplorerQuery(filt=_filt(search="example.com")), rules
        )
        query_probe = service.request_explorer(
            conn, ExplorerQuery(filt=_filt(search="logcarve")), rules
        )
        full = service.request_explorer(conn, ExplorerQuery(filt=_filt(limit=100)), rules)
    finally:
        conn.close()
    assert newest["total_rows"] == 30
    assert [row["path"] for row in newest["items"]] == ["/boom", "/api/events"]
    assert oldest["items"][0]["path"] == "/"
    assert oldest["items"][0]["traffic"] == "browser_like"
    assert {row["path"] for row in ua_search["items"]} == {
        "/robots.txt",
        "/sitemap.xml",
        "/missing",
    }
    assert ua_search["total_rows"] == 3
    assert {row["path"] for row in path_search["items"]} == {"/robots.txt"}
    assert {row["referer_host"] for row in referrer_search["items"]} == {"example.com"}
    # Query values are discarded at import: nothing stored, nothing searchable.
    assert query_probe["total_rows"] == 0
    assert any(row["path"] == "/search" for row in full["items"])
    for row in full["items"]:
        assert "203.0.113" not in "|".join(str(value or "") for value in row.values())
        assert row["user_agent"] is None or len(row["user_agent"]) <= 200
        assert "?" not in row["path"]


def test_explorer_pseudonym_search_round_trip(traffic_db, rules):
    conn = connect(traffic_db, read_only=True)
    try:
        full = service.request_explorer(conn, ExplorerQuery(filt=_filt(limit=100)), rules)
        pseudonym = full["items"][0]["client_pseudonym"]
        narrowed = service.request_explorer(
            conn, ExplorerQuery(filt=_filt(search=pseudonym)), rules
        )
    finally:
        conn.close()
    assert narrowed["total_rows"] >= 1
    assert {row["client_pseudonym"] for row in narrowed["items"]} == {pseudonym}


def test_browser_resource_heatmap_client_panels(traffic_db, rules):
    conn = connect(traffic_db, read_only=True)
    try:
        browsers = service.browser_breakdown(conn, _filt(), rules)
        resources = service.resource_breakdown(conn, _filt(), rules)
        heat = service.heatmap(conn, _filt(), rules, tz_name="Europe/Berlin")
        clients = service.client_top(conn, _filt(limit=5), rules)
    finally:
        conn.close()
    families = {entry["family"]: entry["requests"] for entry in browsers["families"]}
    assert families == {"Other": 8, "Safari": 2, "Chrome": 1, "Edge": 1, "Firefox": 1}
    systems = {entry["os"]: entry["requests"] for entry in browsers["systems"]}
    assert systems == {"Other": 7, "Windows": 3, "Linux": 1, "macOS": 1, "iOS": 1}
    by_kind = {entry["kind"]: entry for entry in resources["items"]}
    assert by_kind["page"]["requests"] == 15
    assert by_kind["page"]["bytes_total"] == 1320
    # Independently counted: one /data.json plus two /sitemap.xml.
    assert by_kind["data"]["requests"] == 3
    assert by_kind["data"]["bytes_total"] == 240
    assert by_kind["style"] == {"kind": "style", "requests": 1, "errors": 0, "bytes_total": 500}
    assert by_kind["media"]["bytes_total"] == 5000
    assert heat["timezone"] == "Europe/Berlin"
    assert heat["utc_buckets"] == 3
    assert heat["dst_merges"] == 0
    # 2026-10-27 is after the fall-back: Berlin is CET (+1).
    assert heat["matrix"][1][10] == 22
    assert heat["matrix"][1][11] == 6
    assert heat["matrix"][1][12] == 2
    assert sum(sum(week) for week in heat["matrix"]) == 30
    assert clients["total_clients"] == 29
    assert clients["items"][0]["requests"] == 2
    assert all(entry["requests"] == 1 for entry in clients["items"][1:])
    assert clients["items"][0]["first_seen"] is not None


def test_heatmap_dst_overlap_and_fractional_rejection(tmp_path, rules):
    from app.db.migrations_runner import migrate as migrate_db

    root = tmp_path / "logs"
    root.mkdir()
    lines = [
        # Berlin fall-back 2026: 02:00-02:59 occurs twice (CEST then CET).
        '203.0.113.1 - - [25/Oct/2026:02:15:00 +0200] "GET /a HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
        '203.0.113.2 - - [25/Oct/2026:02:15:00 +0100] "GET /b HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
        '203.0.113.3 - - [25/Oct/2026:04:15:00 +0100] "GET /c HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
    ]
    (root / "access.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    db = tmp_path / "dst.sqlite3"
    migrate_db(db)
    run_import(
        db,
        source=SourceConfig(
            source_id="example-combined",
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="access.log",
        ),
        site_id="default",
        site_name="s",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="access.log",
        hmac_key=HMAC_KEY,
    )
    filt = AnalyticsFilter(
        site_id="default",
        window=TimeWindow(
            time_from=datetime(2026, 10, 25, 0, 0, 0, tzinfo=UTC),
            time_to=datetime(2026, 10, 26, 0, 0, 0, tzinfo=UTC),
        ),
    )
    conn = connect(db, read_only=True)
    try:
        heat = service.heatmap(conn, filt, rules, tz_name="Europe/Berlin")
        assert heat["dst_merges"] == 1
        # 2026-10-25 is a Sunday; both fall-back hours share local hour 2.
        assert heat["matrix"][6][2] == 2
        assert heat["matrix"][6][4] == 1
        assert sum(sum(week) for week in heat["matrix"]) == 3
        with pytest.raises(ValueError):
            service.heatmap(conn, filt, rules, tz_name="Nope/Zone")
        with pytest.raises(ValueError):
            service.heatmap(conn, filt, rules, tz_name="Asia/Kathmandu")
    finally:
        conn.close()


def test_heatmap_two_ordinary_weeks_have_no_dst_merges(tmp_path, rules):
    from app.db.migrations_runner import migrate as migrate_db

    root = tmp_path / "logs"
    root.mkdir()
    lines = [
        '203.0.113.1 - - [13/Oct/2026:10:00:00 +0200] "GET /a HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
        '203.0.113.2 - - [20/Oct/2026:10:00:00 +0200] "GET /b HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
    ]
    (root / "access.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    db = tmp_path / "weeks.sqlite3"
    migrate_db(db)
    run_import(
        db,
        source=SourceConfig(
            source_id="example-combined",
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="access.log",
        ),
        site_id="default",
        site_name="s",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="access.log",
        hmac_key=HMAC_KEY,
    )
    filt = AnalyticsFilter(
        site_id="default",
        window=TimeWindow(
            time_from=datetime(2026, 10, 12, 0, 0, 0, tzinfo=UTC),
            time_to=datetime(2026, 10, 26, 0, 0, 0, tzinfo=UTC),
        ),
    )
    conn = connect(db, read_only=True)
    try:
        heat = service.heatmap(conn, filt, rules, tz_name="Europe/Berlin")
    finally:
        conn.close()
    assert heat["dst_merges"] == 0
    assert heat["matrix"][1][10] == 2


def test_exact_counts_beyond_five_thousand_distinct_agents(tmp_path, rules):
    from app.db.migrations_runner import migrate as migrate_db

    root = tmp_path / "logs"
    root.mkdir()
    lines = []
    for i in range(5001):
        ua = f"ProbeBot-{i}/1.0" if i % 2 == 0 else f"Mozilla/5.0 TestBrowser-{i}"
        lines.append(
            f'203.0.113.9 - - [27/Oct/2026:10:00:00 +0100] "GET /p{i} HTTP/1.1" 200 10 "-" "{ua}"'
        )
    (root / "access.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    db = tmp_path / "many.sqlite3"
    migrate_db(db)
    run_import(
        db,
        source=SourceConfig(
            source_id="example-combined",
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="access.log",
        ),
        site_id="default",
        site_name="s",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="access.log",
        hmac_key=HMAC_KEY,
    )
    filt = AnalyticsFilter(
        site_id="default",
        window=TimeWindow(
            time_from=datetime(2026, 10, 27, 9, 0, 0, tzinfo=UTC),
            time_to=datetime(2026, 10, 27, 10, 0, 0, tzinfo=UTC),
        ),
    )
    conn = connect(db, read_only=True)
    try:
        result = service.traffic_breakdown(conn, filt, rules)
        table = service.bot_table(conn, BotTableQuery(filt=filt), rules)
    finally:
        conn.close()
    by_bucket = {b["traffic"]: b for b in result["buckets"]}
    assert by_bucket["other_automation"]["requests"] == 2501
    assert by_bucket["browser_like"]["requests"] == 2500
    assert sum(b["requests"] for b in result["buckets"]) == 5001
    assert table["total_rules"] == 1
    assert table["items"][0]["rule_id"] == "bot-suspected-generic"
    assert table["items"][0]["requests"] == 2501
    assert table["items"][0]["distinct_agents"] == 2501
