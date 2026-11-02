"""Stage B tests: sortable Requests explorer + conflicting-bot signal.

Hand-authored synthetic Combined lines only (TEST-NET addresses, no
real logs, no fixture edits). Every selected sort order is asserted
ascending AND descending with stable timestamp/id ties; paging,
filters, API-vs-service agreement, hostile sorts, cross-site/source
bounds, legacy newest/oldest stability and privacy are covered. The
conflicting-bot-identity candidate is verified positive (three shapes),
negative (single claims, same-provider variants, docs URLs, missing
and hostile agents), exact beyond 5000 distinct agents, bounded in
samples, and visible identically to the API and the typed AI tool
projection without leaking original IPs or full agents.
"""

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.ai.egress import serialize_evidence
from app.analytics import queries, service
from app.analytics.classification import build_classifier
from app.analytics.contracts import AnalyticsFilter, ExplorerQuery, TimeWindow
from app.analytics.rules import load_rules
from app.auth.tokens import create_admin_user, issue_token
from app.db.database import connect, writer_transaction
from app.db.importer import run_import
from app.ingestion.combined import pseudonymize_client
from app.ingestion.sources import SourceConfig

ROOT = Path(__file__).resolve().parent.parent.parent
HMAC_KEY = b"synthetic-test-hmac-key"
BOT_RULES = load_rules(ROOT / "config" / "bot_rules.yaml").rules
SEC_RULES = load_rules(ROOT / "config" / "security_rules.yaml").rules
RULES = BOT_RULES + SEC_RULES

WINDOW = TimeWindow(
    time_from=datetime(2026, 10, 27, 8, 0, 0, tzinfo=UTC),
    time_to=datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC),
)

UA_MOZILLA = "Mozilla/5.0"
UA_CURL = "curl/8.0"
UA_GOOGLE = "Mozilla/5.0 (compatible; Googlebot/2.1; +https://www.google.example/bot.html)"
UA_GOOGLE_BING = "Mozilla/5.0 (compatible; Googlebot/2.1; bingbot/2.0; +https://example.org/)"
UA_GPT_CLAUDE = "GPTBot/1.1 (+https://openai.example/) ClaudeBot/1.0"
UA_AHREFS_SEMRUSH = "AhrefsBot/7.0; SemrushBot/7~bl (+https://example.org/)"
UA_GOOGLE_VARIANTS = "Googlebot/2.1 Googlebot-Image/1.2"
UA_DOCS_URL = "SomeCrawler/1.0 (+https://example.com/googlebot-info)"
UA_LONG = "LongCrawler/9.9 " + "x" * 240


def _line(host, stamp, method, path, status, size=10, ua="test/1.0", referer="-"):
    return f'{host} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "{referer}" "{ua}"'


def _explorer_lines():
    # Six rows: ties (same UTC instant), lowercase method, NULL vs zero
    # bytes, bot claim, conflicting claim, query-bearing path.
    return [
        _line("203.0.113.10", "27/Oct/2026:10:00:00 +0100", "GET", "/b-path", 200, 100, UA_MOZILLA),
        _line("203.0.113.11", "27/Oct/2026:10:00:00 +0100", "GET", "/a-path", 200, 200, UA_MOZILLA),
        _line(
            "203.0.113.12",
            "27/Oct/2026:10:01:00 +0100",
            "get",
            "/lower?x=secret",
            404,
            "-",
            UA_CURL,
        ),
        _line(
            "203.0.113.13", "27/Oct/2026:10:02:00 +0100", "POST", "/submit", 500, 2048, UA_GOOGLE
        ),
        _line("203.0.113.10", "27/Oct/2026:10:03:00 +0100", "DELETE", "/item", 200, 0, UA_LONG),
        _line(
            "203.0.113.14",
            "27/Oct/2026:10:04:00 +0100",
            "GET",
            "/conflict",
            200,
            50,
            UA_GOOGLE_BING,
        ),
    ]


def _conflict_lines():
    return [
        _line("203.0.113.31", "27/Oct/2026:10:10:00 +0100", "GET", "/c1", 200, 10, UA_GOOGLE_BING),
        _line("203.0.113.32", "27/Oct/2026:10:11:00 +0100", "GET", "/c2", 200, 10, UA_GPT_CLAUDE),
        _line(
            "203.0.113.33", "27/Oct/2026:10:12:00 +0100", "GET", "/c3", 404, 10, UA_AHREFS_SEMRUSH
        ),
        _line("203.0.113.34", "27/Oct/2026:10:13:00 +0100", "GET", "/ok1", 200, 10, UA_GOOGLE),
        _line(
            "203.0.113.35", "27/Oct/2026:10:14:00 +0100", "GET", "/ok2", 200, 10, UA_GOOGLE_VARIANTS
        ),
        _line("203.0.113.36", "27/Oct/2026:10:15:00 +0100", "GET", "/ok3", 200, 10, UA_DOCS_URL),
        _line("203.0.113.37", "27/Oct/2026:10:16:00 +0100", "GET", "/ok4", 200, 10, UA_MOZILLA),
        _line("203.0.113.38", "27/Oct/2026:10:17:00 +0100", "GET", "/ok5", 200, 10, "-"),
    ]


def _import(db, name, site, lines, source_id=None):
    root = db.parent / f"logs_{name}"
    root.mkdir(exist_ok=True)
    (root / "access.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    run_import(
        db,
        source=SourceConfig(
            source_id=source_id or f"{name}-combined",
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="access.log",
        ),
        site_id=site,
        site_name=f"{site} site",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="access.log",
        hmac_key=HMAC_KEY,
    )


@pytest.fixture
def stage_b_db(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    db = tmp_path / "stage_b.sqlite3"
    _import(db, "explorer", "default", _explorer_lines())
    _import(db, "conflict", "default", _conflict_lines(), source_id="conflict-combined")
    _import(
        db,
        "other",
        "other",
        [
            _line(
                "203.0.113.99", "27/Oct/2026:10:00:00 +0100", "GET", "/s1", 200, 10, UA_GOOGLE_BING
            )
        ],
    )
    return db


def _filt(**overrides):
    base = {"site_id": "default", "window": WINDOW}
    base.update(overrides)
    return AnalyticsFilter(**base)


def _rows(db, filt, sort, limit=100, offset=0):
    conn = connect(db, read_only=True)
    try:
        clf = build_classifier(list(BOT_RULES))
        query = ExplorerQuery(
            filt=filt.model_copy(update={"limit": limit, "offset": offset}), sort=sort
        )
        return queries.request_rows(conn, query, clf)
    finally:
        conn.close()


def _paths(db, filt, sort, **page):
    items, total = _rows(db, filt, sort, **page)
    return [item["path"] for item in items], total


def test_every_sort_orders_exactly_with_stable_ties(stage_b_db):
    filt = _filt()
    sorts = (
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
    by_sort = {}
    for sort in sorts:
        paths, total = _paths(stage_b_db, filt, sort)
        assert total == 14, sort
        assert len(paths) == 14, sort
        by_sort[sort] = paths
    # Time sorts: the two 09:00 UTC rows tie; id order decides.
    assert by_sort["newest"] == [
        "/ok5",
        "/ok4",
        "/ok3",
        "/ok2",
        "/ok1",
        "/c3",
        "/c2",
        "/c1",
        "/conflict",
        "/item",
        "/submit",
        "/lower",
        "/a-path",
        "/b-path",
    ]
    assert by_sort["oldest"] == list(reversed(by_sort["newest"]))
    assert by_sort["time_desc"] == by_sort["newest"]
    assert by_sort["time_asc"] == by_sort["oldest"]
    # Method sorts are ASCII-ordered (uppercase before lowercase) with
    # timestamp/id ties; lowercase "get" sorts after every standard verb.
    assert by_sort["method_asc"] == [
        "/item",
        "/b-path",
        "/a-path",
        "/conflict",
        "/c1",
        "/c2",
        "/c3",
        "/ok1",
        "/ok2",
        "/ok3",
        "/ok4",
        "/ok5",
        "/submit",
        "/lower",
    ]
    assert by_sort["method_desc"] == [
        "/lower",
        "/submit",
        "/b-path",
        "/a-path",
        "/conflict",
        "/c1",
        "/c2",
        "/c3",
        "/ok1",
        "/ok2",
        "/ok3",
        "/ok4",
        "/ok5",
        "/item",
    ]
    # Path sorts are plain alphabetical in both directions.
    assert by_sort["path_asc"] == [
        "/a-path",
        "/b-path",
        "/c1",
        "/c2",
        "/c3",
        "/conflict",
        "/item",
        "/lower",
        "/ok1",
        "/ok2",
        "/ok3",
        "/ok4",
        "/ok5",
        "/submit",
    ]
    assert by_sort["path_desc"] == list(reversed(by_sort["path_asc"]))
    # Status sorts compare numbers, ties by timestamp/id.
    assert by_sort["status_asc"] == [
        "/b-path",
        "/a-path",
        "/item",
        "/conflict",
        "/c1",
        "/c2",
        "/ok1",
        "/ok2",
        "/ok3",
        "/ok4",
        "/ok5",
        "/lower",
        "/c3",
        "/submit",
    ]
    assert by_sort["status_desc"] == [
        "/submit",
        "/lower",
        "/c3",
        "/b-path",
        "/a-path",
        "/item",
        "/conflict",
        "/c1",
        "/c2",
        "/ok1",
        "/ok2",
        "/ok3",
        "/ok4",
        "/ok5",
    ]
    # Byte sorts are numeric with NULLs last in BOTH directions; zero
    # bytes sort first ascending and are distinct from NULL.
    assert by_sort["bytes_desc"] == [
        "/submit",
        "/a-path",
        "/b-path",
        "/conflict",
        "/c1",
        "/c2",
        "/c3",
        "/ok1",
        "/ok2",
        "/ok3",
        "/ok4",
        "/ok5",
        "/item",
        "/lower",
    ]
    assert by_sort["bytes_asc"] == [
        "/item",
        "/c1",
        "/c2",
        "/c3",
        "/ok1",
        "/ok2",
        "/ok3",
        "/ok4",
        "/ok5",
        "/conflict",
        "/b-path",
        "/a-path",
        "/submit",
        "/lower",
    ]
    # Client sorts follow pseudonym order, stable on timestamp/id ties.
    items, _ = _rows(stage_b_db, filt, "client_asc")
    got = [item["client_pseudonym"] for item in items]
    assert got == sorted(got)
    assert got[0] == min(
        pseudonymize_client(f"203.0.113.{n}", HMAC_KEY)
        for n in (10, 11, 12, 13, 14, 31, 32, 33, 34, 35, 36, 37, 38)
    )
    items, _ = _rows(stage_b_db, filt, "client_desc")
    assert [item["client_pseudonym"] for item in items] == sorted(got, reverse=True)


def test_paging_and_filters_apply_before_sorting(stage_b_db):
    filt = _filt()
    full, total = _paths(stage_b_db, filt, "bytes_desc")
    assert total == 14
    page, _ = _paths(stage_b_db, filt, "bytes_desc", limit=5, offset=5)
    assert page == full[5:10]
    last, _ = _paths(stage_b_db, filt, "bytes_desc", limit=5, offset=10)
    assert last == full[10:]
    # Filters narrow before the sort: status, method case, traffic.
    only_404, total = _paths(stage_b_db, _filt(status=404), "path_asc")
    assert total == 2 and only_404 == ["/c3", "/lower"]
    only_lower, total = _paths(stage_b_db, _filt(method="get"), "newest")
    assert total == 1 and only_lower == ["/lower"]
    bots, total = _paths(stage_b_db, _filt(traffic="claimed_bot"), "path_asc")
    # Googlebot singles, same-provider variants, all three conflict
    # pairs, and the docs-URL row (substring claim, unverified) classify
    # claimed by first match; nothing is unmasked by the signal.
    assert total == 8
    assert bots == ["/c1", "/c2", "/c3", "/conflict", "/ok1", "/ok2", "/ok3", "/submit"]
    # Search replays over sanitized fields only.
    searched, total = _paths(stage_b_db, _filt(search="conflict"), "newest")
    assert total == 1 and searched == ["/conflict"]


def test_cross_site_and_source_bounds(stage_b_db):
    other, total = _paths(stage_b_db, _filt(site_id="other"), "newest")
    assert total == 1 and other == ["/s1"]
    scoped, total = _paths(stage_b_db, _filt(source_id="conflict-combined"), "path_asc")
    assert total == 8 and scoped == ["/c1", "/c2", "/c3", "/ok1", "/ok2", "/ok3", "/ok4", "/ok5"]
    _, total = _paths(stage_b_db, _filt(source_id="explorer-combined"), "path_asc")
    assert total == 6
    # Unknown sites and foreign sources select nothing, never neighbours.
    missing, total = _paths(
        stage_b_db, _filt(site_id="other", source_id="conflict-combined"), "newest"
    )
    assert total == 0 and missing == []


def test_service_and_queries_agree_with_stable_legacy_sorts(stage_b_db):
    filt = _filt()
    conn = connect(stage_b_db, read_only=True)
    try:
        for sort in ("newest", "oldest", "bytes_desc", "status_asc", "path_desc"):
            query = ExplorerQuery(filt=filt, sort=sort)
            via_service = service.request_explorer(conn, query, RULES)
            clf = build_classifier(list(BOT_RULES))
            items, total = queries.request_rows(conn, query, clf)
            assert via_service["total_rows"] == total == 14
            assert via_service["sort"] == sort
            assert [row["path"] for row in via_service["items"]] == [row["path"] for row in items]
            for row in via_service["items"]:
                assert set(row) == {
                    "ts_utc",
                    "method",
                    "path",
                    "status",
                    "bytes",
                    "referer_host",
                    "user_agent",
                    "ua_truncated",
                    "client_pseudonym",
                    "traffic",
                    "rule_id",
                    "conflict",
                    # Approved SAFE per-request enrichment (PAR-03/T3).
                    "format_id",
                    "policy_version",
                    "referer_scheme",
                    "referer_path",
                    "server_host",
                    "http_version",
                    "request_time_ms",
                    "upstream_time_ms",
                    "upstream_count",
                    "cache_status",
                    "mime_type",
                    "tls_protocol",
                    "timing_available",
                    "upstream_available",
                    # T5a/PAR-09 offline country: safe ISO code plus
                    # lookup source/release/status, never an address.
                    "country_code",
                    "geo_source",
                    "geo_release",
                    "geo_status",
                }
    finally:
        conn.close()


def test_explorer_privacy_no_raw_leaks(stage_b_db):
    filt = _filt()
    conn = connect(stage_b_db, read_only=True)
    try:
        clf = build_classifier(list(BOT_RULES))
        items, _ = queries.request_rows(conn, ExplorerQuery(filt=filt, sort="newest"), clf)
    finally:
        conn.close()
    blob = " ".join(str(value) for row in items for value in row.values())
    assert "203.0.113" not in blob, "original IPs never leave storage"
    assert "x=secret" not in blob and "secret" not in blob, "query values are discarded"
    assert UA_LONG not in blob, "full agents never exposed"
    long_row = next(row for row in items if row["path"] == "/item")
    assert long_row["ua_truncated"] is True
    assert len(long_row["user_agent"]) == 200
    short_row = next(row for row in items if row["path"] == "/b-path")
    assert short_row["ua_truncated"] is False
    conflict_row = next(row for row in items if row["path"] == "/conflict")
    assert conflict_row["conflict"] is True
    assert conflict_row["rule_id"] == "bot-search-google", "first match still wins"
    assert conflict_row["traffic"] == "claimed_bot"
    single_row = next(row for row in items if row["path"] == "/ok1")
    assert single_row["conflict"] is False
    # The docs-URL row claims Googlebot by substring (unverified claim)
    # yet carries no conflicting identity: token boundaries plus URL
    # stripping keep the conservative signal silent.
    docs_row = next(row for row in items if row["path"] == "/ok3")
    assert docs_row["rule_id"] == "bot-search-google"
    assert docs_row["traffic"] == "claimed_bot"
    assert docs_row["conflict"] is False


def test_conflict_counts_exact_and_bounded_samples(stage_b_db):
    filt = _filt()
    conn = connect(stage_b_db, read_only=True)
    try:
        clf = build_classifier(list(BOT_RULES))
        totals = queries.conflict_counts(conn, filt, clf)
        # /conflict + c1 share one UA (Googlebot+bingbot), c2
        # (GPTBot+ClaudeBot), c3 (Ahrefs+Semrush): 4 rows, 3 agents.
        assert totals == {"requests": 4, "distinct_agents": 3}
        sample, total = queries.conflict_sample_agents(conn, filt, clf, limit=2)
        assert total == 3
        assert len(sample) == 2, "samples bounded with explicit shown/total"
        assert sample[0]["requests"] == 2, "shared agent counted twice"
        assert all(len(entry["user_agent"]) <= 200 for entry in sample)
        joined = " ".join(entry["user_agent"] for entry in sample)
        assert "203.0.113" not in joined
    finally:
        conn.close()


def test_security_findings_expose_conflict_candidate(stage_b_db):
    filt = _filt()
    conn = connect(stage_b_db, read_only=True)
    try:
        findings = service.security_findings(
            conn, filt, RULES, observation_time=datetime(2026, 10, 28, tzinfo=UTC)
        )
    finally:
        conn.close()
    by_rule = {finding.rule_id: finding for finding in findings}
    candidate = by_rule["sec-conflicting-bot-identity"]
    assert candidate.rule_version == 1
    assert candidate.category == "conflicting_bot_identity"
    assert candidate.counts == {"requests": 4, "distinct_agents": 3}
    assert candidate.evidence["agents_shown"] == 3
    assert candidate.evidence["agents_total"] == 3
    assert "never proof of a fake bot" in candidate.meaning
    assert "never a reason to block" in candidate.meaning
    assert candidate.filters["site_id"] == "default"
    assert set(candidate.window) == {"time_from", "time_to"}
    assert candidate.coverage_summary["unique_events"] == 14
    assert any("never proof of compromise" in limit for limit in candidate.limitations)
    assert any("claimed identity only" in limit for limit in candidate.limitations)
    # Honest scope: empty window yields no candidate, never a clean bill.
    conn = connect(stage_b_db, read_only=True)
    try:
        empty = service.security_findings(
            conn,
            AnalyticsFilter(
                site_id="default",
                window=TimeWindow(
                    time_from=datetime(2026, 10, 28, 12, tzinfo=UTC),
                    time_to=datetime(2026, 10, 28, 13, tzinfo=UTC),
                ),
            ),
            RULES,
            observation_time=datetime(2026, 10, 28, tzinfo=UTC),
        )
    finally:
        conn.close()
    assert "sec-conflicting-bot-identity" not in {finding.rule_id for finding in empty}


def test_conflict_respects_exact_scope(stage_b_db):
    conn = connect(stage_b_db, read_only=True)
    try:
        clf = build_classifier(list(BOT_RULES))
        narrow = queries.conflict_counts(conn, _filt(source_id="explorer-combined"), clf)
        assert narrow == {"requests": 1, "distinct_agents": 1}
        conflict_only = queries.conflict_counts(conn, _filt(source_id="conflict-combined"), clf)
        assert conflict_only == {"requests": 3, "distinct_agents": 3}
        other = queries.conflict_counts(conn, _filt(site_id="other"), clf)
        assert other == {"requests": 1, "distinct_agents": 1}
        windowed = queries.conflict_counts(
            conn,
            _filt(
                window=TimeWindow(
                    time_from=datetime(2026, 10, 27, 9, 5, tzinfo=UTC),
                    time_to=datetime(2026, 10, 27, 9, 8, tzinfo=UTC),
                )
            ),
            clf,
        )
        assert windowed == {"requests": 0, "distinct_agents": 0}
    finally:
        conn.close()


def test_ai_evidence_projection_keeps_conflict_counts_and_limits(stage_b_db):
    from dataclasses import asdict

    from app.ai.egress import project_evidence_summary

    filt = _filt()
    conn = connect(stage_b_db, read_only=True)
    try:
        findings = service.security_findings(
            conn, filt, RULES, observation_time=datetime(2026, 10, 28, tzinfo=UTC)
        )
    finally:
        conn.close()
    projected = serialize_evidence(
        "get_security_findings",
        {"items": [asdict(f) for f in findings], "total": len(findings)},
    )
    wire = project_evidence_summary(
        tool_name="get_security_findings",
        tool_call_id="call-conflict-1",
        minimized=projected,
        filters={"site_id": "default"},
        observation_time="2026-10-28T00:00:00+00:00",
        coverage={"unique_events": 14},
    )
    assert len(wire) <= 1600, "projection stays within existing caps"
    assert '"rule":"sec-conflicting-bot-identity"' in wire
    assert '"v":1' in wire
    assert '"requests":4' in wire, "named request counts travel, never zeroed"
    assert '"distinct_agents":3' in wire
    assert '"limited":true' in wire, "claim limitations retained"
    assert "203.0.113" not in wire and "Mozilla" not in wire, "no raw exfiltration"


def _stage_b_client(tmp_path, monkeypatch):
    from starlette.testclient import TestClient

    from app.main import create_app

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    db = tmp_path / "stage_b_web.sqlite3"
    _import(db, "explorer", "default", _explorer_lines())
    _import(db, "conflict", "default", _conflict_lines(), source_id="conflict-combined")
    from app.auth.passwords import hash_password

    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
        _, token = issue_token(conn, name="stage-b", site_id="default")
    client = TestClient(create_app(db_path=db, secure_cookies=False), raise_server_exceptions=False)
    response = client.post(
        "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
    )
    assert response.status_code == 200
    return client, token


WINDOW_QS = "range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"


def _req_paths(html):
    return re.findall(r'<td class="tech req-path">([^<]+)</td>', html)


def test_requests_page_has_eight_columns_and_sort_headers(tmp_path, monkeypatch):
    client, _ = _stage_b_client(tmp_path, monkeypatch)
    page = client.get(f"/requests?site=default&{WINDOW_QS}&tz=UTC").text
    assert "Sanitized request rows" in page
    # Eight readable columns in the requested front order.
    headers = re.findall(r'<th scope="col"[^>]*>(.*?)</th>', page, re.DOTALL)
    labels = [re.sub(r"<[^>]+>", "", header).strip() for header in headers]
    compact = [" ".join(label.split()) for label in labels]
    assert compact[0].startswith("Client")
    assert compact[1] == "Access"
    assert compact[2].startswith("Time (UTC)")
    assert compact[3] == "Method"
    assert compact[4] == "Path"
    assert compact[5] == "Status"
    assert compact[6] == "Bytes"
    assert compact[7] == "Details"
    # The default newest sort marks Time descending with a visible marker.
    assert 'aria-sort="descending"' in page
    assert "sorted descending" in page
    assert "sort=bytes_desc" in page and "sort=status_asc" in page
    # Every row carries a keyboard-operable Details toggle bound to its panel.
    toggles = re.findall(r"<button[^>]*data-detail-toggle[^>]*>", page)
    assert len(toggles) == 14, "one toggle per visible row"
    assert all('aria-expanded="false"' in toggle for toggle in toggles)
    controls = re.findall(r'aria-controls="([^"]+)"', "".join(toggles))
    assert len(set(controls)) == 14, "unique detail panels"
    for control in controls:
        assert f'<tr id="{control}" class="req-detail" hidden>' in page
    # Human status phrases and explicit byte units; NULL reads unavailable.
    assert "Not Found" in page and "Internal Server Error" in page
    assert "2.0 KiB" in page
    assert "unavailable" in page
    # Access signals: human badge, named bot without repeated prefix, conflict.
    assert "Browser-like" in page
    assert "Claimed " not in page
    assert "Potential conflicting identity" in page
    # Full pseudonym in details and titles; compact cell never leaks raw data.
    assert "203.0.113" not in page
    assert "x=secret" not in page


def test_requests_sort_links_change_actual_row_order(tmp_path, monkeypatch):
    client, _ = _stage_b_client(tmp_path, monkeypatch)
    base = f"/requests?site=default&{WINDOW_QS}&tz=UTC"
    default = _req_paths(client.get(base).text)
    assert default[0] == "/ok5"
    by_bytes = _req_paths(client.get(f"{base}&sort=bytes_desc").text)
    assert by_bytes[0] == "/submit" and by_bytes[-1] == "/lower"
    by_bytes_asc = _req_paths(client.get(f"{base}&sort=bytes_asc").text)
    assert by_bytes_asc[0] == "/item" and by_bytes_asc[-1] == "/lower"
    assert 'aria-sort="ascending"' in client.get(f"{base}&sort=path_asc").text
    by_status = _req_paths(client.get(f"{base}&sort=status_desc").text)
    assert by_status[0] == "/submit"
    # Paging keeps the sort and the full scope.
    page = client.get(f"{base}&sort=bytes_desc&limit=5&offset=5").text
    assert _req_paths(page) == by_bytes[5:10]
    assert "sort=bytes_desc" in page and "offset=10" in page
    # Hostile sorts reject instead of defaulting, on pages and fragments.
    assert client.get(f"{base}&sort=bogus").status_code == 400
    assert (
        client.get(f"/partials/requests?site=default&{WINDOW_QS}&tz=UTC&sort=bogus").status_code
        == 400
    )


def test_requests_details_carry_full_sanitized_context(tmp_path, monkeypatch):
    client, _ = _stage_b_client(tmp_path, monkeypatch)
    page = client.get(f"/requests?site=default&{WINDOW_QS}&tz=UTC").text
    # Detail panels span the table width and wrap internally.
    assert 'colspan="8"' in page
    # UTC instant plus shown time with offset travel together.
    assert "UTC instant" in page and "2026-10-27T09:00:00+00:00" in page
    # Truncated agents are labelled honestly; rule refs stay versioned.
    assert "truncated to 200 characters" in page
    assert "bot-search-google v1" in page
    # Timing from Combined sources is unavailable, never zero.
    assert "Response-time data unavailable" in page
    # No raw lines, IPs, query values or countries anywhere. The
    # allowlisted per-request HTTP version renders in its labelled
    # detail row, so the raw-line sentinel below pins the Combined
    # timestamp shape instead of the bare protocol token.
    assert "203.0.113" not in page and "[27/Oct/2026" not in page and "secret" not in page
    assert "HTTP version:" in page and "Logged host:" in page


def test_apply_refreshes_option_metadata_out_of_band(tmp_path, monkeypatch):
    client, _ = _stage_b_client(tmp_path, monkeypatch)
    full = client.get(f"/?site=default&{WINDOW_QS}&tz=UTC").text
    assert full.count('id="f-tz"') == 1, "exactly one timezone select per full page"
    assert full.count('id="filter-times-notice"') == 1
    winter = client.get(f"/partials/overview?site=default&{WINDOW_QS}&tz=Europe%2FBerlin").text
    assert "UTC+01:00" in winter
    summer_qs = "range=custom&from=2026-07-27T00:00:00%2B00:00&to=2026-07-28T00:00:00%2B00:00"
    summer = client.get(f"/partials/overview?site=default&{summer_qs}&tz=Europe%2FBerlin").text
    assert "UTC+02:00" in summer, "offset labels follow the applied window start"
    # The out-of-band selects carry the refreshed labels, not just the notice.
    oob = re.findall(
        r'<select id="f-tz"[^>]*hx-swap-oob="true"[^>]*>(.*?)</select>', summer, re.DOTALL
    )
    assert len(oob) == 1 and "UTC+02:00" in oob[0]
    assert 'id="f-method"' in summer and 'id="f-status"' in summer


def test_largest_responses_quick_view_sorts_individual_requests(tmp_path, monkeypatch):
    client, _ = _stage_b_client(tmp_path, monkeypatch)
    overview = client.get(f"/?site=default&{WINDOW_QS}&tz=UTC").text
    links = {
        label: url
        for url, label in re.findall(
            r'<a class="btn btn-outline btn-xs" href="([^"]+)">([^<]+)</a>', overview
        )
    }
    target = links["Largest responses"]
    assert "/requests?" in target
    assert "sort=bytes_desc" in target, "largest means individual responses by bytes"
    params = dict(re.findall(r"([a-z_]+)=([^&\"']+)", target))
    assert params.get("site") == "default" and params.get("offset") == "0"
    followed = client.get(target.replace("&amp;", "&")).text
    assert _req_paths(followed)[0] == "/submit"


def test_api_requests_sorts_agree_and_reject(tmp_path, monkeypatch):
    client, token = _stage_b_client(tmp_path, monkeypatch)
    auth = {"Authorization": f"Bearer {token}"}
    base = {
        "site_id": "default",
        "from": "2026-10-27T00:00:00+00:00",
        "to": "2026-10-28T00:00:00+00:00",
    }
    newest = client.get("/api/v1/requests", params={**base, "sort": "newest"}, headers=auth).json()
    assert newest["total_rows"] == 14 and newest["sort"] == "newest"
    assert newest["items"][0]["path"] == "/ok5"
    by_bytes = client.get(
        "/api/v1/requests", params={**base, "sort": "bytes_desc"}, headers=auth
    ).json()
    assert next(row["path"] for row in by_bytes["items"]) == "/submit"
    assert by_bytes["items"][0]["conflict"] is False, "single Googlebot claim is not a conflict"
    conflict_rows = [row for row in newest["items"] if row["conflict"]]
    assert len(conflict_rows) == 4, "API rows carry the same derived signal"
    assert all("203.0.113" not in str(row) for row in newest["items"])
    assert (
        client.get("/api/v1/requests", params={**base, "sort": "bogus"}, headers=auth).status_code
        == 400
    )
    denied = client.get("/api/v1/requests", params={**base, "site_id": "other"}, headers=auth)
    assert denied.status_code == 403
    # The deterministic findings endpoint carries the same candidate.
    findings = client.get("/api/v1/security/findings", params=base, headers=auth).json()
    conflict = next(
        item for item in findings["items"] if item["rule_id"] == "sec-conflicting-bot-identity"
    )
    assert conflict["counts"] == {"requests": 4, "distinct_agents": 3}
    assert conflict["rule_version"] == 1


def test_browser_family_edge_opera_before_chrome(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    edge_ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    )
    opera_ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0"
    )
    chrome_ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    db = tmp_path / "browser.sqlite3"
    _import(
        db,
        "browser",
        "default",
        [
            _line("203.0.113.41", "27/Oct/2026:10:00:00 +0100", "GET", "/e", 200, 10, edge_ua),
            _line("203.0.113.42", "27/Oct/2026:10:01:00 +0100", "GET", "/o", 200, 10, opera_ua),
            _line("203.0.113.43", "27/Oct/2026:10:02:00 +0100", "GET", "/c", 200, 10, chrome_ua),
        ],
    )
    conn = connect(db, read_only=True)
    try:
        filt = AnalyticsFilter(
            site_id="default",
            window=TimeWindow(
                time_from=datetime(2026, 10, 27, 8, tzinfo=UTC),
                time_to=datetime(2026, 10, 27, 12, tzinfo=UTC),
            ),
        )
        clf = build_classifier(list(BOT_RULES))
        parts = queries.browser_breakdown(conn, filt, clf)
    finally:
        conn.close()
    families = {row["family"]: row["requests"] for row in parts["families"]}
    assert families == {"Chrome": 1, "Edge": 1, "Opera": 1}, families


def test_many_distinct_conflicts_counted_exactly(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "many.sqlite3"
    lines = [
        _line(
            f"198.51.100.{(index % 250) + 1}",
            f"27/Oct/2026:10:{(index // 60) % 60:02d}:{index % 60:02d} +0100",
            "GET",
            f"/bulk{i}",
            200,
            10,
            f"Googlebot/2.1 bingbot/2.0 session-{i}",
        )
        for i, index in enumerate(range(5100))
    ]
    (tmp_path / "logs_many").mkdir()
    (tmp_path / "logs_many" / "access.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    run_import(
        db,
        source=SourceConfig(
            source_id="many-combined",
            format_id="nginx_combined",
            allowed_root=tmp_path / "logs_many",
            relative_path="access.log",
        ),
        site_id="default",
        site_name="default site",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="access.log",
        hmac_key=HMAC_KEY,
    )
    filt = _filt(limit=1000)
    conn = connect(db, read_only=True)
    try:
        clf = build_classifier(list(BOT_RULES))
        totals = queries.conflict_counts(conn, filt, clf)
        assert totals == {"requests": 5100, "distinct_agents": 5100}
        sample, total = queries.conflict_sample_agents(conn, filt, clf, limit=10)
        assert total == 5100 and len(sample) == 10
        # One page of the explorer stays bounded while totals stay exact.
        items, total_rows = queries.request_rows(
            conn,
            ExplorerQuery(filt=filt.model_copy(update={"limit": 100, "offset": 0}), sort="newest"),
            clf,
        )
        assert total_rows == 5100 and len(items) == 100
        assert all(item["conflict"] is True for item in items)
    finally:
        conn.close()
