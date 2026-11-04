"""T4b2 integration tests: journeys/entry-paths/timeline + expanded security UI.

Session-gated report pages over a temporary synthetic enriched store:
service/API/page agreement, every filter/sort/page/drilldown for the
new views, shown/total/truncation honesty, central locale keys,
evidence-link replay onto the proper pages, and the inherited
referrer host-only model-clarity regression. Synthetic data only; no
browser here (repeatable Playwright slice in tests/e2e).
"""

import re
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlsplit

import pytest
from starlette.testclient import TestClient

from app.ai import service as ai_service
from app.ai.tools import definitions as tool_defs
from app.analytics import service as analytics_service
from app.analytics.contracts import (
    AnalyticsFilter,
    JourneyIdQuery,
    JourneyQuery,
    TimeWindow,
)
from app.analytics.rules import load_rules
from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user, issue_token
from app.db.database import connect, writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.combined import pseudonymize_client
from app.ingestion.sources import SourceConfig
from app.web import evidence as evidence_mod
from app.web.locales import load_catalog

ROOT = Path(__file__).resolve().parent.parent.parent
HMAC_KEY = b"t4b2-integration-hmac-key"
BROWSER = "Browser/1.0"
WINDOW_QS = "range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"
BASE = f"site=default&{WINDOW_QS}&tz=UTC"
FROM = datetime.fromisoformat("2026-10-27T00:00:00+00:00")
TO = datetime.fromisoformat("2026-10-28T00:00:00+00:00")
NOW = datetime.fromisoformat("2026-10-29T12:00:00+00:00")
C1 = "198.51.100.21"
C3 = "198.51.100.23"


def _line(host, stamp, method, path, status, referer, ua="Browser/1.0"):
    return (
        f'{host} - - [{stamp}] "{method} {path} HTTP/1.1" {status} 128 '
        f'"{referer}" "{ua}" example.org - - - - "-"'
    )


def _seed_lines():
    lines = [
        # One client, two journeys: 10:00 + 5m continues, +35m splits.
        _line(C1, "27/Oct/2026:10:00:00 +0000", "GET", "/in", 200, "-"),
        _line(C1, "27/Oct/2026:10:05:00 +0000", "GET", "/mid", 200, "-"),
        _line(C1, "27/Oct/2026:10:40:00 +0000", "GET", "/late", 200, "-"),
        _line("198.51.100.22", "27/Oct/2026:11:00:00 +0000", "GET", "/other", 200, "-"),
        # Five 4xx from one client: repeated-client-errors offender.
        _line(C3, "27/Oct/2026:12:00:00 +0000", "GET", "/gone-1", 404, "-"),
        _line(C3, "27/Oct/2026:12:01:00 +0000", "GET", "/gone-2", 404, "-"),
        _line(C3, "27/Oct/2026:12:02:00 +0000", "GET", "/gone-3", 404, "-"),
        _line(C3, "27/Oct/2026:12:03:00 +0000", "GET", "/gone-4", 404, "-"),
        _line(C3, "27/Oct/2026:12:04:00 +0000", "GET", "/gone-5", 404, "-"),
        # Same-host different-path referrers for the host-only regression.
        _line("198.51.100.24", "27/Oct/2026:12:10:00 +0000", "GET", "/.env", 404, "-"),
        _line("198.51.100.24", "27/Oct/2026:12:11:00 +0000", "GET", "/.env", 404, "-"),
        _line("198.51.100.25", "27/Oct/2026:12:20:00 +0000", "GET", "/login", 401, "-"),
        _line("198.51.100.25", "27/Oct/2026:12:21:00 +0000", "GET", "/login", 401, "-"),
        _line("198.51.100.25", "27/Oct/2026:12:22:00 +0000", "GET", "/admin", 403, "-"),
        _line(
            "198.51.100.26",
            "27/Oct/2026:13:00:00 +0000",
            "GET",
            "/ok",
            200,
            "http://example.org/start",
        ),
        _line(
            "198.51.100.26",
            "27/Oct/2026:13:01:00 +0000",
            "GET",
            "/ok2",
            200,
            "http://example.org/other-page",
        ),
    ]
    return lines


@pytest.fixture
def b2(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    monkeypatch.delenv("DEFAULT_TIMEZONE", raising=False)
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_text("\n".join(_seed_lines()) + "\n", encoding="utf-8")
    db = tmp_path / "t4b2.sqlite3"
    migrate(db)
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
    run_import(
        db,
        source=SourceConfig(
            source_id="enriched",
            format_id="nginx_extended",
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
    with writer_transaction(db) as conn:
        _, token = issue_token(conn, name="t4b2", site_id="default")
    from app.main import create_app

    client = TestClient(create_app(db_path=db, secure_cookies=False), raise_server_exceptions=False)
    login = client.post("/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"})
    assert login.status_code == 200
    rules = (
        load_rules(ROOT / "config" / "bot_rules.yaml").rules
        + load_rules(ROOT / "config" / "security_rules.yaml").rules
    )
    return {"client": client, "db": db, "token": token, "rules": rules}


def _page(client, path, extra=""):
    url = f"{path}?{BASE}{extra}"
    response = client.get(url)
    assert response.status_code == 200, (url, response.text[:300])
    return response.text


def _filt(**overrides):
    base: dict = {"limit": 20, "offset": 0}
    base.update(overrides)
    return AnalyticsFilter(site_id="default", window=TimeWindow(time_from=FROM, time_to=TO), **base)


def _pseudo(ip):
    return pseudonymize_client(ip, HMAC_KEY)


# --- Journeys list: shared service/API/page agreement. ---


def test_journeys_page_agrees_with_service_and_api(b2):
    client = b2["client"]
    html = _page(client, "/journeys")
    assert "Technical request journeys" in html and "Window fit" in html
    assert "journeys-chart-data" in html
    conn = connect(b2["db"], read_only=True)
    try:
        svc = analytics_service.journeys(
            conn, JourneyQuery(filt=_filt(), sort="requests_desc"), b2["rules"]
        )
    finally:
        conn.close()
    assert svc["total_groups"] == 7
    assert f"of {svc['total_groups']}" in html
    first = svc["items"][0]
    assert first["entry_path"] == "/gone-1" and first["requests_shown"] == 5
    assert "/gone-1" in html and first["journey_id"][:12] in html
    api = client.get(
        "/api/v1/journeys?site_id=default"
        "&from=2026-10-27T00%3A00%3A00%2B00%3A00&to=2026-10-28T00%3A00%3A00%2B00%3A00"
        "&limit=100&offset=0&sort=requests_desc",
        headers={"Authorization": f"Bearer {b2['token']}"},
    )
    assert api.status_code == 200, api.text[:300]
    assert api.json()["total_groups"] == svc["total_groups"]
    assert api.json()["items"][0]["journey_id"] == first["journey_id"]


def test_journey_sorts_rank_server_side(b2):
    client = b2["client"]
    by_requests = _page(client, "/journeys", "&sort=requests_desc")
    assert by_requests.index("/gone-1") < by_requests.index("/login") < by_requests.index("/in")
    by_start = _page(client, "/journeys", "&sort=start_asc")
    assert by_start.index("/in") < by_start.index("/ok")
    by_latest = _page(client, "/journeys", "&sort=start_desc")
    assert "/ok" in by_latest
    assert by_latest.index("/ok") < by_latest.index("/in")
    by_duration = _page(client, "/journeys", "&sort=duration_desc")
    assert by_duration.index("/in") < by_duration.index("/gone-1") < by_duration.index("/login")
    for bad in ("bogus", "requests_asc"):
        response = client.get(f"/journeys?{BASE}&sort={bad}")
        assert response.status_code == 400, bad


def test_journey_min_requests_floor(b2):
    client = b2["client"]
    html = _page(client, "/journeys", "&min_requests=2")
    assert "of 5" in html
    assert "/late" not in html and "/other" not in html
    assert "/gone-1" in html and "/.env" in html
    for bad in ("0", "1001", "many"):
        response = client.get(f"/journeys?{BASE}&min_requests={bad}")
        assert response.status_code == 400, bad
    conn = connect(b2["db"], read_only=True)
    try:
        svc = analytics_service.journeys(
            conn,
            JourneyQuery(filt=_filt(), sort="requests_desc", min_requests=2),
            b2["rules"],
        )
    finally:
        conn.close()
    assert svc["total_groups"] == 5
    api = client.get(
        "/api/v1/journeys?site_id=default"
        "&from=2026-10-27T00%3A00%3A00%2B00%3A00&to=2026-10-28T00%3A00%3A00%2B00%3A00"
        "&limit=100&offset=0&min_requests=2",
        headers={"Authorization": f"Bearer {b2['token']}"},
    )
    assert api.status_code == 200
    assert api.json()["total_groups"] == 5


def test_journey_paging_and_client_filter(b2):
    client = b2["client"]
    first = _page(client, "/journeys", "&limit=2")
    assert "Showing 1–2 of 7" in first and "offset=2" in first
    second = _page(client, "/journeys", "&limit=2&offset=2")
    assert "Showing 3–4 of 7" in second
    assert "/gone-1" not in second
    target = _pseudo(C1)
    html = _page(client, "/journeys", f"&client={target}")
    assert "of 2" in html
    assert "/in" in html and "/late" in html and "/gone-1" not in html
    conn = connect(b2["db"], read_only=True)
    try:
        svc = analytics_service.journeys(conn, JourneyQuery(filt=_filt(client=target)), b2["rules"])
    finally:
        conn.close()
    assert svc["total_groups"] == 2


def test_journey_opaque_timeline_detail(b2):
    client = b2["client"]
    conn = connect(b2["db"], read_only=True)
    try:
        svc = analytics_service.journeys(
            conn, JourneyQuery(filt=_filt(), sort="requests_desc"), b2["rules"]
        )
    finally:
        conn.close()
    target = next(item for item in svc["items"] if item["entry_path"] == "/in")
    start_enc = quote(target["started_at"], safe="")
    html = _page(
        client,
        "/journeys",
        f"&journey_id={target['journey_id']}"
        f"&journey_client={target['client_pseudonym']}"
        f"&journey_start={start_enc}",
    )
    assert "Journey timeline" in html
    assert target["journey_id"] in html
    assert "/in" in html and "/mid" in html
    assert "Timeline sample table" in html
    # Complete timeline: no truncation note when shown covers the total.
    assert "Showing the first" not in html
    # Bounded timeline: a small page limit truncates honestly.
    conn = connect(b2["db"], read_only=True)
    try:
        sweep = analytics_service.journeys(
            conn, JourneyQuery(filt=_filt(), sort="requests_desc"), b2["rules"]
        )
    finally:
        conn.close()
    big = next(item for item in sweep["items"] if item["entry_path"] == "/gone-1")
    big_start = quote(big["started_at"], safe="")
    cut = _page(
        client,
        "/journeys",
        "&limit=2"
        f"&journey_id={big['journey_id']}"
        f"&journey_client={big['client_pseudonym']}"
        f"&journey_start={big_start}",
    )
    assert "Showing the first 2 of 5" in cut
    conn = connect(b2["db"], read_only=True)
    try:
        detail = analytics_service.journey_timeline_by_id(
            conn,
            JourneyIdQuery(
                filt=_filt(),
                client_pseudonym=target["client_pseudonym"],
                journey_start=datetime.fromisoformat(target["started_at"]),
                journey_id=target["journey_id"],
            ),
            b2["rules"],
        )
    finally:
        conn.close()
    assert detail["requests_shown"] == 2
    assert [row["path"] for row in detail["items"]] == ["/in", "/mid"]
    # Unknown opaque ID stays a scoped empty state, never a 500.
    missing = _page(
        client,
        "/journeys",
        "&journey_id=" + "0" * 64 + f"&journey_client={target['client_pseudonym']}"
        f"&journey_start={start_enc}",
    )
    assert "No journey matches that opaque ID" in missing
    # Partial selectors and malformed IDs reject instead of widening.
    assert client.get(f"/journeys?{BASE}&journey_id={target['journey_id']}").status_code == 400
    assert (
        client.get(f"/journeys?{BASE}&journey_id=xyz&journey_client=a&journey_start=b").status_code
        == 400
    )


# --- Entry paths share the eligible set and the floor. ---


def test_entry_paths_view_agrees_with_service_and_api(b2):
    client = b2["client"]
    html = _page(client, "/journeys", "&view=entries")
    assert "Entry paths" in html and "journey-entries-chart-data" in html
    conn = connect(b2["db"], read_only=True)
    try:
        svc = analytics_service.journey_entry_paths(conn, _filt(), b2["rules"], min_requests=1)
    finally:
        conn.close()
    assert svc["total_groups"] == 7
    assert "of 7" in html
    assert "/gone-1" in html
    api = client.get(
        "/api/v1/journeys/entry-paths?site_id=default"
        "&from=2026-10-27T00%3A00%3A00%2B00%3A00&to=2026-10-28T00%3A00%3A00%2B00%3A00"
        "&limit=100&offset=0&min_requests=1",
        headers={"Authorization": f"Bearer {b2['token']}"},
    )
    assert api.status_code == 200, api.text[:300]
    assert api.json()["total_groups"] == 7
    assert api.json()["items"][0]["entry_path"] in html
    floored = _page(client, "/journeys", "&view=entries&min_requests=2")
    assert "of 5" in floored
    for bad in ("bogus",):
        assert client.get(f"/journeys?{BASE}&view={bad}").status_code == 400


# --- Expanded security: rates, peaks, sequences, 401/403. ---


def test_security_page_expanded_evidence(b2):
    html = _page(b2["client"], "/security")
    assert "Findings by matching requests" in html
    assert "security-findings-chart-data" in html
    # 401 challenge honesty and the repeated 401/403 candidate.
    assert ">401<" in html and ">403<" in html
    assert "authentication challenge" in html
    assert "Average per minute" in html and "Peak UTC minute" in html
    assert "Chronological path sequence sample" in html
    assert "Gap from previous (s)" in html
    # Exact offender scope: the 5-error client with shown/total honesty.
    target = _pseudo(C3)
    assert target in html
    assert "Showing 5 of 5" in html
    assert "/gone-1" in html
    # Exact path and client drilldowns ride the shared filter scope.
    assert "path_exact=" in html and f"client={target}" in html
    # 401/403 aggregate candidate with exact counts.
    assert "/login" in html and "/admin" in html


def test_security_support_links_avoid_overview(b2):
    html = _page(b2["client"], "/security")
    hrefs = re.findall(
        r'<a class="link" href="([^"]+)">Open supporting data</a>', html.replace("&amp;", "&")
    )
    assert hrefs, "finding cards must carry supporting-data links"
    for href in hrefs:
        path = urlsplit(href).path
        assert path in ("/requests", "/errors", "/crawlers"), href
    query = dict(parse_qsl(urlsplit(hrefs[0]).query))
    assert query.get("site") == "default"


def test_security_service_api_page_counts_agree(b2):
    client = b2["client"]
    html = _page(client, "/security")
    conn = connect(b2["db"], read_only=True)
    try:
        findings = analytics_service.security_findings(conn, _filt(), b2["rules"])
    finally:
        conn.close()
    by_rule = {finding.rule_id: finding for finding in findings}
    assert by_rule["sec-repeated-client-errors"].counts == {"errors": 5, "distinct_paths": 5}
    assert by_rule["sec-sensitive-path"].counts == {"requests": 2, "distinct_paths": 1}
    assert by_rule["sec-auth-challenge-cluster"].counts == {"requests": 3, "distinct_paths": 2}
    assert "sec-repeated-auth-challenges" not in by_rule
    offender = next(
        finding for finding in findings if finding.rule_id == "sec-repeated-client-errors"
    )
    assert offender.evidence["peak_minute_requests"] >= 1
    assert offender.evidence["path_sequence_shown"] == offender.evidence["path_sequence_total"] == 5
    assert str(offender.evidence["peak_minute_requests"]) in html
    api = client.get(
        "/api/v1/security/findings?site_id=default"
        "&from=2026-10-27T00%3A00%3A00%2B00%3A00&to=2026-10-28T00%3A00%3A00%2B00%3A00",
        headers={"Authorization": f"Bearer {b2['token']}"},
    )
    assert api.status_code == 200, api.text[:300]
    assert api.json()["total"] == len(findings)


# --- Evidence links land on the proper pages with replayed scope. ---


def test_evidence_links_replay_on_proper_pages(b2):
    client = b2["client"]
    base_filters = {
        "site_id": "default",
        "time_from": FROM.isoformat(),
        "time_to": TO.isoformat(),
    }
    journeys_href = evidence_mod.envelope_href(
        "get_report", {**base_filters, "report": "journeys", "limit": 100, "offset": 0}
    )
    assert journeys_href is not None and journeys_href.startswith("/journeys?")
    assert "view=journeys" in journeys_href and "sort=requests_desc" in journeys_href
    assert "min_requests=1" in journeys_href
    entries_href = evidence_mod.envelope_href(
        "get_report", {**base_filters, "report": "journey_entries", "limit": 100, "offset": 0}
    )
    assert entries_href is not None and entries_href.startswith("/journeys?")
    assert "view=entries" in entries_href
    for href in (journeys_href, entries_href):
        replay = client.get(href)
        assert replay.status_code == 200, (href, replay.text[:300])
        assert "Request journeys" in replay.text
    sec_href = evidence_mod.envelope_href(
        "get_security_findings", {**base_filters, "limit": 100, "offset": 0}
    )
    assert sec_href is not None and sec_href.startswith("/security?")
    assert client.get(sec_href).status_code == 200


# --- Inherited model clarity: host-only URL-group samples. ---


def test_referrer_urls_projection_is_host_only_with_withheld_paths(b2):
    conn = connect(b2["db"], read_only=True)
    try:
        local = analytics_service.referrer_urls(conn, _filt(), b2["rules"])
    finally:
        conn.close()
    assert local["total_groups"] == 2
    outcome = ai_service._execute_bounded_tool(
        b2["db"],
        b2["rules"],
        "get_report",
        {"report": "referrer_urls"},
        site_id="default",
        source_id=None,
        time_from=FROM,
        time_to=TO,
        tool_index=0,
        investigation_id="t4b2-host-only",
        observation_time=NOW,
    )
    assert len(outcome["history_line"]) <= 1600
    line = outcome["history_line"]
    assert "host_sample" in line
    assert "withheld" in line
    assert "never host totals" in line
    # Both same-host groups arrive as repeated host-only samples ...
    assert line.count("example.org") >= 2
    # ... while the withheld source paths never reach the model.
    assert "/start" not in line and "/other-page" not in line
    assert outcome["envelope"]["result"]["total_groups"] == 2


# --- Locale audit for every new visible key. ---


def test_new_templates_use_only_central_locale_keys():
    catalog = load_catalog("en")
    missing: list[str] = []
    partials = ROOT / "app" / "web" / "templates" / "partials"
    pages = ROOT / "app" / "web" / "templates" / "pages"
    for directory, name in (
        (partials, "journeys_content.html"),
        (partials, "security_content.html"),
        (pages, "journeys.html"),
        (pages, "security.html"),
    ):
        text = (directory / name).read_text(encoding="utf-8")
        for key in sorted(set(re.findall(r"""\bt\(\s*[\"']([\w.]+)[\"']""", text))):
            if key not in catalog:
                missing.append(f"{name}: {key}")
    assert missing == []
    assert "referrer_urls" in tool_defs.REPORT_NAMES
