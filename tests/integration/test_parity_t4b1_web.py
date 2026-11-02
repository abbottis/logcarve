"""T4b1 integration tests: performance/SEO/referrer report UI + T4a residuals.

Session-gated report pages over a temporary synthetic enriched store:
service/API/page agreement, every shared filter/sort/page/drilldown,
shown/total/truncation honesty, central locale keys, and the two
review-carried T4a residuals (IP-search form preserves the explorer
sort; bounded journeys/journey_entries evidence fits 1600 chars).
Synthetic data only; no browser here (repeatable Playwright slice in
tests/e2e).
"""

import re
from datetime import datetime
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from app.ai import service as ai_service
from app.ai.service import InvestigationError
from app.analytics import service as analytics_service
from app.analytics.contracts import AnalyticsFilter, JourneyQuery, SlowEndpointsQuery, TimeWindow
from app.analytics.rules import load_rules
from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user, issue_token
from app.db.database import connect, writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.sources import SourceConfig
from app.web.locales import load_catalog

ROOT = Path(__file__).resolve().parent.parent.parent
HMAC_KEY = b"t4b1-integration-hmac-key"
V4 = "203.0.113.20"
WINDOW_QS = "range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"
BASE = f"site=default&{WINDOW_QS}&tz=UTC"
FROM = datetime.fromisoformat("2026-10-27T00:00:00+00:00")
TO = datetime.fromisoformat("2026-10-28T00:00:00+00:00")
NOW = datetime.fromisoformat("2026-10-29T12:00:00+00:00")
MISSING = "-"
NO_UPSTREAM = '"-"'


def _line(host, stamp, method, path, status, referer, ua, cache, timing, mime, tls, upstream):
    return (
        f'{host} - - [{stamp}] "{method} {path} HTTP/1.1" {status} 128 '
        f'"{referer}" "{ua}" example.org {cache} {timing} {mime} {tls} {upstream}'
    )


def _seed_lines():
    browser, bot = "Browser/1.0", "GPTBot/1.0"
    return [
        _line(
            "198.51.100.7",
            "27/Oct/2026:10:00:00 +0000",
            "GET",
            "/fast",
            200,
            "-",
            browser,
            "HIT",
            "0.010",
            "text/html",
            "TLSv1.3",
            '"0.005"',
        ),
        _line(
            "198.51.100.7",
            "27/Oct/2026:10:01:00 +0000",
            "GET",
            "/fast",
            200,
            "-",
            browser,
            "HIT",
            "0.020",
            "text/html",
            "TLSv1.3",
            NO_UPSTREAM,
        ),
        _line(
            "198.51.100.8",
            "27/Oct/2026:10:02:00 +0000",
            "GET",
            "/slow",
            200,
            "-",
            browser,
            "MISS",
            "0.900",
            "application/json",
            "-",
            NO_UPSTREAM,
        ),
        _line(
            "198.51.100.9",
            "27/Oct/2026:10:03:00 +0000",
            "GET",
            "/bot-redir",
            301,
            "-",
            bot,
            "-",
            MISSING,
            "-",
            "-",
            NO_UPSTREAM,
        ),
        _line(
            "198.51.100.9",
            "27/Oct/2026:10:04:00 +0000",
            "GET",
            "/bot-gone",
            404,
            "https://external.example/page",
            bot,
            "-",
            MISSING,
            "-",
            "-",
            NO_UPSTREAM,
        ),
        _line(
            "198.51.100.10",
            "27/Oct/2026:10:05:00 +0000",
            "GET",
            "/gone",
            404,
            "http://example.org/start",
            browser,
            "-",
            MISSING,
            "-",
            "-",
            NO_UPSTREAM,
        ),
        _line(
            "198.51.100.10",
            "27/Oct/2026:10:06:00 +0000",
            "GET",
            "/ai-only",
            200,
            "-",
            bot,
            "-",
            "0.050",
            "text/html",
            "-",
            NO_UPSTREAM,
        ),
        _line(
            "198.51.100.10",
            "27/Oct/2026:10:07:00 +0000",
            "GET",
            "/shared",
            200,
            "-",
            bot,
            "-",
            "0.060",
            "text/html",
            "-",
            NO_UPSTREAM,
        ),
        _line(
            "198.51.100.7",
            "27/Oct/2026:10:08:00 +0000",
            "GET",
            "/shared",
            200,
            "-",
            browser,
            "-",
            "0.070",
            "text/html",
            "-",
            NO_UPSTREAM,
        ),
    ]


@pytest.fixture
def b1(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    monkeypatch.delenv("DEFAULT_TIMEZONE", raising=False)
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_text("\n".join(_seed_lines()) + "\n", encoding="utf-8")
    db = tmp_path / "t4b1.sqlite3"
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
        _, token = issue_token(conn, name="t4b1", site_id="default")
    from app.main import create_app

    client = TestClient(create_app(db_path=db, secure_cookies=False), raise_server_exceptions=False)
    login = client.post("/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"})
    assert login.status_code == 200
    return {"client": client, "csrf": login.json()["csrf_token"], "db": db, "token": token}


def _page(client, path, extra=""):
    url = f"{path}?{BASE}{extra}"
    response = client.get(url)
    assert response.status_code == 200, (url, response.text[:300])
    return response.text


def _filt(**overrides):
    return AnalyticsFilter(
        site_id="default", window=TimeWindow(time_from=FROM, time_to=TO), **overrides
    )


# --- Residual (a): the rendered IP-search form preserves explorer sort. ---


def test_ip_search_form_action_preserves_explorer_sort(b1):
    from urllib.parse import parse_qsl, urlsplit

    client = b1["client"]
    for sort in ("oldest", "path_asc"):
        html = _page(client, "/requests", f"&sort={sort}")
        match = re.search(r'<form method="post" action="([^"]*ip-search[^"]*)"', html)
        assert match, "IP search form missing"
        action = match.group(1).replace("&amp;", "&")
        query = dict(parse_qsl(urlsplit(action).query))
        assert urlsplit(action).path == "/requests/ip-search"
        assert query.get("sort") == sort
        assert query.get("site") == "default" and query.get("tz") == "UTC"


def test_ip_search_post_via_rendered_action_keeps_sort_and_pseudonym(b1):
    client = b1["client"]
    html = _page(client, "/requests", "&sort=oldest")
    match = re.search(r'<form method="post" action="([^"]*ip-search[^"]*)"', html)
    assert match, "IP search form missing"
    action = match.group(1).replace("&amp;", "&")
    assert "sort=oldest" in action
    response = client.post(
        action, data={"ip": V4, "csrf_token": b1["csrf"]}, follow_redirects=False
    )
    assert response.status_code == 303, response.text[:300]
    location = response.headers["location"]
    assert V4 not in location and "sort=oldest" in location and "client=" in location
    followed = client.get(location)
    assert followed.status_code == 200
    assert V4 not in followed.text


def test_page_specific_sort_never_leaks_into_shared_navigation(b1):
    html = _page(b1["client"], "/requests", "&sort=path_asc")
    nav = html.split('id="side-nav"')[1].split("</nav>")[0]
    # The active view keeps its full canonical state (including its own
    # page-local sort); every OTHER page link must stay sort-free so a
    # Requests sort can never break SEO or other views.
    import re as _re

    hrefs = _re.findall(r'href="([^"]+)"', nav)
    assert hrefs, "side nav links missing"
    others = [h for h in hrefs if not h.startswith("/requests")]
    assert others, "cross-page nav links missing"
    assert all("sort=" not in h for h in others), others
    assert any(h.startswith("/seo") for h in others)


# --- Residual (b): bounded journeys evidence fits the 1600-char bound. ---


def test_bounded_journey_reports_fit_evidence_bound_with_exact_scope(b1):
    conn = connect(b1["db"], read_only=True)
    try:
        target = conn.execute("SELECT client_pseudonym FROM requests LIMIT 1").fetchone()[0]
    finally:
        conn.close()
    assert len(target) == 64
    for report in ("journeys", "journey_entries"):
        try:
            outcome = ai_service._execute_bounded_tool(
                b1["db"],
                None,
                "get_report",
                {"report": report},
                site_id="default",
                source_id=None,
                time_from=FROM,
                time_to=TO,
                client=target,
                tool_index=0,
                investigation_id="residual",
                observation_time=NOW,
            )
        except InvestigationError as exc:
            pytest.fail(f"bounded {report} still exceeds its evidence bound: {exc}")
        line = outcome["history_line"]
        assert len(line) <= 1600, (report, len(line))
        assert outcome["arguments"]["client"] == target
        assert outcome["envelope"]["filters"]["client"] == target
        assert target in line  # the exact selected scope travels, never thinned
    # The full service payload keeps the exact long-form limitations.
    raw = connect(b1["db"], read_only=True)
    try:
        full = analytics_service.journeys(
            raw, JourneyQuery(filt=_filt(client=target, limit=100, offset=0)), None
        )
    finally:
        raw.close()
    assert any("1800 seconds" in note for note in full["limitations"])


# --- Performance page: shared service/API/page agreement. ---


def test_performance_page_agrees_with_service_and_api(b1):
    client = b1["client"]
    html = _page(client, "/performance")
    assert "Slow endpoints" in html and "Cache behavior" in html
    assert "Measured media type" in html and "HTTP versions" in html
    rules = load_rules(ROOT / "config" / "bot_rules.yaml").rules
    conn = connect(b1["db"], read_only=True)
    try:
        filt = _filt(limit=100, offset=0)
        overview = analytics_service.performance_overview(conn, filt, rules)
        slow = analytics_service.slow_endpoints(conn, SlowEndpointsQuery(filt=filt), rules)
    finally:
        conn.close()
    assert slow["total_paths"] == 4  # /fast, /slow, /ai-only, /shared are measured
    assert "/slow" in html and "/fast" in html
    assert f"of {slow['total_paths']}" in html
    assert str(overview["cache"]["hit_requests"]) in html
    api = client.get(
        "/api/v1/performance/slow-endpoints?site_id=default"
        "&from=2026-10-27T00%3A00%3A00%2B00%3A00&to=2026-10-28T00%3A00%3A00%2B00%3A00",
        headers={"Authorization": f"Bearer {b1['token']}"},
    )
    assert api.status_code == 200, api.text[:300]
    assert api.json()["total_paths"] == slow["total_paths"]


def test_performance_sorts_page_and_rank_server_side(b1):
    client = b1["client"]
    avg = _page(client, "/performance", "&sort=avg_desc")
    assert avg.index("/slow") < avg.index("/shared") < avg.index("/fast")
    p95 = _page(client, "/performance", "&sort=p95_desc")
    assert "/slow" in p95 and "/fast" in p95
    assert "P95" in p95 or "p95" in p95.lower()
    second = _page(client, "/performance", "&sort=avg_desc&limit=1&offset=1")
    assert (
        "of 4" in second and "/slow" not in second.split("Slow endpoints")[1].split("</table>")[0]
    )
    for bad in ("&sort=bogus", "&sort=oldest"):
        assert client.get(f"/performance?{BASE}{bad}").status_code == 400


def test_performance_shared_filters_apply(b1):
    html = _page(b1["client"], "/performance", "&timing_available=no")
    assert "/slow" not in html and "/fast" not in html
    assert "No measured timing" in html


def test_report_partials_serve_the_same_context(b1):
    client = b1["client"]
    for path, marker in (
        ("/partials/performance", "Slow endpoints"),
        ("/partials/seo?view=client_errors", "/bot-gone"),
        ("/partials/referrers?relation=external", "external.example"),
    ):
        response = client.get(f"{path}{'&' if '?' in path else '?'}{BASE}")
        assert response.status_code == 200, (path, response.text[:200])
        assert marker in response.text
        assert "nav.performance" not in response.text


# --- SEO page: views, drilldowns, caveats. ---


def test_seo_views_and_exact_drilldowns(b1):
    client = b1["client"]
    redirects = _page(client, "/seo", "&view=redirects")
    assert "/bot-redir" in redirects and "Bot redirects (3xx)" in redirects
    clients = _page(client, "/seo", "&view=client_errors")
    assert "/bot-gone" in clients
    servers = _page(client, "/seo", "&view=server_errors")
    assert "No groups" in servers
    only = _page(client, "/seo", "&view=redirects&path_exact=/bot-redir")
    assert "/bot-redir" in only and "/bot-gone" not in only
    assert "of 1" in only
    bot_only = _page(client, "/seo", "&view=client_errors&bot=bot-ai-gpt")
    assert "/bot-gone" in bot_only
    assert client.get(f"/seo?{BASE}&view=bogus").status_code == 400
    assert "/requests?" in redirects and "path_exact=" in redirects


def test_seo_ai_only_reports_universe_with_caveat(b1):
    html = _page(b1["client"], "/seo", "&view=ai_only")
    assert "AI-only observed paths" in html
    assert "observed absence, never proof of absence" in html
    assert "/ai-only" in html and "/shared" not in html
    assert "Comparison universe" in html
    assert "identity not verified" in html


# --- Referrers page: relations, full paths, honesty. ---


def test_referrers_relations_and_full_paths(b1):
    client = b1["client"]
    everything = _page(client, "/referrers")
    assert "https://external.example/page" in everything
    assert "http://example.org/start" in everything
    assert "Broken inbound links" in everything
    internal = _page(client, "/referrers", "&relation=internal")
    assert "http://example.org/start" in internal
    assert "external.example" not in internal
    external = _page(client, "/referrers", "&relation=external")
    assert "external.example" in external
    assert "example.org/start" not in external
    assert "Internal" in everything and "External" in everything
    assert "query values are never stored" in everything
    assert client.get(f"/referrers?{BASE}&relation=bogus").status_code == 400
    one = _page(client, "/referrers", "&path_exact=/gone")
    assert "/gone" in one and "of 1" in one


# --- Locale audit for every new visible key. ---


def test_new_templates_use_only_central_locale_keys():
    catalog = load_catalog("en")
    missing: list[str] = []
    partials = ROOT / "app" / "web" / "templates" / "partials"
    pages = ROOT / "app" / "web" / "templates" / "pages"
    for directory, name in (
        (partials, "performance_content.html"),
        (partials, "seo_content.html"),
        (partials, "referrers_content.html"),
        (pages, "performance.html"),
        (pages, "seo.html"),
        (pages, "referrers.html"),
    ):
        text = (directory / name).read_text(encoding="utf-8")
        for key in sorted(set(re.findall(r"""\bt\(\s*[\"']([\w.]+)[\"']""", text))):
            if key not in catalog:
                missing.append(f"{name}: {key}")
    assert missing == []
