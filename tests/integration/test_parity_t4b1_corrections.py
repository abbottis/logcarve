"""T4b1 review corrections: Apply-state, full referrer URLs, honest links, hrefs, labels."""

import re
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl

import pytest
from starlette.testclient import TestClient

from app.ai import service as ai_service
from app.ai.tools import definitions as tool_defs
from app.analytics import service as analytics_service
from app.analytics.contracts import AnalyticsFilter, SlowEndpointsQuery, TimeWindow
from app.analytics.rules import load_rules
from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user, issue_token
from app.db.database import connect, writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.sources import SourceConfig
from app.web import evidence as evidence_mod
from app.web.locales import load_catalog

ROOT = Path(__file__).resolve().parent.parent.parent
HMAC_KEY = b"t4b1-corrections-hmac-key"
WINDOW_QS = "range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"
BASE = f"site=default&{WINDOW_QS}&tz=UTC"
FROM = datetime.fromisoformat("2026-10-27T00:00:00+00:00")
TO = datetime.fromisoformat("2026-10-28T00:00:00+00:00")
NOW = datetime.fromisoformat("2026-10-29T12:00:00+00:00")


def _line(
    host,
    stamp,
    method,
    path,
    status,
    size,
    referer,
    ua,
    cache="-",
    timing="-",
    mime="-",
    tls="-",
    upstream='"-"',
):
    return (
        f'{host} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} '
        f'"{referer}" "{ua}" example.org {cache} {timing} {mime} {tls} {upstream}'
    )


def _seed_lines():
    b, bot = "Browser/1.0", "GPTBot/1.0"
    lines = [
        # Same hostname, different source paths + http/https to same 404 target.
        _line(
            "198.51.100.7",
            "27/Oct/2026:10:00:00 +0000",
            "GET",
            "/missing",
            404,
            128,
            "https://source.example/a",
            b,
            "-",
            "0.010",
        ),
        _line(
            "198.51.100.7",
            "27/Oct/2026:10:01:00 +0000",
            "GET",
            "/missing",
            404,
            128,
            "https://source.example/b",
            b,
            "-",
            "0.011",
        ),
        _line(
            "198.51.100.8",
            "27/Oct/2026:10:02:00 +0000",
            "GET",
            "/missing",
            404,
            128,
            "http://source.example/a",
            b,
            "-",
            "0.012",
        ),
        # Ordinary 2xx/304 referrals with known https paths.
        _line(
            "198.51.100.9",
            "27/Oct/2026:10:03:00 +0000",
            "GET",
            "/ordinary-0",
            200,
            256,
            "https://origin.example/ordinary-source-0",
            b,
            "HIT",
            "0.020",
            "text/html",
            "TLSv1.3",
        ),
        _line(
            "198.51.100.9",
            "27/Oct/2026:10:04:00 +0000",
            "GET",
            "/ordinary-1",
            200,
            512,
            "https://origin.example/ordinary-source-1",
            b,
            "MISS",
            "0.030",
            "text/html",
            "TLSv1.3",
        ),
        _line(
            "198.51.100.9",
            "27/Oct/2026:10:05:00 +0000",
            "GET",
            "/cached",
            304,
            0,
            "https://origin.example/ordinary-source-0",
            b,
            "HIT",
            "0.005",
        ),
        # Internal alias referrer (shop.example.org is a configured alias).
        _line(
            "198.51.100.10",
            "27/Oct/2026:10:06:00 +0000",
            "GET",
            "/internal-page",
            200,
            128,
            "https://shop.example.org/sale",
            b,
            "-",
            "0.015",
        ),
        # Missing referer stays out of both referrer reports.
        _line(
            "198.51.100.11",
            "27/Oct/2026:10:07:00 +0000",
            "GET",
            "/noref",
            200,
            128,
            "-",
            b,
            "-",
            "0.016",
        ),
        # Host-only legacy metadata (no path) + query-secret referrer.
        _line(
            "198.51.100.12",
            "27/Oct/2026:10:08:00 +0000",
            "GET",
            "/legacy",
            200,
            128,
            "http://legacy.example",
            b,
            "-",
            "0.017",
        ),
        _line(
            "198.51.100.13",
            "27/Oct/2026:10:09:00 +0000",
            "GET",
            "/secret-target",
            200,
            128,
            "https://origin.example/page?token=secret123&x=1",
            b,
            "-",
            "0.018",
        ),
        # Unknown bytes (NCSA "-" size) on a referred 200.
        _line(
            "198.51.100.14",
            "27/Oct/2026:10:10:00 +0000",
            "GET",
            "/unknown-bytes",
            200,
            "-",
            "https://origin.example/ordinary-source-1",
            b,
            "-",
            "0.019",
        ),
        # Bot 404 for the SEO contradictory-filter check.
        _line(
            "198.51.100.15",
            "27/Oct/2026:10:11:00 +0000",
            "GET",
            "/bot-gone",
            404,
            128,
            "https://external.example/page",
            bot,
        ),
    ]
    return lines


@pytest.fixture
def cx(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    monkeypatch.delenv("DEFAULT_TIMEZONE", raising=False)
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_text("\n".join(_seed_lines()) + "\n", encoding="utf-8")
    db = tmp_path / "t4b1c.sqlite3"
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
            allowed_hosts=["example.org", "shop.example.org"],
        ),
        site_id="default",
        site_name="s",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="access.log",
        hmac_key=HMAC_KEY,
    )
    with writer_transaction(db) as conn:
        _, token = issue_token(conn, name="t4b1c", site_id="default")
    from app.main import create_app

    client = TestClient(create_app(db_path=db, secure_cookies=False), raise_server_exceptions=False)
    login = client.post("/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"})
    assert login.status_code == 200
    return {"client": client, "db": db, "token": token}


def _page(client, path, extra=""):
    url = f"{path}?{BASE}{extra}"
    response = client.get(url)
    assert response.status_code == 200, (url, response.status_code, response.text[:400])
    return response.text


def _filt(**overrides):
    return AnalyticsFilter(
        site_id="default", window=TimeWindow(time_from=FROM, time_to=TO), **overrides
    )


# --- Issue 1: page-local state survives Apply/canonical/history. ---


def test_filter_bar_carries_page_local_state(cx):
    html = _page(cx["client"], "/performance", "&sort=p95_desc")
    assert 'name="sort" value="p95_desc"' in html
    assert "sort=p95_desc" in html  # canonical/side-nav active state
    seo = _page(cx["client"], "/seo", "&view=ai_only")
    assert 'name="view" value="ai_only"' in seo
    assert "view=ai_only" in seo
    ref = _page(cx["client"], "/referrers", "&view=broken&relation=external")
    assert 'name="view" value="broken"' in ref
    assert 'name="relation" value="external"' in ref
    assert "view=broken" in ref and "relation=external" in ref


def test_partial_apply_preserves_page_local_in_push_url(cx):
    client = cx["client"]
    # Serialize the actual rendered #filter-bar successful controls to hx-get.
    html = _page(client, "/performance", "&sort=p95_desc")
    m = re.search(r'<form id="filter-bar"[^>]*hx-get="([^"]+)"', html)
    assert m, "filter bar must htmx-GET its fragment"
    fragment = m.group(1)
    assert fragment == "/partials/performance"
    inputs = dict(re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', html))
    selects = dict(
        re.findall(
            r'<select[^>]*name="([^"]+)"[^>]*>.*?<option value="([^"]*)" selected', html, re.DOTALL
        )
    )
    params = {**inputs, **selects}
    assert params.get("sort") == "p95_desc"
    for base_path, fragment_path, marker in (
        ("/performance", "/partials/performance", "Slow endpoints"),
        ("/seo", "/partials/seo", "Bot redirects"),
        ("/referrers", "/partials/referrers", "Referrer view"),
    ):
        page_html = _page(
            client,
            base_path,
            "&sort=p95_desc"
            if base_path == "/performance"
            else ("&view=ai_only" if base_path == "/seo" else "&view=broken&relation=external"),
        )
        form = re.search(r'<form id="filter-bar".*?</form>', page_html, re.DOTALL)
        assert form
        serialized = dict(re.findall(r'name="([^"]+)" value="([^"]*)"', form.group(0)))
        for sel in re.finditer(
            r'<select[^>]*name="([^"]+)"[^>]*>(.*?)</select>', form.group(0), re.DOTALL
        ):
            name, body = sel.group(1), sel.group(2)
            opt = re.search(r'<option value="([^"]*)" selected', body)
            if opt:
                serialized[name] = opt.group(1)
        query = dict(
            parse_qsl(
                f"site=default&{WINDOW_QS}&tz=UTC&"
                + "&".join(f"{k}={v}" for k, v in serialized.items() if v != "")
            )
        )
        # Every serialized control replays through the partial endpoint.
        from urllib.parse import urlencode

        partial = client.get(f"{fragment_path}?{urlencode(query)}")
        assert partial.status_code == 200, (fragment_path, partial.text[:300])
        push = partial.headers.get("HX-Push-Url", "")
        assert marker in partial.text or "Slow endpoints" in partial.text
        if base_path == "/performance":
            assert "sort=p95_desc" in push, push
        elif base_path == "/seo":
            assert "view=ai_only" in push, push
        else:
            assert "view=broken" in push and "relation=external" in push, push


def test_paging_and_variant_links_keep_page_local(cx):
    html = _page(cx["client"], "/performance", "&sort=p95_desc&limit=1")
    assert "sort=p95_desc" in html
    assert "sort%3Dp95_desc" not in html or "sort=p95_desc" in html
    seo = _page(cx["client"], "/seo", "&view=ai_only")
    assert "view=ai_only" in seo
    ref = _page(cx["client"], "/referrers", "&view=all&relation=external")
    assert "relation=external" in ref and "view=all" in ref


# --- Issue 2: full sanitized referrer-URL overview. ---


def test_referrer_urls_service_api_ui_agree(cx):
    client, rules = cx["client"], load_rules(ROOT / "config" / "bot_rules.yaml").rules
    conn = connect(cx["db"], read_only=True)
    try:
        filt = _filt(limit=100, offset=0)
        svc = analytics_service.referrer_urls(conn, filt, rules)
    finally:
        conn.close()
    # Ordinary 2xx/304 referrals are present (404-only page missed them).
    hosts = {(r["referer_host"], r["referer_path"]) for r in svc["items"]}
    assert ("origin.example", "/ordinary-source-0") in hosts
    assert ("origin.example", "/ordinary-source-1") in hosts
    # Same hostname, different source paths and http/https stay distinct.
    src_paths = {
        (r["referer_scheme"], r["referer_path"])
        for r in svc["items"]
        if r["referer_host"] == "source.example"
    }
    assert ("https", "/a") in src_paths and ("https", "/b") in src_paths
    assert ("http", "/a") in src_paths
    # Internal alias labelling.
    alias = [r for r in svc["items"] if r["referer_host"] == "shop.example.org"]
    assert alias and all(r["internal"] for r in alias)
    ext = [r for r in svc["items"] if r["referer_host"] == "external.example"]
    assert ext and all(not r["internal"] for r in ext)
    # API agrees exactly.
    api = client.get(
        "/api/v1/referrers/urls?site_id=default"
        "&from=2026-10-27T00%3A00%3A00%2B00%3A00&to=2026-10-28T00%3A00%3A00%2B00%3A00",
        headers={"Authorization": f"Bearer {cx['token']}"},
    )
    assert api.status_code == 200, api.text[:300]
    assert api.json()["total_groups"] == svc["total_groups"]
    assert api.json()["items"] == [
        {
            k: r[k]
            for k in (
                "referer_host",
                "referer_scheme",
                "referer_path",
                "requests",
                "errors",
                "bytes_total",
                "bytes_known",
                "internal",
            )
        }
        for r in svc["items"]
    ]
    # Web all view agrees; broken view retained.
    all_html = _page(client, "/referrers", "&view=all")
    assert "All referring pages" in all_html
    assert "/ordinary-source-0" in all_html and "/ordinary-source-1" in all_html
    broken = _page(client, "/referrers", "&view=broken")
    assert "Broken inbound links" in broken and "/missing" in broken
    # Query secrets never appear; unknown bytes stay honest.
    assert "secret123" not in all_html and "secret123" not in api.text
    assert "token=" not in all_html
    assert "—" in all_html  # unknown bytes render as em dash
    # Missing referer never enters either report.
    assert svc["total_groups"] == api.json()["total_groups"]
    assert all(r["referer_host"] for r in svc["items"])


def test_referrer_urls_paging_stable_and_filtered(cx):
    client = cx["client"]
    first = client.get(
        "/api/v1/referrers/urls?site_id=default"
        "&from=2026-10-27T00%3A00%3A00%2B00%3A00&to=2026-10-28T00%3A00%3A00%2B00%3A00"
        "&limit=1&offset=0",
        headers={"Authorization": f"Bearer {cx['token']}"},
    )
    second = client.get(
        "/api/v1/referrers/urls?site_id=default"
        "&from=2026-10-27T00%3A00%3A00%2B00%3A00&to=2026-10-28T00%3A00%3A00%2B00%3A00"
        "&limit=1&offset=1",
        headers={"Authorization": f"Bearer {cx['token']}"},
    )
    assert first.status_code == 200 and second.status_code == 200
    assert first.json()["items"] != second.json()["items"]
    assert first.json()["total_groups"] == second.json()["total_groups"]
    internal = client.get(
        "/api/v1/referrers/urls?site_id=default"
        "&from=2026-10-27T00%3A00%3A00%2B00%3A00&to=2026-10-28T00%3A00%3A00%2B00%3A00"
        "&relation=internal",
        headers={"Authorization": f"Bearer {cx['token']}"},
    )
    assert internal.status_code == 200
    assert internal.json()["items"]
    assert all(r["internal"] for r in internal.json()["items"])


def test_referrer_api_negatives_and_offline(cx):
    client = cx["client"]
    good_qs = (
        "site_id=default&from=2026-10-27T00%3A00%3A00%2B00%3A00"
        "&to=2026-10-28T00%3A00%3A00%2B00%3A00"
    )
    assert client.get(f"/api/v1/referrers/urls?{good_qs}").status_code in (401, 403)
    assert client.get(
        f"/api/v1/referrers/urls?{good_qs}",
        headers={"Authorization": "Bearer lc_invalidtoken12345678"},
    ).status_code in (401, 403)
    assert (
        client.get(
            f"/api/v1/referrers/urls?{good_qs}&relation=bogus",
            headers={"Authorization": f"Bearer {cx['token']}"},
        ).status_code
        == 400
    )
    # No original IPs, ciphertext, keys or raw lines in API or UI.
    api = client.get(
        f"/api/v1/referrers/urls?{good_qs}", headers={"Authorization": f"Bearer {cx['token']}"}
    )
    for needle in ("198.51.100", "BEGIN", "HMAC", "secret123", "203.0.113"):
        assert needle not in api.text
    html = _page(client, "/referrers", "&view=all")
    for needle in ("198.51.100", "secret123", "203.0.113"):
        assert needle not in html


# --- Issue 3: honest supporting-data scope. ---


def test_referrer_links_are_honestly_related_not_exact(cx):
    broken = _page(cx["client"], "/referrers", "&view=broken")
    assert "Related requests" in broken
    assert "different source paths on the same host are included" in broken
    assert "Open supporting data" not in broken
    all_html = _page(cx["client"], "/referrers", "&view=all")
    assert "Related requests" in all_html
    # Legacy unknown scheme/path never becomes an invented URL.
    assert "None://" not in broken and "None://" not in all_html
    assert "Unknown" in all_html or "Unknown" in broken


# --- Issue 4: tool envelope hrefs replay the executed report. ---


def test_report_hrefs_replay_exact_counts(cx):
    conn = connect(cx["db"], read_only=True)
    try:
        target = conn.execute("SELECT client_pseudonym FROM requests LIMIT 1").fetchone()[0]
    finally:
        conn.close()
    rules = load_rules(ROOT / "config" / "bot_rules.yaml").rules
    cases = {
        "slow_endpoints": ("/performance", "sort=avg_desc"),
        "seo_redirects": ("/seo", "view=redirects"),
        "seo_client_errors": ("/seo", "view=client_errors"),
        "seo_server_errors": ("/seo", "view=server_errors"),
        "seo_ai_only": ("/seo", "view=ai_only"),
        "referrer_404s": ("/referrers", "view=broken"),
    }
    for report, (path, marker) in cases.items():
        outcome = ai_service._execute_bounded_tool(
            cx["db"],
            rules,
            "get_report",
            {"report": report},
            site_id="default",
            source_id=None,
            time_from=FROM,
            time_to=TO,
            tool_index=0,
            investigation_id="hrefcheck",
            observation_time=NOW,
        )
        href = evidence_mod.envelope_href("get_report", outcome["envelope"]["filters"])
        assert href is not None and href.startswith(path), (report, href)
        assert marker in href, (report, href)
        assert "client=" not in href  # unfiltered case carries no client
    # Contradictory parent status filter stays empty through the href.
    outcome = ai_service._execute_bounded_tool(
        cx["db"],
        rules,
        "get_report",
        {"report": "seo_redirects"},
        site_id="default",
        source_id=None,
        time_from=FROM,
        time_to=TO,
        status=404,
        tool_index=0,
        investigation_id="contra",
        observation_time=NOW,
    )
    href = evidence_mod.envelope_href("get_report", outcome["envelope"]["filters"])
    assert href is not None and "view=redirects" in href and "status=404" in href
    replay = cx["client"].get(href)
    assert replay.status_code == 200
    assert "No groups" in replay.text
    # Exact client travels and replays to the same scope.
    outcome = ai_service._execute_bounded_tool(
        cx["db"],
        rules,
        "get_report",
        {"report": "referrer_404s"},
        site_id="default",
        source_id=None,
        time_from=FROM,
        time_to=TO,
        client=target,
        tool_index=0,
        investigation_id="exact",
        observation_time=NOW,
    )
    assert outcome["envelope"]["filters"]["client"] == target
    href = evidence_mod.envelope_href("get_report", outcome["envelope"]["filters"])
    assert href is not None and f"client={target}" in href and "view=broken" in href
    # Model bounds hold for the new aggregate report.
    bounded = ai_service._execute_bounded_tool(
        cx["db"],
        rules,
        "get_report",
        {"report": "referrer_urls"},
        site_id="default",
        source_id=None,
        time_from=FROM,
        time_to=TO,
        tool_index=0,
        investigation_id="bounds",
        observation_time=NOW,
    )
    assert len(bounded["history_line"]) <= 1600


def test_tool_definitions_cover_new_report(cx):
    assert "referrer_urls" in tool_defs.REPORT_NAMES
    schema = tool_defs.ReportArguments.model_json_schema()
    assert "referrer_urls" in str(schema.get("properties", {}).get("report", {}))


# --- Issue 5: measured-request labels, preserved backend. ---


def test_slow_endpoint_labels_are_measured(cx):
    html = _page(cx["client"], "/performance", "&sort=requests_desc")
    assert "Measured requests (most first)" in html
    assert "Requests (most first)" not in html.replace("Measured requests (most first)", "")
    catalog = load_catalog("en")
    assert catalog["perf.sort_requests"].startswith("Measured")
    assert catalog["perf.measured_requests"] == "Measured requests"
    conn = connect(cx["db"], read_only=True)
    try:
        filt = _filt(limit=100, offset=0)
        svc = analytics_service.slow_endpoints(
            conn,
            SlowEndpointsQuery(filt=filt, sort="requests_desc"),
            load_rules(ROOT / "config" / "bot_rules.yaml").rules,
        )
    finally:
        conn.close()
    assert svc["sort"] == "requests_desc" and svc["total_paths"] >= 1
    assert all("measured" in r for r in svc["items"])
