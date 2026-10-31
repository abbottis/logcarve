"""T9-B web tests: Security/Crawlers/Errors/Ask/Settings/Data Sources.

Every view reads through the shared analytics services over the
fixtures from the shared `web` fixture (10 Combined lines plus one
attack line). Synthetic data only.
"""

import html as html_lib
import re

from app.ai.providers.base import BackendUnavailable
from app.ai.providers.fake import FakeProvider
from app.ai.tools.definitions import execute_tool
from app.analytics import queries, service
from app.analytics.contracts import AnalyticsFilter, TimeWindow
from app.db.database import connect
from app.web.evidence import evidence_url as _evidence_url
from app.web.locales import t

WINDOW_QS = "range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"


def _login(client):
    response = client.post(
        "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
    )
    assert response.status_code == 200
    return response.json()["csrf_token"]


def _window():
    return TimeWindow(time_from="2026-10-27T00:00:00+00:00", time_to="2026-10-28T00:00:00+00:00")


def test_evidence_envelope_carries_full_read_contract(web):
    _, db = web
    conn = connect(db, read_only=True)
    try:
        from pathlib import Path

        from app.analytics.rules import load_rules

        root = Path(__file__).resolve().parent.parent.parent
        rules = load_rules(root / "config" / "bot_rules.yaml").rules
        envelope = execute_tool(
            conn,
            rules,
            name="get_error_groups",
            arguments={
                "site_id": "default",
                "time_from": "2026-10-27T00:00:00+00:00",
                "time_to": "2026-10-28T00:00:00+00:00",
                "method": "GET",
                "status": 404,
                "path_prefix": "/",
                "referer_host": "example.org",
                "limit": 5,
                "offset": 0,
            },
            tool_call_id="tc1",
        )
    finally:
        conn.close()
    filters = envelope["filters"]
    assert filters["site_id"] == "default"
    assert filters["method"] == "GET"
    assert filters["status"] == 404
    assert filters["path_prefix"] == "/"
    assert filters["referer_host"] == "example.org"
    assert filters["limit"] == 5
    assert filters["offset"] == 0
    assert filters["bucket"] == "hour"
    link = _evidence_url("/errors", {**filters, "bucket": "day"})
    for key in (
        "site=default",
        "method=GET",
        "status=404",
        "path_prefix=%2F",
        "referer_host=example.org",
        "limit=5",
        "offset=0",
        "bucket=day",
    ):
        assert key in link, link


def _crawler_db(tmp_path, monkeypatch):
    """Self-contained DB with one claimed family (Googlebot) plus others."""
    from app.db.importer import run_import
    from app.db.migrations_runner import migrate
    from app.ingestion.sources import SourceConfig

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    root = tmp_path / "crawler-logs"
    root.mkdir()
    (root / "access.log").write_bytes(
        b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /robots.txt HTTP/1.1"'
        b' 200 100 "-" "Googlebot/2.1"\n'
        b'203.0.113.20 - - [27/Oct/2026:11:15:44 +0100] "GET /missing HTTP/1.1"'
        b' 404 50 "-" "Googlebot/2.1"\n'
        b'198.51.100.7 - - [27/Oct/2026:11:20:00 +0100] "GET / HTTP/1.1"'
        b' 200 10 "-" "curl/8.0"\n'
    )
    db = tmp_path / "crawler.sqlite3"
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
        site_name="s",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="access.log",
        hmac_key=b"synthetic-test-hmac-key",
    )
    return db


def test_crawler_details_structure(tmp_path, monkeypatch):
    from pathlib import Path

    from app.analytics.rules import load_rules

    db = _crawler_db(tmp_path, monkeypatch)
    conn = connect(db, read_only=True)
    try:
        root = Path(__file__).resolve().parent.parent.parent
        rules = load_rules(root / "config" / "bot_rules.yaml").rules
        filt = AnalyticsFilter(site_id="default", window=_window())
        details = service.crawler_details(conn, filt, rules)
    finally:
        conn.close()
    assert len(details) == 1
    family = details[0]
    assert family["rule_id"] == "bot-search-google"
    assert family["requests"] == 2
    assert family["distinct_agents"] == 1
    assert set(family) >= {
        "rule_id",
        "rule_version",
        "title",
        "requests",
        "distinct_agents",
        "top_agents",
        "top_paths",
        "not_found",
        "limitations",
    }
    assert {(row["path"], row["status"]) for row in family["top_paths"]} == {
        ("/robots.txt", 200),
        ("/missing", 404),
    }
    assert [(row["path"], row["status"]) for row in family["not_found"]] == [("/missing", 404)]
    for row in family["top_paths"]:
        assert set(row) == {"path", "status", "requests"}
    rows, truncated = queries.paths_for_agents(conn, filt, [])
    assert rows == [] and truncated is False


def test_security_view_and_matchers(web):
    client, _ = web
    _login(client)
    html = client.get(f"/security?site=default&{WINDOW_QS}&tz=UTC").text
    assert "Security findings" in html
    assert "Repeated client-error statuses" in html
    assert "404" in html
    matched = client.get(f"/security?site=default&{WINDOW_QS}&tz=UTC&method=GET").text
    assert "method=GET" in matched
    assert "Active evidence filters" in matched


def test_empty_findings_show_no_cards(web):
    """With no matching rule the page honestly shows the empty state;
    regression against tests that accidentally matched nav links."""
    client, _ = web
    _login(client)
    html = client.get(f"/security?site=default&{WINDOW_QS}&tz=UTC").text
    assert t("security.no_findings") in html
    assert t("finding.supporting_data") not in html


def test_errors_pagination_and_escaping(web):
    client, _ = web
    _login(client)
    first = client.get(f"/errors?site=default&{WINDOW_QS}&tz=UTC&limit=1").text
    assert "Showing 1–1 of 4" in first
    assert "offset=1" in first
    second = client.get(f"/errors?site=default&{WINDOW_QS}&tz=UTC&limit=1&offset=1").text
    assert "Showing 2–2 of 4" in second
    assert "&lt;script&gt;" in first or "&lt;script&gt;" in second
    assert "<script>alert" not in first and "<script>alert" not in second
    filtered = client.get(f"/errors?site=default&{WINDOW_QS}&tz=UTC&status=404").text
    assert "status=404" in filtered
    assert ">500<" not in filtered


def test_invalid_filter_params_rejected(web):
    client, _ = web
    _login(client)
    base = f"site=default&{WINDOW_QS}&tz=UTC"
    for extra in (
        "status=abc",
        "status=99",
        "limit=0",
        "limit=101",
        "offset=-1",
        "bucket=week",
        "path_prefix=noslash",
        "source=ghost",
    ):
        response = client.get(f"/errors?{base}&{extra}")
        assert response.status_code == 400, extra


def test_crawlers_view(web):
    client, _ = web
    _login(client)
    html = client.get(f"/crawlers?site=default&{WINDOW_QS}&tz=UTC").text
    assert "Claimed crawler families" in html
    assert "Well-known path observations" in html
    assert "robots.txt requests" in html
    # The shared fixture matches no versioned bot rule: the page must say
    # so honestly instead of inventing a family.
    assert "No claimed crawlers in this window." in html


def test_crawler_truncation_labels_first_agents(tmp_path, monkeypatch):
    """With 55 matching agents the family labels its samples: first 10
    agents shown of 55, path sample over the first-50 cap, full counts kept."""
    from pathlib import Path

    from app.analytics.rules import load_rules

    lines = []
    for index in range(55):
        lines.append(
            b'203.0.113.20 - - [27/Oct/2026:10:%02d:00 +0000] "GET / HTTP/1.1"'
            b' 200 10 "-" "Googlebot-test-%d/1.0"\n' % (index % 60, index)
        )
    db = _seed_db(tmp_path, monkeypatch, b"".join(lines), "many_agents.sqlite3")
    root = Path(__file__).resolve().parent.parent.parent
    rules = load_rules(root / "config" / "bot_rules.yaml").rules
    conn = connect(db, read_only=True)
    try:
        filt = AnalyticsFilter(site_id="default", window=_window())
        details = service.crawler_details(conn, filt, rules)
    finally:
        conn.close()
    assert len(details) == 1
    family = details[0]
    assert family["rule_id"] == "bot-search-google"
    assert family["distinct_agents"] == 55
    assert family["agents_shown"] == 10
    assert family["agents_total"] == 55
    assert family["paths_truncated"] is True
    assert len(family["top_agents"]) == 10

    client = _authed_client(db)
    html = client.get(f"/crawlers?site=default&{WINDOW_QS}&tz=UTC").text
    assert "first 10 of 55" in html
    assert "first 50 matching agents" in html
    assert "Claimed Googlebot" in html
    assert "identity not verified" in html
    assert t("finding.limitations") in html


def test_ask_view_starters_and_disabled_state(web):
    client, _ = web
    _login(client)
    html = client.get(f"/ask?site=default&{WINDOW_QS}&tz=UTC").text
    assert html.count("data-starter-prompt") == 8
    assert t("ai.disabled") in html
    assert t("ask.hint") in html
    assert 'data-site="default"' in html
    assert "2026-10-27T00:00:00+00:00" in html


def test_chat_disabled_and_failure_states(web, monkeypatch):
    client, _ = web
    csrf = _login(client)
    headers = {"X-CSRF-Token": csrf}
    chat_body = {
        "question": "How many requests arrived?",
        "site_id": "default",
        "time_from": "2026-10-27T00:00:00+00:00",
        "time_to": "2026-10-28T00:00:00+00:00",
    }
    disabled = client.post("/api/v1/chat/ask", json=chat_body, headers=headers)
    assert disabled.status_code == 409
    assert disabled.json()["code"] == "ai_disabled"

    for name in (
        "AI_ENABLED",
        "MODEL_DATA_POLICY_VERIFIED",
        "MODEL_ALLOW_REAL_DATA",
        "LLM_DAILY_LIMIT_USD",
    ):
        monkeypatch.setenv(name, "true" if name != "LLM_DAILY_LIMIT_USD" else "50")
    import app.ai.service as ai_service
    from app.ai.providers.base import ProviderResponse, ToolCall

    script = [
        ProviderResponse(
            text="",
            input_tokens=10,
            output_tokens=5,
            tool_calls=(ToolCall(name="get_summary", arguments={"limit": 5}),),
        ),
        ProviderResponse(text="Ten requests in range.", input_tokens=20, output_tokens=8),
    ]
    monkeypatch.setattr(
        ai_service, "select_provider", lambda settings: FakeProvider(script=list(script))
    )
    ok = client.post("/api/v1/chat/ask", json=chat_body, headers=headers)
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert body["answer"] == "Ten requests in range."
    assert body["evidence"], "success must return traceable evidence"
    envelope = body["evidence"][0]
    # The dashboard rebuilds evidence links from this envelope plus the
    # server contract: every link input must travel with the call.
    assert set(envelope) >= {
        "tool",
        "tool_call_id",
        "observation_time",
        "filters",
        "coverage",
        "result",
    }
    assert envelope["tool"] == "get_summary"
    assert envelope["filters"]["limit"] == 5

    failing = FakeProvider(fail_with=BackendUnavailable)
    monkeypatch.setattr(ai_service, "select_provider", lambda settings: failing)
    down = client.post("/api/v1/chat/ask", json=chat_body, headers=headers)
    assert down.status_code == 503
    assert down.json()["code"] == "provider_unavailable"


def test_settings_and_sources_views(web):
    client, _ = web
    _login(client)
    settings = client.get("/settings").text
    assert "analytics:read" in settings
    assert "120.0" in settings and "140.0" in settings and "150.0" in settings
    assert "30 days (UTC)" in settings
    assert "SecretStr" not in settings and "api_key" not in settings
    sources = client.get("/data-sources").text
    assert "example-combined" in sources
    assert "completed" in sources
    assert "allowed_root" not in sources
    assert "python -m app.db.cli" in sources
    assert "python -m app.auth.cli" in sources


def test_evidence_url_maps_source_id(web):
    link = _evidence_url(
        "/errors",
        {
            "site_id": "default",
            "source_id": "example-combined",
            "time_from": "2026-10-27T00:00:00+00:00",
            "time_to": "2026-10-28T00:00:00+00:00",
            "status": 404,
            "limit": 5,
            "offset": 10,
        },
    )
    assert "source=example-combined" in link, link
    assert "source_id" not in link, link
    assert "status=404" in link and "limit=5" in link and "offset=10" in link


def test_ask_scope_contract_and_plain_filter(web):
    client, _ = web
    _login(client)
    html = client.get(f"/ask?site=default&{WINDOW_QS}&tz=UTC&source=example-combined").text
    # The ask root wraps both the starters and the chat panel, so the
    # starter buttons are actually wired; it carries the selected source.
    # Evidence links are server-generated per-result hrefs on the chat
    # response: no route map or URL builder ships to the browser.
    assert html.index("data-ask") < html.index("data-starter-prompt")
    assert 'data-source="example-combined"' in html
    assert "data-evidence-contract" not in html
    assert "tool_pages" not in html
    # The ask filter bar is a plain GET form (no fragment endpoint) that
    # preserves the applied window and source.
    assert 'method="get" action="/ask"' in html
    assert 'name="source" value="example-combined"' in html
    assert 'name="from"' in html and 'name="to"' in html
    bare = client.get(f"/ask?site=default&{WINDOW_QS}&tz=UTC").text
    assert 'data-source=""' in bare


def test_filter_apply_preserves_scope(web):
    client, _ = web
    _login(client)
    html = client.get(
        f"/errors?site=default&{WINDOW_QS}&tz=UTC&status=404&source=example-combined&limit=25"
    ).text
    # Matchers, source and page size resubmit with the window on Apply.
    assert 'name="status" value="404"' in html
    assert 'name="source" value="example-combined"' in html
    assert 'name="limit" value="25"' in html
    # Paging offset resets deliberately: a new window starts at page one.
    assert 'name="offset"' not in html
    # Same-window navigation keeps the applied source.
    assert "source=example-combined" in html
    assert re.search(r'href="/security\?[^"]*source=example-combined', html)


def test_finding_links_preserve_source(web):
    client, _ = web
    _login(client)
    html = client.get(f"/security?site=default&{WINDOW_QS}&tz=UTC&source=example-combined").text
    links = re.findall(r'href="(/errors\?[^"]+)"', html)
    assert links, "findings must carry evidence links"
    for link in links:
        assert "source=example-combined" in link, link


def _section(html: str, heading_id: str) -> str:
    return html.split(f'id="{heading_id}"')[1].split("</section>")[0]


def _table_rows(section: str) -> list[str]:
    return re.findall(r'<tr><td class="tech break-all">(.*?)</td>', section)


def _showing(section: str) -> tuple[int, int, int]:
    match = re.search(r"Showing (\d+)–(\d+) of (\d+)", section)
    assert match, "tables must state their visible position honestly"
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def test_overview_tables_honor_requested_paging(web):
    client, _ = web
    _login(client)
    base = f"site=default&{WINDOW_QS}&tz=UTC"
    default = client.get(f"/?{base}").text
    _, _, path_total = _showing(_section(default, "paths-h"))
    assert path_total > 3, "fixture needs several path groups for paging"
    _, _, ref_total = _showing(_section(default, "ref-h"))
    assert len(_table_rows(_section(default, "paths-h"))) == min(10, path_total)
    narrow = client.get(f"/?{base}&limit=3").text
    assert _showing(_section(narrow, "paths-h")) == (1, 3, path_total)
    assert len(_table_rows(_section(narrow, "paths-h"))) == 3
    assert _showing(_section(narrow, "ref-h")) == (1, min(3, ref_total), ref_total)
    assert len(_table_rows(_section(narrow, "ref-h"))) == min(3, ref_total)
    shifted = client.get(f"/?{base}&limit=3&offset=3").text
    assert _showing(_section(shifted, "paths-h")) == (4, 6, path_total)
    rows = _table_rows(_section(shifted, "paths-h"))
    assert len(rows) == 3
    assert rows != _table_rows(_section(narrow, "paths-h"))
    partial = client.get(f"/partials/overview?{base}&limit=3&offset=3")
    assert "limit=3" in partial.headers["HX-Push-Url"]
    assert "offset=3" in partial.headers["HX-Push-Url"]


def test_reversed_window_rejected_and_filter_carries_failure_message(web):
    client, _ = web
    _login(client)
    bad = client.get(
        "/partials/errors?site=default&range=custom"
        "&from=2026-10-27T13:00:00%2B00:00&to=2026-10-27T12:00:00%2B00:00&tz=UTC"
    )
    assert bad.status_code == 400
    html = client.get(f"/?site=default&{WINDOW_QS}&tz=UTC").text
    assert "/static/js/filter.js" in html
    assert 'data-msg-apply-failed="The filters could not be applied.' in html


def _populated_lines() -> bytes:
    """One 200 sensitive-path hit plus five 404s from a single client."""
    lines = [
        (
            b'203.0.113.20 - - [27/Oct/2026:09:00:00 +0000] "GET /.env HTTP/1.1"'
            b' 200 42 "-" "Mozilla/5.0"\n'
        ),
        (
            b'198.51.100.7 - - [27/Oct/2026:09:01:00 +0000] "GET / HTTP/1.1"'
            b' 200 10 "-" "Mozilla/5.0"\n'
        ),
    ]
    for index in range(5):
        lines.append(
            b'198.51.100.9 - - [27/Oct/2026:10:0%d:00 +0000] "GET /missing-%d HTTP/1.1"'
            b' 404 12 "-" "evil/1.0"\n' % (index, index)
        )
    return b"".join(lines)


def _seed_db(tmp_path, monkeypatch, lines: bytes, name: str):
    from app.auth.passwords import hash_password
    from app.auth.tokens import create_admin_user
    from app.db.database import writer_transaction
    from app.db.importer import run_import
    from app.db.migrations_runner import migrate
    from app.ingestion.sources import SourceConfig

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    root = tmp_path / "logs"
    root.mkdir(exist_ok=True)
    (root / "access.log").write_bytes(lines)
    db = tmp_path / name
    migrate(db)
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
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
        hmac_key=b"synthetic-test-hmac-key",
    )
    return db


def _authed_client(db):
    from starlette.testclient import TestClient

    from app.main import create_app

    client = TestClient(create_app(db_path=db, secure_cookies=False), raise_server_exceptions=False)
    response = client.post(
        "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
    )
    assert response.status_code == 200
    return client


def test_security_populated_findings_render_both_rules(tmp_path, monkeypatch):
    """Populated findings render fully: meaning, counts, evidence,
    window, coverage, limitations and an honest support link per card."""
    from pathlib import Path

    from app.analytics.contracts import AnalyticsFilter
    from app.analytics.rules import load_rules

    db = _seed_db(tmp_path, monkeypatch, _populated_lines(), "populated.sqlite3")
    client = _authed_client(db)
    response = client.get(f"/security?site=default&{WINDOW_QS}&tz=UTC")
    assert response.status_code == 200, "populated findings must not crash the page"
    html = response.text
    # Sensitive-path card: request counts, path evidence, meaning.
    assert "Sensitive or scan-typical path requested" in html
    assert "/.env" in html
    assert "Path matches a sensitive/scan-typical pattern" in html
    # Repeated-client-errors card: error counts, pseudonym, samples.
    assert "Repeated client errors from one pseudonym" in html
    assert "One client pseudonym produced repeated 4xx responses" in html
    assert "/missing-0" in html
    assert t("table.errors") in html
    assert t("finding.limitations") in html
    assert "never proof of compromise or attribution" in html
    assert "2026-10-27T00:00:00+00:00" in html
    assert t("finding.supporting_data") in html
    # The 200 sensitive-path card links to overview context, never to the
    # error groups that cannot list it; the 4xx card links to /errors.
    cards = html.split('<li class="rounded-lg border border-base-300 p-3">')[1:]
    assert len(cards) == 2
    sensitive = next(card for card in cards if "sec-sensitive-path" in card)
    assert 'href="/?' in sensitive and 'href="/errors?' not in sensitive
    repeated = next(card for card in cards if "sec-repeated-client-errors" in card)
    assert 'href="/errors?' in repeated
    assert "site=default" in repeated

    root = Path(__file__).resolve().parent.parent.parent
    rules = load_rules(root / "config" / "security_rules.yaml").rules
    conn = connect(db, read_only=True)
    try:
        filt = AnalyticsFilter(site_id="default", window=_window())
        findings = service.security_findings(conn, filt, rules)
    finally:
        conn.close()
    by_rule = {finding.rule_id: finding for finding in findings}
    assert set(by_rule) == {"sec-sensitive-path", "sec-repeated-client-errors"}
    assert by_rule["sec-sensitive-path"].counts["requests"] == 1
    assert by_rule["sec-repeated-client-errors"].counts["errors"] == 5
    assert by_rule["sec-sensitive-path"].evidence["paths_total"] == 1


def test_malformed_query_values_are_safe_400(web):
    client, _ = web
    _login(client)
    base = f"site=default&{WINDOW_QS}&tz=UTC"
    bad = [
        "status=%C2%B2",  # superscript two passes isdigit() but int() fails
        "status=12a",
        "limit=%C2%B2",
        "offset=%C2%B2",
        "referer_host=" + "a" * 254,  # past the shared 253 bound
        "path_prefix=/" + "a" * 1024,  # 1025 chars, past the shared 1024 bound
    ]
    for extra in bad:
        for path in ("/", "/security", "/crawlers", "/errors", "/ask"):
            full = client.get(f"{path}?{base}&{extra}")
            assert full.status_code == 400, (path, extra, full.status_code)
        # Ask has no fragment endpoint; the full page above covers it.
        for fragment in ("/partials/overview", "/partials/security", "/partials/crawlers"):
            response = client.get(f"{fragment}?{base}&{extra}")
            assert response.status_code == 400, (fragment, extra, response.status_code)
        response = client.get(f"/partials/errors?{base}&{extra}")
        assert response.status_code == 400, (extra, response.status_code)
    ok = [
        "status=404",
        "referer_host=" + "a" * 253,  # shared bound itself is accepted
        "path_prefix=/" + "a" * 1023,  # 1024 chars total, accepted
    ]
    for extra in ok:
        response = client.get(f"/errors?{base}&{extra}")
        assert response.status_code == 200, (extra, response.status_code)


def test_paging_links_carry_exact_parsed_filters(web):
    """Prev/next URLs parse to exact filter keys: regression for the
    mangled first key the path-prefixed canonical extraction produced."""
    from urllib.parse import parse_qsl, urlsplit

    client, _ = web
    _login(client)
    base = f"site=default&{WINDOW_QS}&tz=UTC&status=404&source=example-combined&limit=1"
    html = client.get(f"/errors?{base}").text
    assert "Showing 1–1 of " in html
    links = re.findall(r'href="([^"]+)"[^>]*data-paging', html)
    assert len(links) == 1, links
    parts = urlsplit(html_lib.unescape(links[0]))
    assert parts.path == "/errors", links[0]
    query = dict(parse_qsl(parts.query))
    assert query == {
        "site": "default",
        "range": "custom",
        "from": "2026-10-27T00:00:00+00:00",
        "to": "2026-10-28T00:00:00+00:00",
        "tz": "UTC",
        "status": "404",
        "source": "example-combined",
        "limit": "1",
        "offset": "1",
    }
    assert not any("?" in key for key in query)


def test_active_nav_keeps_full_filters(web):
    """The active view link preserves the complete current state while
    other views take only the shared window state."""
    client, _ = web
    _login(client)
    html = client.get(
        f"/errors?site=default&{WINDOW_QS}&tz=UTC&status=404&source=example-combined"
    ).text
    active = re.search(r'<a href="([^"]+)"[^>]*aria-current="page"', html)
    assert active, "active view must be marked"
    assert "status=404" in active.group(1) and "source=example-combined" in active.group(1)
    assert active.group(1).startswith("/errors?"), active.group(1)
    security = re.search(r'href="(/security\?[^"]+)"', html)
    assert security and "site=default" in security.group(1)
    assert "status=404" not in security.group(1)


def test_canonical_urls_match_their_routes(web):
    client, _ = web
    _login(client)
    base = f"site=default&{WINDOW_QS}&tz=UTC"
    for prefix, fragment in (
        ("", "/partials/overview"),
        ("/security", "/partials/security"),
        ("/crawlers", "/partials/crawlers"),
        ("/errors", "/partials/errors"),
    ):
        response = client.get(f"{fragment}?{base}&limit=3")
        push_url = response.headers["HX-Push-Url"]
        assert push_url.startswith(f"{prefix or '/'}?"), push_url
        assert "limit=3" in push_url and "site=default" in push_url


def test_chat_evidence_hrefs_reproduce_tool_reads(web, monkeypatch):
    """Server-generated chat hrefs carry the exact read: following the
    error-groups href through the shared services returns the same total
    the envelope reported, not a generic anchor."""
    import app.ai.service as ai_service
    from app.ai.providers.base import ProviderResponse, ToolCall
    from app.ai.providers.fake import FakeProvider

    client, _ = web
    csrf = _login(client)
    headers = {"X-CSRF-Token": csrf}
    for name in (
        "AI_ENABLED",
        "MODEL_DATA_POLICY_VERIFIED",
        "MODEL_ALLOW_REAL_DATA",
        "LLM_DAILY_LIMIT_USD",
    ):
        monkeypatch.setenv(name, "true" if name != "LLM_DAILY_LIMIT_USD" else "50")
    script = [
        ProviderResponse(
            text="",
            input_tokens=10,
            output_tokens=5,
            tool_calls=(
                ToolCall(
                    name="get_error_groups",
                    arguments={
                        "site_id": "default",
                        "source_id": "example-combined",
                        "time_from": "2026-10-27T00:00:00+00:00",
                        "time_to": "2026-10-28T00:00:00+00:00",
                        "status": 404,
                        "limit": 5,
                        "offset": 0,
                    },
                ),
            ),
        ),
        ProviderResponse(text="Five groups.", input_tokens=20, output_tokens=8),
    ]
    monkeypatch.setattr(
        ai_service, "select_provider", lambda settings: FakeProvider(script=list(script))
    )
    response = client.post(
        "/api/v1/chat/ask",
        json={
            "question": "What failed?",
            "site_id": "default",
            "source_id": "example-combined",
            "time_from": "2026-10-27T00:00:00+00:00",
            "time_to": "2026-10-28T00:00:00+00:00",
        },
        headers=headers,
    )
    assert response.status_code == 200, response.text
    envelope = response.json()["evidence"][0]
    href = envelope["href"]
    assert href.startswith("/errors?"), href
    assert "source=example-combined" in href and "status=404" in href
    assert "limit=5" in href and "offset=0" in href
    # Replay the href through the shared services: same total as reported.
    from urllib.parse import parse_qsl, urlsplit

    query = dict(parse_qsl(urlsplit(href).query))
    _, db = web
    conn = connect(db, read_only=True)
    try:
        replay = AnalyticsFilter(
            site_id=query["site"],
            source_id=query.get("source"),
            window=_window(),
            status=int(query["status"]),
            limit=int(query["limit"]),
            offset=int(query["offset"]),
        )
        items, total = queries.error_groups(conn, replay)
    finally:
        conn.close()
    assert total == envelope["result"]["total_groups"]
    assert len(items) == len(envelope["result"]["items"])


def test_envelope_href_allowlists_tool_pages():
    from app.web.evidence import TOOL_PAGE_MAP, envelope_href

    filters = {
        "site_id": "default",
        "time_from": "2026-10-27T00:00:00+00:00",
        "time_to": "2026-10-28T00:00:00+00:00",
    }
    for tool, page in TOOL_PAGE_MAP.items():
        assert envelope_href(tool, filters).startswith(page + "?"), tool
    assert envelope_href("drop_tables", filters) is None
    assert envelope_href(None, filters) is None
    assert envelope_href("get_summary", None) is None


def test_new_pages_csp_no_store_and_nav(web):
    client, _ = web
    for path in ("/security", "/crawlers", "/errors", "/ask", "/settings", "/data-sources"):
        denied = client.get(path, follow_redirects=False)
        assert denied.status_code == 302, path
    _login(client)
    window = f"?site=default&{WINDOW_QS}&tz=UTC"
    for path in ("/security", "/crawlers", "/errors", "/ask", "/settings", "/data-sources"):
        response = client.get(path + window if path not in ("/settings", "/data-sources") else path)
        assert response.status_code == 200, path
        assert "default-src 'self'" in response.headers["content-security-policy"], path
        assert response.headers["cache-control"] == "no-store", path
    overview = client.get("/" + window).text
    for target in ("/security", "/crawlers", "/errors", "/ask", "/settings", "/data-sources"):
        assert f'href="{target}' in overview, target
    security = client.get("/security" + window).text
    assert 'aria-current="page"' in security
