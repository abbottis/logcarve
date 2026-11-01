"""Slice B correction browser suite: accepted-gap regressions with real
control interaction, real Chart.js values and real request capture.

Covers the independent-review blockers: selected traffic survives
sidebar navigation; Ask narrows by every selected matcher; timelines
plot errors/bytes; provider/purpose/category groups are exact and
pagination-independent; paths sort visibly with bytes; heatmap cells
shade quantitatively in both themes; explorer shows bytes/referrer/
rule with timezone-aware times and sanitized agents; 390px narrow
layouts in both themes stay clean with no off-origin requests.

Repeatable against a loopback server with synthetic fixtures. Skips
cleanly when loopback sockets or protected browser launch are
unavailable (coordinator runs ``uv run --locked pytest tests/e2e -q``).
No provider calls: the Ask test captures the outbound JSON and answers
locally with ai_disabled.
"""

import socket
import threading
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
W1 = "range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"
SHOT_DIR = ROOT / "artifacts" / "e2e-slice-b"

# Hand-counted synthetic traffic: 4 Googlebot (search_crawler/Google,
# one /robots.txt + one 404), 3 GPTBot (ai_crawler/OpenAI, one
# /sitemap.xml), 2 curl (automation_tool, one 500), 3 browser-like
# Mozilla (page/style/script kinds), 1 NULL-UA unknown 404, 1 hostile
# unknown UA. Totals: 14 requests, errors 3 (two 404 + one 500),
# claimed_bot 7, named-bot rows 9 (4+3+2).
ACCESS_LOG = (
    b'203.0.113.20 - - [27/Oct/2026:10:00:00 +0000] "GET /docs/a HTTP/1.1"'
    b' 200 1000 "https://example.org/" "Googlebot/2.1 (+http://www.google.com/bot.html)"\n'
    b'203.0.113.20 - - [27/Oct/2026:10:05:00 +0000] "GET /robots.txt HTTP/1.1"'
    b' 200 100 "-" "Googlebot/2.1 (+http://www.google.com/bot.html)"\n'
    b'203.0.113.20 - - [27/Oct/2026:10:10:00 +0000] "GET /missing HTTP/1.1"'
    b' 404 50 "-" "Googlebot/2.1 (+http://www.google.com/bot.html)"\n'
    b'203.0.113.20 - - [27/Oct/2026:10:15:00 +0000] "GET /docs/b HTTP/1.1"'
    b' 200 3000 "-" "Googlebot/2.1 (+http://www.google.com/bot.html)"\n'
    b'198.51.100.8 - - [27/Oct/2026:10:20:00 +0000] "GET /docs/a HTTP/1.1"'
    b' 200 500 "-" "GPTBot/1.2"\n'
    b'198.51.100.8 - - [27/Oct/2026:10:25:00 +0000] "GET /docs/a HTTP/1.1"'
    b' 200 500 "-" "GPTBot/1.2"\n'
    b'198.51.100.8 - - [27/Oct/2026:10:30:00 +0000] "GET /sitemap.xml HTTP/1.1"'
    b' 200 300 "-" "GPTBot/1.2"\n'
    b'198.51.100.7 - - [27/Oct/2026:10:35:00 +0000] "GET / HTTP/1.1"'
    b' 200 10 "-" "curl/8.0"\n'
    b'198.51.100.7 - - [27/Oct/2026:10:40:00 +0000] "GET /api HTTP/1.1"'
    b' 500 20 "-" "curl/8.0"\n'
    b'192.0.2.1 - - [27/Oct/2026:10:45:00 +0000] "GET / HTTP/1.1"'
    b' 200 100 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"\n'
    b'192.0.2.1 - - [27/Oct/2026:10:50:00 +0000] "GET /style.css HTTP/1.1"'
    b' 200 200 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"\n'
    b'192.0.2.1 - - [27/Oct/2026:10:55:00 +0000] "GET /app.js HTTP/1.1"'
    b' 200 300 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X) Firefox/120.0"\n'
    b'192.0.2.2 - - [27/Oct/2026:11:00:00 +0000] "GET /gone HTTP/1.1"'
    b' 404 5 "-" "-"\n'
    b'198.51.100.9 - - [27/Oct/2026:11:05:00 +0000] "GET /x HTTP/1.1"'
    b' 200 8 "-" "evil/1.0 <script>alert(1)</script>"\n'
)


def _free_port() -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]
    except PermissionError:
        pytest.skip("loopback sockets are unavailable in this sandbox")


@pytest.fixture
def slice_base(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(ROOT / "artifacts" / "playwright-browsers"))
    import uvicorn

    from app.auth.passwords import hash_password
    from app.auth.tokens import create_admin_user
    from app.db.database import writer_transaction
    from app.db.importer import run_import
    from app.db.migrations_runner import migrate
    from app.ingestion.sources import SourceConfig
    from app.main import create_app

    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes(ACCESS_LOG)
    db = tmp_path / "slice_b.sqlite3"
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
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(db_path=db, secure_cookies=False),
            host="127.0.0.1",
            port=port,
            log_level="error",
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 20
    while True:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2):
                break
        except OSError:
            pass
        assert time.monotonic() < deadline, "test server did not start"
        time.sleep(0.1)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=10)


@pytest.fixture
def observed(page):
    errors: list[str] = []
    requests: list[str] = []
    page.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    page.on("request", lambda req: requests.append(req.url))
    return {"errors": errors, "requests": requests}


def _login(page, base):
    page.goto(f"{base}/login")
    page.fill("#username", "admin")
    page.fill("#password", "s3cret-pw")
    page.click("button[type=submit]")
    page.wait_for_url(f"{base}/", timeout=10000)


def _assert_clean(observed, base):
    assert observed["errors"] == [], observed["errors"]
    for url in observed["requests"]:
        assert url.startswith(base), url


def _kpi_requests(page) -> str:
    return page.locator(".stats .stat-value").first.inner_text().strip()


def test_traffic_selection_survives_sidebar_navigation(page, slice_base, observed):
    _login(page, slice_base)
    page.goto(f"{slice_base}/?site=default&{W1}&tz=UTC")
    page.get_by_role("heading", name="Traffic timeline").wait_for(timeout=10000)
    assert _kpi_requests(page) == "14"
    # Narrow through the real traffic control and Apply.
    page.select_option("#f-traffic", "claimed_bot")
    with page.expect_response(
        lambda r: "/partials/overview" in r.url and r.status == 200, timeout=10000
    ):
        page.get_by_role("button", name="Apply").click()
    page.wait_for_function(
        "() => document.querySelector('.stats .stat-value').textContent.trim() === '7'",
        timeout=10000,
    )
    assert "traffic=claimed_bot" in page.url
    # Sidebar navigation keeps the selection: no silent widening to 14.
    page.get_by_role("navigation").get_by_role("link", name="Crawlers").click()
    page.get_by_role("heading", name="Named bots").wait_for(timeout=10000)
    assert "traffic=claimed_bot" in page.url
    # The named-bot table itself narrows (the filter dropdown still
    # lists every catalog rule, so assert on table rows, not the page).
    rows = page.evaluate(
        """() => Array.from(document.querySelectorAll("table")).filter(
          (t) => t.caption && t.caption.textContent.trim() === "Named bots")[0]
          .querySelectorAll("tbody tr").length"""
    )
    assert rows == 2, "only Googlebot + GPTBot rows are claimed_bot"
    assert "Googlebot" in page.content()
    _assert_clean(observed, slice_base)


def test_settings_roundtrip_keeps_matchers(page, slice_base, observed):
    _login(page, slice_base)
    page.goto(f"{slice_base}/?site=default&{W1}&tz=UTC&traffic=claimed_bot&status=404")
    page.get_by_role("heading", name="Traffic timeline").wait_for(timeout=10000)
    page.get_by_role("navigation").get_by_role("link", name="Settings").click()
    page.wait_for_function("() => location.pathname === '/settings'", timeout=10000)
    assert "traffic=claimed_bot" in page.url
    page.go_back()
    page.get_by_role("heading", name="Traffic timeline").wait_for(timeout=10000)
    assert "traffic=claimed_bot" in page.url
    assert "status=404" in page.url
    _assert_clean(observed, slice_base)


def test_ask_sends_selected_matchers(page, slice_base, observed):
    _login(page, slice_base)
    page.goto(
        f"{slice_base}/ask?site=default&{W1}&tz=UTC&traffic=claimed_bot"
        "&bot=bot-auto-curl&method=GET&status=404&search=docs"
    )
    page.get_by_role("heading", name="Ask AI").first.wait_for(timeout=10000)
    captured: dict = {}

    def _route(route):
        try:
            captured.update(route.request.post_data_json or {})
        finally:
            route.fulfill(status=409, json={"code": "ai_disabled", "message": "off"})

    page.route("**/api/v1/chat/ask", _route)
    page.locator("[data-ask-input]").fill("What crawled /docs/?")
    page.locator("[data-ask-send]").click()
    # The local ai_disabled answer renders only after the request ran,
    # so the captured payload is complete once the status shows.
    page.locator("[data-ask-status]").wait_for(state="visible", timeout=10000)
    assert captured["traffic"] == "claimed_bot"
    assert captured["bot"] == "bot-auto-curl"
    assert captured["method"] == "GET"
    assert captured["status"] == 404
    assert captured["search"] == "docs"
    page.unroute("**/api/v1/chat/ask")
    for url in observed["requests"]:
        assert url.startswith(slice_base), url


def test_timeline_charts_match_tables_and_json(page, slice_base, observed):
    _login(page, slice_base)
    page.goto(f"{slice_base}/?site=default&{W1}&tz=UTC")
    page.get_by_role("heading", name="Traffic timeline").wait_for(timeout=10000)
    for name in ("Requests per time bucket", "Requests per status code"):
        summary = page.locator("details", has_text=name).locator("summary")
        if not page.evaluate("(el) => el.closest('details').open", summary.element_handle()):
            summary.click()
    values = page.evaluate(
        """() => {
          const data = (id) => JSON.parse(document.getElementById(id).textContent);
          const live = (id) => {
            const inst = window.Chart.getChart(document.getElementById(id));
            return inst.data.datasets.map((d) => ({label: d.label, values: Array.from(d.data)}));
          };
          const table = (caption) => Array.from(document.querySelectorAll("table")).filter(
            (t) => t.caption && t.caption.textContent.trim() === caption)[0];
          const rows = (caption) => Array.from(table(caption).querySelectorAll("tbody tr")).map(
            (tr) => Array.from(tr.querySelectorAll("td")).map((td) => td.innerText.trim()));
          return {
            timeline: data("traffic-timeline-data"),
            liveTimeline: live("traffic-timeline"),
            timelineRows: rows("Requests per time bucket"),
          };
        }"""
    )
    timeline = values["timeline"]
    assert len(timeline["buckets"]) > 0
    assert sum(b["requests"] for b in timeline["buckets"]) == 14
    assert sum(b["errors"] for b in timeline["buckets"]) == 3
    assert sum(b["bytes_total"] for b in timeline["buckets"]) > 0
    live = {d["label"]: d["values"] for d in values["liveTimeline"]}
    labels = list(live)
    assert live[labels[0]] == [b["requests"] for b in timeline["buckets"]]
    assert live[labels[1]] == [b["errors"] for b in timeline["buckets"]]
    assert live[labels[2]] == [b["bytes_total"] for b in timeline["buckets"]]
    table_requests = [int(r[1]) for r in values["timelineRows"]]
    assert table_requests == [b["requests"] for b in timeline["buckets"]]
    assert [int(r[2]) for r in values["timelineRows"]] == [b["errors"] for b in timeline["buckets"]]
    _assert_clean(observed, slice_base)


def test_provider_chart_matches_table_and_ignores_paging(page, slice_base, observed):
    _login(page, slice_base)
    page.goto(f"{slice_base}/crawlers?site=default&{W1}&tz=UTC")
    page.get_by_role("heading", name="Named bots").wait_for(timeout=10000)
    first = page.evaluate(
        """() => {
          const data = JSON.parse(document.getElementById("bot-provider-groups-data").textContent);
          const inst = window.Chart.getChart(document.getElementById("bot-provider-groups"));
          const tables = Array.from(document.querySelectorAll("table")).filter(
            (t) => t.caption && t.caption.textContent.trim() === "Provider");
          const rows = Array.from(tables[0].querySelectorAll("tbody tr")).map(
            (tr) => Array.from(tr.querySelectorAll("td")).map((td) => td.innerText.trim()));
          return {
            providers: data.rows,
            liveLabels: Array.from(inst.data.labels),
            liveValues: Array.from(inst.data.datasets[0].data),
            tableRows: rows,
          };
        }"""
    )
    assert [r["name"] for r in first["providers"]] == first["liveLabels"]
    assert [r["requests"] for r in first["providers"]] == first["liveValues"]
    assert [r[0] for r in first["tableRows"]] == first["liveLabels"]
    assert sum(r["requests"] for r in first["providers"]) == 9
    # Paging the named-bot table never changes the grouped aggregates.
    page.goto(f"{slice_base}/crawlers?site=default&{W1}&tz=UTC&limit=1&offset=1")
    page.get_by_role("heading", name="Named bots").wait_for(timeout=10000)
    second = page.evaluate(
        """() => JSON.parse(
          document.getElementById("bot-provider-groups-data").textContent).rows"""
    )
    assert second == first["providers"]
    _assert_clean(observed, slice_base)


def test_paths_sort_bytes_and_heatmap_colors_both_themes(page, slice_base, observed):
    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    _login(page, slice_base)
    for theme in ("light", "dark"):
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto(f"{slice_base}/?site=default&{W1}&tz=UTC")
        page.select_option("#theme-select", theme)
        page.get_by_role("heading", name="Traffic timeline").wait_for(timeout=10000)
        page.wait_for_timeout(800)
        assert page.evaluate("document.documentElement.scrollWidth") <= 390
        # Visible bytes column plus allowlisted sort with stable effect.
        assert "Known bytes" in page.content()
        page.get_by_role("link", name="Sort by bytes").click()
        page.get_by_role("heading", name="Traffic timeline").wait_for(timeout=10000)
        assert "paths_sort=bytes_desc" in page.url
        first_path = page.evaluate(
            """() => {
              const tables = Array.from(document.querySelectorAll("table")).filter(
                (t) => t.caption && t.caption.textContent.trim() === "Top paths");
              return tables[0].querySelector("tbody tr").innerText;
            }"""
        )
        assert "/docs/b" in first_path, "bytes_desc must rank the 2000-byte path first"
        # Quantitative shading: distinct levels map to distinct colors.
        colors = page.evaluate(
            """() => {
              const sample = {};
              document.querySelectorAll("td[data-heat-level]").forEach((td) => {
                const level = td.getAttribute("data-heat-level");
                if (!(level in sample)) sample[level] = getComputedStyle(td).backgroundColor;
              });
              return sample;
            }"""
        )
        assert set(colors) >= {"0", "4"}
        assert len(set(colors.values())) >= 2, colors
        page.screenshot(path=str(SHOT_DIR / f"overview-390-{theme}.png"))
    _assert_clean(observed, slice_base)


def test_explorer_columns_sanitized_and_timezone_aware(page, slice_base, observed):
    _login(page, slice_base)
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{slice_base}/requests?site=default&{W1}&tz=Europe%2FBerlin")
    page.get_by_role("heading", name="Sanitized request rows").wait_for(timeout=10000)
    headers = page.evaluate(
        """() => Array.from(document.querySelectorAll("table caption"))
          .filter((c) => c.textContent.trim() === "Sanitized request rows")[0]
          .parentElement.querySelectorAll("thead th").length"""
    )
    assert headers >= 9, "bytes/referrer/rule columns must render"
    content = page.content()
    assert "<script>alert(1)" not in content, "hostile UA must stay escaped"
    assert "&lt;script&gt;" in content
    agents = page.evaluate(
        """() => Array.from(document.querySelectorAll("table")).filter(
          (t) => t.caption && t.caption.textContent.trim() === "Sanitized request rows")[0]
          .querySelectorAll("tbody tr")"""
    )
    assert len(agents) > 0
    # Display times follow Europe/Berlin while the UTC instant stays in title.
    cells = page.evaluate(
        """() => Array.from(document.querySelectorAll("table")).filter(
          (t) => t.caption && t.caption.textContent.trim() === "Sanitized request rows")[0]
          .querySelector("tbody tr td").innerText"""
    )
    assert "CET" in cells
    assert page.evaluate(
        """() => Array.from(document.querySelectorAll("table")).filter(
          (t) => t.caption && t.caption.textContent.trim() === "Sanitized request rows")[0]
          .querySelector("tbody tr td").title"""
    ).endswith("+00:00")
    # Oldest/newest sort actually reorders rows.
    newest_first = page.evaluate(
        """() => Array.from(document.querySelectorAll("table")).filter(
          (t) => t.caption && t.caption.textContent.trim() === "Sanitized request rows")[0]
          .querySelector("tbody tr td").innerText"""
    )
    page.get_by_role("link", name="Oldest first").click()
    page.get_by_role("heading", name="Sanitized request rows").wait_for(timeout=10000)
    oldest_first = page.evaluate(
        """() => Array.from(document.querySelectorAll("table")).filter(
          (t) => t.caption && t.caption.textContent.trim() === "Sanitized request rows")[0]
          .querySelector("tbody tr td").innerText"""
    )
    assert newest_first != oldest_first
    _assert_clean(observed, slice_base)
