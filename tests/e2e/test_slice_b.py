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


def _status_code(label: str) -> str:
    """Numeric status code from a chart/table label.

    Labels read human-friendly (`200 · OK`); the numeric identity is
    the text before the middle dot, while the phrase after it must be
    asserted separately, never dropped.
    """
    return label.split("·")[0].strip()


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
    # Two navs render now (Main navigation + Quick views presets).
    page.get_by_role("navigation", name="Main navigation").get_by_role(
        "link", name="Crawlers"
    ).click()
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
    page.get_by_role("navigation", name="Main navigation").get_by_role(
        "link", name="Settings"
    ).click()
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
        detail = page.locator("details", has_text=name)
        summary = detail.locator("summary")
        if not page.evaluate("(el) => el.closest('details').open", summary.element_handle()):
            summary.click()
        # Readiness, not rendering: daisyUI animates the collapse open, so
        # innerText reads "" until the rows actually paint. Wait for the
        # opened table's first data cell to be populated: no sleep, no
        # skipped blank rows, no weakened assertions.
        page.wait_for_function(
            """(caption) => {
              const t = Array.from(document.querySelectorAll("table")).filter(
                (t) => t.caption && t.caption.textContent.trim() === caption)[0];
              if (!t) return false;
              const first = t.querySelector("tbody tr td");
              return first !== null && first.innerText.trim() !== "";
            }""",
            arg=name,
            timeout=10000,
        )
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
          const statusInst = window.Chart.getChart(
            document.getElementById("status-distribution"));
          return {
            timeline: data("traffic-timeline-data"),
            liveTimeline: live("traffic-timeline"),
            timelineRows: rows("Requests per time bucket"),
            status: data("status-distribution-data"),
            liveStatus: live("status-distribution"),
            statusAxisLabels: Array.from(statusInst.data.labels),
            statusRows: rows("Requests per status code"),
          };
        }"""
    )
    timeline = values["timeline"]
    assert len(timeline["buckets"]) > 0
    expected_requests = [b["requests"] for b in timeline["buckets"]]
    expected_errors = [b["errors"] for b in timeline["buckets"]]
    expected_bytes = [b["bytes_total"] for b in timeline["buckets"]]
    # Hand-counted fixture totals (14 rows above); the old weak bytes>0
    # assertion could not catch a dropped bucket.
    assert sum(expected_requests) == 14
    assert sum(expected_errors) == 3
    assert sum(expected_bytes) == 6093
    live = {d["label"]: d["values"] for d in values["liveTimeline"]}
    labels = list(live)
    assert live[labels[0]] == expected_requests
    assert live[labels[1]] == expected_errors
    assert live[labels[2]] == expected_bytes
    # Every timeline table cell (label/requests/errors/bytes) matches JSON.
    assert [r[0] for r in values["timelineRows"]] == [b["label"] for b in timeline["buckets"]]
    assert [int(r[1]) for r in values["timelineRows"]] == expected_requests
    assert [int(r[2]) for r in values["timelineRows"]] == expected_errors
    assert [int(r[3]) for r in values["timelineRows"]] == expected_bytes
    # The status table opened above matches its JSON and live chart too.
    # Status identity is numeric AND human: table cells read `200 · OK`,
    # so compare parsed codes while keeping the phrase assertions.
    status = values["status"]
    status_labels = [r[0] for r in values["statusRows"]]
    assert [_status_code(label) for label in status_labels] == [
        str(r["status"]) for r in status["rows"]
    ]
    assert all("·" in label for label in status_labels), status_labels
    assert any("· OK" in label for label in status_labels), status_labels
    assert any("Not Found" in label for label in status_labels), status_labels
    assert any("Internal Server Error" in label for label in status_labels)
    assert [int(r[1]) for r in values["statusRows"]] == [r["requests"] for r in status["rows"]]
    # Live chart axis labels agree on the same numeric codes (parsed so
    # the `200 · OK` phrasing never breaks the identity comparison).
    assert [_status_code(str(v)) for v in values["statusAxisLabels"]] == [
        str(r["status"]) for r in status["rows"]
    ]
    live_status = {d["label"]: d["values"] for d in values["liveStatus"]}
    assert live_status[next(iter(live_status))] == [r["requests"] for r in status["rows"]]
    assert sum(r["requests"] for r in status["rows"]) == 14
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
    # Eight readable columns in front order: Client, Access, Time
    # (zone-aware), Method, Path, Status, Bytes, Details. Referrer,
    # rule and full User-Agent live in the expandable row details.
    headers = page.evaluate(
        """() => Array.from(document.querySelectorAll("table")).filter(
          (t) => t.caption && t.caption.textContent.trim() === "Sanitized request rows")[0]
          .querySelectorAll("thead th").length"""
    )
    assert headers == 8, "the explorer renders exactly eight columns"
    header_texts = page.evaluate(
        """() => Array.from(Array.from(document.querySelectorAll("table")).filter(
          (t) => t.caption && t.caption.textContent.trim() === "Sanitized request rows")[0]
          .querySelectorAll("thead th")).map((th) => th.innerText.trim())"""
    )
    assert header_texts[0].startswith("Client"), header_texts
    assert header_texts[1] == "Access", header_texts
    assert header_texts[2].startswith("Time (Europe/Berlin)"), header_texts
    assert header_texts[3].startswith("Method"), header_texts
    assert header_texts[4].startswith("Path"), header_texts
    assert header_texts[5].startswith("Status"), header_texts
    assert header_texts[6].startswith("Bytes"), header_texts
    assert header_texts[7] == "Details", header_texts
    time_idx = next(index for index, text in enumerate(header_texts) if text.startswith("Time ("))
    content = page.content()
    assert "<script>alert(1)" not in content, "hostile UA must stay escaped"
    assert "&lt;script&gt;" in content
    main_rows = page.locator("table tbody tr:not(.req-detail)")
    assert main_rows.count() > 0

    def _time_cells():
        return page.evaluate(
            """(idx) => Array.from(Array.from(document.querySelectorAll("table")).filter(
              (t) => t.caption && t.caption.textContent.trim() === "Sanitized request rows")[0]
              .querySelectorAll("tbody tr:not(.req-detail)")).map(
              (tr) => ({text: tr.querySelectorAll("td")[idx].innerText,
                       title: tr.querySelectorAll("td")[idx].title}))""",
            time_idx,
        )

    # Display times follow Europe/Berlin while the UTC instant stays typed
    # in the cell title (Time-header semantics, not the first Client cell).
    time_cells = _time_cells()
    assert "CET" in time_cells[0]["text"], time_cells[0]
    assert time_cells[0]["title"].endswith("+00:00"), time_cells[0]
    # The Time sort header toggles newest/oldest and actually reorders.
    newest_first_title = time_cells[0]["title"]
    page.locator("thead th", has_text="Time (Europe/Berlin)").locator("a").click()
    page.wait_for_function("() => window.location.href.includes('sort=oldest')", timeout=10000)
    page.get_by_role("heading", name="Sanitized request rows").wait_for(timeout=10000)
    assert "sorted ascending" in page.content()
    oldest_cells = _time_cells()
    assert oldest_cells[0]["text"] != time_cells[0]["text"]
    assert oldest_cells[0]["title"] <= newest_first_title
    page.locator("thead th", has_text="Time (Europe/Berlin)").locator("a").click()
    page.wait_for_function("() => window.location.href.includes('sort=newest')", timeout=10000)
    assert "sorted descending" in page.content()
    assert _time_cells()[0]["title"] == newest_first_title
    # Expanded row details carry referrer, rule and full User-Agent plus
    # the honest timing-unavailable note; the hostile UA stays escaped.
    row = page.locator("tbody tr", has_text="/docs/a").first
    toggle = row.locator("button[data-detail-toggle]")
    panel_id = toggle.get_attribute("aria-controls")
    assert panel_id and toggle.get_attribute("aria-expanded") == "false"
    toggle.click()
    page.wait_for_selector(f"tr#{panel_id}:not([hidden])", timeout=10000)
    panel = page.locator(f"tr#{panel_id}")
    assert "User-Agent" in panel.inner_text()
    assert "Referring domain" in panel.inner_text()
    assert "Rule" in panel.inner_text()
    assert "Response-time data unavailable" in panel.inner_text()
    assert "<script>alert(1)" not in (panel.evaluate("el => el.innerHTML") or "")
    toggle.focus()
    page.keyboard.press("Enter")
    page.wait_for_selector(f"tr#{panel_id}[hidden]", timeout=10000)
    assert toggle.get_attribute("aria-expanded") == "false"
    _assert_clean(observed, slice_base)
