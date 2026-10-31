"""T9-A correction browser checks (A2–A6): real filter interaction with
reload/back/forward, logout+Back privacy, overlay menu geometry, actual
computed theme colors, working charts, and clean console/network.

Repeatable against a loopback server with synthetic fixtures. Skips
cleanly when loopback sockets are unavailable. Screenshots complement
assertions; no screenshot-only claims.
"""

import socket
import threading
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "combined" / "nginx_combined.txt"
W1 = "range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"
W2 = "range=custom&from=2026-10-27T10:00:00%2B00:00&to=2026-10-27T12:00:00%2B00:00"
SHOT_DIR = ROOT / "artifacts" / "e2e-t9a"


def _free_port() -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]
    except PermissionError:
        pytest.skip("loopback sockets are unavailable in this sandbox")


@pytest.fixture
def live_base(tmp_path, monkeypatch):
    # Function scope: the monkeypatch fixture is function-scoped, so a
    # module-scoped server fixture must not depend on it.
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
    (root / "access.log").write_bytes(FIXTURE.read_bytes())
    db = tmp_path / "e2e.sqlite3"
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
    """Collect console errors, page errors and request URLs per test.

    Console entries keep structured source metadata (the location URL
    Playwright reports) so a test can allow exactly one deliberately
    rejected request instead of broadly ignoring console noise.
    """
    errors: list[str] = []
    sources: list[tuple[str, str]] = []
    requests: list[str] = []

    def _on_console(msg):
        if msg.type != "error":
            return
        errors.append(msg.text)
        location = msg.location or {}
        url = location.get("url", "") if isinstance(location, dict) else ""
        sources.append((msg.text, url))

    page.on("console", _on_console)
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    page.on("request", lambda req: requests.append(req.url))
    return {"errors": errors, "console_sources": sources, "requests": requests}


POPULATED_LINES = (
    b'203.0.113.20 - - [27/Oct/2026:09:00:00 +0000] "GET /.env HTTP/1.1"'
    b' 200 42 "-" "Mozilla/5.0"\n'
    b'198.51.100.7 - - [27/Oct/2026:09:01:00 +0000] "GET / HTTP/1.1"'
    b' 200 10 "-" "Mozilla/5.0"\n'
) + b"".join(
    b'198.51.100.9 - - [27/Oct/2026:10:0%d:00 +0000] "GET /missing-%d HTTP/1.1"'
    b' 404 12 "-" "evil/1.0"\n' % (index, index)
    for index in range(5)
)


@pytest.fixture
def populated_base(tmp_path, monkeypatch):
    """Loopback server seeded with populated findings (one 200
    sensitive-path hit plus five 4xx from one client). Mirrors
    live_base; kept separate so shared-fixture counts never shift."""
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
    (root / "access.log").write_bytes(POPULATED_LINES)
    db = tmp_path / "populated.sqlite3"
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


def _login(page, base):
    page.goto(f"{base}/login")
    page.fill("#username", "admin")
    page.fill("#password", "s3cret-pw")
    page.click("button[type=submit]")
    page.wait_for_url(f"{base}/", timeout=10000)


def _assert_clean(observed, base):
    assert observed["errors"] == []
    for url in observed["requests"]:
        assert url.startswith(base), url


def _assert_only_expected_request_error(observed, base, status, path):
    """Allow exactly one console error: Chromium's native failed-resource
    notice for the deliberately exercised negative response, with the
    request URL in the structured location. Every unrelated error still
    fails; browser logs are never suppressed."""
    for url in observed["requests"]:
        assert url.startswith(base), url
    assert len(observed["errors"]) == 1, observed["errors"]
    assert len(observed["console_sources"]) == 1, observed["console_sources"]
    text, url = observed["console_sources"][0]
    assert "Failed to load resource" in text, text
    assert str(status) in text, text
    assert path in url, url


def test_login_and_overview_kpis(page, live_base, observed):
    _login(page, live_base)
    page.goto(f"{live_base}/?{W1}")
    page.get_by_role("heading", name="Overview").wait_for(timeout=10000)
    assert "10" in page.content()
    assert "Response-time data unavailable for this log source" in page.content()
    _assert_clean(observed, live_base)


def _kpi_requests(page) -> str:
    return page.locator(".stats .stat-value").first.inner_text().strip()


def _observation_window(page) -> str:
    return page.locator("[data-observation-window]").inner_text()


def test_real_filter_apply_reload_back_forward(page, live_base, observed):
    _login(page, live_base)
    page.goto(f"{live_base}/?site=default&{W1}&tz=UTC")
    page.get_by_role("heading", name="Traffic timeline").wait_for(timeout=10000)
    # Controls show the applied window in datetime-local form (A2).
    assert page.input_value("#f-from") == "2026-10-27T00:00"
    assert page.input_value("#f-to") == "2026-10-28T00:00"
    assert _kpi_requests(page) == "10"
    # Narrow the window through actual controls and Apply, awaiting the
    # real partial response and the swapped DOM (never a pre-true URL).
    page.fill("#f-from", "2026-10-27T10:00")
    page.fill("#f-to", "2026-10-27T12:00")
    with page.expect_response(
        lambda response: "/partials/overview" in response.url and response.status == 200,
        timeout=10000,
    ):
        page.get_by_role("button", name="Apply").click()
    page.wait_for_function(
        "() => document.querySelector('[data-observation-window]').textContent.includes('10:00')",
        timeout=10000,
    )
    # Canonical page URL, never the fragment endpoint (A2).
    assert "/partials/" not in page.url
    assert "from=2026-10-27T10" in page.url
    # Displayed window and KPI/chart data changed together. Hand-derived
    # narrow-window count is 8: missing-page is 09:15:32Z and the 500 is
    # 07:14Z (both excluded); the other eight run 10:02:03Z–11:04Z.
    assert "2026-10-27T10:00:00+00:00" in _observation_window(page)
    assert "2026-10-27T12:00:00+00:00" in _observation_window(page)
    assert _kpi_requests(page) == "8"
    assert page.input_value("#f-from") == "2026-10-27T10:00"
    # Reload keeps the applied window and its data.
    page.reload()
    page.get_by_role("heading", name="Traffic timeline").wait_for(timeout=10000)
    assert page.input_value("#f-from") == "2026-10-27T10:00"
    assert "2026-10-27T10:00:00+00:00" in _observation_window(page)
    assert _kpi_requests(page) == "8"
    # Back returns to the wider window with its own data.
    page.go_back()
    page.get_by_role("heading", name="Traffic timeline").wait_for(timeout=10000)
    assert page.input_value("#f-from") == "2026-10-27T00:00"
    assert _kpi_requests(page) == "10"
    page.go_forward()
    page.get_by_role("heading", name="Traffic timeline").wait_for(timeout=10000)
    assert page.input_value("#f-from") == "2026-10-27T10:00"
    assert _kpi_requests(page) == "8"
    _assert_clean(observed, live_base)


def test_logout_then_back_shows_no_analytics(page, live_base, observed):
    _login(page, live_base)
    page.goto(f"{live_base}/?site=default&{W1}&tz=UTC")
    page.get_by_role("heading", name="Traffic timeline").wait_for(timeout=10000)
    page.get_by_role("button", name="Log out").click()
    page.wait_for_function("() => location.pathname === '/login'", timeout=10000)
    page.go_back()
    # History restoration reloads through the server session check, so a
    # logged-out Back lands on /login (possibly with an encoded next
    # target) and never restores private analytics (A3).
    page.wait_for_function("() => location.pathname === '/login'", timeout=10000)
    assert "Total requests" not in page.content()
    assert "Log in" in page.content()
    _assert_clean(observed, live_base)


def test_narrow_menu_overlay_without_overflow(page, live_base, observed):
    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    _login(page, live_base)
    for theme in ("light", "dark"):
        # Direct narrow load, then theme switch in place.
        page.set_viewport_size({"width": 360, "height": 800})
        page.goto(f"{live_base}/?site=default&{W1}&tz=UTC")
        page.select_option("#theme-select", theme)
        page.get_by_role("heading", name="Traffic timeline").wait_for(timeout=10000)
        page.wait_for_timeout(800)  # debounced chart re-render after layout
        assert page.evaluate("document.documentElement.scrollWidth") <= 360
        menu = page.get_by_role("button", name="Menu")
        assert menu.is_visible()
        assert menu.get_attribute("aria-expanded") == "false"
        menu.click()
        assert menu.get_attribute("aria-expanded") == "true"
        assert page.get_by_role("navigation").is_visible()
        # Overlay panel: no document overflow, content not compressed.
        assert page.evaluate("document.documentElement.scrollWidth") <= 360
        assert page.evaluate("document.getElementById('main').offsetWidth") >= 300
        page.screenshot(path=str(SHOT_DIR / f"overview-narrow-{theme}-menu-open.png"))
        page.keyboard.press("Escape")
        assert menu.get_attribute("aria-expanded") == "false"
        page.screenshot(path=str(SHOT_DIR / f"overview-narrow-{theme}.png"))
    _assert_clean(observed, live_base)


COLOR_HELPER = """() => {
  // Browser-native color sampling: fillStyle text itself retains the
  // authored serialization (e.g. OKLCH), so rasterize one sRGB pixel
  // and read it back instead of parsing strings. 8-bit rounding.
  window.__lcCssToRgb = window.__lcCssToRgb || function (value) {
    const text = String(value).trim();
    if (!window.CSS || !window.CSS.supports("color", text)) {
      throw new Error("unsupported color: " + value);
    }
    const cv = window.__lcCanvas || (window.__lcCanvas = document.createElement("canvas"));
    cv.width = 1;
    cv.height = 1;
    const ctx = cv.getContext("2d", { colorSpace: "srgb" });
    ctx.clearRect(0, 0, 1, 1);
    ctx.fillStyle = text;
    ctx.fillRect(0, 0, 1, 1);
    return Array.from(ctx.getImageData(0, 0, 1, 1).data.slice(0, 3));
  };
  window.__lcLuminance = window.__lcLuminance || function (rgb) {
    const f = (v) => {
      v /= 255;
      return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
    };
    return 0.2126 * f(rgb[0]) + 0.7152 * f(rgb[1]) + 0.0722 * f(rgb[2]);
  };
  return true;
}"""


def _rgb(page, selector: str, prop: str) -> list:
    page.evaluate(COLOR_HELPER)
    return page.evaluate(
        "([sel, prop]) => window.__lcCssToRgb(getComputedStyle(document.querySelector(sel)).getPropertyValue(prop))",
        [selector, prop],
    )


def _token_rgb(page, name: str) -> list:
    """Current value of a named theme token (e.g. --color-sky-600)."""
    page.evaluate(COLOR_HELPER)
    return page.evaluate(
        "(token) => window.__lcCssToRgb(getComputedStyle(document.documentElement).getPropertyValue(token))",
        name,
    )


def _assert_same_color(actual: list, expected: list, tolerance: float = 5.0):
    assert len(actual) == 3 and len(expected) == 3
    for got, want in zip(actual, expected):
        assert abs(got - want) <= tolerance, f"{actual} != {expected}"


def _wait_for_visual_settle(page, timeout: int = 8000):
    """Wait until theme color transitions actually settle.

    Right after a theme switch the button sits mid CSS color transition
    (e.g. an oklab() interpolation value); exact palette and contrast
    checks must await the settled end state, bounded by the timeout.
    """
    page.wait_for_function(
        """() => {
          const running = document.getAnimations({subtree: true}).filter(
            (a) => a.playState === "running");
          if (running.length > 0) return false;
          const btn = document.querySelector("#filter-bar button[type=submit]");
          const cur = btn ? getComputedStyle(btn).backgroundColor : "";
          if (window.__lcLastBg === undefined) {
            window.__lcLastBg = cur;
            return false;
          }
          const stable = window.__lcLastBg === cur;
          window.__lcLastBg = cur;
          return stable;
        }""",
        timeout=timeout,
    )


def _assert_contrast(page, text_selector: str, bg_selector: str, minimum: float = 4.5):
    ratio = page.evaluate(
        "([textSel, bgSel]) => {"
        "const text = window.__lcCssToRgb(getComputedStyle(document.querySelector(textSel)).color);"
        "const bg = window.__lcCssToRgb(getComputedStyle(document.querySelector(bgSel)).backgroundColor);"
        "const l1 = window.__lcLuminance(text), l2 = window.__lcLuminance(bg);"
        "const hi = Math.max(l1, l2), lo = Math.min(l1, l2);"
        "return (hi + 0.05) / (lo + 0.05);"
        "}",
        [text_selector, bg_selector],
    )
    assert ratio >= minimum, ratio


def _assert_chart_matches_tables(page):
    """Chart datasets must equal the accessible data tables row for row."""
    # The data tables live inside closed <details> disclosure widgets,
    # whose innerText reads empty until opened: open the actual summaries
    # first and assert the tables become visible.
    for name in ("Requests per time bucket", "Requests per status code"):
        # Idempotent across repeated calls (e.g. light then dark theme):
        # click only while the disclosure is still closed.
        summary = page.locator("details", has_text=name).locator("summary")
        if not page.evaluate("(el) => el.closest('details').open", summary.element_handle()):
            summary.click()
    page.get_by_role("table", name="Requests per time bucket").wait_for(
        state="visible", timeout=10000
    )
    page.get_by_role("table", name="Requests per status code").wait_for(
        state="visible", timeout=10000
    )
    series = page.evaluate(
        """() => {
          const data = (id) => JSON.parse(document.getElementById(id).textContent);
          const live = (id) => {
            const instance = window.Chart.getChart(document.getElementById(id));
            return {labels: instance.data.labels, values: instance.data.datasets[0].data};
          };
          const table = (caption) => Array.from(document.querySelectorAll("table")).filter(
            (t) => t.caption && t.caption.textContent.trim() === caption)[0];
          const rows = (caption) => Array.from(table(caption).querySelectorAll("tbody tr")).map(
            (tr) => Array.from(tr.querySelectorAll("td")).map((td) => td.innerText.trim()));
          return {
            timeline: data("traffic-timeline-data"),
            status: data("status-distribution-data"),
            liveTimeline: live("traffic-timeline"),
            liveStatus: live("status-distribution"),
            timelineRows: rows("Requests per time bucket"),
            statusRows: rows("Requests per status code"),
          };
        }"""
    )
    timeline = series["timeline"]
    status = series["status"]
    table_labels = [row[0] for row in series["timelineRows"]]
    table_counts = [int(row[1]) for row in series["timelineRows"]]
    assert table_labels == [b["label"] for b in timeline["buckets"]]
    assert table_counts == [b["requests"] for b in timeline["buckets"]]
    assert table_labels == list(series["liveTimeline"]["labels"])
    assert table_counts == list(series["liveTimeline"]["values"])
    status_labels = [row[0] for row in series["statusRows"]]
    status_counts = [int(row[1]) for row in series["statusRows"]]
    assert status_labels == [str(r["status"]) for r in status["rows"]]
    assert status_counts == [r["requests"] for r in status["rows"]]
    assert status_labels == [str(v) for v in series["liveStatus"]["labels"]]
    assert status_counts == list(series["liveStatus"]["values"])
    assert sum(table_counts) > 0
    assert sum(table_counts) == sum(status_counts)


def test_actual_theme_colors_and_charts(page, live_base, observed):
    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    _login(page, live_base)
    page.goto(f"{live_base}/?site=default&{W1}&tz=UTC")
    page.get_by_role("heading", name="Traffic timeline").wait_for(timeout=10000)

    # Rendered colors must match the live named tokens in a common
    # space (Chromium serializes them as OKLCH; never hardcode stale
    # RGB constants for the current gamut).
    _assert_same_color(_rgb(page, "body", "background-color"), _token_rgb(page, "--color-slate-50"))
    _assert_same_color(
        _rgb(page, "#filter-bar button[type=submit]", "background-color"),
        _token_rgb(page, "--color-sky-600"),
    )
    _assert_contrast(page, "body", "body")
    _assert_contrast(page, "#filter-bar button[type=submit]", "#filter-bar button[type=submit]")
    assert canvas_size(page, "#traffic-timeline") > 0
    assert canvas_size(page, "#status-distribution") > 0
    _assert_chart_matches_tables(page)
    page.screenshot(path=str(SHOT_DIR / "overview-desktop-light.png"))

    page.select_option("#theme-select", "dark")
    page.get_by_role("heading", name="Traffic timeline").wait_for(timeout=10000)
    _wait_for_visual_settle(page)
    _assert_same_color(
        _rgb(page, "body", "background-color"), _token_rgb(page, "--color-slate-950")
    )
    _assert_same_color(
        _rgb(page, "#filter-bar button[type=submit]", "background-color"),
        _token_rgb(page, "--color-sky-400"),
    )
    _assert_contrast(page, "body", "body")
    _assert_contrast(page, "#filter-bar button[type=submit]", "#filter-bar button[type=submit]")
    # Charts survive the theme change with readable size and matching data.
    assert canvas_size(page, "#traffic-timeline") > 0
    assert canvas_size(page, "#status-distribution") > 0
    _assert_chart_matches_tables(page)
    page.screenshot(path=str(SHOT_DIR / "overview-desktop-dark.png"))
    _assert_clean(observed, live_base)


def test_ask_starter_fills_input_and_disabled_send_is_honest(page, live_base, observed):
    _login(page, live_base)
    page.goto(f"{live_base}/ask?site=default&{W1}&tz=UTC")
    page.get_by_role("heading", name="Ask AI").first.wait_for(timeout=10000)
    starters = page.locator("[data-starter-prompt]")
    assert starters.count() == 8
    # Starter questions only populate the input; nothing is sent.
    first_prompt = starters.first.get_attribute("data-starter-prompt")
    assert first_prompt
    starters.first.click()
    assert page.input_value("#ask-input") == first_prompt
    # With no real transport configured, Send reports the honest
    # disabled state and never fabricates an answer.
    page.get_by_role("button", name="Send").click()
    status = page.locator("[data-ask-status]")
    status.wait_for(state="visible", timeout=10000)
    assert "The AI assistant is disabled." in status.inner_text()
    assert page.locator("[data-ask-answer]").inner_text().strip() == ""
    assert page.locator("[data-ask-evidence]").inner_text().strip() == ""
    # The deliberate 409 is a normal native request log, matched exactly.
    _assert_only_expected_request_error(observed, live_base, 409, "/api/v1/chat/ask")


def test_errors_apply_preserves_matchers_source_and_nav(page, live_base, observed):
    _login(page, live_base)
    page.goto(f"{live_base}/errors?site=default&{W1}&tz=UTC&status=404&source=example-combined")
    page.get_by_role("heading", name="Errors").wait_for(timeout=10000)
    # Evidence scope survives in the filter bar as resubmitted state.
    assert page.get_attribute('#filter-bar input[name="status"]', "value") == "404"
    assert page.get_attribute('#filter-bar input[name="source"]', "value") == "example-combined"
    # Narrow the window through actual controls and Apply, awaiting the
    # real partial response and the swapped DOM.
    page.fill("#f-from", "2026-10-27T10:00")
    page.fill("#f-to", "2026-10-27T12:00")
    with page.expect_response(
        lambda response: "/partials/errors" in response.url and response.status == 200,
        timeout=10000,
    ):
        page.get_by_role("button", name="Apply").click()
    page.wait_for_function(
        "() => document.querySelector('[data-observation-window]').textContent.includes('10:00')",
        timeout=10000,
    )
    # The applied window keeps the evidence matchers and source.
    assert "status=404" in page.url
    assert "source=example-combined" in page.url
    assert "from=2026-10-27T10" in page.url
    assert "/partials/" not in page.url
    page.reload()
    page.get_by_role("heading", name="Errors").wait_for(timeout=10000)
    # Reload lands back on the Errors page itself with the applied scope,
    # never on the Overview root the old canonical push produced.
    assert page.url.startswith(f"{live_base}/errors?"), page.url
    assert "status=404" in page.url
    assert "source=example-combined" in page.url
    assert "from=2026-10-27T10" in page.url
    # The active Errors nav keeps the full current filters after reload;
    # other pages keep only the shared window state.
    active_href = page.locator('#side-nav a[aria-current="page"]').get_attribute("href")
    assert active_href is not None and active_href.startswith("/errors?"), active_href
    assert "status=404" in active_href, active_href
    assert "source=example-combined" in active_href, active_href
    assert "from=2026-10-27T10" in active_href, active_href
    reloaded_security = page.get_attribute('#side-nav a[href^="/security"]', "href")
    assert reloaded_security is not None and "site=default" in reloaded_security
    assert "status=404" not in reloaded_security, reloaded_security
    # Same-page navigation now reuses the NEW window, not the shell hrefs.
    nav_href = page.get_attribute('#side-nav a[href^="/errors"]', "href")
    assert nav_href is not None
    assert "from=2026-10-27T10" in nav_href
    assert "status=404" in nav_href
    assert "source=example-combined" in nav_href
    # Cross-page navigation carries the same NEW shared window state.
    security_href = page.get_attribute('#side-nav a[href^="/security"]', "href")
    assert security_href is not None
    assert "from=2026-10-27T10" in security_href
    assert "to=2026-10-27T12" in security_href
    assert "site=default" in security_href
    assert "source=example-combined" in security_href
    _assert_clean(observed, live_base)


def test_reversed_window_shows_visible_alert_and_keeps_previous_results(page, live_base, observed):
    _login(page, live_base)
    page.goto(f"{live_base}/errors?site=default&{W1}&tz=UTC")
    page.get_by_role("heading", name="Errors").wait_for(timeout=10000)
    before = page.locator("[data-observation-window]").inner_text()
    # Submit an invalid window through the actual controls: the server
    # rejects it with 400 and swaps nothing.
    page.fill("#f-from", "2026-10-27T13:00")
    page.fill("#f-to", "2026-10-27T12:00")
    with page.expect_response(
        lambda response: "/partials/errors" in response.url and response.status == 400,
        timeout=10000,
    ):
        page.get_by_role("button", name="Apply").click()
    # A visible alert says the invalid window was NOT applied; the
    # previous valid results stay identifiable below it.
    banner = page.locator("[data-filter-error]")
    banner.wait_for(state="visible", timeout=10000)
    assert "could not be applied" in banner.inner_text()
    assert "previous results" in banner.inner_text()
    assert page.locator("[data-observation-window]").inner_text() == before
    assert "/partials/" not in page.url
    # Exactly two console errors belong to the deliberately rejected
    # request and nothing else: Chromium's native failed-resource notice
    # (request URL in the structured location) and htmx's own response
    # error. The visible banner above is the user-facing handling.
    assert len(observed["errors"]) == 2, observed["errors"]
    native = [url for text, url in observed["console_sources"] if "Failed to load resource" in text]
    assert len(native) == 1 and "/partials/errors" in native[0], native
    assert "400" in observed["errors"][0] or "400" in observed["errors"][1]
    htmx_errors = [
        text for text, _ in observed["console_sources"] if "Response Status Error Code 400" in text
    ]
    assert len(htmx_errors) == 1 and "partials/errors" in htmx_errors[0]


def _enable_fake_chat(monkeypatch, script=None, fail_with=None):
    """Enable the assistant for the in-process server with a scripted,
    network-free provider. Synthetic data only; no real transport."""
    import app.ai.service as ai_service
    from app.ai.providers.fake import FakeProvider

    for name in (
        "AI_ENABLED",
        "MODEL_DATA_POLICY_VERIFIED",
        "MODEL_ALLOW_REAL_DATA",
        "LLM_DAILY_LIMIT_USD",
    ):
        monkeypatch.setenv(name, "true" if name != "LLM_DAILY_LIMIT_USD" else "50")
    provider = FakeProvider(script=list(script or []), fail_with=fail_with)
    monkeypatch.setattr(ai_service, "select_provider", lambda settings: provider)


def _success_script():
    from app.ai.providers.base import ProviderResponse, ToolCall

    return [
        ProviderResponse(
            text="",
            input_tokens=10,
            output_tokens=5,
            tool_calls=(ToolCall(name="get_summary", arguments={"limit": 5}),),
        ),
        ProviderResponse(text="Ten requests in range.", input_tokens=20, output_tokens=8),
    ]


def test_ask_send_reaches_server_and_renders_answer_and_evidence(
    page, live_base, observed, monkeypatch
):
    import json

    _enable_fake_chat(monkeypatch, script=_success_script())
    posted: dict = {}

    def _capture(req):
        if req.method == "POST" and "/api/v1/chat/ask" in req.url and req.post_data:
            posted.update(json.loads(req.post_data))

    page.on("request", _capture)
    _login(page, live_base)
    page.goto(f"{live_base}/ask?site=default&{W1}&tz=UTC&source=example-combined")
    page.get_by_role("heading", name="Ask AI").first.wait_for(timeout=10000)
    page.locator("[data-starter-prompt]").first.click()
    page.get_by_role("button", name="Send").click()
    # The POST actually reaches the server: the scripted answer renders
    # with a server-generated evidence link, not a fabricated message.
    page.wait_for_function(
        "() => document.querySelector('[data-ask-answer]').textContent.includes('Ten requests')",
        timeout=15000,
    )
    assert "Ten requests in range." in page.locator("[data-ask-answer]").inner_text()
    link = page.locator("[data-ask-evidence] a")
    assert link.count() >= 1
    href = link.first.get_attribute("href")
    assert href is not None and "site=default" in href, href
    assert "limit=5" in href, href
    # The request carried the applied scope: site, source and window.
    assert posted.get("site_id") == "default", posted
    assert posted.get("source_id") == "example-combined", posted
    assert str(posted.get("time_from", "")).startswith("2026-10-27"), posted
    assert str(posted.get("time_to", "")).startswith("2026-10-28"), posted
    _assert_clean(observed, live_base)


def test_ask_send_failure_shows_unavailable(page, live_base, observed, monkeypatch):
    from app.ai.providers.base import BackendUnavailable

    _enable_fake_chat(monkeypatch, fail_with=BackendUnavailable)
    _login(page, live_base)
    page.goto(f"{live_base}/ask?site=default&{W1}&tz=UTC")
    page.get_by_role("heading", name="Ask AI").first.wait_for(timeout=10000)
    page.fill("#ask-input", "How many requests arrived?")
    page.get_by_role("button", name="Send").click()
    status = page.locator("[data-ask-status]")
    status.wait_for(state="visible", timeout=15000)
    assert "unavailable" in status.inner_text().lower()
    assert page.locator("[data-ask-answer]").inner_text().strip() == ""
    # The deliberate 503 is a normal native request log, matched exactly.
    _assert_only_expected_request_error(observed, live_base, 503, "/api/v1/chat/ask")


def test_ask_apply_updates_scope_for_later_posts(page, live_base, observed):
    _login(page, live_base)
    page.goto(f"{live_base}/ask?site=default&{W1}&tz=UTC&source=example-combined")
    page.get_by_role("heading", name="Ask AI").first.wait_for(timeout=10000)
    ask_root = page.locator("[data-ask]")
    assert ask_root.get_attribute("data-source") == "example-combined"
    assert "2026-10-27T00" in (ask_root.get_attribute("data-from") or "")
    # The Ask filter is a real full-page GET: Apply reloads with the new
    # window and the POST scope follows it.
    page.fill("#f-from", "2026-10-27T10:00")
    page.fill("#f-to", "2026-10-27T12:00")
    with page.expect_navigation(timeout=10000):
        page.get_by_role("button", name="Apply").click()
    page.get_by_role("heading", name="Ask AI").first.wait_for(timeout=10000)
    assert "from=2026-10-27T10" in page.url
    ask_root = page.locator("[data-ask]")
    assert "2026-10-27T10" in (ask_root.get_attribute("data-from") or "")
    assert "2026-10-27T12" in (ask_root.get_attribute("data-to") or "")
    assert ask_root.get_attribute("data-source") == "example-combined"
    assert page.locator("[data-starter-prompt]").count() == 8
    # Sending still works against the applied scope (honest disabled
    # state here; the POST would carry the attrs above).
    page.locator("[data-starter-prompt]").first.click()
    page.get_by_role("button", name="Send").click()
    status = page.locator("[data-ask-status]")
    status.wait_for(state="visible", timeout=10000)
    assert "The AI assistant is disabled." in status.inner_text()
    _assert_only_expected_request_error(observed, live_base, 409, "/api/v1/chat/ask")


def test_errors_next_previous_navigate_real_pages(page, live_base, observed):
    import re

    _login(page, live_base)
    page.goto(f"{live_base}/errors?site=default&{W1}&tz=UTC&limit=1")
    page.get_by_role("heading", name="Errors").wait_for(timeout=10000)
    match = re.search(r"Showing 1–1 of (\d+)", page.content())
    assert match and int(match.group(1)) > 1
    total = match.group(1)
    # Next is a real full-page navigation whose URL parses to exact
    # filters with the advanced offset (regression: mangled first key).
    with page.expect_navigation(timeout=10000):
        page.get_by_role("link", name="Next").click()
    page.get_by_role("heading", name="Errors").wait_for(timeout=10000)
    assert f"Showing 2–2 of {total}" in page.content()
    assert "offset=1" in page.url and "limit=1" in page.url
    assert "site=default" in page.url
    with page.expect_navigation(timeout=10000):
        page.get_by_role("link", name="Previous").click()
    page.get_by_role("heading", name="Errors").wait_for(timeout=10000)
    assert f"Showing 1–1 of {total}" in page.content()
    assert "offset=1" not in page.url
    _assert_clean(observed, live_base)


def test_populated_security_fits_narrow_viewport(page, populated_base, observed):
    _login(page, populated_base)
    for theme in ("light", "dark"):
        page.set_viewport_size({"width": 360, "height": 800})
        page.goto(f"{populated_base}/security?site=default&{W1}&tz=UTC")
        page.select_option("#theme-select", theme)
        page.get_by_role("heading", name="Security findings").wait_for(timeout=10000)
        page.wait_for_timeout(500)  # late font/layout settle before measuring
        # Both finding cards render, and the 64-char client pseudonym
        # wraps: the document never overflows 360px in either theme.
        assert "Client pseudonym" in page.content()
        assert "/.env" in page.content()
        assert page.evaluate("document.documentElement.scrollWidth") <= 360
    _assert_clean(observed, populated_base)


def test_overview_paging_note_matches_requested_limit(page, live_base, observed):
    _login(page, live_base)
    page.goto(f"{live_base}/?site=default&{W1}&tz=UTC&limit=3")
    page.get_by_role("heading", name="Traffic timeline").wait_for(timeout=10000)
    body = page.content()
    assert "Showing 1–3 of " in body
    _assert_clean(observed, live_base)


def canvas_size(page, selector: str) -> int:
    return page.evaluate(
        "(sel) => { const el = document.querySelector(sel);"
        " return el ? Math.round(el.getBoundingClientRect().width * el.getBoundingClientRect().height) : 0; }",
        selector,
    )
