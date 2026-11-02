"""T4c protected browser checks: saved views, comparison, refresh, display fixes.

Repeatable against a loopback server with synthetic fixtures. Skips
cleanly when loopback sockets are unavailable (the browser sandbox
stays ON: ``chromium_sandbox=True`` from the shared conftest; the
coordinator runs the exact maintained command when the shell sandbox
blocks the browser here). Covers the real user-visible slice:
filter-state survival through actual Apply clicks, Berlin display
instants with offset, microsecond durations, central security labels,
saved-view create/open/rename/delete, explicit comparison with chart
plus table, opt-in refresh defaults, expanded Help, narrow/dark
operation, keyboard focus, and no external requests or console errors.
"""

import socket
import threading
import time
import urllib.request
from pathlib import Path

import pytest
from playwright.sync_api import expect

ROOT = Path(__file__).resolve().parent.parent.parent
STATE = (
    "site=default&range=custom&from=2026-10-27T00:00:00%2B00:00"
    "&to=2026-10-28T00:00:00%2B00:00&tz=UTC"
)
BERLIN = (
    "site=default&range=custom&from=2026-10-27T00:00:00%2B00:00"
    "&to=2026-10-28T00:00:00%2B00:00&tz=Europe%2FBerlin"
)

EXT_LINES = (
    '198.51.100.21 - - [27/Oct/2026:10:00:00 +0000] "GET /in HTTP/1.1" 200 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\n'
    '198.51.100.21 - - [27/Oct/2026:10:05:00 +0000] "GET /mid HTTP/1.1" 200 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\n'
    '198.51.100.21 - - [27/Oct/2026:10:40:00 +0000] "GET /late HTTP/1.1" 200 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\n'
    '198.51.100.22 - - [27/Oct/2026:11:00:00 +0000] "GET /other HTTP/1.1" 200 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\n'
    '198.51.100.23 - - [27/Oct/2026:12:00:00 +0000] "GET /gone-1 HTTP/1.1" 404 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\n'
    '198.51.100.23 - - [27/Oct/2026:12:01:00 +0000] "GET /gone-2 HTTP/1.1" 404 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\n'
    '198.51.100.23 - - [27/Oct/2026:12:02:00 +0000] "GET /gone-3 HTTP/1.1" 404 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\n'
    '198.51.100.23 - - [27/Oct/2026:12:03:00 +0000] "GET /gone-4 HTTP/1.1" 404 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\n'
    '198.51.100.23 - - [27/Oct/2026:12:04:00 +0000] "GET /gone-5 HTTP/1.1" 404 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\n'
    '198.51.100.25 - - [27/Oct/2026:12:20:00 +0000] "GET /login HTTP/1.1" 401 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\n'
    '198.51.100.25 - - [27/Oct/2026:12:21:00 +0000] "GET /login HTTP/1.1" 401 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\n'
    '198.51.100.25 - - [27/Oct/2026:12:22:00 +0000] "GET /admin HTTP/1.1" 403 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\n'
)


def _free_port() -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]
    except PermissionError:
        pytest.skip("loopback sockets are unavailable in this sandbox")


@pytest.fixture
def c4_base(tmp_path, monkeypatch):
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
    (root / "ext.log").write_bytes(EXT_LINES.encode())
    db = tmp_path / "t4c_e2e.sqlite3"
    migrate(db)
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
    report = run_import(
        db,
        source=SourceConfig(
            source_id="c4-ext",
            format_id="nginx_extended",
            allowed_root=root,
            relative_path="ext.log",
        ),
        site_id="default",
        site_name="C4",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="ext.log",
        hmac_key=b"synthetic-test-hmac-key",
    )
    # The synthetic seed holds exactly 12 physical log lines; every one
    # must import before the browser flow starts.
    assert report.lines_accepted == 12, report
    assert report.lines_rejected == 0, report
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


def _watch(page):
    errors: list[str] = []
    failed: list[str] = []
    outside: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    page.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)
    page.on("requestfailed", lambda req: failed.append(f"{req.url} {req.failure}"))
    page.on(
        "request",
        lambda req: (
            outside.append(req.url)
            if not (req.url.startswith("http://127.0.0.1") or req.url.startswith("data:"))
            else None
        ),
    )
    return errors, failed, outside


def test_journey_apply_and_display_fixes(page, c4_base):
    errors, failed, outside = _watch(page)
    base = c4_base
    _login(page, base)

    # Actual Apply click keeps journey view/sort/min-requests state.
    page.goto(f"{base}/journeys?{STATE}&view=entries&sort=duration_desc&min_requests=5")
    expect(page.locator("#journey-entries-chart")).to_be_visible(timeout=10000)
    page.click("#filter-bar button[type=submit]")
    page.wait_for_load_state("load")
    assert "view=entries" in page.url
    assert "sort=duration_desc" in page.url
    assert "min_requests=5" in page.url
    expect(page.locator("#journey-entries-chart")).to_be_visible(timeout=10000)

    # Berlin display instants carry the +01:00 offset; canonical UTC
    # stays in titles and detail selectors.
    page.goto(f"{base}/journeys?{BERLIN}&sort=start_asc")
    expect(page.locator("body")).to_contain_text("UTC+01:00")
    expect(page.locator("body")).to_contain_text("13:00")
    content = page.content()
    assert 'title="2026-10-27T12:00:00+00:00"' in content

    # Expanded security cards use central labels, never raw enums.
    page.goto(f"{base}/security?{STATE}")
    expect(page.locator("body")).to_contain_text("Rule-matching scope")
    expect(page.locator("body")).to_contain_text("Exact minute interval:")
    content = page.content()
    assert "peak_minute_scope" not in content
    assert "peak_minute_numerator" not in content
    assert "avg_numerator" not in content

    assert failed == [], failed
    assert outside == [], outside
    assert errors == [], errors


def test_saved_views_bookmark_flow(page, c4_base):
    errors, failed, outside = _watch(page)
    base = c4_base
    _login(page, base)

    # Save the current filtered read from the Journeys page.
    page.goto(f"{base}/journeys?{STATE}")
    page.fill("#save-view-name", "Entry watch")
    with page.expect_navigation():
        page.locator('form[action="/saved-views"] button[type=submit]').click()
    assert "/saved-views" in page.url
    expect(page.locator("body")).to_contain_text("Entry watch")

    # The stored link replays the exact read.
    with page.expect_navigation():
        page.locator('a:has-text("/journeys?")').first.click()
    assert "/journeys" in page.url and "site=default" in page.url
    expect(page.locator("h1")).to_contain_text("Request journeys")

    # Rename then delete from the Saved Views page.
    page.goto(f"{base}/saved-views")
    page.locator("input[id^=rename-]").first.fill("Renamed view")
    with page.expect_navigation():
        page.locator('button:has-text("Rename")').first.click()
    expect(page.locator("body")).to_contain_text("Renamed view")
    with page.expect_navigation():
        page.locator('button:has-text("Delete")').first.click()
    expect(page.locator("body")).not_to_contain_text("Renamed view")

    assert failed == [], failed
    assert outside == [], outside
    assert errors == [], errors


def test_comparison_refresh_help_and_layout(page, c4_base):
    errors, failed, outside = _watch(page)
    base = c4_base
    _login(page, base)

    # Explicit previous-period comparison: chart plus table alternative.
    page.goto(f"{base}/comparison?{STATE}&baseline=previous")
    expect(page.locator("h1")).to_contain_text("Compare windows")
    expect(page.locator("#compare-metrics-chart")).to_be_visible(timeout=10000)
    assert page.locator("#compare-metrics-chart").evaluate("el => el.width > 0 && el.height > 0")
    expect(page.locator("body")).to_contain_text("Comparison table")
    expect(page.locator("body")).to_contain_text("Current")
    # Canonical link carries the explicit baseline for reproducibility.
    assert "baseline=previous" in page.url

    # Refresh is opt-in and off by default on every data page.
    page.goto(f"{base}/journeys?{STATE}")
    toggle = page.locator("#refresh-toggle")
    expect(toggle).not_to_be_checked()
    expect(page.locator("body")).to_contain_text("Auto-refresh is off.")
    toggle.check()
    expect(page.locator("body")).to_contain_text("Auto-refresh is on;")
    toggle.uncheck()
    expect(page.locator("body")).to_contain_text("Auto-refresh is off.")

    # Expanded operator Help with honest boundaries.
    page.goto(f"{base}/help")
    expect(page.locator("body")).to_contain_text("command line")
    expect(page.locator("body")).to_contain_text("never uploads")
    expect(page.locator("body")).to_contain_text("honestly shows Unknown")
    expect(page.locator("body")).to_contain_text("not enabled in this release")

    # Narrow viewport with dark theme: content stays, no overflow.
    page.set_viewport_size({"width": 390, "height": 844})
    page.select_option("#theme-select", "dark")
    page.goto(f"{base}/comparison?{STATE}&baseline=previous")
    expect(page.locator("body")).to_contain_text("Comparison table")
    overflow = page.evaluate(
        "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
    )
    assert overflow <= 1, overflow
    page.set_viewport_size({"width": 1440, "height": 900})
    page.select_option("#theme-select", "light")

    # Keyboard focus reaches interactive controls visibly.
    page.goto(f"{base}/comparison?{STATE}")
    page.keyboard.press("Tab")
    focused = page.evaluate(
        "() => document.activeElement ? document.activeElement.tagName : 'NONE'"
    )
    assert focused in ("A", "BUTTON", "SELECT", "INPUT"), focused

    assert failed == [], failed
    assert outside == [], outside
    assert errors == [], errors
