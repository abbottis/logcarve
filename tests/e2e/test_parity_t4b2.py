"""T4b2 protected browser checks: journeys + expanded security report UI.

Repeatable against a loopback server with synthetic fixtures. Skips
cleanly when loopback sockets are unavailable (the browser sandbox
stays ON: ``chromium_sandbox=True`` from the shared conftest; the
coordinator runs the exact maintained command when the shell sandbox
blocks the browser here). Covers the real user-visible slice:
navigation to the Journeys page, journey list/entry-path views with
server sort and minimum-requests controls, opaque timeline detail,
expanded security evidence (rates, peaks, sequences, 401/403) with
chart plus table alternatives, narrow-viewport/dark-theme operation,
keyboard focus, and no external requests or console errors.
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

EXT_LINES = (
    '198.51.100.21 - - [27/Oct/2026:10:00:00 +0000] "GET /in HTTP/1.1" 200 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\\n'
    '198.51.100.21 - - [27/Oct/2026:10:05:00 +0000] "GET /mid HTTP/1.1" 200 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\\n'
    '198.51.100.21 - - [27/Oct/2026:10:40:00 +0000] "GET /late HTTP/1.1" 200 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\\n'
    '198.51.100.22 - - [27/Oct/2026:11:00:00 +0000] "GET /other HTTP/1.1" 200 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\\n'
    '198.51.100.23 - - [27/Oct/2026:12:00:00 +0000] "GET /gone-1 HTTP/1.1" 404 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\\n'
    '198.51.100.23 - - [27/Oct/2026:12:01:00 +0000] "GET /gone-2 HTTP/1.1" 404 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\\n'
    '198.51.100.23 - - [27/Oct/2026:12:02:00 +0000] "GET /gone-3 HTTP/1.1" 404 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\\n'
    '198.51.100.23 - - [27/Oct/2026:12:03:00 +0000] "GET /gone-4 HTTP/1.1" 404 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\\n'
    '198.51.100.23 - - [27/Oct/2026:12:04:00 +0000] "GET /gone-5 HTTP/1.1" 404 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\\n'
    '198.51.100.25 - - [27/Oct/2026:12:20:00 +0000] "GET /login HTTP/1.1" 401 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\\n'
    '198.51.100.25 - - [27/Oct/2026:12:21:00 +0000] "GET /login HTTP/1.1" 401 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\\n'
    '198.51.100.25 - - [27/Oct/2026:12:22:00 +0000] "GET /admin HTTP/1.1" 403 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\\n'
)


def _free_port() -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]
    except PermissionError:
        pytest.skip("loopback sockets are unavailable in this sandbox")


@pytest.fixture
def b2_base(tmp_path, monkeypatch):
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
    db = tmp_path / "t4b2_e2e.sqlite3"
    migrate(db)
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
    run_import(
        db,
        source=SourceConfig(
            source_id="b2-ext",
            format_id="nginx_extended",
            allowed_root=root,
            relative_path="ext.log",
        ),
        site_id="default",
        site_name="B2",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="ext.log",
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


def test_journeys_navigation_charts_tables_and_detail(page, b2_base):
    errors, failed, outside = _watch(page)
    base = b2_base
    _login(page, base)

    # Obvious navigation: the side nav reaches Journeys and Security.
    page.goto(f"{base}/journeys?{STATE}")
    expect(page.locator("nav#side-nav")).to_contain_text("Journeys")
    expect(page.locator("nav#side-nav")).to_contain_text("Security")
    expect(page.locator("h1")).to_contain_text("Request journeys")
    expect(page.locator("body")).to_contain_text("never visitors")

    # Journey list chart plus its semantic table alternative.
    expect(page.locator("#journeys-chart")).to_be_visible(timeout=10000)
    assert page.locator("#journeys-chart").evaluate("el => el.width > 0 && el.height > 0")
    expect(page.locator("body")).to_contain_text("/gone-1")
    expect(page.locator("body")).to_contain_text("/in")

    # Server-side duration rank: the 300s /in journey leads.
    page.click('a:has-text("Longest duration first")')
    page.wait_for_load_state("load")
    assert "sort=duration_desc" in page.url
    rows = page.locator("table tbody tr td:first-child")
    assert "/in" in rows.first.inner_text(timeout=10000)

    # Minimum-requests floor narrows the eligible set server-side.
    page.click('a:has-text("Entry paths")')
    page.wait_for_load_state("load")
    assert "view=entries" in page.url
    expect(page.locator("#journey-entries-chart")).to_be_visible(timeout=10000)
    expect(page.locator("body")).to_contain_text("/gone-1")

    # Opaque timeline detail opens from the list without raw addresses.
    page.goto(f"{base}/journeys?{STATE}")
    with page.expect_navigation():
        page.locator('a:has-text("Open journey timeline")').first.click()
    assert "journey_id=" in page.url and "journey_client=" in page.url
    assert "journey_start=" in page.url
    expect(page.locator("body")).to_contain_text("Journey timeline")
    expect(page.locator("body")).to_contain_text("Technical request journeys")

    # Expanded security evidence: chart, rates, sequences, 401 honesty.
    page.goto(f"{base}/security?{STATE}")
    expect(page.locator("h1")).to_contain_text("Security")
    expect(page.locator("#security-findings-chart")).to_be_visible(timeout=10000)
    assert page.locator("#security-findings-chart").evaluate("el => el.width > 0 && el.height > 0")
    expect(page.locator("body")).to_contain_text("authentication challenge")
    expect(page.locator("body")).to_contain_text("Average per minute")
    expect(page.locator("body")).to_contain_text("Chronological path sequence")
    expect(page.locator("body")).to_contain_text("/gone-1")

    # Narrow viewport with dark theme: no page overflow, content stays.
    page.set_viewport_size({"width": 390, "height": 844})
    page.select_option("#theme-select", "dark")
    page.goto(f"{base}/journeys?{STATE}")
    expect(page.locator("body")).to_contain_text("/gone-1")
    overflow = page.evaluate(
        "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
    )
    assert overflow <= 1, overflow
    page.set_viewport_size({"width": 1440, "height": 900})
    page.select_option("#theme-select", "light")

    # Keyboard focus reaches interactive controls visibly.
    page.goto(f"{base}/journeys?{STATE}")
    page.keyboard.press("Tab")
    focused = page.evaluate(
        "() => document.activeElement ? document.activeElement.tagName : 'NONE'"
    )
    assert focused in ("A", "BUTTON", "SELECT", "INPUT"), focused

    assert failed == [], failed
    assert outside == [], outside
    assert errors == [], errors
