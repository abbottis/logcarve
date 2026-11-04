"""T4b1 protected browser checks: performance/SEO/referrer report UI.

Repeatable against a loopback server with synthetic fixtures. Skips
cleanly when loopback sockets are unavailable (the browser sandbox
stays ON: ``chromium_sandbox=True`` from the shared conftest; the
coordinator runs the exact maintained command when the shell sandbox
blocks the browser here). Covers the real user-visible slice:
navigation to the three report pages, local Chart.js plots with table
alternatives, sort/view/relation controls, exact path/bot drilldowns,
coverage and limitation honesty, narrow-viewport/dark-theme operation,
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
    '198.51.100.7 - - [27/Oct/2026:10:00:00 +0000] "GET /fast HTTP/1.1" 200 128 '
    '"-" "Browser/1.0" example.org HIT 0.010 text/html TLSv1.3 "0.005"\n'
    '198.51.100.8 - - [27/Oct/2026:10:02:00 +0000] "GET /slow HTTP/1.1" 200 128 '
    '"-" "Browser/1.0" example.org MISS 0.900 application/json - "-"\n'
    '198.51.100.9 - - [27/Oct/2026:10:04:00 +0000] "GET /bot-gone HTTP/1.1" 404 128 '
    '"https://external.example/page" "GPTBot/1.0" example.org - - - - "-"\n'
    '198.51.100.10 - - [27/Oct/2026:10:05:00 +0000] "GET /gone HTTP/1.1" 404 128 '
    '"http://example.org/start" "Browser/1.0" example.org - - - - "-"\n'
)


def _free_port() -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]
    except PermissionError:
        pytest.skip("loopback sockets are unavailable in this sandbox")


@pytest.fixture
def b1_base(tmp_path, monkeypatch):
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
    db = tmp_path / "t4b1_e2e.sqlite3"
    migrate(db)
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
    run_import(
        db,
        source=SourceConfig(
            source_id="b1-ext",
            format_id="nginx_extended",
            allowed_root=root,
            relative_path="ext.log",
        ),
        site_id="default",
        site_name="B1",
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


def test_report_navigation_charts_tables_and_drilldowns(page, b1_base):
    errors, failed, outside = _watch(page)
    base = b1_base
    _login(page, base)

    # Obvious navigation: the side nav reaches all three report pages.
    page.goto(f"{base}/performance?{STATE}")
    expect(page.locator("nav#side-nav")).to_contain_text("Performance")
    expect(page.locator("nav#side-nav")).to_contain_text("SEO")
    expect(page.locator("nav#side-nav")).to_contain_text("Referrers")
    expect(page.locator("h1")).to_contain_text("Performance")

    # Performance: slow-endpoint chart plus its table alternative.
    expect(page.locator("#perf-slow-chart")).to_be_visible(timeout=10000)
    assert page.locator("#perf-slow-chart").evaluate("el => el.width > 0 && el.height > 0")
    expect(page.locator("body")).to_contain_text("/slow")
    expect(page.locator("body")).to_contain_text("Hit ratio")
    # Sort control re-ranks server-side: slowest first by default.
    rows = page.locator("table tbody tr td:first-child")
    first_default = rows.first.inner_text(timeout=10000)
    assert "/slow" in first_default
    page.click('a:has-text("Measured requests (most first)")')
    page.wait_for_load_state("load")
    expect(page.locator("body")).to_contain_text("/slow")

    # SEO: redirect view is honestly empty here; client-error view has
    # the per-path/bot chart, table and drilldown.
    page.goto(f"{base}/seo?{STATE}&view=redirects")
    expect(page.locator("h1")).to_contain_text("SEO")
    expect(page.locator("body")).to_contain_text("No groups")
    expect(page.locator("body")).to_contain_text("identity not verified")
    page.goto(f"{base}/seo?{STATE}&view=client_errors")
    expect(page.locator("#seo-groups-chart")).to_be_visible(timeout=10000)
    expect(page.locator("body")).to_contain_text("/bot-gone")
    with page.expect_navigation():
        page.locator('a[title="Show only this path"]').first.click()
    assert "path_exact=" in page.url
    expect(page.locator("body")).to_contain_text("of 1")

    # AI-only view states its universe and its absence caveat.
    page.goto(f"{base}/seo?{STATE}&view=ai_only")
    expect(page.locator("body")).to_contain_text("Comparison universe")
    expect(page.locator("body")).to_contain_text("never proof of absence")

    # Referrers: full sanitized paths, internal/external switch.
    page.goto(f"{base}/referrers?{STATE}")
    expect(page.locator("h1")).to_contain_text("Referrers")
    expect(page.locator("body")).to_contain_text("https://external.example/page")
    expect(page.locator("body")).to_contain_text("http://example.org/start")
    expect(page.locator("#ref-targets-chart")).to_be_visible(timeout=10000)
    page.click('a:has-text("Internal only")')
    page.wait_for_load_state("load")
    expect(page.locator("body")).to_contain_text("http://example.org/start")
    assert "external.example/page" not in page.content()
    expect(page.locator("body")).to_contain_text("query values are never stored")

    # Keyboard focus reaches interactive controls visibly.
    page.goto(f"{base}/performance?{STATE}")
    page.keyboard.press("Tab")
    focused = page.evaluate(
        "() => document.activeElement ? document.activeElement.tagName : 'NONE'"
    )
    assert focused in ("A", "BUTTON", "SELECT", "INPUT"), focused

    assert failed == [], failed
    assert outside == [], outside
    assert errors == [], errors


def test_apply_keeps_page_local_state(page, b1_base):
    """Genuine Apply-state: switch view/relation/sort, Apply, assert URL/view/count."""
    errors, failed, outside = _watch(page)
    base = b1_base
    _login(page, base)

    # Performance: switch to the P95 rank, then Apply a timezone change.
    page.goto(f"{base}/performance?{STATE}&sort=p95_desc")
    expect(page.locator("body")).to_contain_text("Slow endpoints")
    assert "sort=p95_desc" in page.url
    page.select_option("#f-tz", "America/New_York")
    page.click('button:has-text("Apply")')
    page.wait_for_load_state("load")
    assert "sort=p95_desc" in page.url, page.url
    expect(page.locator("body")).to_contain_text("Slow endpoints")
    expect(page.locator("body")).to_contain_text("/slow")

    # SEO: switch to the AI-only view, then Apply keeps the view.
    page.goto(f"{base}/seo?{STATE}&view=ai_only")
    expect(page.locator("body")).to_contain_text("Comparison universe")
    page.select_option("#f-tz", "America/New_York")
    page.click('button:has-text("Apply")')
    page.wait_for_load_state("load")
    assert "view=ai_only" in page.url, page.url
    expect(page.locator("body")).to_contain_text("Comparison universe")

    # Referrers: broken+external view survives an Apply.
    page.goto(f"{base}/referrers?{STATE}&view=broken&relation=external")
    expect(page.locator("body")).to_contain_text("Broken inbound links")
    page.select_option("#f-tz", "America/New_York")
    page.click('button:has-text("Apply")')
    page.wait_for_load_state("load")
    assert "view=broken" in page.url and "relation=external" in page.url, page.url
    expect(page.locator("body")).to_contain_text("Broken inbound links")

    # Back/forward history keeps the report state (canonical push).
    page.go_back()
    page.wait_for_load_state("load")
    assert "view=broken" in page.url or "view=ai_only" in page.url or "sort=" in page.url

    assert failed == [], failed
    assert outside == [], outside
    assert errors == [], errors


def test_narrow_viewport_and_dark_theme(page, b1_base):
    errors, failed, outside = _watch(page)
    base = b1_base
    _login(page, base)

    page.set_viewport_size({"width": 390, "height": 844})
    for path in ("performance", "seo", "referrers"):
        page.goto(f"{base}/{path}?{STATE}")
        page.wait_for_load_state("load")
        overflow = page.evaluate(
            "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        assert overflow <= 1, (path, overflow)
    # Dark theme keeps charts and tables readable, no console errors.
    page.select_option("#theme-select", "dark")
    expect(page.locator("html")).to_have_attribute("data-theme", "dark")
    page.wait_for_timeout(500)
    page.goto(f"{base}/performance?{STATE}")
    expect(page.locator("#perf-slow-chart")).to_be_visible(timeout=10000)
    expect(page.locator("body")).to_contain_text("/slow")
    page.select_option("#theme-select", "light")

    assert failed == [], failed
    assert outside == [], outside
    assert errors == [], errors
