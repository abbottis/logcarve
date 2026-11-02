"""T5a protected browser checks: offline country UI integration (PAR-09).

Repeatable against a loopback server with synthetic documentation
fixtures (every row stays Unknown by design; no database file, no
network, no real addresses). Skips cleanly when loopback sockets are
unavailable (the browser sandbox stays ON: ``chromium_sandbox=True``
from the shared conftest; the coordinator runs the exact maintained
command when the shell sandbox blocks the browser here). Covers the
real user-visible slice: country filter select with the Unknown
option, Unknown breakdown with coverage and DB-IP attribution,
country drilldown links that replay the filtered read, per-row
Unknown details with attribution, saved-view country roundtrip and
Ask filter carriage, with no external requests or console errors.
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
    '203.0.113.21 - - [27/Oct/2026:10:00:00 +0000] "GET /in HTTP/1.1" 200 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\n'
    '203.0.113.22 - - [27/Oct/2026:11:00:00 +0000] "GET /other HTTP/1.1" 200 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\n'
    '198.51.100.23 - - [27/Oct/2026:12:00:00 +0000] "GET /gone HTTP/1.1" 404 128 '
    '"-" "Browser/1.0" example.org - - - - "-"\n'
    '10.9.9.9 - - [27/Oct/2026:12:01:00 +0000] "GET /local HTTP/1.1" 500 64 '
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
def c5_base(tmp_path, monkeypatch):
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
    db = tmp_path / "t5a_e2e.sqlite3"
    migrate(db)
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
    report = run_import(
        db,
        source=SourceConfig(
            source_id="c5-ext",
            format_id="nginx_extended",
            allowed_root=root,
            relative_path="ext.log",
        ),
        site_id="default",
        site_name="C5",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="ext.log",
        hmac_key=b"synthetic-test-hmac-key",
    )
    # The synthetic seed holds exactly four log lines; every one must
    # import (no database is configured, so all stay Unknown).
    assert report.lines_accepted == 4, report
    assert report.lines_rejected == 0, report
    assert report.geoip_available is False
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


def test_country_unknown_breakdown_and_drilldown(page, c5_base):
    errors, failed, outside = _watch(page)
    base = c5_base
    _login(page, base)

    # Overview shows the Unknown breakdown with honest coverage, the
    # DB-IP credit and a drilldown link back to the filtered read.
    page.goto(f"{base}/?{STATE}")
    expect(page.locator("#country-h")).to_be_visible(timeout=10000)
    expect(page.locator("body")).to_contain_text("Unknown")
    expect(page.locator("body")).to_contain_text("IP Geolocation by DB-IP")
    assert page.locator('a[href="https://db-ip.com"]').count() >= 1
    drilldown = page.locator('section:has(#country-h) a[href*="country="]')
    assert drilldown.count() >= 1
    href = drilldown.first.get_attribute("href")
    assert href is not None and "country=UNKNOWN" in href

    # Following the drilldown replays the Unknown-filtered read.
    with page.expect_navigation():
        drilldown.first.click()
    assert "country=UNKNOWN" in page.url
    expect(page.locator("body")).to_contain_text("Unknown")

    assert failed == [], failed
    assert outside == [], outside
    assert errors == [], errors


def test_country_filter_select_and_row_details(page, c5_base):
    errors, failed, outside = _watch(page)
    base = c5_base
    _login(page, base)

    # The shared filter bar offers the Unknown country selector on the
    # Requests page; applying it narrows to the four synthetic rows.
    page.goto(f"{base}/requests?{STATE}")
    options = page.locator("#f-country option").all_inner_texts()
    assert any("Unknown" in text for text in options), options
    page.select_option("#f-country", "UNKNOWN")
    page.click("#filter-bar button[type=submit]")
    page.wait_for_function(
        "() => window.location.href.includes('country=UNKNOWN')",
        timeout=10000,
    )
    expect(page.locator("body")).to_contain_text("Unknown")

    # Row details show the Unknown outcome with provenance and the
    # DB-IP credit; no original address ever renders.
    page.locator("[data-detail-toggle]").first.click()
    expect(page.locator("body")).to_contain_text("Unknown")
    assert page.locator('a[href="https://db-ip.com"]').count() >= 1
    content = page.content()
    assert "203.0.113.21" not in content
    assert "10.9.9.9" not in content

    assert failed == [], failed
    assert outside == [], outside
    assert errors == [], errors


def test_country_saved_view_and_ask_carriage(page, c5_base):
    errors, failed, outside = _watch(page)
    base = c5_base
    _login(page, base)

    # A saved view stores and replays the Unknown country selector.
    page.goto(f"{base}/requests?{STATE}&country=UNKNOWN")
    page.fill("#save-view-name", "Unknown countries")
    with page.expect_navigation():
        page.locator("form[data-save-current] button[type=submit]").click()
    assert "/saved-views" in page.url
    expect(page.locator("body")).to_contain_text("Unknown countries")
    with page.expect_navigation():
        page.locator('a:has-text("/requests?")').first.click()
    assert "country=UNKNOWN" in page.url

    # The Ask page carries the country filter into the tool scope.
    page.goto(f"{base}/ask?{STATE}&country=UNKNOWN")
    assert page.locator('[data-country="UNKNOWN"]').count() >= 1

    assert failed == [], failed
    assert outside == [], outside
    assert errors == [], errors
