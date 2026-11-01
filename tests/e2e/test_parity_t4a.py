"""T4a protected browser checks: private IP settings/search/requests flows.

Repeatable against a loopback server with synthetic fixtures. Skips
cleanly when loopback sockets are unavailable (Muse sandbox keeps the
browser sandbox ON: ``chromium_sandbox=True`` from the shared
conftest; the coordinator runs the exact maintained command when the
shell sandbox blocks the browser here). Covers the real user-visible
slice: full/masked/pseudonym display with the masked suffix absent
from the DOM, settings persistence through the HTML form, exact-IP
search redirect purity, download controls with the pseudonym privacy
note, detail-inspector metadata, back/forward plus web-storage scans,
and narrow-viewport/dark-theme operation.
"""

import socket
import threading
import time
import urllib.request
from pathlib import Path

import pytest
from playwright.sync_api import expect

ROOT = Path(__file__).resolve().parent.parent.parent
V4 = "203.0.113.20"
V6 = "2001:db8::25"
STATE = (
    "site=default&range=custom&from=2026-10-27T00:00:00%2B00:00"
    "&to=2026-10-28T00:00:00%2B00:00&tz=UTC"
)

EXT_LINES = (
    '203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /shop/item HTTP/1.1" 200 153 '
    '"https://example.org/old" "Mozilla/5.0" example.org MISS 0.123 text/html TLSv1.3 '
    '"0.100, 0.020"\n'
    '2001:db8::25 - - [27/Oct/2026:11:02:03 +0100] "GET /style.css HTTP/1.1" 200 2314 '
    '"-" "curl/8.0" example.org HIT 0.002 text/css TLSv1.2 "-"\n'
)


def _free_port() -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]
    except PermissionError:
        pytest.skip("loopback sockets are unavailable in this sandbox")


@pytest.fixture
def t4a_base(tmp_path, monkeypatch):
    import base64

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    monkeypatch.setenv(
        "ORIGINAL_IP_KEY", base64.b64encode(b"t4a-e2e-key-00000000000000000001").decode()
    )
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
    db = tmp_path / "t4a_e2e.sqlite3"
    migrate(db)
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
    run_import(
        db,
        source=SourceConfig(
            source_id="t4a-ext",
            format_id="nginx_extended",
            allowed_root=root,
            relative_path="ext.log",
        ),
        site_id="default",
        site_name="T4a",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="ext.log",
        hmac_key=b"synthetic-test-hmac-key",
        capture_originals=True,
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


def test_private_display_search_settings_flows(page, t4a_base):
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    page.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)
    base = t4a_base
    _login(page, base)

    # Full default: exact spellings render; downloads carry the note.
    page.goto(f"{base}/requests?{STATE}")
    expect(page.locator("body")).to_contain_text(V4, timeout=10000)
    expect(page.locator("body")).to_contain_text(V6)
    expect(page.locator("body")).to_contain_text("Full-result downloads")
    expect(page.locator("body")).to_contain_text("pseudonyms only")
    csv_href = page.locator('a:has-text("Download filtered CSV")').get_attribute("href")
    assert csv_href and "format=csv" in csv_href and "site=default" in csv_href

    # Exact-IP search: posts the address, lands on the safe pseudonym URL.
    page.fill("#f-exact-ip", V4)
    with page.expect_navigation():
        page.locator('[data-ip-search] button[type="submit"]').click()
    assert V4 not in page.url
    assert "search=" in page.url
    expect(page.locator("body")).to_contain_text("/shop/item")
    assert "/style.css" not in page.content()

    # Settings form persists suffix masking; the full suffix is gone
    # from the entire DOM (list, details, titles, JSON).
    page.goto(f"{base}/settings?{STATE}")
    page.select_option("#f-ip-mode", "suffix_mask")
    page.fill("#f-ip-v4", "1")
    page.fill("#f-ip-v6", "4")
    with page.expect_navigation():
        page.locator('button:has-text("Save display settings")').click()
    expect(page.locator("body")).to_contain_text("Masked suffix")
    page.goto(f"{base}/requests?{STATE}")
    expect(page.locator("body")).to_contain_text("203.0.113.*")
    body_html = page.content()
    assert V4 not in body_html
    assert "2001:db8::25" not in body_html

    # Detail inspector: masked value, recovery-free metadata, safe link.
    page.locator("[data-detail-toggle]").first.click()
    expect(page.locator("body")).to_contain_text("123.0 ms")
    assert "noopener" in body_html or "noopener" in page.content()

    # Pseudonym-only via the same form; nothing original remains.
    page.goto(f"{base}/settings?{STATE}")
    page.select_option("#f-ip-mode", "pseudonym_only")
    with page.expect_navigation():
        page.locator('button:has-text("Save display settings")').click()
    page.goto(f"{base}/requests?{STATE}")
    expect(page.locator("body")).not_to_contain_text(V4, timeout=10000)
    expect(page.locator("body")).not_to_contain_text("2001:db8", timeout=10000)

    # Back/forward plus web storage: no original address survives in
    # localStorage, sessionStorage or the restored DOM.
    page.go_back()
    page.wait_for_load_state("load")
    stored = page.evaluate(
        "() => JSON.stringify({"
        "ls: Object.entries(localStorage), ss: Object.entries(sessionStorage)})"
    )
    assert V4 not in stored and V6 not in stored
    assert "203.0.113" not in stored
    expect(page.locator("body")).not_to_contain_text(V4, timeout=10000)
    page.go_forward()
    page.wait_for_load_state("load")
    expect(page.locator("body")).not_to_contain_text(V4, timeout=10000)

    assert errors == [], errors


def test_narrow_viewport_and_dark_theme(page, t4a_base):
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    base = t4a_base
    page.set_viewport_size({"width": 390, "height": 844})
    _login(page, base)
    page.goto(f"{base}/requests?{STATE}")
    expect(page.locator("body")).to_contain_text(V4, timeout=10000)
    page.select_option("#theme-select", "dark")
    expect(page.locator("html")).to_have_attribute("data-theme", "dark")
    page.fill("#f-exact-ip", V6)
    with page.expect_navigation():
        page.locator('[data-ip-search] button[type="submit"]').click()
    expect(page.locator("body")).to_contain_text("/style.css")
    assert errors == [], errors
