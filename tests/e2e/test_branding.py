"""Focused branding check: login hero wordmark and header home wordmark.

Covers UI-01 (central locale tagline), UI-02 (login + navigation intact)
and UI-03 (both themes, desktop/narrow widths, no page overflow) with one
small repeatable scenario against a loopback server and synthetic fixtures.
Chromium sandbox stays engaged; skips cleanly when loopback is unavailable.
"""

import socket
import threading
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "combined" / "nginx_combined.txt"


def _free_port() -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]
    except PermissionError:
        pytest.skip("loopback sockets are unavailable in this sandbox")


@pytest.fixture
def brand_base(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    monkeypatch.delenv("TZ", raising=False)
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
    db = tmp_path / "brand.sqlite3"
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


def test_login_and_header_wordmark(page, brand_base, observed):
    for theme, width in (("light", 1440), ("dark", 390)):
        page.set_viewport_size({"width": width, "height": 900})
        page.goto(f"{brand_base}/login")
        if theme == "dark":
            page.evaluate("document.documentElement.setAttribute('data-theme', 'dark')")
        # Login brand hero: one inline SVG wordmark, no raster/duplicates.
        hero = page.locator(".brand-hero")
        hero.wait_for(timeout=10000)
        assert hero.locator("svg.brand-logo").count() == 1
        assert hero.locator("svg.brand-logo text").first.inner_text(timeout=5000) == "LogCarve"
        assert hero.locator("img").count() == 0
        assert "Self-hosted log analytics" in hero.inner_text()
        assert page.locator(".brand-hero svg [style]").count() == 0
        box = hero.locator("svg.brand-logo").bounding_box(timeout=5000)
        assert box is not None and box["height"] > 0
        if width >= 1024:
            assert 240 <= box["width"] <= 300, box
        else:
            assert box["width"] <= width, box
        # Login form itself is unchanged and usable.
        assert page.get_by_role("heading", name="Log in").count() >= 1
        assert page.locator("#username").get_attribute("autocomplete") == "username"
        assert page.locator("#password").get_attribute("autocomplete") == "current-password"
        assert page.get_by_role("button", name="Log in").count() == 1
        assert page.evaluate("document.documentElement.scrollWidth") <= width
        # Log in through the real form; header carries the same wordmark.
        page.fill("#username", "admin")
        page.fill("#password", "s3cret-pw")
        page.click("button[type=submit]")
        page.wait_for_url(f"{brand_base}/", timeout=10000)
        home = page.get_by_role("link", name="LogCarve")
        home.wait_for(timeout=10000)
        assert home.get_attribute("href") == "/"
        assert home.locator("svg.brand-logo").count() == 1
        assert home.locator("svg.brand-logo text").first.inner_text(timeout=5000) == "LogCarve"
        header_box = home.locator("svg.brand-logo").bounding_box(timeout=5000)
        assert header_box is not None and header_box["height"] > 0
        if width >= 1024:
            assert 120 <= header_box["width"] <= 200, header_box
        else:
            assert header_box["width"] <= width * 0.6, header_box
        # Surrounding navigation controls stay usable in both layouts.
        assert page.locator("#theme-select").is_visible()
        assert page.get_by_role("button", name="Log out").count() == 1
        assert page.get_by_role("link", name="Overview").first.count() >= 1
        assert page.evaluate("document.documentElement.scrollWidth") <= width
    assert observed["errors"] == [], observed["errors"]
    for url in observed["requests"]:
        assert url.startswith(brand_base), url
