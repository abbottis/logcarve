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


# Each theme/width case runs in its own fresh browser context (the
# pytest-playwright page fixture is function-scoped), so the login
# session from one case can never leak into the next: an authenticated
# /login visit redirects to / instead of rendering the hero.
@pytest.mark.parametrize(
    ("theme", "width"),
    [
        ("light", 1440),
        ("light", 390),
        ("light", 320),
        ("dark", 1440),
        ("dark", 390),
        ("dark", 320),
    ],
)
def test_login_and_header_wordmark(page, brand_base, observed, theme, width):
    page.set_viewport_size({"width": width, "height": 900})
    # Seed the persisted choice so the app's own pre-paint theme script
    # applies the expected theme on first load (the bare login layout
    # has no theme switcher of its own).
    page.add_init_script(f"window.localStorage.setItem('logcarve-theme', '{theme}')")
    page.goto(f"{brand_base}/login")
    # The applied theme is the one the app itself resolved and painted.
    assert page.locator("html").get_attribute("data-theme") == theme
    # The wordmark typeface is the vendored Inter Variable webfont,
    # actually loaded — not a fallback.
    assert page.evaluate("() => document.fonts.ready.then(() => 'ready')") == "ready"
    assert page.evaluate("() => document.fonts.check('800 54px \"Inter Variable\"')")
    family = page.evaluate(
        "() => getComputedStyle(document.querySelector('.brand-hero svg.brand-logo text')).fontFamily"
    )
    assert "Inter Variable" in family, family
    # Login brand hero: one inline SVG wordmark, no raster/duplicates.
    hero = page.locator(".brand-hero")
    hero.wait_for(timeout=10000)
    assert hero.locator("svg.brand-logo").count() == 1
    # SVG <text> is not an HTMLElement, so read it via text_content.
    assert (
        hero.locator("svg.brand-logo text").first.text_content(timeout=5000).strip() == "LogCarve"
    )
    assert hero.locator("img").count() == 0
    assert hero.locator("p").first.text_content().strip() == "Self-hosted log analytics"
    assert hero.locator("span.sr-only").first.text_content().strip() == "LogCarve"
    assert page.locator(".brand-hero svg [style]").count() == 0
    # Glyph ink sits fully inside the viewBox with safe, even margins,
    # so the visible wordmark reads centered above the centered tagline.
    glyph = page.evaluate(
        "() => { const text = document.querySelector('.brand-hero svg.brand-logo text');"
        " const ink = text.getBBox(); const view = text.ownerSVGElement.viewBox.baseVal;"
        " return {x: ink.x, y: ink.y, width: ink.width, height: ink.height,"
        " viewWidth: view.width, viewHeight: view.height}; }"
    )
    assert glyph["viewWidth"] == 282 and glyph["viewHeight"] == 72, glyph
    left = glyph["x"]
    top = glyph["y"]
    right = glyph["viewWidth"] - (glyph["x"] + glyph["width"])
    bottom = glyph["viewHeight"] - (glyph["y"] + glyph["height"])
    assert left >= 2 and top >= 2 and right >= 2 and bottom >= 2, glyph
    assert abs(left - right) <= 3, glyph
    assert abs(top - bottom) <= 2, glyph
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
    # The persisted theme choice survives the login navigation.
    assert page.locator("html").get_attribute("data-theme") == theme
    home = page.get_by_role("link", name="LogCarve")
    home.wait_for(timeout=10000)
    assert home.get_attribute("href") == "/"
    assert home.locator("svg.brand-logo").count() == 1
    assert (
        home.locator("svg.brand-logo text").first.text_content(timeout=5000).strip() == "LogCarve"
    )
    header_box = home.locator("svg.brand-logo").bounding_box(timeout=5000)
    assert header_box is not None and header_box["height"] > 0
    if width >= 1024:
        assert 120 <= header_box["width"] <= 200, header_box
    else:
        assert header_box["width"] <= width * 0.6, header_box
    # The home link is usable: activating it stays on the dashboard.
    home.click()
    assert page.url == f"{brand_base}/"
    # Surrounding navigation controls stay usable in both layouts.
    assert page.locator("#theme-select").is_visible()
    assert page.get_by_role("button", name="Log out").count() == 1
    assert page.get_by_role("link", name="Overview").first.count() >= 1
    assert page.evaluate("document.documentElement.scrollWidth") <= width
    assert observed["errors"] == [], observed["errors"]
    for url in observed["requests"]:
        assert url.startswith(brand_base), url
