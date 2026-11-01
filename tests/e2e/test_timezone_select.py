"""Timezone catalogue browser suite: native select, default, Apply/nav/reload.

Real interaction against a loopback server with synthetic fixtures: the
native timezone select lists the installed catalogue, preselects the
configured server default, applies an explicit Asian/Pacific zone through
Apply, and preserves it across reload and sidebar navigation in both
themes at narrow width. Skips cleanly when loopback sockets or protected
browser launch are unavailable (coordinator runs
``uv run --locked pytest tests/e2e -q``). Chromium sandbox stays engaged
via ``browser_type_launch_args``; nothing here weakens it.
"""

import socket
import threading
import time
import urllib.request
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "combined" / "nginx_combined.txt"
W1 = "range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"
SHOT_DIR = ROOT / "artifacts" / "e2e-timezone"


def _free_port() -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]
    except PermissionError:
        pytest.skip("loopback sockets are unavailable in this sandbox")


@pytest.fixture
def tz_base(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    monkeypatch.setenv("DEFAULT_TIMEZONE", "Europe/Berlin")
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
    db = tmp_path / "tz.sqlite3"
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


def _params(url):
    return parse_qs(urlsplit(url).query)


def test_native_select_default_and_explicit_zone(page, tz_base, observed):
    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    _login(page, tz_base)
    # No explicit tz: the configured server default preselects.
    page.goto(f"{tz_base}/?site=default&{W1}")
    page.get_by_role("heading", name="Traffic timeline").wait_for(timeout=10000)
    assert page.eval_on_selector("#f-tz", "el => el.value") == "Europe/Berlin"
    count = page.eval_on_selector("#f-tz", "el => el.options.length")
    assert count > 100, "the full installed catalogue must be offered"
    assert "Times shown in Europe/Berlin" in page.content()

    for theme in ("light", "dark"):
        page.set_viewport_size({"width": 390, "height": 844})
        page.select_option("#theme-select", theme)
        # Explicit Pacific zone through the native control and Apply.
        page.select_option("#f-tz", "Pacific/Auckland")
        with page.expect_response(
            lambda r: "/partials/overview" in r.url and r.status == 200, timeout=10000
        ):
            page.get_by_role("button", name="Apply").click()
        page.wait_for_function(
            "() => window.location.href.includes('tz=Pacific%2FAuckland')",
            timeout=10000,
        )
        assert _params(page.url).get("tz") == ["Pacific/Auckland"]
        assert "Times shown in Pacific/Auckland" in page.content()
        assert page.evaluate("document.documentElement.scrollWidth") <= 390
        page.screenshot(path=str(SHOT_DIR / f"overview-auckland-390-{theme}.png"))

        # Reload keeps the explicit zone; the explorer renders its times.
        page.reload()
        page.get_by_role("heading", name="Traffic timeline").wait_for(timeout=10000)
        assert _params(page.url).get("tz") == ["Pacific/Auckland"]
        assert page.eval_on_selector("#f-tz", "el => el.value") == "Pacific/Auckland"
    _assert_clean(observed, tz_base)


def test_asian_zone_explorer_and_nav_preservation(page, tz_base, observed):
    _login(page, tz_base)
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{tz_base}/requests?site=default&{W1}&tz=Asia%2FTokyo")
    page.get_by_role("heading", name="Sanitized request rows").wait_for(timeout=10000)
    assert "Time (Asia/Tokyo)" in page.content()
    first_cell = page.evaluate(
        """() => Array.from(document.querySelectorAll("table")).filter(
          (t) => t.caption && t.caption.textContent.trim() === "Sanitized request rows")[0]
          .querySelector("tbody tr td").innerText"""
    )
    assert "JST" in first_cell
    # Sidebar navigation keeps the explicit zone on data pages.
    page.get_by_role("navigation").get_by_role("link", name="Overview").click()
    page.get_by_role("heading", name="Traffic timeline").wait_for(timeout=10000)
    assert _params(page.url).get("tz") == ["Asia/Tokyo"]
    assert "Times shown in Asia/Tokyo" in page.content()
    _assert_clean(observed, tz_base)
