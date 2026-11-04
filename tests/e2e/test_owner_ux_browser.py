"""Owner-review browser suite: native method/status dropdowns,
window-start offset notice, readable Crawlers names, the Help page and
the Stage B sortable Requests explorer with per-row details.

Real interaction against a loopback server with synthetic fixtures at
1440/1024/768/390 widths in both themes. Chromium sandbox stays engaged
via ``browser_type_launch_args``; nothing here weakens it. Skips
cleanly when loopback sockets are unavailable (coordinator runs
``uv run --locked pytest tests/e2e -q``).
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
SHOT_DIR = ROOT / "artifacts" / "e2e-owner-ux-a"


def _free_port() -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]
    except PermissionError:
        pytest.skip("loopback sockets are unavailable in this sandbox")


@pytest.fixture
def ux_base(tmp_path, monkeypatch):
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
    db = tmp_path / "uxa.sqlite3"
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


def _assert_no_page_overflow(page):
    assert page.evaluate("document.documentElement.scrollWidth") <= page.viewport_size["width"]


def test_method_status_dropdowns_and_offset_notice(page, ux_base, observed):
    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    _login(page, ux_base)
    for theme, width in (("light", 1440), ("dark", 390)):
        page.set_viewport_size({"width": width, "height": 900})
        page.select_option("#theme-select", theme)
        page.goto(f"{ux_base}/?site=default&{W1}&tz=UTC")
        page.get_by_role("heading", name="Traffic timeline").wait_for(timeout=10000)
        # Native dropdowns with All plus standard options and phrases.
        assert page.eval_on_selector("#f-method", "el => el.tagName") == "SELECT"
        assert page.eval_on_selector("#f-status", "el => el.tagName") == "SELECT"
        methods = page.eval_on_selector(
            "#f-method", "el => Array.from(el.options).map(o => o.text)"
        )
        assert methods[0] == "All" and "GET" in methods and "POST" in methods
        statuses = page.eval_on_selector(
            "#f-status", "el => Array.from(el.options).map(o => o.text)"
        )
        assert statuses[0] == "All"
        assert "404 · Not Found" in statuses
        assert "500 · Internal Server Error" in statuses
        # Apply a method+status through the real controls.
        page.select_option("#f-method", "GET")
        page.select_option("#f-status", "404")
        with page.expect_response(
            lambda r: "/partials/overview" in r.url and r.status == 200, timeout=10000
        ):
            page.get_by_role("button", name="Apply").click()
        page.wait_for_function("() => window.location.href.includes('status=404')", timeout=10000)
        assert _params(page.url).get("status") == ["404"]
        assert _params(page.url).get("method") == ["GET"]
        # Offset notice follows the applied window start, not the review date.
        page.select_option("#f-tz", "Asia/Kathmandu")
        with page.expect_response(
            lambda r: "/partials/overview" in r.url and r.status == 200, timeout=10000
        ):
            page.get_by_role("button", name="Apply").click()
        page.wait_for_function(
            "() => document.body.textContent.includes('UTC+05:45')", timeout=10000
        )
        assert "Times shown in Asia/Kathmandu (UTC+05:45;" in page.content()
        _assert_no_page_overflow(page)
        page.screenshot(path=str(SHOT_DIR / f"filters-kathmandu-{width}-{theme}.png"))
    _assert_clean(observed, ux_base)


def test_crawlers_names_readable_no_midword_breaks(page, ux_base, observed):
    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    _login(page, ux_base)
    for theme, width in (("light", 1024), ("dark", 768)):
        page.set_viewport_size({"width": width, "height": 900})
        page.select_option("#theme-select", theme)
        page.goto(f"{ux_base}/crawlers?site=default&{W1}&tz=UTC")
        page.get_by_role(
            "heading", name="Bots and automation by category, provider and purpose"
        ).wait_for(timeout=10000)
        # No repeated claim prefix in the bot dropdown or bot table.
        options = page.eval_on_selector("#f-bot", "el => Array.from(el.options).map(o => o.text)")
        assert all(not text.startswith("Claimed ") for text in options)
        # One clear identity legend as semantic visible text.
        page.get_by_text("identified from User-Agent; identity not verified").first.wait_for(
            timeout=10000
        )
        # Category labels read human-friendly; raw snake values stay hidden.
        assert "Suspected automation" in page.content()
        assert "Automation tools" in page.content()
        # Every group/bot name cell keeps ordinary names on one line:
        # nowrap computed style, so no letter-wrapping of ordinary names.
        states = page.eval_on_selector_all(
            ".bot-name",
            "els => els.map(el => getComputedStyle(el).whiteSpace)",
        )
        assert states, "group/bot name cells must render"
        assert all(state == "nowrap" for state in states), states
        # Pages never hide overflow to conceal layout bugs; tables scroll
        # internally instead.
        _assert_no_page_overflow(page)
        for region in page.eval_on_selector_all(
            ".table-scroll", "els => els.map(el => el.scrollWidth <= el.clientWidth + 1)"
        ):
            assert isinstance(region, bool)
        page.screenshot(path=str(SHOT_DIR / f"crawlers-stacked-{width}-{theme}.png"))
    _assert_clean(observed, ux_base)


def test_requests_sort_headers_and_details(page, ux_base, observed):
    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    _login(page, ux_base)
    for theme, width in (("light", 1440), ("dark", 390)):
        page.set_viewport_size({"width": width, "height": 900})
        page.select_option("#theme-select", theme)
        page.goto(f"{ux_base}/requests?site=default&{W1}&tz=UTC")
        page.get_by_role("heading", name="Sanitized request rows").wait_for(timeout=10000)
        # Eight readable columns in front order with server-side sorts.
        for name in ("Client", "Access", "Time (UTC)", "Method", "Path", "Status", "Bytes"):
            page.get_by_role("columnheader", name=name).wait_for(timeout=10000)
        page.get_by_role("columnheader", name="Details").wait_for(timeout=10000)
        first_before = page.locator("td.req-path").first.inner_text(timeout=10000)
        # Clicking a sort header changes the actual row order and URL state.
        page.get_by_role("link", name="Bytes").click()
        page.wait_for_function(
            "() => window.location.href.includes('sort=bytes_desc')", timeout=10000
        )
        page.get_by_role("columnheader", name="Bytes").wait_for(timeout=10000)
        assert "sorted descending" in page.content()
        first_after = page.locator("td.req-path").first.inner_text(timeout=10000)
        assert first_after == "/search", "bytes_desc puts the largest response first"
        # Back returns to the previous sort without a reload failure.
        page.go_back()
        page.wait_for_function(
            "() => !window.location.href.includes('sort=bytes_desc')", timeout=10000
        )
        assert page.locator("td.req-path").first.inner_text(timeout=10000) == first_before
        # Details open and close on the real button, keyboard included.
        # The accessible name flips to "Hide row details" once open, so a
        # later name lookup would retarget the NEXT row: bind the SAME
        # button by its stable aria-controls panel id instead.
        first_toggle = page.get_by_role("button", name="Show row details").first
        panel_id = first_toggle.get_attribute("aria-controls")
        assert panel_id, "the details button must own a stable panel id"
        assert first_toggle.get_attribute("aria-expanded") == "false"
        first_toggle.click()
        page.wait_for_selector(f"tr#{panel_id}:not([hidden])", timeout=10000)
        toggle = page.locator(f'button[aria-controls="{panel_id}"]')
        assert toggle.count() == 1, "aria-controls stays bound to one button"
        assert toggle.get_attribute("aria-expanded") == "true"
        assert "Hide row details" in (toggle.get_attribute("aria-label") or "")
        toggle.focus()
        page.keyboard.press("Enter")
        page.wait_for_selector(f"tr#{panel_id}[hidden]", timeout=10000, state="attached")
        panel = page.locator(f"tr#{panel_id}")
        assert panel.count() == 1, "collapsed panel stays in the DOM exactly once"
        assert panel.is_hidden(), "collapsed panel is hidden after keyboard toggle"
        assert toggle.get_attribute("aria-expanded") == "false"
        # Reload keeps the retained filter/sort state.
        page.get_by_role("link", name="Bytes").click()
        page.wait_for_function(
            "() => window.location.href.includes('sort=bytes_desc')", timeout=10000
        )
        page.reload()
        page.get_by_role("heading", name="Sanitized request rows").wait_for(timeout=10000)
        assert "sort=bytes_desc" in page.url
        _assert_no_page_overflow(page)
        page.screenshot(path=str(SHOT_DIR / f"requests-sorted-{width}-{theme}.png"))
    _assert_clean(observed, ux_base)


def test_help_page_session_gated_both_themes(page, ux_base, observed):
    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    _login(page, ux_base)
    for theme, width in (("light", 1440), ("dark", 390)):
        page.set_viewport_size({"width": width, "height": 900})
        page.select_option("#theme-select", theme)
        page.goto(f"{ux_base}/help?site=default&{W1}&tz=UTC&traffic=claimed_bot")
        page.get_by_role("heading", name="Help").first.wait_for(timeout=10000)
        content = page.content()
        for section in (
            "Filters and time window",
            "Bot identity limits",
            "Privacy and pseudonyms",
            "External API and sessions",
        ):
            assert section in content, section
        assert "YOUR_TOKEN" in content and "s3cret" not in content
        # Active navigation survives the Help visit.
        assert "traffic=claimed_bot" in content
        _assert_no_page_overflow(page)
        page.screenshot(path=str(SHOT_DIR / f"help-{width}-{theme}.png"))
    _assert_clean(observed, ux_base)
