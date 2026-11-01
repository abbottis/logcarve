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


def _time_column_cells(page):
    """Time-column display text + UTC titles for the explorer table.

    The first column is the Client pseudonym now, so times must be read
    through the Time-header semantic column, never the first cell.
    """
    return page.evaluate(
        """() => {
          const table = Array.from(document.querySelectorAll("table")).filter(
            (t) => t.caption && t.caption.textContent.trim() === "Sanitized request rows")[0];
          const heads = Array.from(table.querySelectorAll("thead th")).map(
            (th) => th.innerText.trim());
          const idx = heads.findIndex((h) => h.startsWith("Time ("));
          return Array.from(table.querySelectorAll("tbody tr:not(.req-detail)")).map(
            (tr) => ({text: tr.querySelectorAll("td")[idx].innerText,
                     title: tr.querySelectorAll("td")[idx].title}));
        }"""
    )


def test_asian_zone_explorer_and_nav_preservation(page, tz_base, observed):
    _login(page, tz_base)
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{tz_base}/requests?site=default&{W1}&tz=Asia%2FTokyo")
    page.get_by_role("heading", name="Sanitized request rows").wait_for(timeout=10000)
    assert "Time (Asia/Tokyo)" in page.content()
    time_cells = _time_column_cells(page)
    assert len(time_cells) > 0
    assert "JST" in time_cells[0]["text"], time_cells[0]
    assert time_cells[0]["title"].endswith("+00:00"), time_cells[0]
    # Sidebar navigation keeps the explicit zone on data pages: open the
    # real narrow overlay menu, then follow the actual scoped visible link.
    menu = page.get_by_role("button", name="Menu")
    assert menu.is_visible()
    menu.click()
    assert menu.get_attribute("aria-expanded") == "true"
    assert page.locator("#side-nav").is_visible()
    page.locator("#side-nav").get_by_role("link", name="Overview").click()
    page.get_by_role("heading", name="Traffic timeline").wait_for(timeout=10000)
    assert _params(page.url).get("tz") == ["Asia/Tokyo"]
    assert "Times shown in Asia/Tokyo" in page.content()
    _assert_clean(observed, tz_base)


def _berlin_option_label(page) -> str:
    return page.eval_on_selector(
        "#f-tz",
        "el => Array.from(el.options).filter(o => o.value === 'Europe/Berlin')[0].text",
    )


def test_berlin_option_labels_follow_dst_across_apply(page, tz_base, observed):
    """Europe/Berlin option labels track DST at the applied window start.

    Late-October (standard time) reads UTC+01:00; applying a July window
    relabels the SAME selected option to UTC+02:00 without changing the
    selection or duplicating the control. A failed Apply keeps the labels.
    """
    _login(page, tz_base)
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{tz_base}/?site=default&{W1}&tz=Europe%2FBerlin")
    page.get_by_role("heading", name="Traffic timeline").wait_for(timeout=10000)
    assert page.eval_on_selector("#f-tz", "el => el.value") == "Europe/Berlin"
    assert page.locator("#f-tz").count() == 1
    winter_label = _berlin_option_label(page)
    assert "UTC+01:00" in winter_label, winter_label
    # Apply a summer window through the real controls: the option labels
    # refresh out-of-band at the new window start (DST, +02:00) while the
    # selected zone stays Europe/Berlin with exactly one control.
    page.fill("#f-from", "2026-07-15T00:00")
    page.fill("#f-to", "2026-07-16T00:00")
    with page.expect_response(
        lambda r: "/partials/overview" in r.url and r.status == 200, timeout=10000
    ):
        page.get_by_role("button", name="Apply").click()
    page.wait_for_function("() => window.location.href.includes('from=2026-07-15')", timeout=10000)
    page.wait_for_function(
        "() => document.querySelector('#f-tz').textContent.includes('UTC+02:00')",
        timeout=10000,
    )
    assert page.eval_on_selector("#f-tz", "el => el.value") == "Europe/Berlin"
    assert page.locator("#f-tz").count() == 1
    summer_label = _berlin_option_label(page)
    assert "UTC+02:00" in summer_label, summer_label
    assert summer_label != winter_label
    assert "Times shown in Europe/Berlin" in page.content()
    # A failed Apply (reversed window) keeps the summer labels, the
    # selection and the single control; only the banner is new.
    page.fill("#f-from", "2026-07-15T13:00")
    page.fill("#f-to", "2026-07-15T12:00")
    with page.expect_response(
        lambda r: "/partials/overview" in r.url and r.status == 400, timeout=10000
    ):
        page.get_by_role("button", name="Apply").click()
    page.locator("[data-filter-error]").wait_for(state="visible", timeout=10000)
    assert _berlin_option_label(page) == summer_label
    assert page.eval_on_selector("#f-tz", "el => el.value") == "Europe/Berlin"
    assert page.locator("#f-tz").count() == 1
    # The deliberate 400 is the only console noise: Chromium's native
    # failed-resource notice plus htmx's own response error.
    for url in observed["requests"]:
        assert url.startswith(tz_base), url
    assert len(observed["errors"]) == 2, observed["errors"]
    assert any("400" in text for text in observed["errors"]), observed["errors"]
