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


def test_save_current_replays_applied_state(page, c4_base):
    errors, failed, outside = _watch(page)
    base = c4_base
    _login(page, base)

    # Apply a search through the real htmx filter bar, then read the
    # Save-current hidden target: it must carry the applied state.
    page.goto(f"{base}/journeys?{STATE}")
    page.fill("#f-search", "/login")
    page.click("#filter-bar button[type=submit]")
    page.wait_for_function(
        "() => (document.querySelector('#save-view-target') || {}).value "
        "&& document.querySelector('#save-view-target').value.includes('search=')",
        timeout=10000,
    )
    target = page.evaluate("() => document.querySelector('#save-view-target').value")
    assert "search=%2Flogin" in target
    assert "csrf_token" not in target and "raw_ip" not in target
    # A failed Apply keeps the last displayed state, never the draft.
    page.fill("#f-from", "2026-10-28T00:00")
    page.fill("#f-to", "2026-10-27T00:00")
    page.click("#filter-bar button[type=submit]")
    expect(page.locator("[data-filter-error]")).to_be_visible(timeout=10000)
    assert page.evaluate("() => document.querySelector('#save-view-target').value") == target
    # Save the good state and open it: the stored view replays it.
    page.goto(f"{base}/journeys?{STATE}")
    page.fill("#f-search", "/login")
    page.click("#filter-bar button[type=submit]")
    page.wait_for_function(
        "() => document.querySelector('#save-view-target').value.includes('search=')",
        timeout=10000,
    )
    page.fill("#save-view-name", "Applied watch")
    with page.expect_navigation():
        page.locator("form[data-save-current] button[type=submit]").click()
    assert "/saved-views" in page.url
    expect(page.locator("body")).to_contain_text("Applied watch")
    with page.expect_navigation():
        page.locator('a:has-text("/journeys?")').first.click()
    assert "search=%2Flogin" in page.url

    # The deliberate invalid-window Apply above must surface exactly its
    # expected negative-flow diagnostics (visible banner plus the browser
    # resource 400 and the htmx response error in the console) and
    # nothing else: full negative coverage with zero unexpected errors.
    def _is_expected_400(text):
        return "400" in text and (
            "Failed to load resource" in text or "Response Status Error Code" in text
        )

    expected = [text for text in errors if _is_expected_400(text)]
    assert expected != [], errors
    assert len(errors) == len(expected), errors
    assert failed == [], failed
    assert outside == [], outside


def test_comparison_baseline_survives_apply_and_controls(page, c4_base):
    errors, failed, outside = _watch(page)
    base = c4_base
    _login(page, base)

    # Custom baseline controls show valid UTC values, not blank inputs.
    page.goto(
        f"{base}/comparison?{STATE}"
        "&baseline_from=2026-10-26T00%3A00%3A00%2B00%3A00"
        "&baseline_to=2026-10-27T00%3A00%3A00%2B00%3A00"
    )
    expect(page.locator("#compare-metrics-chart")).to_be_visible(timeout=10000)
    assert page.input_value("#c-bfrom") == "2026-10-26T00:00"
    assert page.input_value("#c-bto") == "2026-10-27T00:00"
    # An actual filter-bar Apply keeps the custom baseline in the URL.
    page.click("#filter-bar button[type=submit]")
    page.wait_for_function("() => window.location.href.includes('baseline_from=')", timeout=10000)
    assert "baseline_from=2026-10-26" in page.url
    assert "baseline_to=2026-10-27" in page.url
    expect(page.locator("#compare-metrics-chart")).to_be_visible(timeout=10000)
    # Previous mode survives the same serialization round-trip.
    page.goto(f"{base}/comparison?{STATE}&baseline=previous")
    expect(page.locator("#compare-metrics-chart")).to_be_visible(timeout=10000)
    assert page.input_value("#c-bfrom") != ""
    assert page.input_value("#c-bto") != ""
    page.click("#filter-bar button[type=submit]")
    page.wait_for_function(
        "() => window.location.href.includes('baseline=previous')", timeout=10000
    )
    assert "baseline=previous" in page.url

    assert failed == [], failed
    assert outside == [], outside
    assert errors == [], errors


def test_refresh_clock_behavior(page, c4_base):
    errors, failed, outside = _watch(page)
    base = c4_base
    _login(page, base)
    page.clock.install()
    try:
        page.goto(f"{base}/journeys?{STATE}")
        partials: list[str] = []
        methods: list[str] = []
        page.on(
            "request",
            lambda req: (
                (
                    partials.append(req.url),
                    methods.append(req.method),
                )
                if "/partials/journeys" in req.url
                else None
            ),
        )
        toggle = page.locator("#refresh-toggle")
        expect(toggle).not_to_be_checked()
        expect(page.locator("body")).to_contain_text("Auto-refresh is off.")
        page.select_option("#refresh-interval", "30")
        # Checking shows the ON state immediately, before any tick.
        toggle.check()
        expect(page.locator("body")).to_contain_text("Auto-refresh is on;")
        # Checking leaves INPUT focus on the checkbox, which correctly
        # pauses ticks: blur to a non-input first, then the tick sends.
        page.locator("h1").click()
        # Advancing past 30s re-reads with the applied state via GET.
        page.clock.fast_forward(31000)
        page.wait_for_timeout(500)
        assert len(partials) >= 1, partials
        assert set(methods) == {"GET"}, methods
        assert all("site=default" in url for url in partials)
        seen = len(partials)
        # Draft edits pause the refresh: move focus away without Apply,
        # then no request, an honest paused note, and the draft value
        # never reaches the server.
        page.fill("#f-search", "typed-but-unapplied")
        page.locator("h1").click()
        page.clock.fast_forward(31000)
        page.wait_for_timeout(500)
        assert len(partials) == seen, partials
        expect(page.locator("body")).to_contain_text("paused while unsaved")
        assert all("typed-but-unapplied" not in url for url in partials)
        # Applying resumes with the ON state and the applied value.
        page.click("#filter-bar button[type=submit]")
        page.wait_for_function(
            "() => window.location.href.includes('search=typed-but-unapplied')",
            timeout=10000,
        )
        page.clock.fast_forward(31000)
        page.wait_for_timeout(500)
        assert len(partials) > seen, partials
        assert "search=typed-but-unapplied" in partials[-1]
        expect(page.locator("body")).to_contain_text("Auto-refresh is on;")
        seen = len(partials)
        # A focused input pauses; moving focus away from the unchanged
        # form resumes.
        page.locator("#f-search").focus()
        page.clock.fast_forward(31000)
        page.wait_for_timeout(500)
        assert len(partials) == seen, partials
        page.locator("h1").click()
        page.clock.fast_forward(31000)
        page.wait_for_timeout(500)
        assert len(partials) > seen, partials
        seen = len(partials)
        # An open modal pauses; closing it resumes.
        page.evaluate(
            "() => { const d = document.createElement('dialog');"
            " d.id = 't4c-probe-dialog'; d.setAttribute('open', '');"
            " d.textContent = 'probe'; document.body.appendChild(d); }"
        )
        page.clock.fast_forward(31000)
        page.wait_for_timeout(500)
        assert len(partials) == seen, partials
        page.evaluate("() => document.querySelector('#t4c-probe-dialog').remove()")
        page.clock.fast_forward(31000)
        page.wait_for_timeout(500)
        assert len(partials) > seen, partials
        seen = len(partials)
        # A hidden tab pauses; becoming visible resumes.
        page.evaluate(
            "() => Object.defineProperty(document, 'hidden', {value: true, configurable: true})"
        )
        page.clock.fast_forward(31000)
        page.wait_for_timeout(500)
        assert len(partials) == seen, partials
        page.evaluate(
            "() => Object.defineProperty(document, 'hidden', {value: false, configurable: true})"
        )
        page.clock.fast_forward(31000)
        page.wait_for_timeout(500)
        assert len(partials) > seen, partials
        # Unchecking stops the timer with the OFF state.
        toggle.uncheck()
        expect(page.locator("body")).to_contain_text("Auto-refresh is off.")
        seen = len(partials)
        page.clock.fast_forward(61000)
        page.wait_for_timeout(500)
        assert len(partials) == seen, partials
    finally:
        page.clock.resume()

    assert failed == [], failed
    assert outside == [], outside
    assert errors == [], errors


def test_refresh_ignores_inflight_draft(page, c4_base):
    errors, failed, outside = _watch(page)
    base = c4_base
    _login(page, base)
    page.clock.install()
    try:
        page.goto(f"{base}/journeys?{STATE}")
        partials: list[str] = []
        page.on(
            "request",
            lambda req: partials.append(req.url) if "/partials/journeys" in req.url else None,
        )
        page.select_option("#refresh-interval", "30")
        page.locator("#refresh-toggle").check()
        expect(page.locator("body")).to_contain_text("Auto-refresh is on;")
        page.locator("h1").click()

        # Hold the first automatic GET response at the network layer so
        # drafts can be typed while it is in flight.
        held = []
        seen = {"n": 0}

        def _hold(route):
            seen["n"] += 1
            if seen["n"] == 1:
                held.append((route, route.fetch()))
            else:
                route.continue_()

        page.route("**/partials/journeys*", _hold)
        try:
            # The first tick dispatches with no search; it stays held.
            page.clock.fast_forward(31000)
            deadline = time.monotonic() + 15
            while not held:
                assert time.monotonic() < deadline, "first refresh GET was never held"
                page.wait_for_timeout(200)
            assert len(partials) == 1, partials
            assert "search=%2Flogin" not in partials[0], partials[0]
            # While the stale response is held, edit search, method,
            # status, timezone and country, then blur: only draft
            # detection may pause ticks.
            page.fill("#f-search", "/login")
            page.select_option("#f-method", "POST")
            page.select_option("#f-status", "401")
            page.select_option("#f-tz", "Europe/Berlin")
            page.select_option("#f-country", "UNKNOWN")
            page.locator("h1").click()
            # Releasing the stale automatic response must neither swap
            # results nor reset any draft control (out-of-band
            # method/status/timezone/country included): every draft
            # stays exactly as typed, with no implicit Apply.
            route, response = held[0]
            route.fulfill(response=response)
            page.wait_for_timeout(500)
            assert page.input_value("#f-search") == "/login", page.input_value("#f-search")
            assert page.input_value("#f-method") == "POST"
            assert page.input_value("#f-status") == "401"
            assert page.input_value("#f-tz") == "Europe/Berlin"
            assert page.input_value("#f-country") == "UNKNOWN"
            saved_before = page.evaluate("() => document.querySelector('#save-view-target').value")
            assert "search=%2Flogin" not in saved_before, saved_before
            # The next tick must not implicitly Apply any draft field.
            page.clock.fast_forward(31000)
            page.wait_for_timeout(500)
            assert len(partials) == 1, partials
            expect(page.locator("body")).to_contain_text("paused while unsaved")
            # A deliberate manual Apply clears the pause and replays the
            # full draft; the following tick then carries its exact scope.
            page.click("#filter-bar button[type=submit]")
            page.wait_for_function(
                "() => window.location.href.includes('search=%2Flogin')",
                timeout=10000,
            )
            saved_after = page.evaluate("() => document.querySelector('#save-view-target').value")
            assert "search=%2Flogin" in saved_after, saved_after
            assert "method=POST" in saved_after, saved_after
            assert "status=401" in saved_after, saved_after
            assert "country=UNKNOWN" in saved_after, saved_after
            page.clock.fast_forward(31000)
            page.wait_for_timeout(500)
            assert len(partials) > 1, partials
            assert "search=%2Flogin" in partials[-1], partials
            assert "method=POST" in partials[-1], partials
            assert "status=401" in partials[-1], partials
            assert "country=UNKNOWN" in partials[-1], partials
            expect(page.locator("body")).to_contain_text("Auto-refresh is on;")
        finally:
            page.unroute("**/partials/journeys*")
    finally:
        page.clock.resume()

    assert failed == [], failed
    assert outside == [], outside
    assert errors == [], errors


def test_refresh_inflight_reversal_and_error(page, c4_base):
    errors, failed, outside = _watch(page)
    base = c4_base
    _login(page, base)
    page.clock.install()
    try:
        page.goto(f"{base}/journeys?{STATE}")
        partials: list[str] = []
        page.on(
            "request",
            lambda req: partials.append(req.url) if "/partials/journeys" in req.url else None,
        )
        page.select_option("#refresh-interval", "30")
        page.locator("#refresh-toggle").check()
        expect(page.locator("body")).to_contain_text("Auto-refresh is on;")
        page.locator("h1").click()

        # Hold the first two fragment GETs at the network layer: the
        # automatic tick (clean applied state) and the deliberate
        # manual Apply (search/method/status draft) that follows it.
        # One phase-aware handler serves the whole test: every route
        # gets exactly one fulfillment action and the handler is never
        # unrouted while a held route is still alive, so a held route
        # can always be fulfilled exactly once later.
        held: list = []
        fail_apply = {"active": False}

        def _router(route):
            if fail_apply["active"] and "search=%2Fadmin" in route.request.url:
                route.fulfill(status=500, body="synthetic failure")
            elif len(held) < 2:
                held.append((route, route.fetch()))
            else:
                route.continue_()

        page.route("**/partials/journeys*", _router)
        try:
            page.clock.fast_forward(31000)
            deadline = time.monotonic() + 15
            while len(held) < 1:
                assert time.monotonic() < deadline, "tick GET was never held"
                page.wait_for_timeout(200)
            assert len(partials) == 1, partials
            assert "search=%2Flogin" not in partials[0], partials[0]

            # Draft while the tick is in flight, then Apply: the Apply
            # dispatches its own request carrying the draft.
            page.fill("#f-search", "/login")
            page.select_option("#f-method", "POST")
            page.select_option("#f-status", "401")
            page.locator("h1").click()
            page.click("#filter-bar button[type=submit]")
            deadline = time.monotonic() + 15
            while len(held) < 2:
                assert time.monotonic() < deadline, "Apply GET was never held"
                page.wait_for_timeout(200)
            assert len(partials) == 2, partials
            assert "search=%2Flogin" in partials[1], partials
            assert "method=POST" in partials[1], partials
            assert "status=401" in partials[1], partials

            # Fulfill out of order: the Apply first, then the stale
            # tick. The newer explicit Apply wins: its swap is
            # accepted (results, controls, save target and canonical
            # state all move to the draft), and the superseded tick
            # is cancelled before any swap — main, out-of-band or
            # history — so it cannot overwrite the Apply.
            apply_route, apply_response = held[1]
            tick_route, tick_response = held[0]
            apply_route.fulfill(response=apply_response)
            page.wait_for_function(
                "() => window.location.href.includes('search=%2Flogin')",
                timeout=10000,
            )
            saved = page.evaluate("() => document.querySelector('#save-view-target').value")
            assert "search=%2Flogin" in saved, saved
            assert "method=POST" in saved, saved
            assert "status=401" in saved, saved
            # The typed POST/401 draft is preserved as the applied
            # control state (never reset to the older tick state).
            assert page.input_value("#f-search") == "/login", page.input_value("#f-search")
            assert page.input_value("#f-method") == "POST"
            assert page.input_value("#f-status") == "401"
            tick_route.fulfill(response=tick_response)
            page.wait_for_timeout(500)
            # The stale tick changed nothing: controls, results, save
            # target and canonical URL all still carry the Apply.
            assert page.input_value("#f-search") == "/login", page.input_value("#f-search")
            assert page.input_value("#f-method") == "POST"
            assert page.input_value("#f-status") == "401"
            assert page.evaluate("() => document.querySelector('#save-view-target').value") == saved
            assert "search=%2Flogin" in page.url, page.url

            # The next tick replays the accepted applied state instead
            # of pausing: the form matches it, so the tick carries the
            # full search/method/status scope with the ON status.
            page.clock.fast_forward(31000)
            page.wait_for_timeout(500)
            assert len(partials) == 3, partials
            assert "search=%2Flogin" in partials[-1], partials
            assert "method=POST" in partials[-1], partials
            assert "status=401" in partials[-1], partials
            expect(page.locator("body")).to_contain_text("Auto-refresh is on;")

            # Error leg: dispatch the next clean tick FIRST (the form
            # still matches the applied state, so the tick is held),
            # THEN draft a new search and fail its Apply with a 500
            # before releasing the tick. The failed Apply must adopt
            # nothing; the tick still carries the current clean state
            # so it swaps normally, and the following tick pauses on
            # the draft.
            held.clear()
            page.clock.fast_forward(31000)
            deadline = time.monotonic() + 15
            while not held:
                assert time.monotonic() < deadline, "clean tick GET was never held"
                page.wait_for_timeout(200)
            assert len(partials) == 4, partials
            assert "search=%2Flogin" in partials[-1], partials
            assert "search=%2Fadmin" not in partials[-1], partials
            tick2_route, tick2_response = held[0]
            page.fill("#f-search", "/admin")
            page.locator("h1").click()
            # Error leg under the same handler: only the failed Apply
            # (identifiable by its draft query) is answered 500; the
            # held tick keeps its fetched clean response and is
            # fulfilled exactly once below. No unroute/re-route while
            # the held route is alive.
            fail_apply["active"] = True
            page.click("#filter-bar button[type=submit]")
            expect(page.locator("[data-filter-error]")).to_be_visible(timeout=10000)
            assert "search=%2Fadmin" in partials[-1], partials
            failed_count = len(partials)
            tick2_route.fulfill(response=tick2_response)
            page.wait_for_timeout(500)
            # The failed draft never became applied or canonical: the
            # tick kept the clean state and the draft is still only a
            # draft in the input.
            assert page.input_value("#f-search") == "/admin", page.input_value("#f-search")
            assert "search=%2Fadmin" not in page.url, page.url
            page.clock.fast_forward(31000)
            page.wait_for_timeout(500)
            assert len(partials) == failed_count, partials
            expect(page.locator("body")).to_contain_text("paused while unsaved")
            # The Save target still carries the last displayed state,
            # never the failed draft.
            assert page.evaluate("() => document.querySelector('#save-view-target').value") == saved
        finally:
            page.unroute("**/partials/journeys*")
    finally:
        page.clock.resume()

    # The deliberate 500 Apply surfaces exactly its expected
    # negative-flow diagnostics (visible banner plus the browser
    # resource 500 and the htmx response error in the console) and
    # nothing else.
    def _is_expected_500(text):
        return "500" in text and (
            "Failed to load resource" in text or "Response Status Error Code" in text
        )

    expected = [text for text in errors if _is_expected_500(text)]
    assert expected != [], errors
    assert len(errors) == len(expected), errors
    assert failed == [], failed
    assert outside == [], outside


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
    expect(page.locator("body")).to_contain_text("explicit opt-in command-line operation")
    expect(page.locator("body")).to_contain_text("no live watcher")

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
