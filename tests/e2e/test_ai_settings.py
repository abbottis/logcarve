"""AI settings browser checks: save, masking, status, provider switching.

Repeatable against a loopback server with synthetic fixtures. Skips
cleanly when loopback sockets are unavailable (the browser sandbox
stays ON: ``chromium_sandbox=True`` from the shared conftest; the
coordinator runs the exact maintained command when the shell sandbox
blocks the browser here). Fake transport only: the settings page
never dispatches a provider call, so zero network billing is
possible by construction — the watch below proves no outside
requests happen. Covers the real user-visible slice: assistant
status, enable/provider/model/policy controls, per-provider key
masking (never prefilled, never echoed), provider switching, and
both themes plus narrow/desktop viewports.
"""

import socket
import threading
import time
import urllib.request
from pathlib import Path

import pytest
from playwright.sync_api import expect

ROOT = Path(__file__).resolve().parent.parent.parent


def _free_port() -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]
    except PermissionError:
        pytest.skip("loopback sockets are unavailable in this sandbox")


@pytest.fixture
def ai_base(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    monkeypatch.setenv("AI_SETTINGS_KEY", "44" * 32)
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(ROOT / "artifacts" / "playwright-browsers"))
    import uvicorn

    from app.auth.passwords import hash_password
    from app.auth.tokens import create_admin_user
    from app.db.database import writer_transaction
    from app.db.migrations_runner import migrate
    from app.main import create_app

    db = tmp_path / "ai_settings_e2e.sqlite3"
    migrate(db)
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
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
    # The fixture seeds no site/source, so "/" would 404 after login:
    # land directly on the settings page under test instead.
    page.goto(f"{base}/login?next=/settings")
    page.fill("#username", "admin")
    page.fill("#password", "s3cret-pw")
    page.click("button[type=submit]")
    page.wait_for_url(f"{base}/settings*", timeout=10000)


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


def test_ai_settings_save_masking_and_status(page, ai_base):
    errors, failed, outside = _watch(page)
    base = ai_base
    _login(page, base)
    page.goto(f"{base}/settings")
    expect(page.locator("#set-ai-h")).to_contain_text("Assistant")

    # Assistant starts disabled with no runtime allowance granted.
    expect(page.locator("#set-ai-h").locator("..")).to_contain_text("Not granted")
    # Password inputs are never prefilled.
    for provider in ("meta", "openai", "gemini", "anthropic"):
        expect(page.locator(f"#f-ai-key-{provider}")).to_have_value("")

    # Save: enable, OpenAI, Luna, synthetic demo mode + synthetic assertion.
    page.check("#f-ai-enabled")
    page.select_option("#f-ai-provider", "openai")
    page.select_option("#f-ai-model", "gpt-6-luna")
    page.select_option("#f-ai-policy", "synthetic")
    page.check("#f-ai-synthetic")
    secret = "synthetic-e2e-openai-key"
    page.fill("#f-ai-key-openai", secret)
    page.click("text=Save assistant settings")
    page.wait_for_url(f"{base}/settings?*", timeout=10000)

    # Status reflects the save; no key material is ever rendered.
    expect(page.locator("#set-ai-h").locator("..")).to_contain_text("OpenAI")
    expect(page.locator("#set-ai-h").locator("..")).to_contain_text("gpt-6-luna")
    expect(page.locator("#set-ai-h").locator("..")).to_contain_text("Configured")
    content = page.content()
    assert secret not in content
    for provider in ("meta", "openai", "gemini", "anthropic"):
        expect(page.locator(f"#f-ai-key-{provider}")).to_have_value("")

    # Provider switching through the real UI: changing the provider
    # resets the model to the new default, clears the policy select
    # (no carry-over of the previous acknowledgment), rebinds the
    # policy identity and shows provider-correct guidance.
    page.select_option("#f-ai-provider", "gemini")
    expect(page.locator("#f-ai-model")).to_have_value("gemini-3.5-flash-lite")
    expect(page.locator("#f-ai-policy")).to_have_value("")
    expect(page.locator("#f-ai-policy-provider")).to_have_value("gemini")
    expect(page.locator("#ai-provider-guide")).to_contain_text("Paid API")
    # Save WITHOUT touching the policy select: Gemini must persist
    # unacknowledged even though OpenAI previously held "synthetic".
    page.click("text=Save assistant settings")
    page.wait_for_url(f"{base}/settings?*", timeout=10000)
    expect(page.locator("#set-ai-h").locator("..")).to_contain_text("Google Gemini")
    expect(page.locator("#f-ai-policy")).to_have_value("")
    # Deliberate acknowledgment for the new provider saves explicitly.
    page.select_option("#f-ai-policy", "synthetic")
    page.click("text=Save assistant settings")
    page.wait_for_url(f"{base}/settings?*", timeout=10000)
    expect(page.locator("#f-ai-policy")).to_have_value("synthetic")
    content = page.content()
    assert secret not in content

    assert errors == []
    assert failed == []
    assert outside == []


def test_ai_settings_themes_and_narrow_viewport(page, ai_base):
    base = ai_base
    _login(page, base)
    for theme, width in (("light", 1280), ("dark", 1280), ("dark", 390), ("dark", 320)):
        page.set_viewport_size({"width": width, "height": 800})
        page.goto(f"{base}/settings")
        expect(page.locator("#set-ai-h")).to_be_visible()
        expect(page.locator("text=Save assistant settings")).to_be_visible()
        # Drive the real persisted theme switcher and assert the app
        # really paints the requested theme on <html>.
        page.select_option("#theme-select", theme)
        expect(page.locator("html")).to_have_attribute("data-theme", theme)
        # No horizontal overflow at desktop or narrow widths.
        assert page.evaluate("document.documentElement.scrollWidth") <= width
