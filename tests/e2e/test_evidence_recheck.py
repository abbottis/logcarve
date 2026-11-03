"""Evidence-recheck browser flow: real receipt, real click, real states.

Repeatable against a loopback server with synthetic fixtures: login,
Ask AI with a scripted network-free fake provider, send a question so
the server returns a real evidence envelope plus signed receipt, click
the rendered Recheck button and assert the current state with its
recheck-time/coverage detail. A synthetic retention wipe followed by a
second click then asserts the unavailable state. No provider network or
billing; the lead runs this outside the sandboxed session if the local
Chromium launch stays blocked there.
"""

import socket
import threading
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "combined" / "nginx_combined.txt"
W1 = "range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"


def _free_port() -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]
    except PermissionError:
        pytest.skip("loopback sockets are unavailable in this sandbox")


@pytest.fixture
def ask_live(tmp_path, monkeypatch):
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
    db = tmp_path / "askre.sqlite3"
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
    yield {"base": f"http://127.0.0.1:{port}", "db": db}
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


def _enable_fake_chat(monkeypatch):
    """Scripted network-free provider: one summary tool call, then text."""
    import app.ai.service as ai_service
    from app.ai.providers.base import ProviderResponse, ToolCall
    from app.ai.providers.fake import FakeProvider

    for name in (
        "AI_ENABLED",
        "MODEL_DATA_POLICY_VERIFIED",
        "MODEL_ALLOW_REAL_DATA",
        "LLM_DAILY_LIMIT_USD",
    ):
        monkeypatch.setenv(name, "true" if name != "LLM_DAILY_LIMIT_USD" else "50")
    provider = FakeProvider(
        script=[
            ProviderResponse(
                text="",
                input_tokens=10,
                output_tokens=5,
                tool_calls=(ToolCall(name="get_summary", arguments={"limit": 5}),),
            ),
            ProviderResponse(text="Ten requests in range.", input_tokens=20, output_tokens=8),
        ]
    )
    monkeypatch.setattr(ai_service, "select_provider", lambda settings: provider)


def _login(page, base):
    page.goto(f"{base}/login")
    page.fill("#username", "admin")
    page.fill("#password", "s3cret-pw")
    page.click("button[type=submit]")
    page.wait_for_url(f"{base}/", timeout=10000)


def test_ask_recheck_button_flow_current_then_unavailable(page, ask_live, observed, monkeypatch):
    from app.db.database import writer_transaction
    from app.db.retention import apply_retention

    base = ask_live["base"]
    _enable_fake_chat(monkeypatch)
    _login(page, base)
    page.goto(f"{base}/ask?site=default&{W1}&tz=UTC&source=example-combined")
    page.get_by_role("heading", name="Ask AI").first.wait_for(timeout=10000)
    # The locale-wired affordance strings stay on the page.
    ask = page.locator("[data-ask]")
    for key, text in (
        ("recheck", "Recheck evidence"),
        ("recheck-current", "still matches"),
        ("recheck-detail", "Rechecked"),
        ("evidence-rerun-note", "not archived snapshots"),
    ):
        value = ask.get_attribute(f"data-msg-{key}")
        assert value and text in value, (key, value)
    # A real chat round-trip returns a real envelope plus signed receipt,
    # which renders the real Recheck button (no fabricated message).
    page.fill("#ask-input", "How many requests arrived?")
    page.get_by_role("button", name="Send").click()
    page.wait_for_function(
        "() => document.querySelector('[data-ask-answer]').textContent.includes('Ten requests')",
        timeout=15000,
    )
    recheck = page.get_by_role("button", name="Recheck evidence")
    recheck.wait_for(timeout=10000)
    recheck.click()
    page.wait_for_function(
        "() => document.querySelector('[data-recheck-status]').textContent.includes('still matches')",
        timeout=15000,
    )
    # The state carries its context: recheck time, surviving coverage and
    # the original scope, announced through a live region as plain text.
    detail = page.locator("[data-recheck-detail]").first.inner_text()
    assert "Rechecked" in detail, detail
    assert "unique events" in detail, detail
    assert "example-combined" in detail, detail
    status_role = page.locator("[data-recheck-status]").first.get_attribute("role")
    assert status_role == "status", status_role
    assert page.locator("[data-ask-evidence] a").first.get_attribute("href") is not None
    # A synthetic retention wipe removes the whole window: the same
    # receipt then reports unavailable on the very next click.
    with writer_transaction(ask_live["db"]) as conn:
        assert apply_retention(conn, days=1, now=datetime(2027, 1, 1, tzinfo=UTC)) > 0
    recheck.click()
    page.wait_for_function(
        "() => document.querySelector('[data-recheck-status]').textContent.includes('no longer resolves')",
        timeout=15000,
    )
    assert observed["errors"] == [], observed["errors"]
    for url in observed["requests"]:
        assert url.startswith(base), url
