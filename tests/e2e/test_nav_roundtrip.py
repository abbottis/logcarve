"""T10 shared-window click roundtrips through every nav entry (coordinator run).

Real browser clicks: from Overview with a selected source, custom window
and Europe/Berlin, click each side-nav entry, then return to a data view
and assert the shared site/source/window/tz state survived — including the
previously lossy Settings and Data Sources legs. Repeatable against a
loopback server with synthetic fixtures. Skips cleanly when loopback
sockets are unavailable (Muse sandbox); coordinator executes:
  uv run --locked pytest tests/e2e/test_nav_roundtrip.py -q
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
STATE = (
    "site=default&range=custom&from=2026-10-27T00:00:00%2B00:00"
    "&to=2026-10-28T00:00:00%2B00:00&tz=Europe%2FBerlin&source=example-combined"
)
ENTRIES = [
    ("/security", "Security"),
    ("/crawlers", "Crawlers"),
    ("/errors", "Errors"),
    ("/ask", "Ask AI"),
    ("/settings", "Settings"),
    ("/data-sources", "Data Sources"),
]


def _free_port() -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]
    except PermissionError:
        pytest.skip("loopback sockets are unavailable in this sandbox")


@pytest.fixture
def nav_base(tmp_path, monkeypatch):
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
    (root / "access.log").write_bytes(FIXTURE.read_bytes())
    db = tmp_path / "nav.sqlite3"
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


def _params(url):
    return parse_qs(urlsplit(url).query)


def test_nav_roundtrip_through_every_entry(page, nav_base):
    page.goto(f"{nav_base}/login")
    page.fill("#username", "admin")
    page.fill("#password", "s3cret-pw")
    page.click("button[type=submit]")
    page.wait_for_url(f"{nav_base}/", timeout=10000)

    page.goto(f"{nav_base}/?{STATE}")
    for href, label in ENTRIES:
        with page.expect_navigation():
            page.locator(f'#side-nav a[href^="{href}"]').click()
        assert page.url.startswith(f"{nav_base}{href}"), (label, page.url)
        if href in ("/settings", "/data-sources"):
            continue  # non-data pages carry state forward, verified below
        kept = _params(page.url)
        assert kept.get("source") == ["example-combined"], (label, page.url)
        assert kept.get("tz") == ["Europe/Berlin"], (label, page.url)
        assert kept.get("range") == ["custom"], (label, page.url)

    # Lossy legs: Settings and Data Sources must hand the same state back.
    for href in ("/settings", "/data-sources"):
        page.goto(f"{nav_base}/?{STATE}")
        with page.expect_navigation():
            page.locator(f'#side-nav a[href^="{href}"]').click()
        with page.expect_navigation():
            page.locator("#side-nav a").filter(has_text="Overview").click()
        returned = _params(page.url)
        assert returned.get("source") == ["example-combined"], (href, page.url)
        assert returned.get("tz") == ["Europe/Berlin"], (href, page.url)
        assert returned.get("range") == ["custom"], (href, page.url)
        assert returned.get("from") == ["2026-10-27T00:00:00+00:00"], (href, page.url)
        assert returned.get("to") == ["2026-10-28T00:00:00+00:00"], (href, page.url)
