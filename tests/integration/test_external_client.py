"""T5 external-client test: reproducible stdlib client against real HTTP.

Starts the app on a loopback ephemeral port (threaded uvicorn, no
TestClient transport) and runs clients/logcarve_api_client.py as a
subprocess with a scoped token. Proves the contract works for a
genuine external HTTP caller with chat disabled and no model key.
"""

import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent


def _free_port() -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]
    except PermissionError:
        pytest.skip("loopback sockets are unavailable in this sandbox")


@pytest.fixture
def live_server(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    import uvicorn

    from app.auth.tokens import issue_token
    from app.db.database import writer_transaction
    from app.db.importer import run_import
    from app.ingestion.sources import SourceConfig
    from app.main import create_app

    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes(
        (ROOT / "tests" / "fixtures" / "combined" / "nginx_combined.txt").read_bytes()
    )
    db = tmp_path / "external.sqlite3"
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
    with writer_transaction(db) as conn:
        _, token = issue_token(conn, name="external", site_id="default")
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
    deadline = time.monotonic() + 15
    while True:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as response:
                if response.status == 200:
                    break
        except OSError:
            pass
        assert time.monotonic() < deadline, "test server did not start"
        time.sleep(0.1)
    yield port, token
    server.should_exit = True
    thread.join(timeout=10)


def test_external_client_summary_crawlers_findings(live_server):
    port, token = live_server
    env = dict(os.environ)
    env["LOGCARVE_API_TOKEN"] = token
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "clients" / "logcarve_api_client.py"),
            "--base-url",
            f"http://127.0.0.1:{port}",
            "--site",
            "default",
            "--from",
            "2026-10-27T00:00:00+00:00",
            "--to",
            "2026-10-28T00:00:00+00:00",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    documents = json.loads(proc.stdout)
    assert set(documents) == {"summary", "crawlers", "findings"}
    assert documents["summary"]["totals"]["requests"] == 10
    assert documents["summary"]["duration"]["available"] is False
    assert documents["summary"]["site_id"] == "default"


def test_external_client_rejects_bad_token(live_server):
    port, _ = live_server
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "clients" / "logcarve_api_client.py"),
            "--base-url",
            f"http://127.0.0.1:{port}",
            "--site",
            "default",
            "--from",
            "2026-10-27T00:00:00+00:00",
            "--to",
            "2026-10-28T00:00:00+00:00",
            "--token",
            "lc_bogus",
            "--endpoint",
            "summary",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 1
    assert "401" in proc.stderr
