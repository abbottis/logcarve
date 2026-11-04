"""T5 admin CLI tests: credential administration without secrets in arguments."""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent


def _run(db: Path, *args: str, env_extra: dict[str, str] | None = None):
    env = dict(os.environ)
    env.update(env_extra or {})
    return subprocess.run(
        [sys.executable, "-m", "app.auth.cli", "--db", str(db), *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_create_admin_and_issue_token(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    db = tmp_path / "admin.sqlite3"
    created = _run(
        db,
        "create-admin",
        "--username",
        "admin",
        env_extra={"LOGCARVE_ADMIN_PASSWORD": "s3cret-pw"},
    )
    assert created.returncode == 0, created.stderr
    assert json.loads(created.stdout)["username"] == "admin"
    from app.db import repositories
    from app.db.database import connect

    conn = connect(db)
    with conn:
        repositories.ensure_site(
            conn,
            site_id="default",
            name="s",
            hostname="example.org",
            created_at="2026-10-29T00:00:00+00:00",
        )
    conn.close()
    issued = _run(db, "issue-token", "--name", "ext", "--site-id", "default")
    assert issued.returncode == 0, issued.stderr
    payload = json.loads(issued.stdout)
    assert payload["token"].startswith("lc_")
    assert payload["token_id"] == 1


def test_create_admin_requires_env_password(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    monkeypatch.delenv("LOGCARVE_ADMIN_PASSWORD", raising=False)
    db = tmp_path / "admin.sqlite3"
    proc = _run(db, "create-admin", "--username", "admin")
    assert proc.returncode != 0
