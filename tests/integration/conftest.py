"""Shared seeded dashboard fixture for web integration tests (synthetic data only)."""

from pathlib import Path

import pytest
from starlette.testclient import TestClient

from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user
from app.db.database import writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.sources import SourceConfig

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "combined" / "nginx_combined.txt"
HMAC_KEY = b"synthetic-test-hmac-key"

ATTACK_LINE = (
    b'198.51.100.9 - - [27/Oct/2026:12:05:00 +0100] "GET /<script>alert(1)</script> HTTP/1.1"'
    b' 404 12 "-" "evil/1.0"\n'
)


def seed_web_db(db, root):
    migrate(db)
    (root / "access.log").write_bytes(FIXTURE.read_bytes() + ATTACK_LINE)
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
        hmac_key=HMAC_KEY,
    )


@pytest.fixture
def web(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    root = tmp_path / "logs"
    root.mkdir()
    db = tmp_path / "web.sqlite3"
    seed_web_db(db, root)
    from app.main import create_app

    client = TestClient(create_app(db_path=db, secure_cookies=False), raise_server_exceptions=False)
    return client, db
