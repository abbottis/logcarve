"""T5b3 readiness (integration): supported-schema gate and safe rejection.

Synthetic fixtures only. Proves /readyz accepts an upgraded store and
rejects outdated or structurally incomplete stores even when a current
migration MAX row exists, without creating files or scanning data.
"""

import sqlite3
from pathlib import Path

from starlette.testclient import TestClient

from app.api.deps import SUPPORTED_SCHEMA_VERSION, schema_supported
from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user
from app.db.database import connect, writer_transaction
from app.db.migrations_runner import migrate


def _app(db: Path):
    from app.main import create_app

    return create_app(db_path=db, secure_cookies=False)


def _login(client: TestClient):
    response = client.post(
        "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
    )
    assert response.status_code == 200, response.text


def _seeded_db(db: Path):
    migrate(db)
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))


def test_readyz_accepts_upgraded_store(tmp_path):
    db = tmp_path / "t.db"
    _seeded_db(db)
    client = TestClient(_app(db), raise_server_exceptions=False)
    _login(client)
    response = client.get("/readyz")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ready"] is True
    assert body["database"] == "ok"
    assert body["schema_version"] == SUPPORTED_SCHEMA_VERSION == 8
    assert response.headers["X-Request-ID"]


def test_readyz_rejects_structurally_incomplete_store(tmp_path):
    db = tmp_path / "t.db"
    _seeded_db(db)
    conn = sqlite3.connect(db)
    try:
        conn.execute("DROP TABLE follow_generations")
        conn.execute("DROP INDEX IF EXISTS idx_requests_country")
        conn.execute("ALTER TABLE requests DROP COLUMN country_code")
        conn.commit()
        max_version = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
    finally:
        conn.close()
    assert max_version == SUPPORTED_SCHEMA_VERSION
    conn = connect(db, read_only=True)
    try:
        supported, version = schema_supported(conn)
    finally:
        conn.close()
    assert supported is False and version == SUPPORTED_SCHEMA_VERSION
    client = TestClient(_app(db), raise_server_exceptions=False)
    _login(client)
    response = client.get("/readyz")
    assert response.status_code == 503, response.text
    body = response.json()
    assert body["code"] == "not_ready"
    assert body["request_id"] == response.headers["X-Request-ID"]


def test_readyz_rejects_outdated_migration_version(tmp_path):
    db = tmp_path / "t.db"
    _seeded_db(db)
    conn = sqlite3.connect(db)
    try:
        conn.execute("DELETE FROM schema_migrations WHERE version = 8")
        conn.commit()
        max_version = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
    finally:
        conn.close()
    assert max_version == 7
    client = TestClient(_app(db), raise_server_exceptions=False)
    _login(client)
    response = client.get("/readyz")
    assert response.status_code == 503, response.text
    assert response.json()["code"] == "not_ready"


def test_readyz_missing_store_creates_no_file(tmp_path):
    db = tmp_path / "absent.sqlite3"
    assert not db.exists()
    from app.main import create_app

    client = TestClient(create_app(db_path=db, secure_cookies=False), raise_server_exceptions=False)
    login = client.post("/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"})
    assert login.status_code == 503
    response = client.get("/readyz")
    assert response.status_code in (401, 503)
    assert not db.exists()
    assert not list(tmp_path.glob("absent*"))
