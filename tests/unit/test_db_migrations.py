"""T3 migration tests: versioned upgrades, idempotency and backup-before-migrate."""

import sqlite3

from app.db import migrations_runner
from app.db.database import connect
from app.db.migrations_runner import migrate


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }


def test_fresh_migrate_applies_initial_schema(tmp_path):
    db = tmp_path / "fresh.sqlite3"
    result = migrate(db)
    assert result.applied == (1, 2, 3, 4)
    assert result.backup_path is None
    conn = connect(db, read_only=True)
    try:
        tables = _tables(conn)
    finally:
        conn.close()
    assert {"schema_migrations", "sites", "log_sources", "imports", "requests"} <= tables
    assert {"admin_users", "admin_sessions", "api_tokens"} <= tables
    assert {"ai_spend"} <= tables
    assert {"smoke_allowance", "smoke_holds"} <= tables
    for index in (
        "idx_requests_ts",
        "idx_requests_status",
        "idx_requests_path",
        "idx_requests_source",
    ):
        assert index in {
            row[0]
            for row in connect(db, read_only=True).execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            )
        }


def test_migrate_is_idempotent(tmp_path):
    db = tmp_path / "fresh.sqlite3"
    assert migrate(db).applied == (1, 2, 3, 4)
    assert migrate(db).applied == ()
    assert migrate(db, backup_dir=tmp_path / "backups").backup_path is None


def test_backup_before_migrate_on_pending_upgrade(tmp_path, monkeypatch):
    staged = tmp_path / "migrations"
    staged.mkdir()
    (staged / "0001_initial.sql").write_text(
        "CREATE TABLE t (id INTEGER PRIMARY KEY, note TEXT NOT NULL);", encoding="utf-8"
    )
    monkeypatch.setattr(migrations_runner, "MIGRATIONS_DIR", staged)
    db = tmp_path / "evolving.sqlite3"
    assert migrate(db).applied == (1,)
    conn = connect(db)
    with conn:
        conn.execute("INSERT INTO t (note) VALUES ('pre-upgrade row')")
    conn.close()
    (staged / "0002_extra.sql").write_text("ALTER TABLE t ADD COLUMN extra TEXT;", encoding="utf-8")
    backups = tmp_path / "backups"
    result = migrate(db, backup_dir=backups)
    assert result.applied == (2,)
    assert result.backup_path is not None and result.backup_path.is_file()
    import stat as statmod

    assert statmod.S_IMODE(result.backup_path.stat().st_mode) == 0o600
    probe = sqlite3.connect(str(result.backup_path))
    try:
        assert probe.execute("SELECT note FROM t").fetchall() == [("pre-upgrade row",)]
    finally:
        probe.close()
