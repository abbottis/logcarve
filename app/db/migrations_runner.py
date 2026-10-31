"""Versioned SQL migrations with backup-before-migrate (T3).

Migration files are named ``NNNN_name.sql`` and apply in numeric order.
Each file runs inside one transaction; applied versions are recorded in
``schema_migrations``. When ``backup_dir`` is given and migrations are
pending on a non-empty database, a timestamped online backup is taken
first (see :mod:`app.db.backup`); the backup path is returned alongside
the applied versions.
"""

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.db.backup import backup_database
from app.db.database import connect

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


@dataclass(frozen=True)
class MigrationResult:
    applied: tuple[int, ...]
    backup_path: Path | None


def _pending_versions(conn: sqlite3.Connection) -> list[tuple[int, Path]]:
    exists = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
    ).fetchone()
    applied = set()
    if exists is not None:
        applied = {row[0] for row in conn.execute("SELECT version FROM schema_migrations")}
    files = sorted(MIGRATIONS_DIR.glob("[0-9][0-9][0-9][0-9]_*.sql"))
    pending = []
    for path in files:
        version = int(path.stem.split("_", 1)[0])
        if version not in applied:
            pending.append((version, path))
    return pending


def _database_has_tables(db_path: Path) -> bool:
    if not db_path.exists() or db_path.stat().st_size == 0:
        return False
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
            " AND name NOT LIKE 'sqlite_%' AND name != 'schema_migrations'"
        ).fetchall()
        return len(rows) > 0
    finally:
        conn.close()


def migrate(db_path: Path, backup_dir: Path | None = None) -> MigrationResult:
    """Apply pending migrations; back the database up first when asked."""
    conn = connect(db_path)
    try:
        with conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                " version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
        pending = _pending_versions(conn)
        if not pending:
            return MigrationResult(applied=(), backup_path=None)
        backup_path: Path | None = None
        if backup_dir is not None and _database_has_tables(db_path):
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            backup_path = backup_database(
                db_path, backup_dir / f"{db_path.stem}-pre-migrate-{stamp}.sqlite3"
            )
        applied: list[int] = []
        for version, path in pending:
            sql = path.read_text(encoding="utf-8")
            with conn:
                conn.executescript(sql)
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (version, datetime.now(UTC).isoformat()),
                )
            applied.append(version)
        return MigrationResult(applied=tuple(applied), backup_path=backup_path)
    finally:
        conn.close()
