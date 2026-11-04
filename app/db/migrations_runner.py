"""Versioned SQL migrations with backup-before-migrate (T3, atomicity fix T1b).

Migration files are named ``NNNN_name.sql`` and apply in numeric order.
Each file applies atomically: all of its statements plus the
``schema_migrations`` version row commit together under one bounded
writer lock (``BEGIN IMMEDIATE`` via :func:`writer_transaction`), and any
mid-file failure rolls everything back, leaving neither partial DDL nor
a version row. A valid retry afterwards applies cleanly.

The runner never uses ``executescript`` (which implicitly commits before
a ``with connection`` transaction, so multi-statement files plus the
version insert were not truly atomic). Statement framing uses
:func:`sqlite3.complete_statement` -- SQLite's own tokenizer -- so
quoted literals, comments, bracketed identifiers and trigger bodies
(``CREATE TRIGGER ... BEGIN ... CASE ... END ... END``) survive without
a homemade lexer. Trusted migration scripts must not carry their own
transaction control (``BEGIN``/``COMMIT``/``ROLLBACK``/``END``/
``SAVEPOINT``/``RELEASE``/``VACUUM``/``ATTACH``/``DETACH``): such a
statement is rejected before anything runs (after stripping leading SQL
comments, so a comment-prefixed ``COMMIT`` cannot slip through), and a
SQLite authorizer additionally denies transaction/savepoint/attach
operations at execution time inside the runner-owned transaction, so
scripts can never break the runner transaction policy.

When ``backup_dir`` is given and migrations are pending on a non-empty
database, a timestamped online backup is taken first (see
:mod:`app.db.backup`); the backup path is returned alongside the applied
versions. Backups hold ciphertext only; key recovery stays separately
documented.
"""

import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.db.backup import backup_database
from app.db.database import WriterBusy, connect, writer_transaction

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"

_TX_CONTROL_RE = re.compile(
    r"(BEGIN|COMMIT|END|ROLLBACK|SAVEPOINT|RELEASE|VACUUM|ATTACH|DETACH)\b",
    re.IGNORECASE,
)

_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def _strip_leading_trivia(statement: str) -> str:
    """Remove leading whitespace and SQL comments from one statement."""
    rest = statement
    while True:
        stripped = rest.lstrip()
        if stripped.startswith("--"):
            newline = stripped.find("\n")
            if newline == -1:
                return ""
            rest = stripped[newline + 1 :]
            continue
        if stripped.startswith("/*"):
            match = _BLOCK_COMMENT_RE.match(stripped)
            if match is None:
                return stripped
            rest = stripped[match.end() :]
            continue
        return stripped


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


def _split_statements(sql: str) -> list[str]:
    """Split migration SQL into statements with SQLite's own tokenizer.

    :func:`sqlite3.complete_statement` frames each statement, so
    semicolons inside quoted literals, comments, bracketed identifiers
    and trigger bodies (including ``CASE ... END``) never split. Returns
    the non-empty statements without their trailing semicolons.
    """
    statements: list[str] = []
    buf: list[str] = []
    for char in sql:
        buf.append(char)
        if char != ";":
            continue
        # Only SQLite's own tokenizer decides: a semicolon inside a
        # quoted literal, a comment, a bracketed identifier or a trigger
        # body (including CASE ... END) is not a boundary, so
        # ``complete_statement`` stays False and accumulation continues.
        # Several statements on one line each terminate separately.
        candidate = "".join(buf)
        if sqlite3.complete_statement(candidate):
            body = candidate.strip()[:-1].strip()
            if body:
                statements.append(body)
            buf = []
    tail = "".join(buf).strip()
    if tail:
        if sqlite3.complete_statement(tail):
            statements.append(tail)
        elif _strip_leading_trivia(tail):
            raise ValueError(f"migration holds an incomplete trailing statement: {tail[:60]!r}")
        # Else pure trailing trivia (comments/whitespace): ignored.
    return statements


def _check_no_transaction_control(statements: list[str], version: int) -> None:
    """Reject trusted scripts that would break the runner transaction policy.

    Leading SQL comments and whitespace are stripped first, so a
    comment-prefixed ``COMMIT``/``ROLLBACK`` cannot slip through.
    """
    for statement in statements:
        head = _strip_leading_trivia(statement)
        if _TX_CONTROL_RE.match(head):
            raise ValueError(f"migration {version:04d} must not carry transaction control")


def _deny_runner_foreign_control(
    action: int, _arg1: str | None, _arg2: str | None, _db: str | None, _src: str | None
) -> int:
    """SQLite authorizer: the runner owns BEGIN/COMMIT; scripts never do."""
    if action in (
        sqlite3.SQLITE_TRANSACTION,
        sqlite3.SQLITE_SAVEPOINT,
        sqlite3.SQLITE_ATTACH,
        sqlite3.SQLITE_DETACH,
    ):
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def _apply_migration(db_path: Path, version: int, path: Path, lock_timeout_s: float) -> None:
    """Apply one migration file atomically with its version row."""
    sql = path.read_text(encoding="utf-8")
    statements = _split_statements(sql)
    if not statements:
        raise ValueError(f"migration {version:04d} holds no statements")
    _check_no_transaction_control(statements, version)
    with writer_transaction(db_path, lock_timeout_s=lock_timeout_s) as conn:
        conn.set_authorizer(_deny_runner_foreign_control)
        try:
            for statement in statements:
                conn.execute(statement)
            conn.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                (version, datetime.now(UTC).isoformat()),
            )
        finally:
            conn.set_authorizer(None)


def migrate(
    db_path: Path, backup_dir: Path | None = None, *, lock_timeout_s: float = 30.0
) -> MigrationResult:
    """Apply pending migrations; back the database up first when asked."""
    conn = connect(db_path)
    try:
        with conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                " version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
        pending = _pending_versions(conn)
    finally:
        conn.close()
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
        _apply_migration(db_path, version, path, lock_timeout_s)
        applied.append(version)
    return MigrationResult(applied=tuple(applied), backup_path=backup_path)


__all__ = [
    "MigrationResult",
    "WriterBusy",
    "migrate",
]
