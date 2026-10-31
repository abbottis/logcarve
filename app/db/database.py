"""SQLite connection lifecycle and one-writer coordination (T3).

Every connection enables WAL, foreign keys and a bounded busy timeout.
Writers take the database reserved lock with ``BEGIN IMMEDIATE`` inside
:func:`writer_transaction`; when the lock cannot be acquired within
``lock_timeout_s`` a :class:`WriterBusy` error is raised instead of
blocking forever. Readers never take write locks.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path


class WriterBusy(RuntimeError):
    """Another writer holds the database lock past the bounded wait."""


def connect(
    db_path: Path, *, timeout_s: float = 30.0, read_only: bool = False
) -> sqlite3.Connection:
    """Open a SQLite connection with the project pragmas applied."""
    db_path = Path(db_path)
    if read_only:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=timeout_s)
    else:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path), timeout=timeout_s)
    try:
        if not read_only:
            conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(f"PRAGMA busy_timeout={max(1, int(timeout_s * 1000))}")
        return conn
    except Exception:
        conn.close()
        raise


@contextmanager
def writer_transaction(db_path: Path, *, lock_timeout_s: float = 30.0):
    """Yield a connection holding the write lock; commit on success, roll back on error."""
    conn = connect(db_path, timeout_s=lock_timeout_s)
    try:
        try:
            conn.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise WriterBusy(f"database writer lock unavailable: {db_path}") from exc
            raise
        try:
            yield conn
        except BaseException:
            conn.rollback()
            raise
        else:
            conn.commit()
    finally:
        conn.close()
