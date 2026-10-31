"""Configurable UTC event retention for owned import data (T3).

Retention deletes normalized request events older than the cutoff
``now - days`` (event timestamps are UTC). It affects only LogCarve's
own ``requests`` rows: source logs are never touched, import reports
are kept for audit, and restored backups must have retention reapplied
before serving. Deleting rows that a fingerprint still references is
expected: a later replay re-inserts them as new rows.
"""

import sqlite3
from datetime import datetime, timedelta


def retention_cutoff_utc(days: int, *, now: datetime) -> str:
    """ISO cutoff; events strictly older than this are eligible for deletion."""
    if days < 1:
        raise ValueError("retention days must be at least 1")
    return (now - timedelta(days=days)).isoformat()


def apply_retention(conn: sqlite3.Connection, *, days: int, now: datetime) -> int:
    """Delete owned events older than the cutoff; return the deleted count."""
    cutoff = retention_cutoff_utc(days, now=now)
    cursor = conn.execute("DELETE FROM requests WHERE ts_utc < ?", (cutoff,))
    return cursor.rowcount if cursor.rowcount is not None else 0
