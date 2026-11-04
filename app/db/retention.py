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
    """Delete owned events older than the cutoff; return the deleted count.

    The delete cascades to the encrypted private originals
    (``request_original_ips``) through ``ON DELETE CASCADE``, which
    requires foreign keys to be enforced on this connection. A
    ``PRAGMA foreign_keys=ON`` issued inside an active transaction is
    silently ignored when keys were off, so enforcement is verified,
    not just claimed: when keys are off inside the caller's active
    transaction the delete fails closed before touching any row;
    otherwise keys are enabled (a no-op outside a transaction, never a
    commit of caller work) and verified before deleting. Only owned
    ``requests`` rows (and their private sidecars) go; sources, auth,
    usage and allowance tables are preserved, and source logs are never
    touched.
    """
    enforced = conn.execute("PRAGMA foreign_keys").fetchone()[0]
    if not enforced:
        if conn.in_transaction:
            raise sqlite3.IntegrityError(
                "retention requires foreign_keys=ON, which cannot be"
                " enabled inside an active transaction"
            )
        conn.execute("PRAGMA foreign_keys=ON")
        enforced = conn.execute("PRAGMA foreign_keys").fetchone()[0]
        if not enforced:
            raise sqlite3.IntegrityError("retention requires foreign_keys=ON")
    cutoff = retention_cutoff_utc(days, now=now)
    cursor = conn.execute("DELETE FROM requests WHERE ts_utc < ?", (cutoff,))
    return cursor.rowcount if cursor.rowcount is not None else 0
