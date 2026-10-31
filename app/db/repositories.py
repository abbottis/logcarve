"""Parameterized repositories for the T3 domain tables.

All values are bound parameters; no SQL is built from input. Selectable
identifiers and sort orders are fixed queries, never interpolated
client input. Repository code performs no model, network or transport
calls.
"""

import sqlite3
from dataclasses import dataclass


@dataclass(frozen=True)
class ImportCounts:
    lines_total: int = 0
    lines_accepted: int = 0
    lines_rejected: int = 0
    records_inserted: int = 0
    records_replayed: int = 0


def ensure_site(
    conn: sqlite3.Connection,
    *,
    site_id: str,
    name: str,
    hostname: str,
    timezone: str = "UTC",
    created_at: str,
) -> None:
    conn.execute(
        "INSERT INTO sites (id, name, hostname, timezone, created_at)"
        " VALUES (?, ?, ?, ?, ?)"
        " ON CONFLICT (id) DO NOTHING",
        (site_id, name, hostname, timezone, created_at),
    )


def ensure_source(
    conn: sqlite3.Connection,
    *,
    source_id: str,
    site_id: str,
    server_type: str,
    format_id: str,
    path_alias: str,
    enabled: bool = True,
) -> None:
    conn.execute(
        "INSERT INTO log_sources (id, site_id, server_type, format_id, path_alias, enabled)"
        " VALUES (?, ?, ?, ?, ?, ?)"
        " ON CONFLICT (id) DO NOTHING",
        (source_id, site_id, server_type, format_id, path_alias, int(enabled)),
    )


def create_import(
    conn: sqlite3.Connection,
    *,
    source_id: str,
    file_fingerprint: str,
    file_size: int,
    started_at: str,
) -> int:
    cursor = conn.execute(
        "INSERT INTO imports (source_id, file_fingerprint, file_size, started_at, status)"
        " VALUES (?, ?, ?, ?, 'running')",
        (source_id, file_fingerprint, file_size, started_at),
    )
    row_id = cursor.lastrowid
    assert row_id is not None
    return row_id


def finish_import(
    conn: sqlite3.Connection,
    *,
    import_id: int,
    finished_at: str,
    status: str,
    counts: ImportCounts,
    error_summary: str | None = None,
) -> None:
    conn.execute(
        "UPDATE imports SET finished_at = ?, status = ?,"
        " lines_total = ?, lines_accepted = ?, lines_rejected = ?,"
        " records_inserted = ?, records_replayed = ?, error_summary = ?"
        " WHERE id = ?",
        (
            finished_at,
            status,
            counts.lines_total,
            counts.lines_accepted,
            counts.lines_rejected,
            counts.records_inserted,
            counts.records_replayed,
            error_summary,
            import_id,
        ),
    )


_INSERT_EVENT = (
    "INSERT INTO requests (import_id, site_id, source_id, file_fingerprint,"
    " byte_offset, line_number, ts_utc, method, path, status, bytes,"
    " referer_host, user_agent, client_pseudonym, duration_ms)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    " ON CONFLICT (source_id, file_fingerprint, byte_offset) DO NOTHING"
)


def insert_events(conn: sqlite3.Connection, rows: list[tuple]) -> int:
    """Insert one bounded batch; return the number of rows actually added.

    Replays of the same (source, fingerprint, position) insert nothing and
    are counted by the caller as replayed.
    """
    if not rows:
        return 0
    before = conn.total_changes
    conn.executemany(_INSERT_EVENT, rows)
    return conn.total_changes - before


def count_events(conn: sqlite3.Connection, *, source_id: str | None = None) -> int:
    if source_id is None:
        return conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
    return conn.execute(
        "SELECT COUNT(*) FROM requests WHERE source_id = ?", (source_id,)
    ).fetchone()[0]


def fetch_events_by_path(conn: sqlite3.Connection, *, path: str) -> list[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT * FROM requests WHERE path = ? ORDER BY byte_offset", (path,)
        ).fetchall()
    finally:
        conn.row_factory = None
