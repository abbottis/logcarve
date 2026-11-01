"""Parameterized repositories for the T3 domain tables.

All values are bound parameters; no SQL is built from input. Selectable
identifiers and sort orders are fixed queries, never interpolated
client input. Repository code performs no model, network or transport
calls.
"""

import json
import sqlite3
from dataclasses import dataclass

#: Fixed code when a source id is bound to a different site than the one
#: requested: the operation is rejected before any write and existing
#: core/metadata/private/auth/usage state stays unchanged.
SOURCE_SITE_MISMATCH_CODE = "source_site_mismatch"


class SourceBindingError(ValueError):
    """A source id is already bound to another site; fixed code only."""

    def __init__(self, code: str = SOURCE_SITE_MISMATCH_CODE) -> None:
        super().__init__(code)
        self.code = code


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
    allowed_hosts: list[str] | None = None,
) -> None:
    """Register a source; persist the configured host aliases for later use.

    ``allowed_hosts`` (site hostname plus configured aliases) is stored as
    sorted JSON so later internal/external referrer classification can
    reuse the same configured set. Existing rows are never overwritten
    (``ON CONFLICT DO NOTHING``), so legacy rows keep their prior value.
    """
    hosts_json: str | None = None
    if allowed_hosts:
        hosts_json = json.dumps(
            sorted({str(item).strip().lower() for item in allowed_hosts if str(item).strip()})
        )
    conn.execute(
        "INSERT INTO log_sources (id, site_id, server_type, format_id, path_alias, enabled,"
        " allowed_hosts)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)"
        " ON CONFLICT (id) DO NOTHING",
        (source_id, site_id, server_type, format_id, path_alias, int(enabled), hosts_json),
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


#: Core event columns (legacy, preserved) plus nullable T1b enrichment
#: metadata. ``duration_ms`` stays legacy (Combined never supplies it and
#: reprocessing must never overwrite it); measured timings live in
#: ``request_time_ms``/``upstream_time_ms``/``upstream_count`` with
#: ``None`` meaning absent, and ``policy_version`` records the parser
#: policy that produced the enrichment (NULL on legacy rows).
_INSERT_EVENT = (
    "INSERT INTO requests (import_id, site_id, source_id, file_fingerprint,"
    " byte_offset, line_number, ts_utc, method, path, status, bytes,"
    " referer_host, user_agent, client_pseudonym, duration_ms,"
    " format_id, http_version, server_host, referer_scheme, referer_path,"
    " cache_status, mime_type, tls_protocol, request_time_ms, upstream_time_ms,"
    " upstream_count, policy_version)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
    " ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    " ON CONFLICT (source_id, file_fingerprint, byte_offset) DO NOTHING"
)


def event_row_width() -> int:
    """Number of bound values one event row carries (insert contract)."""
    return 27


#: Columns only reprocessing may update; core identity stays read-only.
_METADATA_COLUMNS = (
    "format_id",
    "http_version",
    "server_host",
    "referer_scheme",
    "referer_path",
    "cache_status",
    "mime_type",
    "tls_protocol",
    "request_time_ms",
    "upstream_time_ms",
    "upstream_count",
    "policy_version",
)

_UPDATE_METADATA = (
    "UPDATE requests SET format_id = ?, http_version = ?, server_host = ?,"
    " referer_scheme = ?, referer_path = ?, cache_status = ?, mime_type = ?,"
    " tls_protocol = ?, request_time_ms = ?, upstream_time_ms = ?,"
    " upstream_count = ?, policy_version = ? WHERE id = ?"
)


_UPDATE_METADATA_GUARDED = (
    "UPDATE requests SET format_id = ?, http_version = ?, server_host = ?,"
    " referer_scheme = ?, referer_path = ?, cache_status = ?, mime_type = ?,"
    " tls_protocol = ?, request_time_ms = ?, upstream_time_ms = ?,"
    " upstream_count = ?, policy_version = ? WHERE id = ?"
    " AND site_id = ? AND source_id = ? AND file_fingerprint = ?"
)


def update_request_metadata(conn: sqlite3.Connection, *, request_id: int, values: tuple) -> None:
    """Update ONLY the nullable enrichment metadata of one event row.

    Core identity columns (timestamps, method, path, status, HMAC, ...)
    are never touched here; callers verify them before calling.
    """
    if len(values) != len(_METADATA_COLUMNS):
        raise ValueError("metadata values must match the enrichment columns")
    conn.execute(_UPDATE_METADATA, (*values, request_id))


def update_request_metadata_guarded(
    conn: sqlite3.Connection,
    *,
    request_id: int,
    site_id: str,
    source_id: str,
    file_fingerprint: str,
    values: tuple,
) -> None:
    """Update enrichment metadata only when the stored identity still matches.

    The ``WHERE`` clause carries the validated stored site/source/
    fingerprint identity, so a row that changed scope underfoot is never
    touched: zero updated rows raise instead of silently writing.
    """
    if len(values) != len(_METADATA_COLUMNS):
        raise ValueError("metadata values must match the enrichment columns")
    cursor = conn.execute(
        _UPDATE_METADATA_GUARDED, (*values, request_id, site_id, source_id, file_fingerprint)
    )
    if cursor.rowcount != 1:
        raise RuntimeError("reprocess binding changed underfoot")


def metadata_columns() -> tuple[str, ...]:
    """Names of the reprocess-writable enrichment columns, in order."""
    return _METADATA_COLUMNS


#: Hard bound on one reprocess read page: reprocessing streams stored
#: rows in keyset pages and never materializes a whole source.
REPROCESS_PAGE_MAX = 1000


def fetch_source(conn: sqlite3.Connection, *, source_id: str) -> sqlite3.Row | None:
    """One registered source row, or ``None`` when never registered."""
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT id, site_id, server_type, format_id, path_alias, enabled"
            " FROM log_sources WHERE id = ?",
            (source_id,),
        ).fetchone()
    finally:
        conn.row_factory = None


def count_reprocess_rows(
    conn: sqlite3.Connection, *, source_id: str, file_fingerprint: str, site_id: str | None = None
) -> int:
    """Row totals come from SQL COUNT, never from retained rows."""
    if site_id is None:
        row = conn.execute(
            "SELECT COUNT(*) FROM requests WHERE source_id = ? AND file_fingerprint = ?",
            (source_id, file_fingerprint),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT COUNT(*) FROM requests"
            " WHERE source_id = ? AND file_fingerprint = ? AND site_id = ?",
            (source_id, file_fingerprint, site_id),
        ).fetchone()
    return int(row[0])


def fetch_reprocess_page(
    conn: sqlite3.Connection,
    *,
    source_id: str,
    file_fingerprint: str,
    site_id: str,
    after_offset: int,
    limit: int,
) -> list[sqlite3.Row]:
    """One bounded keyset page of stored rows past ``after_offset``.

    ``limit`` is clamped to :data:`REPROCESS_PAGE_MAX`: callers page in
    ``byte_offset`` order with short read transactions and never hold a
    long-lived snapshot while writing. The stored site/source identity
    travels with every row so updates use validated identity, never
    caller-supplied scope.
    """
    limit = max(1, min(int(limit), REPROCESS_PAGE_MAX))
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT id, site_id, source_id, file_fingerprint, byte_offset,"
            " line_number, ts_utc, method, path, status,"
            " bytes, referer_host, user_agent, client_pseudonym, duration_ms,"
            " format_id, http_version, server_host, referer_scheme, referer_path,"
            " cache_status, mime_type, tls_protocol, request_time_ms,"
            " upstream_time_ms, upstream_count, policy_version"
            " FROM requests"
            " WHERE source_id = ? AND file_fingerprint = ? AND site_id = ?"
            " AND byte_offset > ? ORDER BY byte_offset LIMIT ?",
            (source_id, file_fingerprint, site_id, after_offset, limit),
        ).fetchall()
    finally:
        conn.row_factory = None


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
