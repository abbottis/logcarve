"""Parameterized analytics repositories (T4).

Every query is a fixed SQL string with bound parameters; sort orders
come from allowlisted contract literals, never from input. Large
cardinality scans (distinct agents/paths) are bounded with explicit
truncation flags so reads never load the whole database into memory.
"""

import sqlite3
from datetime import datetime, timedelta

from app.analytics.contracts import AnalyticsFilter, BucketSize, TopPathsQuery, TopReferrersQuery
from app.db.importer import sanitize_error_summary

MAX_DISTINCT_SCAN = 5000


def _like_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _where(filt: AnalyticsFilter) -> tuple[str, list[object]]:
    clauses = ["site_id = ?", "ts_utc >= ?", "ts_utc < ?"]
    params: list[object] = [
        filt.site_id,
        filt.window.time_from.isoformat(),
        filt.window.time_to.isoformat(),
    ]
    if filt.source_id is not None:
        clauses.append("source_id = ?")
        params.append(filt.source_id)
    if filt.method is not None:
        clauses.append("method = ?")
        params.append(filt.method)
    if filt.status is not None:
        clauses.append("status = ?")
        params.append(filt.status)
    if filt.path_prefix is not None:
        clauses.append("path LIKE ? ESCAPE '\\'")
        params.append(_like_escape(filt.path_prefix) + "%")
    if filt.referer_host is not None:
        clauses.append("referer_host = ?")
        params.append(filt.referer_host)
    return " AND ".join(clauses), params


def summary_counts(conn: sqlite3.Connection, filt: AnalyticsFilter) -> dict[str, int]:
    where, params = _where(filt)
    row = conn.execute(
        "SELECT COUNT(*),"
        " COUNT(CASE WHEN status BETWEEN 400 AND 499 THEN 1 END),"
        " COUNT(CASE WHEN status BETWEEN 500 AND 599 THEN 1 END),"
        " COALESCE(SUM(bytes), 0),"
        " COUNT(bytes)"
        f" FROM requests WHERE {where}",
        params,
    ).fetchone()
    return {
        "requests": row[0],
        "errors_4xx": row[1],
        "errors_5xx": row[2],
        "bytes_total": row[3],
        "bytes_measured": row[4],
    }


def status_distribution(conn: sqlite3.Connection, filt: AnalyticsFilter) -> list[dict[str, int]]:
    where, params = _where(filt)
    rows = conn.execute(
        f"SELECT status, COUNT(*) FROM requests WHERE {where} GROUP BY status ORDER BY status",
        params,
    ).fetchall()
    return [{"status": status, "requests": count} for status, count in rows]


_TOP_PATH_ORDER: dict[str, str] = {
    "requests_desc": "requests DESC, path ASC, method ASC",
    "errors_desc": "errors DESC, requests DESC, path ASC, method ASC",
}


def top_paths(
    conn: sqlite3.Connection, query: TopPathsQuery
) -> tuple[list[dict[str, object]], int]:
    where, params = _where(query.filt)
    order = _TOP_PATH_ORDER[query.sort]
    total = conn.execute(
        f"SELECT COUNT(DISTINCT path || '\x1f' || method) FROM requests WHERE {where}", params
    ).fetchone()[0]
    rows = conn.execute(
        "SELECT path, method, COUNT(*) AS requests,"
        " COUNT(CASE WHEN status >= 400 THEN 1 END) AS errors"
        f" FROM requests WHERE {where} GROUP BY path, method ORDER BY {order} LIMIT ? OFFSET ?",
        [*params, query.filt.limit, query.filt.offset],
    ).fetchall()
    return (
        [
            {"path": path, "method": method, "requests": count, "errors": errors}
            for path, method, count, errors in rows
        ],
        total,
    )


def top_referrers(
    conn: sqlite3.Connection, query: TopReferrersQuery
) -> tuple[list[dict[str, object]], int]:
    where, params = _where(query.filt)
    scoped = f"{where} AND referer_host IS NOT NULL"
    total = conn.execute(
        f"SELECT COUNT(DISTINCT referer_host) FROM requests WHERE {scoped}", params
    ).fetchone()[0]
    rows = conn.execute(
        "SELECT referer_host, COUNT(*) AS requests, COUNT(DISTINCT path) AS paths"
        f" FROM requests WHERE {scoped} GROUP BY referer_host"
        " ORDER BY requests DESC, referer_host ASC LIMIT ? OFFSET ?",
        [*params, query.filt.limit, query.filt.offset],
    ).fetchall()
    return (
        [{"referer_host": host, "requests": count, "paths": paths} for host, count, paths in rows],
        total,
    )


def _bucket_edges(filt: AnalyticsFilter, bucket: BucketSize) -> list[datetime]:
    step = timedelta(hours=1) if bucket == "hour" else timedelta(days=1)
    start = filt.window.time_from.replace(minute=0, second=0, microsecond=0)
    if bucket == "day":
        start = start.replace(hour=0)
    edges = []
    cursor = start
    while cursor < filt.window.time_to:
        edges.append(cursor)
        cursor += step
    return edges


def time_buckets(
    conn: sqlite3.Connection, filt: AnalyticsFilter, bucket: BucketSize
) -> list[dict[str, object]]:
    where, params = _where(filt)
    width = 13 if bucket == "hour" else 10
    rows = conn.execute(
        f"SELECT substr(ts_utc, 1, {width}), COUNT(*),"
        " COUNT(CASE WHEN status >= 400 THEN 1 END)"
        f" FROM requests WHERE {where} GROUP BY substr(ts_utc, 1, {width})",
        params,
    ).fetchall()
    by_key = {key: {"requests": count, "errors": errors} for key, count, errors in rows}
    result = []
    for edge in _bucket_edges(filt, bucket):
        key = edge.strftime("%Y-%m-%dT%H") if bucket == "hour" else edge.strftime("%Y-%m-%d")
        counts = by_key.get(key, {"requests": 0, "errors": 0})
        result.append({"bucket": edge.isoformat(), **counts})
    return result


def count_measured_durations(conn: sqlite3.Connection, filt: AnalyticsFilter) -> int:
    """Rows with a measured duration; Combined-only data yields zero."""
    where, params = _where(filt)
    row = conn.execute(f"SELECT COUNT(duration_ms) FROM requests WHERE {where}", params).fetchone()
    return int(row[0])


def error_groups(
    conn: sqlite3.Connection, filt: AnalyticsFilter
) -> tuple[list[dict[str, object]], int]:
    """Groups of error responses by path and status, with referrer breadth."""
    where, params = _where(filt)
    scoped = f"{where} AND status >= 400"
    total = conn.execute(
        f"SELECT COUNT(DISTINCT path || '\x1f' || status) FROM requests WHERE {scoped}", params
    ).fetchone()[0]
    rows = conn.execute(
        "SELECT path, status, COUNT(*) AS requests, COUNT(DISTINCT referer_host) AS referrers"
        f" FROM requests WHERE {scoped} GROUP BY path, status"
        " ORDER BY requests DESC, path ASC, status ASC LIMIT ? OFFSET ?",
        [*params, filt.limit, filt.offset],
    ).fetchall()
    return (
        [
            {"path": path, "status": status, "requests": count, "referrers": referrers}
            for path, status, count, referrers in rows
        ],
        total,
    )


def distinct_user_agents(
    conn: sqlite3.Connection, filt: AnalyticsFilter
) -> tuple[list[tuple[str, int]], bool]:
    where, params = _where(filt)
    scoped = f"{where} AND user_agent IS NOT NULL"
    rows = conn.execute(
        "SELECT user_agent, COUNT(*) AS requests FROM requests"
        f" WHERE {scoped} GROUP BY user_agent ORDER BY requests DESC LIMIT ?",
        [*params, MAX_DISTINCT_SCAN + 1],
    ).fetchall()
    truncated = len(rows) > MAX_DISTINCT_SCAN
    pairs = [(ua, count) for ua, count in rows[:MAX_DISTINCT_SCAN] if ua is not None]
    return pairs, truncated


#: Cap for the agent IN-list in :func:`paths_for_agents`; larger matched
#: sets are labelled truncated by the caller.
PATHS_FOR_AGENTS_CAP = 50


def paths_for_agents(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    user_agents: list[str],
    *,
    status: int | None = None,
    limit: int = 10,
) -> tuple[list[dict[str, object]], bool]:
    """Top path/status rows for an explicit server-side agent set.

    The agent set always comes from our own bounded distinct scan
    matched by versioned rules — never from client input — so the
    IN-list stays small and every value is bound, never interpolated.
    Used for claimed-crawler path and 404 evidence. Returns the rows
    plus whether the agent set was truncated to the IN-list cap, so
    callers label samples explicitly instead of silently narrowing them.
    """
    agents = [ua for ua in user_agents[:PATHS_FOR_AGENTS_CAP] if ua]
    truncated = len(user_agents) > PATHS_FOR_AGENTS_CAP
    if not agents:
        return [], truncated
    where, params = _where(filt)
    placeholders = ", ".join(["?"] * len(agents))
    scoped = f"{where} AND user_agent IN ({placeholders})"
    args: list[object] = [*params, *agents]
    if status is not None:
        scoped += " AND status = ?"
        args.append(status)
    rows = conn.execute(
        "SELECT path, status, COUNT(*) AS requests"
        f" FROM requests WHERE {scoped} GROUP BY path, status"
        " ORDER BY requests DESC, path ASC, status ASC LIMIT ?",
        [*args, limit],
    ).fetchall()
    return (
        [{"path": path, "status": code, "requests": count} for path, code, count in rows],
        truncated,
    )


def distinct_paths(
    conn: sqlite3.Connection, filt: AnalyticsFilter
) -> tuple[list[tuple[str, int, int]], bool]:
    where, params = _where(filt)
    rows = conn.execute(
        "SELECT path, COUNT(*) AS requests, COUNT(CASE WHEN status >= 400 THEN 1 END) AS errors"
        f" FROM requests WHERE {where} GROUP BY path ORDER BY requests DESC LIMIT ?",
        [*params, MAX_DISTINCT_SCAN + 1],
    ).fetchall()
    truncated = len(rows) > MAX_DISTINCT_SCAN
    return [(path, count, errors) for path, count, errors in rows[:MAX_DISTINCT_SCAN]], truncated


def repeated_client_errors(
    conn: sqlite3.Connection, filt: AnalyticsFilter, *, min_errors: int, limit: int = 100
) -> list[dict[str, object]]:
    where, params = _where(filt)
    scoped = f"{where} AND status BETWEEN 400 AND 499"
    rows = conn.execute(
        "SELECT client_pseudonym, COUNT(*) AS errors, COUNT(DISTINCT path) AS paths"
        f" FROM requests WHERE {scoped} GROUP BY client_pseudonym"
        " HAVING COUNT(*) >= ? ORDER BY errors DESC, client_pseudonym ASC LIMIT ?",
        [*params, min_errors, limit],
    ).fetchall()
    return [
        {"client_pseudonym": ident, "errors": count, "paths": paths} for ident, count, paths in rows
    ]


def sample_paths_for_client(
    conn: sqlite3.Connection, filt: AnalyticsFilter, *, client_pseudonym: str, limit: int = 5
) -> list[dict[str, object]]:
    where, params = _where(filt)
    rows = conn.execute(
        "SELECT path, status, COUNT(*) AS hits FROM requests"
        f" WHERE {where} AND client_pseudonym = ?"
        " GROUP BY path, status ORDER BY hits DESC, path ASC, status ASC LIMIT ?",
        [*params, client_pseudonym, limit],
    ).fetchall()
    return [{"path": path, "status": status, "hits": hits} for path, status, hits in rows]


def coverage(conn: sqlite3.Connection, filt: AnalyticsFilter) -> dict[str, object]:
    """Observed range and unique events for the site/source/window scope.

    Unique stored events never double-count replays: replayed import
    attempts add no rows, so ``unique_events`` is the deduplicated total
    while ``import_lines_total`` records every attempt. Proven source
    coverage is never claimed from logs alone (see limitations).
    """
    where, params = _where(filt)
    row = conn.execute(
        f"SELECT COUNT(*), MIN(ts_utc), MAX(ts_utc) FROM requests WHERE {where}", params
    ).fetchone()
    sources = [
        r[0]
        for r in conn.execute(
            f"SELECT DISTINCT source_id FROM requests WHERE {where} ORDER BY source_id", params
        ).fetchall()
    ]
    if filt.source_id is not None:
        source_ids: list[object] = [filt.source_id]
    else:
        source_ids = [
            r[0]
            for r in conn.execute(
                "SELECT id FROM log_sources WHERE site_id = ?", [filt.site_id]
            ).fetchall()
        ]
    imports: list[dict[str, object]] = []
    attempts = {"lines_total": 0, "lines_accepted": 0, "lines_rejected": 0, "records_replayed": 0}
    if source_ids:
        placeholders = ", ".join("?" for _ in source_ids)
        for imp in conn.execute(
            "SELECT id, source_id, file_fingerprint, lines_total, lines_accepted,"
            " lines_rejected, records_inserted, records_replayed, status, error_summary"
            f" FROM imports WHERE source_id IN ({placeholders}) ORDER BY id",
            source_ids,
        ).fetchall():
            imports.append(
                {
                    "import_id": imp[0],
                    "source_id": imp[1],
                    "file_fingerprint": imp[2],
                    "lines_total": imp[3],
                    "lines_accepted": imp[4],
                    "lines_rejected": imp[5],
                    "records_inserted": imp[6],
                    "records_replayed": imp[7],
                    "status": imp[8],
                    # Stored summaries predate allowlisting (free-text
                    # exception output); scrub them at this shared read
                    # boundary so legacy text never reaches any consumer.
                    "error_summary": sanitize_error_summary(imp[9]),
                }
            )
    attempts = {
        "lines_total": sum(i["lines_total"] for i in imports),
        "lines_accepted": sum(i["lines_accepted"] for i in imports),
        "lines_rejected": sum(i["lines_rejected"] for i in imports),
        "records_replayed": sum(i["records_replayed"] for i in imports),
    }
    return {
        "unique_events": row[0],
        "observed_min": row[1],
        "observed_max": row[2],
        "sources": sources,
        "imports": imports,
        "import_attempts": attempts,
    }
