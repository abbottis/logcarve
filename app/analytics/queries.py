"""Parameterized analytics repositories (T4).

Every query is a fixed SQL string with bound parameters; sort orders
come from allowlisted contract literals, never from input. Large
cardinality scans (distinct agents/paths) are bounded with explicit
truncation flags so reads never load the whole database into memory.
"""

import sqlite3
from datetime import datetime, timedelta

from app.analytics.classification import (
    Classifier,
    resolve_selector_indexes,
    traffic_indexes,
)
from app.analytics.contracts import (
    AnalyticsFilter,
    BucketSize,
    ExplorerQuery,
    TopPathsQuery,
    TopReferrersQuery,
)
from app.db.importer import sanitize_error_summary

MAX_DISTINCT_SCAN = 5000


def _like_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


#: Ordered classifier invocation. The spec string is server-generated
#: from the versioned rule file and always bound, never interpolated.
_MATCH = "classify_ua(user_agent, ?)"


def _classification_clauses(
    filt: AnalyticsFilter, classifier: Classifier | None
) -> tuple[list[str], list[object]]:
    """Traffic/bot/category/provider/purpose predicates via ordered match.

    Selectors need the versioned classifier; unknown or contradictory
    values raise ``ValueError`` so callers reject instead of widening.
    Valid but disjoint selectors (e.g. browser traffic plus a named bot)
    yield an empty result, never an error.
    """
    needs_match = (
        filt.traffic != "all"
        or filt.bot is not None
        or filt.category is not None
        or filt.provider is not None
        or filt.purpose is not None
    )
    if not needs_match:
        return [], []
    if classifier is None:
        raise ValueError("traffic/bot selectors need the versioned rule classifier")
    allowed = resolve_selector_indexes(
        classifier,
        bot=filt.bot,
        category=filt.category,
        provider=filt.provider,
        purpose=filt.purpose,
    )
    if filt.traffic != "all":
        bucket = traffic_indexes(classifier, filt.traffic)
        if filt.traffic == "browser_like":
            if allowed is None:
                return [f"{_MATCH} = ?"], [classifier.spec, classifier.browser_index]
            return ["1 = 0"], []
        if filt.traffic == "unknown":
            if allowed is None:
                return [f"{_MATCH} IS NULL"], [classifier.spec]
            return ["1 = 0"], []
        allowed = bucket if allowed is None else (allowed & bucket)
    if not allowed:
        return ["1 = 0"], []
    if len(allowed) == 1:
        (only,) = sorted(allowed)
        return [f"{_MATCH} = ?"], [classifier.spec, only]
    order = sorted(allowed)
    placeholders = ", ".join("?" for _ in order)
    return [f"{_MATCH} IN ({placeholders})"], [classifier.spec, *order]


_STATUS_CLASS_RANGE = {
    "2xx": (200, 299),
    "3xx": (300, 399),
    "4xx": (400, 499),
    "5xx": (500, 599),
}


def _where(filt: AnalyticsFilter, classifier: Classifier | None = None) -> tuple[str, list[object]]:
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
    if filt.status_class is not None:
        low, high = _STATUS_CLASS_RANGE[filt.status_class]
        clauses.append("status BETWEEN ? AND ?")
        params.extend([low, high])
    if filt.path_prefix is not None:
        clauses.append("path LIKE ? ESCAPE '\\'")
        params.append(_like_escape(filt.path_prefix) + "%")
    if filt.referer_host is not None:
        clauses.append("referer_host = ?")
        params.append(filt.referer_host)
    if filt.search is not None:
        # LogWerk-style explorer search over stored sanitized fields only:
        # query-stripped path, truncated-at-read user agent, minimized
        # referrer host and HMAC pseudonym. Method/status have separate
        # controls; no raw IPs or query values are stored to search.
        needle = "%" + _like_escape(filt.search) + "%"
        clauses.append(
            "(path LIKE ? ESCAPE '\\'"
            " OR user_agent LIKE ? ESCAPE '\\'"
            " OR referer_host LIKE ? ESCAPE '\\'"
            " OR client_pseudonym LIKE ? ESCAPE '\\')"
        )
        params.extend([needle, needle, needle, needle])
    match_clauses, match_params = _classification_clauses(filt, classifier)
    clauses.extend(match_clauses)
    params.extend(match_params)
    return " AND ".join(clauses), params


def traffic_case_sql(classifier: Classifier) -> tuple[str, list[object]]:
    """CASE expression mapping each row to its traffic bucket (server-built)."""
    branches = " ".join(f"WHEN {i} THEN '{bucket}'" for i, bucket in enumerate(classifier.traffic))
    sql = (
        f"CASE {_MATCH} {branches} "
        f"WHEN {classifier.browser_index} THEN 'browser_like' "
        "ELSE 'unknown' END"
    )
    return sql, [classifier.spec]


def rule_id_case_sql(classifier: Classifier) -> tuple[str, list[object]]:
    """CASE expression mapping each row to its named rule id (or NULL)."""
    branches = " ".join(
        f"WHEN {i} THEN '{rule_id}'" for i, rule_id in enumerate(classifier.rule_ids)
    )
    return f"CASE {_MATCH} {branches} ELSE NULL END", [classifier.spec]


def summary_counts(
    conn: sqlite3.Connection, filt: AnalyticsFilter, classifier: Classifier | None = None
) -> dict[str, int]:
    where, params = _where(filt, classifier)
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


def status_distribution(
    conn: sqlite3.Connection, filt: AnalyticsFilter, classifier: Classifier | None = None
) -> list[dict[str, int]]:
    where, params = _where(filt, classifier)
    rows = conn.execute(
        f"SELECT status, COUNT(*) FROM requests WHERE {where} GROUP BY status ORDER BY status",
        params,
    ).fetchall()
    return [{"status": status, "requests": count} for status, count in rows]


_TOP_PATH_ORDER: dict[str, str] = {
    "requests_desc": "requests DESC, path ASC, method ASC",
    "errors_desc": "errors DESC, requests DESC, path ASC, method ASC",
    "bytes_desc": "bytes_total DESC, requests DESC, path ASC, method ASC",
}


def top_paths(
    conn: sqlite3.Connection, query: TopPathsQuery, classifier: Classifier | None = None
) -> tuple[list[dict[str, object]], int]:
    where, params = _where(query.filt, classifier)
    order = _TOP_PATH_ORDER[query.sort]
    total = conn.execute(
        f"SELECT COUNT(DISTINCT path || '\x1f' || method) FROM requests WHERE {where}", params
    ).fetchone()[0]
    rows = conn.execute(
        "SELECT path, method, COUNT(*) AS requests,"
        " COUNT(CASE WHEN status >= 400 THEN 1 END) AS errors,"
        " COALESCE(SUM(bytes), 0) AS bytes_total"
        f" FROM requests WHERE {where} GROUP BY path, method ORDER BY {order} LIMIT ? OFFSET ?",
        [*params, query.filt.limit, query.filt.offset],
    ).fetchall()
    return (
        [
            {
                "path": path,
                "method": method,
                "requests": count,
                "errors": errors,
                "bytes_total": nbytes,
            }
            for path, method, count, errors, nbytes in rows
        ],
        total,
    )


def top_referrers(
    conn: sqlite3.Connection, query: TopReferrersQuery, classifier: Classifier | None = None
) -> tuple[list[dict[str, object]], int]:
    where, params = _where(query.filt, classifier)
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
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    bucket: BucketSize,
    classifier: Classifier | None = None,
) -> list[dict[str, object]]:
    where, params = _where(filt, classifier)
    width = 13 if bucket == "hour" else 10
    rows = conn.execute(
        f"SELECT substr(ts_utc, 1, {width}), COUNT(*),"
        " COUNT(CASE WHEN status >= 400 THEN 1 END),"
        " COALESCE(SUM(bytes), 0)"
        f" FROM requests WHERE {where} GROUP BY substr(ts_utc, 1, {width})",
        params,
    ).fetchall()
    by_key = {
        key: {"requests": count, "errors": errors, "bytes_total": nbytes}
        for key, count, errors, nbytes in rows
    }
    result = []
    for edge in _bucket_edges(filt, bucket):
        key = edge.strftime("%Y-%m-%dT%H") if bucket == "hour" else edge.strftime("%Y-%m-%d")
        counts = by_key.get(key, {"requests": 0, "errors": 0, "bytes_total": 0})
        result.append({"bucket": edge.isoformat(), **counts})
    return result


def count_measured_durations(
    conn: sqlite3.Connection, filt: AnalyticsFilter, classifier: Classifier | None = None
) -> int:
    """Rows with a measured duration; Combined-only data yields zero."""
    where, params = _where(filt, classifier)
    row = conn.execute(f"SELECT COUNT(duration_ms) FROM requests WHERE {where}", params).fetchone()
    return int(row[0])


def error_groups(
    conn: sqlite3.Connection, filt: AnalyticsFilter, classifier: Classifier | None = None
) -> tuple[list[dict[str, object]], int]:
    """Groups of error responses by path and status, with referrer breadth."""
    where, params = _where(filt, classifier)
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
    where, params = _where(filt, None)
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
    conn: sqlite3.Connection, filt: AnalyticsFilter, classifier: Classifier | None = None
) -> tuple[list[tuple[str, int, int]], bool]:
    where, params = _where(filt, classifier)
    rows = conn.execute(
        "SELECT path, COUNT(*) AS requests, COUNT(CASE WHEN status >= 400 THEN 1 END) AS errors"
        f" FROM requests WHERE {where} GROUP BY path ORDER BY requests DESC LIMIT ?",
        [*params, MAX_DISTINCT_SCAN + 1],
    ).fetchall()
    truncated = len(rows) > MAX_DISTINCT_SCAN
    return [(path, count, errors) for path, count, errors in rows[:MAX_DISTINCT_SCAN]], truncated


def repeated_client_errors(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    *,
    min_errors: int,
    limit: int = 100,
    classifier: Classifier | None = None,
) -> list[dict[str, object]]:
    where, params = _where(filt, classifier)
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
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    *,
    client_pseudonym: str,
    limit: int = 5,
    classifier: Classifier | None = None,
) -> list[dict[str, object]]:
    where, params = _where(filt, classifier)
    rows = conn.execute(
        "SELECT path, status, COUNT(*) AS hits FROM requests"
        f" WHERE {where} AND client_pseudonym = ?"
        " GROUP BY path, status ORDER BY hits DESC, path ASC, status ASC LIMIT ?",
        [*params, client_pseudonym, limit],
    ).fetchall()
    return [{"path": path, "status": status, "hits": hits} for path, status, hits in rows]


def coverage(
    conn: sqlite3.Connection, filt: AnalyticsFilter, classifier: Classifier | None = None
) -> dict[str, object]:
    """Observed range and unique events for the site/source/window scope.

    Unique stored events never double-count replays: replayed import
    attempts add no rows, so ``unique_events`` is the deduplicated total
    while ``import_lines_total`` records every attempt. Proven source
    coverage is never claimed from logs alone (see limitations).
    """
    # NOTE: coverage applies the same validated filters as every consumer
    # query, so filtered views stay internally consistent.
    where, params = _where(filt, classifier)
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


def traffic_breakdown(
    conn: sqlite3.Connection, filt: AnalyticsFilter, classifier: Classifier
) -> list[dict[str, object]]:
    """Exact per-row traffic totals: every row has exactly one bucket.

    GROUP BY over the ordered match expression counts every filtered row
    in SQL, so bucket totals sum exactly with no distinct-UA sampling.
    """
    where, params = _where(filt, classifier)
    case, case_params = traffic_case_sql(classifier)
    rows = conn.execute(
        "SELECT"
        f" {case} AS traffic, COUNT(*),"
        " COUNT(CASE WHEN status BETWEEN 400 AND 499 THEN 1 END),"
        " COUNT(CASE WHEN status BETWEEN 500 AND 599 THEN 1 END),"
        " COALESCE(SUM(bytes), 0)"
        f" FROM requests WHERE {where} GROUP BY {case}",
        [*case_params, *params, *case_params],
    ).fetchall()
    return [
        {
            "traffic": traffic,
            "requests": count,
            "errors_4xx": e4,
            "errors_5xx": e5,
            "bytes_total": nbytes,
        }
        for traffic, count, e4, e5, nbytes in rows
    ]


def bot_index_rows(
    conn: sqlite3.Connection, filt: AnalyticsFilter, classifier: Classifier
) -> list[dict[str, object]]:
    """Exact per-rule aggregates keyed by ordered rule index.

    Only matched rule indexes appear; browser-like and unknown rows are
    excluded here (they belong to the traffic breakdown, not the bot
    table). All counts are exact GROUP BY results over filtered rows.
    """
    where, params = _where(filt, classifier)
    top = len(classifier.rule_ids) - 1
    rows = conn.execute(
        f"SELECT {_MATCH} AS idx, COUNT(*),"
        " COUNT(CASE WHEN status BETWEEN 400 AND 499 THEN 1 END),"
        " COUNT(CASE WHEN status BETWEEN 500 AND 599 THEN 1 END),"
        " COALESCE(SUM(bytes), 0),"
        " COUNT(DISTINCT user_agent), COUNT(DISTINCT path)"
        f" FROM requests WHERE {where} AND {_MATCH} BETWEEN 0 AND {top}"
        " GROUP BY idx",
        [classifier.spec, *params, classifier.spec],
    ).fetchall()
    return [
        {
            "index": idx,
            "requests": count,
            "errors_4xx": e4,
            "errors_5xx": e5,
            "bytes_total": nbytes,
            "distinct_agents": agents,
            "distinct_paths": paths,
        }
        for idx, count, e4, e5, nbytes, agents, paths in rows
    ]


def bot_rule_stats(
    conn: sqlite3.Connection, filt: AnalyticsFilter, classifier: Classifier, index: int
) -> dict[str, int]:
    """Exact totals for one ordered rule index under the active filters."""
    where, params = _where(filt, classifier)
    row = conn.execute(
        "SELECT COUNT(*),"
        " COUNT(CASE WHEN status BETWEEN 400 AND 499 THEN 1 END),"
        " COUNT(CASE WHEN status BETWEEN 500 AND 599 THEN 1 END),"
        " COALESCE(SUM(bytes), 0), COUNT(DISTINCT user_agent)"
        f" FROM requests WHERE {where} AND {_MATCH} = ?",
        [*params, classifier.spec, index],
    ).fetchone()
    return {
        "requests": row[0],
        "errors_4xx": row[1],
        "errors_5xx": row[2],
        "bytes_total": row[3],
        "distinct_agents": row[4],
    }


def bot_top_paths(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    classifier: Classifier,
    index: int,
    *,
    status: int | None = None,
    limit: int = 10,
) -> list[dict[str, object]]:
    """Exact top path/status rows for one rule index (no agent-list cap)."""
    where, params = _where(filt, classifier)
    scoped = f"{where} AND {_MATCH} = ?"
    args: list[object] = [*params, classifier.spec, index]
    if status is not None:
        scoped += " AND status = ?"
        args.append(status)
    rows = conn.execute(
        "SELECT path, status, COUNT(*) AS requests"
        f" FROM requests WHERE {scoped} GROUP BY path, status"
        " ORDER BY requests DESC, path ASC, status ASC LIMIT ?",
        [*args, limit],
    ).fetchall()
    return [{"path": path, "status": code, "requests": count} for path, code, count in rows]


def bot_sample_agents(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    classifier: Classifier,
    index: int,
    *,
    limit: int = 10,
) -> list[dict[str, object]]:
    """Bounded UA sample for one rule index; UAs truncated, never raw rows."""
    where, params = _where(filt, classifier)
    rows = conn.execute(
        "SELECT substr(user_agent, 1, 200) AS agent, COUNT(*) AS requests"
        f" FROM requests WHERE {where} AND {_MATCH} = ? AND user_agent IS NOT NULL"
        " GROUP BY user_agent ORDER BY requests DESC, user_agent ASC LIMIT ?",
        [*params, classifier.spec, index, limit],
    ).fetchall()
    return [{"user_agent": agent, "requests": count} for agent, count in rows]


def scoped_path_count(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    classifier: Classifier | None,
    *,
    path: str | None = None,
    path_prefix: str | None = None,
) -> int:
    """Exact request count for one stored path or prefix under filters."""
    where, params = _where(filt, classifier)
    if path is not None:
        return int(
            conn.execute(
                f"SELECT COUNT(*) FROM requests WHERE {where} AND path = ?", [*params, path]
            ).fetchone()[0]
        )
    assert path_prefix is not None
    return int(
        conn.execute(
            f"SELECT COUNT(*) FROM requests WHERE {where} AND path LIKE ? ESCAPE '\\'",
            [*params, _like_escape(path_prefix) + "%"],
        ).fetchone()[0]
    )


def request_rows(
    conn: sqlite3.Connection, query: ExplorerQuery, classifier: Classifier
) -> tuple[list[dict[str, object]], int]:
    """Sanitized paginated request rows: newest/oldest with stable id ties.

    Exposes only minimized fields: no raw lines, original IPs, query
    values or full user agents (truncated to 200 chars).
    """
    filt = query.filt
    where, params = _where(filt, classifier)
    traffic_case, traffic_params = traffic_case_sql(classifier)
    rule_case, rule_params = rule_id_case_sql(classifier)
    total = conn.execute(f"SELECT COUNT(*) FROM requests WHERE {where}", params).fetchone()[0]
    order = "ts_utc DESC, id DESC" if query.sort == "newest" else "ts_utc ASC, id ASC"
    rows = conn.execute(
        "SELECT ts_utc, method, path, status, bytes, referer_host,"
        " substr(user_agent, 1, 200), client_pseudonym,"
        f" {traffic_case} AS traffic, {rule_case} AS rule_id"
        f" FROM requests WHERE {where} ORDER BY {order} LIMIT ? OFFSET ?",
        [*traffic_params, *rule_params, *params, filt.limit, filt.offset],
    ).fetchall()
    return (
        [
            {
                "ts_utc": ts,
                "method": method,
                "path": path,
                "status": status,
                "bytes": nbytes,
                "referer_host": host,
                "user_agent": agent,
                "client_pseudonym": pseudonym,
                "traffic": traffic,
                "rule_id": rule_id,
            }
            for ts, method, path, status, nbytes, host, agent, pseudonym, traffic, rule_id in rows
        ],
        total,
    )


#: Path-extension mapping for resource kinds (server-built, documented
#: heuristic over the stored query-stripped path).
_RESOURCE_KIND_CASE = """CASE
        WHEN lower(path) LIKE '%.css' THEN 'style'
        WHEN lower(path) LIKE '%.js' THEN 'script'
        WHEN lower(path) LIKE '%.png' OR lower(path) LIKE '%.jpg'
          OR lower(path) LIKE '%.jpeg' OR lower(path) LIKE '%.gif'
          OR lower(path) LIKE '%.webp' OR lower(path) LIKE '%.svg'
          OR lower(path) LIKE '%.ico' OR lower(path) LIKE '%.avif' THEN 'image'
        WHEN lower(path) LIKE '%.woff2' OR lower(path) LIKE '%.woff'
          OR lower(path) LIKE '%.ttf' OR lower(path) LIKE '%.eot' THEN 'font'
        WHEN lower(path) LIKE '%.mp4' OR lower(path) LIKE '%.webm'
          OR lower(path) LIKE '%.mp3' THEN 'media'
        WHEN lower(path) LIKE '%.pdf' OR lower(path) LIKE '%.doc'
          OR lower(path) LIKE '%.zip' THEN 'document'
        WHEN lower(path) LIKE '%.json' OR lower(path) LIKE '%.xml'
          OR lower(path) LIKE '%.rss' THEN 'data'
        WHEN path LIKE '%/' OR path NOT LIKE '%.%' THEN 'page'
        ELSE 'other' END"""


def resource_breakdown(
    conn: sqlite3.Connection, filt: AnalyticsFilter, classifier: Classifier | None = None
) -> list[dict[str, object]]:
    """Requests/errors/bytes grouped by path-based resource kind."""
    where, params = _where(filt, classifier)
    rows = conn.execute(
        f"SELECT {_RESOURCE_KIND_CASE} AS kind, COUNT(*),"
        " COUNT(CASE WHEN status >= 400 THEN 1 END), COALESCE(SUM(bytes), 0)"
        f" FROM requests WHERE {where} GROUP BY kind ORDER BY COUNT(*) DESC, kind ASC",
        params,
    ).fetchall()
    return [
        {"kind": kind, "requests": count, "errors": errors, "bytes_total": nbytes}
        for kind, count, errors, nbytes in rows
    ]


#: Claimed browser family/OS from UA heuristics, applied only to
#: browser-like rows. Families are claim labels, never verified identities.
_BROWSER_FAMILY_CASE = """CASE
        WHEN lower(user_agent) LIKE '%chrome%' OR lower(user_agent) LIKE '%crios%' THEN 'Chrome'
        WHEN lower(user_agent) LIKE '%firefox%' OR lower(user_agent) LIKE '%fxios%' THEN 'Firefox'
        WHEN lower(user_agent) LIKE '%edg/%' OR lower(user_agent) LIKE '%edgios%' THEN 'Edge'
        WHEN lower(user_agent) LIKE '%opr/%' OR lower(user_agent) LIKE '%opera%' THEN 'Opera'
        WHEN lower(user_agent) LIKE '%safari%' THEN 'Safari'
        ELSE 'Other' END"""
_BROWSER_OS_CASE = """CASE
        WHEN lower(user_agent) LIKE '%windows%' THEN 'Windows'
        WHEN lower(user_agent) LIKE '%android%' THEN 'Android'
        WHEN lower(user_agent) LIKE '%iphone%' OR lower(user_agent) LIKE '%ipad%' THEN 'iOS'
        WHEN lower(user_agent) LIKE '%macintosh%' OR lower(user_agent) LIKE '%mac os%' THEN 'macOS'
        WHEN lower(user_agent) LIKE '%linux%' THEN 'Linux'
        ELSE 'Other' END"""


def browser_breakdown(
    conn: sqlite3.Connection, filt: AnalyticsFilter, classifier: Classifier
) -> dict[str, list[dict[str, object]]]:
    """Claimed browser family and OS shares over browser-like rows only."""
    where, params = _where(filt, classifier)
    scoped = f"{where} AND {_MATCH} = ?"
    args: list[object] = [*params, classifier.spec, classifier.browser_index]
    families = conn.execute(
        f"SELECT {_BROWSER_FAMILY_CASE} AS family, COUNT(*)"
        f" FROM requests WHERE {scoped} GROUP BY family ORDER BY COUNT(*) DESC, family ASC",
        args,
    ).fetchall()
    systems = conn.execute(
        f"SELECT {_BROWSER_OS_CASE} AS os, COUNT(*)"
        f" FROM requests WHERE {scoped} GROUP BY os ORDER BY COUNT(*) DESC, os ASC",
        args,
    ).fetchall()
    return {
        "families": [{"family": name, "requests": count} for name, count in families],
        "systems": [{"os": name, "requests": count} for name, count in systems],
    }


def heatmap_utc_hours(
    conn: sqlite3.Connection, filt: AnalyticsFilter, classifier: Classifier | None = None
) -> list[dict[str, object]]:
    """UTC-hour aggregates for the heatmap; timezone conversion stays in Python.

    Aggregation happens in SQL per UTC hour. Callers convert the bounded
    bucket list (at most one row per window hour) to the display timezone
    with zoneinfo, so multi-hour windows and DST transitions are handled
    without any per-row Python datetime callback.
    """
    where, params = _where(filt, classifier)
    rows = conn.execute(
        "SELECT substr(ts_utc, 1, 13) AS hour, COUNT(*)"
        f" FROM requests WHERE {where} GROUP BY hour ORDER BY hour",
        params,
    ).fetchall()
    return [{"hour": hour, "requests": count} for hour, count in rows]


def client_top(
    conn: sqlite3.Connection, filt: AnalyticsFilter, classifier: Classifier | None = None
) -> tuple[list[dict[str, object]], int]:
    """Top pseudonymized clients: requests, errors, path breadth, span.

    Client addresses never leave storage: only the HMAC pseudonym plus
    aggregates are exposed, bounded by the shared limit/offset.
    """
    where, params = _where(filt, classifier)
    total = conn.execute(
        f"SELECT COUNT(DISTINCT client_pseudonym) FROM requests WHERE {where}", params
    ).fetchone()[0]
    rows = conn.execute(
        "SELECT client_pseudonym, COUNT(*) AS requests,"
        " COUNT(CASE WHEN status >= 400 THEN 1 END) AS errors,"
        " COUNT(DISTINCT path) AS paths, MIN(ts_utc), MAX(ts_utc)"
        f" FROM requests WHERE {where} GROUP BY client_pseudonym"
        " ORDER BY requests DESC, client_pseudonym ASC LIMIT ? OFFSET ?",
        [*params, filt.limit, filt.offset],
    ).fetchall()
    return (
        [
            {
                "client_pseudonym": ident,
                "requests": count,
                "errors": errors,
                "paths": paths,
                "first_seen": first,
                "last_seen": last,
            }
            for ident, count, errors, paths, first, last in rows
        ],
        total,
    )
