"""Parameterized analytics repositories (T4).

Every query is a fixed SQL string with bound parameters; sort orders
come from allowlisted contract literals, never from input. Large
cardinality scans (distinct agents/paths) are bounded with explicit
truncation flags so reads never load the whole database into memory.
"""

import math
import sqlite3
from datetime import datetime, timedelta
from typing import Literal

from app.analytics.classification import (
    Classifier,
    resolve_selector_indexes,
    traffic_indexes,
)
from app.analytics.contracts import (
    AnalyticsFilter,
    BucketSize,
    ExplorerQuery,
    SlowEndpointsQuery,
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
    if filt.path_exact is not None:
        clauses.append("path = ?")
        params.append(filt.path_exact)
    if filt.referer_host is not None:
        clauses.append("referer_host = ?")
        params.append(filt.referer_host)
    if filt.server_host is not None:
        clauses.append("server_host = ?")
        params.append(filt.server_host)
    if filt.http_version is not None:
        clauses.append("http_version = ?")
        params.append(filt.http_version)
    if filt.mime_type is not None:
        clauses.append("mime_type = ?")
        params.append(filt.mime_type)
    if filt.cache_status is not None:
        clauses.append("cache_status = ?")
        params.append(filt.cache_status)
    if filt.tls_protocol is not None:
        clauses.append("tls_protocol = ?")
        params.append(filt.tls_protocol)
    if filt.timing_available is True:
        clauses.append("request_time_ms IS NOT NULL")
    elif filt.timing_available is False:
        clauses.append("request_time_ms IS NULL")
    if filt.upstream_available is True:
        clauses.append("upstream_time_ms IS NOT NULL")
    elif filt.upstream_available is False:
        clauses.append("upstream_time_ms IS NULL")
    if filt.timing_min_ms is not None:
        clauses.append("request_time_ms >= ?")
        params.append(filt.timing_min_ms)
    if filt.timing_max_ms is not None:
        clauses.append("request_time_ms <= ?")
        params.append(filt.timing_max_ms)
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


def _option_scope(filt: AnalyticsFilter) -> AnalyticsFilter:
    """Dropdown scope: window/site/source plus non-method/status matchers.

    Method/status/status-class narrowing is lifted so the dropdown can
    always offer every value in the current scope (the current selection
    is retained separately); everything else still narrows honestly.
    """
    return filt.model_copy(
        update={"method": None, "status": None, "status_class": None, "limit": 1, "offset": 0}
    )


def distinct_methods(
    conn: sqlite3.Connection, filt: AnalyticsFilter, classifier: Classifier | None = None
) -> list[str]:
    """Observed methods in scope; parameterized, bounded, ASCII-safe."""
    scope = _option_scope(filt)
    where, params = _where(scope, classifier)
    rows = conn.execute(
        "SELECT DISTINCT method FROM requests"
        f" WHERE {where} AND method IS NOT NULL"
        " ORDER BY method LIMIT 200",
        params,
    ).fetchall()
    return [row[0] for row in rows if isinstance(row[0], str) and row[0].isascii()]


def distinct_statuses(
    conn: sqlite3.Connection, filt: AnalyticsFilter, classifier: Classifier | None = None
) -> list[int]:
    """Observed statuses in scope; parameterized, bounded, contract-range."""
    scope = _option_scope(filt)
    where, params = _where(scope, classifier)
    rows = conn.execute(
        "SELECT DISTINCT status FROM requests"
        f" WHERE {where} AND status BETWEEN 100 AND 599"
        " ORDER BY status LIMIT 500",
        params,
    ).fetchall()
    return [row[0] for row in rows if isinstance(row[0], int)]


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
    """Rows with an explicitly stored legacy duration (legacy core column).

    Current parsers leave ``duration_ms`` NULL (measured timing lives in
    ``request_time_ms``); only pre-existing rows carrying an explicit
    legacy value count here. Shared availability always follows
    :func:`count_measured_request_timing`.
    """
    where, params = _where(filt, classifier)
    row = conn.execute(f"SELECT COUNT(duration_ms) FROM requests WHERE {where}", params).fetchone()
    return int(row[0])


def count_measured_request_timing(
    conn: sqlite3.Connection, filt: AnalyticsFilter, classifier: Classifier | None = None
) -> int:
    """Rows with a measured request latency; zero stays valid, missing excluded."""
    where, params = _where(filt, classifier)
    row = conn.execute(
        f"SELECT COUNT(request_time_ms) FROM requests WHERE {where}", params
    ).fetchone()
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


#: Bounds for :func:`sample_paths_for_clients`: one batched query replaces
#: up to 100 per-client scans with at most 100 * per-client-limit rows.
MAX_SAMPLE_CLIENTS = 100
SAMPLE_PATHS_PER_CLIENT = 5


def sample_paths_for_clients(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    client_pseudonyms: list[str],
    *,
    limit: int = SAMPLE_PATHS_PER_CLIENT,
    classifier: Classifier | None = None,
) -> dict[str, list[dict[str, object]]]:
    """Batched top-``limit`` (path, status, hits) rows per client pseudonym.

    One parameterized query over the full scoped filter (every base
    selector applies BEFORE grouping, exactly as in
    :func:`sample_paths_for_client`): per-client groups are ranked with
    ``ROW_NUMBER()`` partitioned by client, ordered by hits DESC, path
    ASC, status ASC — the same order as the single-client query. The
    result maps each requested pseudonym to its sample list (missing
    clients map to ``[]``). All-status sampling semantics are preserved:
    no status predicate is added here. An empty request list returns
    without touching the database.
    """
    wanted = [p for p in dict.fromkeys(client_pseudonyms) if p][:MAX_SAMPLE_CLIENTS]
    if not wanted or limit < 1:
        return {p: [] for p in dict.fromkeys(client_pseudonyms) if p}
    where, params = _where(filt, classifier)
    placeholders = ", ".join("?" for _ in wanted)
    rows = conn.execute(
        "SELECT client_pseudonym, path, status, hits FROM ("
        " SELECT client_pseudonym, path, status, COUNT(*) AS hits,"
        " ROW_NUMBER() OVER (PARTITION BY client_pseudonym"
        " ORDER BY COUNT(*) DESC, path ASC, status ASC) AS rn"
        f" FROM requests WHERE {where} AND client_pseudonym IN ({placeholders})"
        " GROUP BY client_pseudonym, path, status"
        ") WHERE rn <= ? ORDER BY client_pseudonym ASC, rn ASC",
        [*params, *wanted, limit],
    ).fetchall()
    grouped: dict[str, list[dict[str, object]]] = {p: [] for p in wanted}
    for client, path, status, hits in rows:
        if len(grouped[client]) < limit:
            grouped[client].append({"path": path, "status": status, "hits": hits})
    for requested in dict.fromkeys(client_pseudonyms):
        grouped.setdefault(requested, [])
    return grouped


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


#: Allowlisted explorer orders: each contract sort literal maps to ONE
#: fixed ORDER BY fragment. Filters/site/source/time/matchers apply in
#: WHERE before sorting; limits/offsets apply after. No client input is
#: ever interpolated into SQL. Ties break by timestamp then id so paging
#: is stable; byte sorts compare numeric values with NULLs last (never
#: formatted strings).
_EXPLORER_ORDER: dict[str, str] = {
    "newest": "ts_utc DESC, id DESC",
    "oldest": "ts_utc ASC, id ASC",
    "time_desc": "ts_utc DESC, id DESC",
    "time_asc": "ts_utc ASC, id ASC",
    "client_asc": "client_pseudonym ASC NULLS LAST, ts_utc ASC, id ASC",
    "client_desc": "client_pseudonym DESC NULLS LAST, ts_utc ASC, id ASC",
    "method_asc": "method ASC NULLS LAST, ts_utc ASC, id ASC",
    "method_desc": "method DESC NULLS LAST, ts_utc ASC, id ASC",
    "path_asc": "path ASC NULLS LAST, ts_utc ASC, id ASC",
    "path_desc": "path DESC NULLS LAST, ts_utc ASC, id ASC",
    "status_asc": "status ASC NULLS LAST, ts_utc ASC, id ASC",
    "status_desc": "status DESC NULLS LAST, ts_utc ASC, id ASC",
    "bytes_asc": "bytes ASC NULLS LAST, ts_utc ASC, id ASC",
    "bytes_desc": "bytes DESC NULLS LAST, ts_utc ASC, id ASC",
}

#: Scalar for the conservative conflicting-identity signal: fixed
#: hand-authored token set, no parameters, shared with the Python
#: helpers in :mod:`app.analytics.conflict`.
_CONFLICT = "conflicting_bot(user_agent)"


def request_rows(
    conn: sqlite3.Connection, query: ExplorerQuery, classifier: Classifier
) -> tuple[list[dict[str, object]], int]:
    """Sanitized paginated request rows in one allowlisted server sort.

    Exposes only minimized fields: no raw lines, original IPs, query
    values or full user agents (truncated to 200 chars with an explicit
    truncation flag). The conflict flag is a derived boolean computed
    from the full stored sanitized agent — the full value itself never
    leaves the database.
    """
    filt = query.filt
    where, params = _where(filt, classifier)
    traffic_case, traffic_params = traffic_case_sql(classifier)
    rule_case, rule_params = rule_id_case_sql(classifier)
    total = conn.execute(f"SELECT COUNT(*) FROM requests WHERE {where}", params).fetchone()[0]
    try:
        order = _EXPLORER_ORDER[query.sort]
    except KeyError as exc:
        raise ValueError(f"unknown explorer sort: {query.sort!r}") from exc
    rows = conn.execute(
        "SELECT ts_utc, method, path, status, bytes, referer_host,"
        " substr(user_agent, 1, 200),"
        " CASE WHEN user_agent IS NOT NULL AND LENGTH(user_agent) > 200 THEN 1 ELSE 0 END,"
        " client_pseudonym,"
        f" {traffic_case} AS traffic, {rule_case} AS rule_id,"
        f" {_CONFLICT} AS conflict"
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
                "ua_truncated": bool(truncated),
                "client_pseudonym": pseudonym,
                "traffic": traffic,
                "rule_id": rule_id,
                "conflict": bool(conflict),
            }
            for (
                ts,
                method,
                path,
                status,
                nbytes,
                host,
                agent,
                truncated,
                pseudonym,
                traffic,
                rule_id,
                conflict,
            ) in rows
        ],
        total,
    )


def conflict_counts(
    conn: sqlite3.Connection, filt: AnalyticsFilter, classifier: Classifier | None = None
) -> dict[str, int]:
    """Exact conflicting-identity totals over the ENTIRE selected scope.

    A single all-row SQL aggregation (no distinct-UA scan cap, no Python
    row loading, no N+1): one row per request counts toward ``requests``
    while ``distinct_agents`` counts stored sanitized agents exactly,
    however many there are.
    """
    where, params = _where(filt, classifier)
    row = conn.execute(
        f"SELECT COUNT(*), COUNT(DISTINCT user_agent) FROM requests WHERE {where} AND {_CONFLICT}",
        params,
    ).fetchone()
    return {"requests": int(row[0]), "distinct_agents": int(row[1])}


def conflict_sample_agents(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    classifier: Classifier | None = None,
    *,
    limit: int = 10,
) -> tuple[list[dict[str, object]], int]:
    """Bounded conflicting-UA sample (200-char truncation) + exact total.

    Returns the top ``limit`` conflicting agents by request count plus the
    exact distinct-agent total so callers label samples explicitly
    (``shown``/``total``) instead of silently narrowing them.
    """
    where, params = _where(filt, classifier)
    total = conn.execute(
        f"SELECT COUNT(DISTINCT user_agent) FROM requests WHERE {where} AND {_CONFLICT}",
        params,
    ).fetchone()[0]
    rows = conn.execute(
        "SELECT substr(user_agent, 1, 200) AS agent, COUNT(*) AS requests"
        f" FROM requests WHERE {where} AND {_CONFLICT} AND user_agent IS NOT NULL"
        " GROUP BY user_agent ORDER BY requests DESC, user_agent ASC LIMIT ?",
        [*params, limit],
    ).fetchall()
    return (
        [{"user_agent": agent, "requests": count} for agent, count in rows],
        int(total),
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
#: Edge and Opera markers precede the generic Chrome marker: both vendors
#: ship a Chromium UA that also contains ``Chrome`` (and ``Safari``), so
#: testing Chrome first would mislabel every Edge/Opera row as Chrome.
_BROWSER_FAMILY_CASE = """CASE
        WHEN lower(user_agent) LIKE '%edg/%' OR lower(user_agent) LIKE '%edgios%' THEN 'Edge'
        WHEN lower(user_agent) LIKE '%opr/%' OR lower(user_agent) LIKE '%opera%' THEN 'Opera'
        WHEN lower(user_agent) LIKE '%chrome%' OR lower(user_agent) LIKE '%crios%' THEN 'Chrome'
        WHEN lower(user_agent) LIKE '%firefox%' OR lower(user_agent) LIKE '%fxios%' THEN 'Firefox'
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


#: T2a measured-timing columns. Internal allowlist only: the column is
#: always one of these literals, never caller input.
_TIMING_COLUMNS = ("request_time_ms", "upstream_time_ms")


def _ordered_timing_value(
    conn: sqlite3.Connection,
    where: str,
    params: list[object],
    column: str,
    offset: int,
) -> float | None:
    """One order statistic over the entire filtered scope (no sampling).

    ``column`` is an internal allowlist literal; ``offset``/``params``
    are bound. Exactly one row is read per call, so percentile
    computation never materializes millions of durations.
    """
    assert column in _TIMING_COLUMNS
    row = conn.execute(
        f"SELECT {column} FROM requests WHERE {where} AND {column} IS NOT NULL"
        f" ORDER BY {column} ASC LIMIT 1 OFFSET ?",
        [*params, offset],
    ).fetchone()
    return None if row is None else float(row[0])


def timing_quantile(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    classifier: Classifier | None,
    column: str,
    measured: int,
    quantum: float,
) -> float | None:
    """Deterministic linear-interpolation quantile over measured values.

    Sorted ascending ``v[0..n-1]`` (NULLs excluded: missing is never
    zero), rank ``r = q * (n - 1)``, ``v[lo] + (v[hi] - v[lo]) * (r -
    lo)``. The ``(hi - lo)`` form keeps the interpolation numerically
    stable when individually finite large timings sit near the float
    ceiling; a non-finite result maps to ``None`` (callers add an
    overflow warning) instead of leaking ``Inf``/``NaN`` into JSON.
    At most two single-row order-statistic reads per call.
    """
    assert column in _TIMING_COLUMNS
    if measured <= 0:
        return None
    import math as _math

    rank = quantum * (measured - 1)
    low = _math.floor(rank)
    high = _math.ceil(rank)
    where, params = _where(filt, classifier)
    first = _ordered_timing_value(conn, where, params, column, low)
    if first is None:
        return None
    if high == low:
        return first if _math.isfinite(first) else None
    second = _ordered_timing_value(conn, where, params, column, high)
    if second is None:
        return None
    value = first + (second - first) * (rank - low)
    return value if _math.isfinite(value) else None


def timing_stats(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    classifier: Classifier | None,
    column: str,
) -> dict[str, object]:
    """Exact measured-timing summary for one timing column (milliseconds).

    ``request_time_ms`` is the measured request latency; zero is a
    valid observation and missing (``NULL``) never contributes zero.
    ``upstream_time_ms`` is the aggregated upstream total; a partial
    multi-leg timing (``"0.100, -"``) stores ``NULL`` with no component
    count, so it lands in ``missing`` here -- never as zero. The
    average comes from SQL ``AVG`` with a finiteness guard: individually
    finite large timings that overflow a naive ``SUM`` yield
    ``average_ms: None`` plus an overflow warning, never ``Inf``/``NaN``.
    Percentiles use :func:`timing_quantile` over the entire filtered
    scope (exact order statistics, no sampling).
    """
    assert column in _TIMING_COLUMNS
    where, params = _where(filt, classifier)
    row = conn.execute(
        f"SELECT COUNT({column}), COUNT(*) - COUNT({column}),"
        f" MIN({column}), MAX({column}), AVG({column})"
        f" FROM requests WHERE {where}",
        params,
    ).fetchone()
    measured, missing, minimum, maximum, average = (
        int(row[0]),
        int(row[1]),
        row[2],
        row[3],
        row[4],
    )
    warnings: list[str] = []
    average_ms: float | None = None
    if average is not None:
        candidate = float(average)
        if math.isfinite(candidate):
            average_ms = candidate
        else:
            warnings.append(f"{column}_average_unavailable:overflow")
    quantiles: dict[str, float | None] = {}
    for name, quantum in (("p50", 0.50), ("p95", 0.95), ("p99", 0.99)):
        value = timing_quantile(conn, filt, classifier, column, measured, quantum)
        if value is None and measured > 0:
            warnings.append(f"{column}_{name}_unavailable:overflow")
        quantiles[name] = value
    return {
        "measured": measured,
        "missing": missing,
        "total": measured + missing,
        "coverage": (measured / (measured + missing)) if (measured + missing) else None,
        "min_ms": float(minimum) if minimum is not None else None,
        "max_ms": float(maximum) if maximum is not None else None,
        "average_ms": average_ms,
        "median_ms": quantiles["p50"],
        "p50_ms": quantiles["p50"],
        "p95_ms": quantiles["p95"],
        "p99_ms": quantiles["p99"],
        "warnings": warnings,
    }


#: Default page size for single-column value distributions. Displayed
#: groups are bounded (no million-element in-memory lists); exact totals
#: and an ``Other`` remainder keep every row counted. Callers needing
#: the complete distribution page through ``limit``/``offset`` via the
#: per-function keyword arguments -- never via an unrelated widget's
#: paging fields.
DISTRIBUTION_TOP_N = 100


def _distribution(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    classifier: Classifier | None,
    column: str,
    *,
    limit: int = DISTRIBUTION_TOP_N,
    offset: int = 0,
) -> tuple[list[dict[str, object]], int, dict[str, object]]:
    """Bounded value distribution with exact totals and a separate Unknown.

    ``column`` is an internal allowlist literal. Totals are exact
    ``GROUP BY`` results over the entire filtered scope (never a capped
    distinct scan). Only known values are ranked (requests DESC, value
    ASC) and paged with explicit ``limit``/``offset``; rows with a
    missing value form their own ``"Unknown"`` bucket that is always
    reported separately and ordered last, count-correct even when the
    known-value page is truncated. ``other_requests`` aggregates every
    ranked-but-unshown row so ``sum(shown) + other == total``; ``shown``,
    ``total_values``, ``truncated`` and ``unknown_requests`` describe
    the page honestly.
    """
    if limit < 1 or offset < 0:
        raise ValueError("distribution paging needs limit >= 1 and offset >= 0")
    where, params = _where(filt, classifier)
    total = int(conn.execute(f"SELECT COUNT(*) FROM requests WHERE {where}", params).fetchone()[0])
    known_values = int(
        conn.execute(
            f"SELECT COUNT(*) FROM (SELECT 1 FROM requests WHERE {where}"
            f" AND {column} IS NOT NULL GROUP BY {column})",
            params,
        ).fetchone()[0]
    )
    unknown_requests = int(
        conn.execute(
            f"SELECT COUNT(*) FROM requests WHERE {where} AND {column} IS NULL", params
        ).fetchone()[0]
    )
    rows = conn.execute(
        f"SELECT {column}, COUNT(*) FROM requests WHERE {where} AND {column} IS NOT NULL"
        f" GROUP BY {column} ORDER BY COUNT(*) DESC, {column} ASC LIMIT ? OFFSET ?",
        [*params, limit, offset],
    ).fetchall()
    items = [{"value": str(value), "requests": int(count)} for value, count in rows]
    shown_known = sum(int(item["requests"]) for item in items)
    if unknown_requests:
        items.append({"value": "Unknown", "requests": unknown_requests})
    other_requests = total - shown_known - unknown_requests
    total_values = known_values + (1 if unknown_requests else 0)
    return (
        items,
        total,
        {
            "shown": len(items),
            "total_values": total_values,
            "known_values": known_values,
            "unknown_requests": unknown_requests,
            "other_requests": other_requests,
            "truncated": other_requests > 0 or offset + len(rows) < known_values,
            "limit": limit,
            "offset": offset,
        },
    )


def cache_distribution(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    classifier: Classifier | None = None,
    *,
    limit: int = DISTRIBUTION_TOP_N,
    offset: int = 0,
) -> dict[str, object]:
    """Bounded cache-status distribution with a documented HIT denominator.

    ``hit_ratio = HIT / cache_measured`` where ``cache_measured`` counts
    rows with a logged cache status (``Unknown``/absent rows are shown
    separately and never enter the denominator). ``HIT`` matches the
    stored uppercase token exactly, counted over the whole scope so the
    numerator stays correct even when ``HIT`` falls outside the displayed
    top page. ``not_modified_304`` counts normal HTTP cache validation
    (status 304) separately: 304s are protocol behavior, never
    automatically crawl waste.
    """
    items, total, page = _distribution(
        conn, filt, classifier, "cache_status", limit=limit, offset=offset
    )
    where, params = _where(filt, classifier)
    measured = int(
        conn.execute(
            f"SELECT COUNT(*) FROM requests WHERE {where} AND cache_status IS NOT NULL",
            params,
        ).fetchone()[0]
    )
    hits = int(
        conn.execute(
            f"SELECT COUNT(*) FROM requests WHERE {where} AND cache_status = 'HIT'",
            params,
        ).fetchone()[0]
    )
    validations = int(
        conn.execute(
            f"SELECT COUNT(*) FROM requests WHERE {where} AND status = 304", params
        ).fetchone()[0]
    )
    return {
        "items": items,
        "total": total,
        "shown": page["shown"],
        "total_values": page["total_values"],
        "truncated": page["truncated"],
        "other_requests": page["other_requests"],
        "unknown_requests": page["unknown_requests"],
        "distribution_limit": limit,
        "distribution_offset": offset,
        "cache_measured": measured,
        "cache_missing": total - measured,
        "hit_requests": hits,
        "hit_ratio": (float(hits) / measured) if measured else None,
        "hit_ratio_denominator": "requests with a logged cache_status (absent excluded)",
        "not_modified_304": validations,
        "not_modified_note": "status 304 is normal cache validation, not crawl waste",
    }


def mime_resource_breakdown(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    classifier: Classifier | None = None,
    *,
    limit: int = DISTRIBUTION_TOP_N,
    offset: int = 0,
) -> dict[str, object]:
    """Bounded measured-MIME by extension-inferred resource kind cross-tab.

    The measured ``mime_type`` is what the origin logged; the resource
    kind is the documented path-extension heuristic
    (:data:`_RESOURCE_KIND_CASE`). ``Unknown`` marks absent MIME data
    and sorts last (NULL-aware ordering, never a guessed MIME or a
    fabricated zero). Only the top ``limit`` pairs are returned with an
    exact whole-scope ``Other`` remainder, so high-cardinality MIME data
    never materializes million-element lists; page through
    ``limit``/``offset`` for the complete cross-tab.
    """
    if limit < 1 or offset < 0:
        raise ValueError("distribution paging needs limit >= 1 and offset >= 0")
    where, params = _where(filt, classifier)
    total = int(conn.execute(f"SELECT COUNT(*) FROM requests WHERE {where}", params).fetchone()[0])
    total_pairs = int(
        conn.execute(
            "SELECT COUNT(*) FROM (SELECT 1 FROM requests"
            f" WHERE {where} GROUP BY mime_type, {_RESOURCE_KIND_CASE})",
            params,
        ).fetchone()[0]
    )
    unknown_requests = int(
        conn.execute(
            f"SELECT COUNT(*) FROM requests WHERE {where} AND mime_type IS NULL", params
        ).fetchone()[0]
    )
    rows = conn.execute(
        "SELECT mime_type,"
        f" {_RESOURCE_KIND_CASE} AS kind, COUNT(*)"
        f" FROM requests WHERE {where} AND mime_type IS NOT NULL"
        " GROUP BY mime_type, kind"
        " ORDER BY COUNT(*) DESC, mime_type ASC, kind ASC"
        " LIMIT ? OFFSET ?",
        [*params, limit, offset],
    ).fetchall()
    items = [
        {"mime_type": mime, "resource_kind": kind, "requests": int(count)}
        for mime, kind, count in rows
    ]
    unknown_rows = conn.execute(
        "SELECT 'Unknown' AS mime,"
        f" {_RESOURCE_KIND_CASE} AS kind, COUNT(*)"
        f" FROM requests WHERE {where} AND mime_type IS NULL"
        " GROUP BY kind ORDER BY COUNT(*) DESC, kind ASC",
        params,
    ).fetchall()
    items.extend(
        {"mime_type": mime, "resource_kind": kind, "requests": int(count)}
        for mime, kind, count in unknown_rows
    )
    shown = sum(int(item["requests"]) for item in items)
    return {
        "items": items,
        "total": total,
        "shown": len(items),
        "total_values": total_pairs,
        "unknown_requests": unknown_requests,
        "unknown_pairs": len(unknown_rows),
        "other_requests": total - shown,
        "truncated": offset + len(rows) < total_pairs - len(unknown_rows),
        "limit": limit,
        "offset": offset,
    }


def version_distribution(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    classifier: Classifier | None = None,
    *,
    limit: int = DISTRIBUTION_TOP_N,
    offset: int = 0,
) -> tuple[list[dict[str, object]], int, dict[str, object]]:
    """HTTP version distribution with ``Unknown`` for missing versions."""
    return _distribution(conn, filt, classifier, "http_version", limit=limit, offset=offset)


def tls_distribution(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    classifier: Classifier | None = None,
    *,
    limit: int = DISTRIBUTION_TOP_N,
    offset: int = 0,
) -> tuple[list[dict[str, object]], int, dict[str, object]]:
    """TLS protocol distribution with ``Unknown`` for missing protocols."""
    return _distribution(conn, filt, classifier, "tls_protocol", limit=limit, offset=offset)


def host_distribution(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    classifier: Classifier | None = None,
    *,
    limit: int = DISTRIBUTION_TOP_N,
    offset: int = 0,
) -> tuple[list[dict[str, object]], int, dict[str, object]]:
    """Logged-host distribution with ``Unknown`` for hostless rows."""
    return _distribution(conn, filt, classifier, "server_host", limit=limit, offset=offset)


_SLOW_ENDPOINT_ORDER: dict[str, str] = {
    "avg_desc": "avg_ms DESC, measured DESC, path ASC",
    "requests_desc": "measured DESC, path ASC",
    "max_desc": "max_ms DESC, measured DESC, path ASC",
}


def _p95_rank_rows(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    classifier: Classifier | None,
) -> tuple[list[tuple[object, ...]], int]:
    """Exact global per-path P95 ranking over the whole filtered scope.

    One SQL statement computes every candidate path's exact P95 (integer
    order-statistic arithmetic, no sampling) and returns the requested
    page already ranked ``p95 DESC, path ASC``. SQLite evaluates the
    window aggregation internally, so Python receives only the page
    rows -- no ``fetchall`` of every duration or every path. The
    interpolation matches :func:`timing_quantile`: for ``q = 95/100``
    and per-path count ``n``, ``num = 95 * (n - 1)``, ``lo0 = num //
    100``, ``rem = num % 100``; ``p95 = v[lo0] + (v[lo0 + 1] - v[lo0])
    * rem / 100`` with 0-based ascending ``v`` (``ROW_NUMBER`` is
    1-based, hence ``+1``). P50 for the same rows uses ``50/100`` the
    same way, so page items carry exact P50 too.
    """
    where, params = _where(filt, classifier)
    measured_scope = f"{where} AND request_time_ms IS NOT NULL"
    total = int(
        conn.execute(
            f"SELECT COUNT(DISTINCT path) FROM requests WHERE {measured_scope}", params
        ).fetchone()[0]
    )
    rows = conn.execute(
        "WITH ranked AS ("
        " SELECT path, request_time_ms,"
        " COUNT(*) OVER (PARTITION BY path) AS n,"
        " ROW_NUMBER() OVER (PARTITION BY path ORDER BY request_time_ms ASC) AS rn"
        f" FROM requests WHERE {measured_scope}"
        "), per_path AS ("
        " SELECT path, n AS measured,"
        " MIN(request_time_ms) AS min_ms, MAX(request_time_ms) AS max_ms,"
        " AVG(request_time_ms) AS avg_ms,"
        " MAX(CASE WHEN rn = (95 * (n - 1)) / 100 + 1 THEN request_time_ms END) AS lo95,"
        " MAX(CASE WHEN rn = (95 * (n - 1)) / 100 + CASE WHEN (95 * (n - 1)) % 100 = 0"
        " THEN 1 ELSE 2 END THEN request_time_ms END) AS hi95,"
        " CAST((95 * (n - 1)) % 100 AS REAL) / 100.0 AS frac95,"
        " MAX(CASE WHEN rn = (50 * (n - 1)) / 100 + 1 THEN request_time_ms END) AS lo50,"
        " MAX(CASE WHEN rn = (50 * (n - 1)) / 100 + CASE WHEN (50 * (n - 1)) % 100 = 0"
        " THEN 1 ELSE 2 END THEN request_time_ms END) AS hi50,"
        " CAST((50 * (n - 1)) % 100 AS REAL) / 100.0 AS frac50"
        " FROM ranked GROUP BY path, n"
        ")"
        " SELECT path, measured, min_ms, max_ms, avg_ms,"
        " lo95 + (hi95 - lo95) * frac95 AS p95_ms,"
        " lo50 + (hi50 - lo50) * frac50 AS p50_ms"
        " FROM per_path ORDER BY p95_ms DESC, path ASC LIMIT ? OFFSET ?",
        [*params, filt.limit, filt.offset],
    ).fetchall()
    return rows, total


def slow_endpoints(
    conn: sqlite3.Connection, query: SlowEndpointsQuery, classifier: Classifier | None = None
) -> tuple[list[dict[str, object]], int, dict[str, object]]:
    """Slow measured endpoints with counts and exact per-path percentiles.

    Candidates are paths with at least one measured ``request_time_ms``
    in the filtered scope. ``avg_desc``/``requests_desc``/``max_desc``
    rank every candidate exactly in SQL (stable tie-breaks; NULL
    averages sort last): ``p95_desc`` computes each path's exact P95
    with integer order-statistic arithmetic inside one window-aggregate
    statement and pages the ranked result, so a rare slow path is never
    hidden by a frequency preselection. Reported p50/p95 values are
    exact order statistics over each path's full measured rows.
    Non-finite averages (overflowed ``AVG``) show ``None`` with a
    warning instead of ``Inf``/``NaN``.
    """
    filt = query.filt
    where, params = _where(filt, classifier)
    measured_scope = f"{where} AND request_time_ms IS NOT NULL"
    total = int(
        conn.execute(
            f"SELECT COUNT(DISTINCT path) FROM requests WHERE {measured_scope}", params
        ).fetchone()[0]
    )
    meta: dict[str, object] = {"candidate_paths": total, "ranking": query.sort}
    if query.sort == "p95_desc":
        rows, total = _p95_rank_rows(conn, filt, classifier)
        ranked_items: list[dict[str, object]] = []
        warnings: list[str] = []
        for path, measured, minimum, maximum, average, p95, p50 in rows:
            average_ms: float | None = None
            if average is not None:
                candidate_avg = float(average)
                average_ms = candidate_avg if math.isfinite(candidate_avg) else None
                if average_ms is None:
                    warnings.append(f"path {path}: average unavailable (overflow)")
            ranked_items.append(
                {
                    "path": path,
                    "measured": int(measured),
                    "min_ms": float(minimum) if minimum is not None else None,
                    "max_ms": float(maximum) if maximum is not None else None,
                    "average_ms": average_ms,
                    "p50_ms": (
                        float(p50) if p50 is not None and math.isfinite(float(p50)) else None
                    ),
                    "p95_ms": (
                        float(p95) if p95 is not None and math.isfinite(float(p95)) else None
                    ),
                }
            )
        if warnings:
            meta["warnings"] = warnings
        return ranked_items, total, meta
    try:
        order = _SLOW_ENDPOINT_ORDER[query.sort]
    except KeyError as exc:
        raise ValueError(f"unknown slow-endpoint sort: {query.sort!r}") from exc
    rows = conn.execute(
        "SELECT path, COUNT(*) AS measured,"
        " MIN(request_time_ms) AS min_ms, MAX(request_time_ms) AS max_ms,"
        " AVG(request_time_ms) AS avg_ms FROM requests"
        f" WHERE {measured_scope} GROUP BY path ORDER BY {order} LIMIT ? OFFSET ?",
        [*params, filt.limit, filt.offset],
    ).fetchall()
    items: list[dict[str, object]] = []
    warnings: list[str] = []
    for path, measured, minimum, maximum, average in rows:
        stats = _path_timing(
            conn,
            filt,
            classifier,
            str(path),
            int(measured),
            precomputed=(minimum, maximum, average),
        )
        items.append(stats)
        if stats["average_ms"] is None:
            warnings.append(f"path {path}: average unavailable (overflow)")
    if warnings:
        meta["warnings"] = warnings
    return items, total, meta


def _path_timing(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    classifier: Classifier | None,
    path: str,
    measured: int,
    precomputed: tuple[object, object, object] | None = None,
) -> dict[str, object]:
    """Exact timing summary for one path (full measured rows, no sampling)."""
    if precomputed is None:
        where, params = _where(filt, classifier)
        row = conn.execute(
            "SELECT MIN(request_time_ms), MAX(request_time_ms), AVG(request_time_ms)"
            " FROM requests WHERE " + where + " AND path = ? AND request_time_ms IS NOT NULL",
            [*params, path],
        ).fetchone()
        minimum, maximum, average = row
    else:
        minimum, maximum, average = precomputed
    average_ms: float | None = None
    if average is not None:
        candidate = float(average)
        average_ms = candidate if math.isfinite(candidate) else None
    scoped = filt.model_copy(
        update={"path_prefix": None, "path_exact": None, "limit": 1, "offset": 0}
    )
    where, params = _where(scoped, classifier)
    path_where = f"{where} AND path = ?"
    path_params: list[object] = [*params, path]
    p50 = _scoped_quantile(conn, path_where, path_params, measured, 0.50)
    p95 = _scoped_quantile(conn, path_where, path_params, measured, 0.95)
    return {
        "path": path,
        "measured": measured,
        "min_ms": float(minimum) if minimum is not None else None,
        "max_ms": float(maximum) if maximum is not None else None,
        "average_ms": average_ms,
        "p50_ms": p50,
        "p95_ms": p95,
    }


def _scoped_quantile(
    conn: sqlite3.Connection, where: str, params: list[object], measured: int, quantum: float
) -> float | None:
    """Linear-interpolation quantile over one pre-scoped measured set."""
    if measured <= 0:
        return None
    rank = quantum * (measured - 1)
    low = math.floor(rank)
    high = math.ceil(rank)
    first_row = conn.execute(
        "SELECT request_time_ms FROM requests WHERE " + where + " AND request_time_ms IS NOT NULL"
        " ORDER BY request_time_ms ASC LIMIT 1 OFFSET ?",
        [*params, low],
    ).fetchone()
    if first_row is None:
        return None
    first = float(first_row[0])
    if high == low:
        return first if math.isfinite(first) else None
    second_row = conn.execute(
        "SELECT request_time_ms FROM requests WHERE " + where + " AND request_time_ms IS NOT NULL"
        " ORDER BY request_time_ms ASC LIMIT 1 OFFSET ?",
        [*params, high],
    ).fetchone()
    if second_row is None:
        return None
    value = first + (float(second_row[0]) - first) * (rank - low)
    return value if math.isfinite(value) else None


#: Rule categories treated as AI bots for AI-only path analysis. This
#: is the configured category set from the versioned bot catalog, not a
#: User-Agent sniff: only rows matching a configured ``ai_crawler``
#: rule count as AI-observed.
AI_CATEGORIES = frozenset({"ai_crawler"})


def ai_rule_indexes(classifier: Classifier) -> set[int]:
    """Ordered rule indexes whose configured category is an AI category."""
    return {
        index for index, category in enumerate(classifier.categories) if category in AI_CATEGORIES
    }


def _base_scope(filt: AnalyticsFilter) -> tuple[AnalyticsFilter, list[str]]:
    """Comparison-universe scope: bot/category/traffic selectors removed.

    AI-only analysis compares AI-observed paths against other traffic
    in the SAME site/source/time/base scope. Bot, category, provider,
    purpose and traffic selectors would trivially narrow one side of
    the comparison (an AI-only filter must not prove absence by
    construction), so they are removed here and every removal is
    reported by the caller. All other narrowing (status, path, method,
    enrichment matchers, window) applies equally to both sides.
    """
    removed: list[str] = []
    updates: dict[str, object] = {}
    for name in ("bot", "category", "provider", "purpose"):
        if getattr(filt, name) is not None:
            removed.append(name)
            updates[name] = None
    if filt.traffic != "all":
        removed.append("traffic")
        updates["traffic"] = "all"
    return filt.model_copy(update=updates), removed


def _check_ai_candidate_compatible(
    filt: AnalyticsFilter, classifier: Classifier, ai_indexes: set[int]
) -> None:
    """Reject selectors that cannot hold AI-candidate rows.

    AI-crawler rules live in the ``claimed_bot`` traffic bucket, so a
    ``browser_like``/``unknown``/``other_automation`` traffic selector --
    or a bot/category/provider/purpose selector matching no AI rule --
    would yield an empty candidate set. Raising here (instead of
    silently ignoring the selector) keeps evidence, counts and
    drilldowns honest about the selected scope.
    """
    if filt.traffic not in ("all", "claimed_bot"):
        raise ValueError(
            "ai-only analysis needs traffic 'all' or 'claimed_bot': "
            f"{filt.traffic!r} can hold no AI-crawler rows"
        )
    for name in ("bot", "category", "provider", "purpose"):
        value = getattr(filt, name)
        if value is None:
            continue
        allowed = resolve_selector_indexes(classifier, **{name: value})
        assert allowed is not None
        if not (allowed & ai_indexes):
            raise ValueError(
                f"ai-only analysis: {name} selector {value!r} matches no AI-crawler rule"
            )


def _ai_candidate_condition(
    filt: AnalyticsFilter, classifier: Classifier, ai_indexes: set[int]
) -> tuple[str, list[object]]:
    """SQL predicate (plus bound params) for the SELECTED AI-candidate rows.

    Conjunction of the AI-category match with the caller's own
    bot/category/provider/purpose/traffic predicates -- every selector
    is preserved on the candidate side. The comparison universe widens
    by dropping those predicates (see :func:`_base_scope`); both sides
    share the site/source/time/content scope. Incompatible selectors
    raise ``ValueError`` via :func:`_check_ai_candidate_compatible`.
    """
    ordered = sorted(ai_indexes)
    placeholders = ", ".join("?" for _ in ordered)
    _check_ai_candidate_compatible(filt, classifier, ai_indexes)
    ai_match = f"{_MATCH} IN ({placeholders})"
    ai_params: list[object] = [classifier.spec, *ordered]
    extra_clauses, extra_params = _classification_clauses(filt, classifier)
    if not extra_clauses:
        return ai_match, ai_params
    return (
        ai_match + " AND " + " AND ".join(f"({clause})" for clause in extra_clauses),
        [*ai_params, *extra_params],
    )


def ai_only_paths(
    conn: sqlite3.Connection, filt: AnalyticsFilter, classifier: Classifier
) -> dict[str, object]:
    """Paths observed ONLY by the SELECTED AI candidates, not other traffic.

    A path is AI-only when it holds rows matching the caller's own
    AI-candidate scope (bot/category/provider/purpose/traffic selectors
    preserved) and NO other-traffic rows in the widened comparison
    universe (those same selectors removed, everything else -- site,
    source, time, content matchers -- shared). Exact single-``GROUP
    BY`` SQL over the whole scope: totals never pass a capped distinct
    scan. The result carries both the candidate scope and the comparison
    universe with their own filters/coverage, plus the absence caveat;
    vacuously AI-only universes (no other traffic at all) are flagged,
    never hidden. A shared browser path always contributes other-traffic
    rows, so it can never be AI-only. Incompatible selectors (traffic
    outside ``all``/``claimed_bot``, or a bot/category/provider/purpose
    matching no AI rule) raise ``ValueError`` instead of being silently
    ignored. No indexing, training-use or ranking claim is made.
    """
    ai_indexes = ai_rule_indexes(classifier)
    base, removed = _base_scope(filt)
    where, params = _where(base, None)
    universe_paths = int(
        conn.execute(f"SELECT COUNT(DISTINCT path) FROM requests WHERE {where}", params).fetchone()[
            0
        ]
    )
    universe_requests = int(
        conn.execute(f"SELECT COUNT(*) FROM requests WHERE {where}", params).fetchone()[0]
    )
    if not ai_indexes:
        return {
            "items": [],
            "total_paths": 0,
            "comparison": {
                "universe_paths": universe_paths,
                "universe_requests": universe_requests,
                "ai_observed_paths": 0,
                "other_observed_paths": 0,
                "selectors_removed": removed,
            },
            "comparison_filter": base,
            "vacuous": universe_requests == 0,
            "warnings": ["no configured AI-bot categories: nothing can be AI-only"],
            "limit": base.limit,
            "offset": base.offset,
        }
    ordered = sorted(ai_indexes)
    placeholders = ", ".join("?" for _ in ordered)
    # NOTE: the WHERE clause stays on the whole base scope (no AI
    # pre-filter): the HAVING below must still see each path's
    # non-AI universe rows, otherwise every AI-observed path would
    # wrongly qualify. The candidate predicate (selected AI scope)
    # and the universe other-traffic predicate enter as conditional
    # aggregates over the full per-path groups instead.
    cand_sql, cand_params = _ai_candidate_condition(filt, classifier, ai_indexes)
    other_sql = f"({_MATCH} IS NULL OR {_MATCH} NOT IN ({placeholders}))"
    other_params: list[object] = [classifier.spec, classifier.spec, *ordered]
    ai_paths = int(
        conn.execute(
            f"SELECT COUNT(DISTINCT path) FROM requests WHERE {where} AND {cand_sql}",
            [*params, *cand_params],
        ).fetchone()[0]
    )
    other_paths = int(
        conn.execute(
            f"SELECT COUNT(DISTINCT path) FROM requests WHERE {where} AND {other_sql}",
            [*params, *other_params],
        ).fetchone()[0]
    )
    total = int(
        conn.execute(
            "SELECT COUNT(*) FROM (SELECT path FROM requests WHERE "
            + where
            + f" GROUP BY path HAVING SUM(CASE WHEN {cand_sql} THEN 1 ELSE 0 END) > 0"
            + f" AND SUM(CASE WHEN {other_sql} THEN 1 ELSE 0 END) = 0)",
            [*params, *cand_params, *other_params],
        ).fetchone()[0]
    )
    rows = conn.execute(
        "SELECT path,"
        f" SUM(CASE WHEN {cand_sql} THEN 1 ELSE 0 END) AS ai_requests,"
        f" COALESCE(SUM(CASE WHEN {cand_sql} THEN bytes ELSE 0 END), 0),"
        f" GROUP_CONCAT(DISTINCT CASE WHEN {cand_sql} THEN {_MATCH} END)"
        f" FROM requests WHERE {where}"
        " GROUP BY path"
        f" HAVING SUM(CASE WHEN {cand_sql} THEN 1 ELSE 0 END) > 0"
        f" AND SUM(CASE WHEN {other_sql} THEN 1 ELSE 0 END) = 0"
        " ORDER BY ai_requests DESC, path ASC LIMIT ? OFFSET ?",
        [
            *cand_params,
            *cand_params,
            *cand_params,
            classifier.spec,
            *params,
            *cand_params,
            *other_params,
            base.limit,
            base.offset,
        ],
    ).fetchall()
    by_id = {rule_id: rule for rule_id, rule in zip(classifier.rule_ids, classifier.rules)}
    index_to_id = {index: rule_id for index, rule_id in enumerate(classifier.rule_ids)}
    items: list[dict[str, object]] = []
    for path, count, nbytes, raw_indexes in rows:
        indexes = sorted({int(part) for part in str(raw_indexes).split(",") if part.strip()})
        rules = [index_to_id[i] for i in indexes if i in index_to_id]
        providers = sorted({by_id[r].provider for r in rules if by_id[r].provider})
        items.append(
            {
                "path": path,
                "ai_requests": int(count),
                "ai_bytes": int(nbytes),
                "rules": rules,
                "providers": providers,
                "drilldown": {"path_exact": path, "category": "ai_crawler"},
            }
        )
    vacuous = other_paths == 0 and universe_requests > 0
    warnings: list[str] = []
    if vacuous:
        warnings.append(
            "comparison universe holds no non-AI traffic: every path is trivially AI-only"
        )
    if universe_requests == 0:
        warnings.append("comparison universe is empty: no paths observed at all")
    return {
        "items": items,
        "total_paths": total,
        "comparison": {
            "universe_paths": universe_paths,
            "universe_requests": universe_requests,
            "ai_observed_paths": ai_paths,
            "other_observed_paths": other_paths,
            "selectors_removed": removed,
        },
        "comparison_filter": base,
        "vacuous": vacuous,
        "warnings": warnings,
        "limit": base.limit,
        "offset": base.offset,
    }


def seo_status_by_bot_path(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    classifier: Classifier,
    *,
    status_class: str,
) -> tuple[list[dict[str, object]], int]:
    """Bot 3xx/4xx/5xx grouped by normalized path and responsible rule.

    One exact all-row ``GROUP BY`` over the filtered scope: rows match
    the ordered versioned classifier (first match wins), so every row
    attributes to exactly one configured rule/provider. Groups carry
    exact counts/bytes plus drilldown selectors (``bot`` + exact
    ``path_exact`` + status class) for the future UI/API: the exact
    selector reproduces the reported path group, while the legacy
    ``path_prefix`` remains available as a widening prefix exploration.
    Sort is stable: requests DESC, path ASC, rule ASC. ``status_class``
    is an internal literal.
    """
    try:
        low, high = _STATUS_CLASS_RANGE[status_class]
    except KeyError as exc:
        raise ValueError(f"unknown status class: {status_class!r}") from exc
    where, params = _where(filt, classifier)
    top = len(classifier.rule_ids) - 1
    match_scoped = f"{where} AND status BETWEEN ? AND ? AND {_MATCH} BETWEEN 0 AND {top}"
    match_params: list[object] = [*params, low, high, classifier.spec]
    total = int(
        conn.execute(
            f"SELECT COUNT(DISTINCT path || CHAR(31) || {_MATCH}) FROM requests"
            f" WHERE {match_scoped}",
            [classifier.spec, *match_params],
        ).fetchone()[0]
    )
    rule_case, rule_params = rule_id_case_sql(classifier)
    rows = conn.execute(
        "SELECT path,"
        f" {rule_case} AS rule_id, COUNT(*) AS requests, COALESCE(SUM(bytes), 0) AS bytes_total"
        f" FROM requests WHERE {match_scoped}"
        " GROUP BY path, rule_id ORDER BY requests DESC, path ASC, rule_id ASC"
        " LIMIT ? OFFSET ?",
        [*rule_params, *match_params, filt.limit, filt.offset],
    ).fetchall()
    by_id = {rule_id: rule for rule_id, rule in zip(classifier.rule_ids, classifier.rules)}
    items: list[dict[str, object]] = []
    for path, rule_id, count, nbytes in rows:
        rule = by_id.get(str(rule_id))
        items.append(
            {
                "path": path,
                "status_class": status_class,
                "rule_id": rule_id,
                "category": rule.category if rule else None,
                "provider": rule.provider if rule else None,
                "purpose": rule.purpose if rule else None,
                "requests": int(count),
                "bytes_total": int(nbytes),
                "drilldown": {"bot": rule_id, "path_exact": path, "status_class": status_class},
            }
        )
    return items, total


def own_hosts_for_scope(conn: sqlite3.Connection, filt: AnalyticsFilter) -> set[str]:
    """Configured own hosts (site hostname + stored source aliases).

    Internal/external referrer classification compares the stored
    lowercase referrer hostname against this set. Sources bound before
    the alias column existed contribute the site hostname; sources with
    stored aliases contribute hostname plus aliases. Matching rules
    (documented): hosts compare lowercased; ports are never stored
    (``urlsplit().hostname`` drops them); userinfo is never stored;
    IDN compares in its stored encoded form on both sides.
    """
    hosts: set[str] = set()
    site_row = conn.execute("SELECT hostname FROM sites WHERE id = ?", (filt.site_id,)).fetchone()
    if site_row is not None and site_row[0]:
        hosts.add(str(site_row[0]).strip().lower())
    if filt.source_id is not None:
        rows = conn.execute(
            "SELECT allowed_hosts FROM log_sources WHERE id = ?", (filt.source_id,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT allowed_hosts FROM log_sources WHERE site_id = ?", (filt.site_id,)
        ).fetchall()
    import json as _json

    for (raw,) in rows:
        if not raw:
            continue
        try:
            stored = _json.loads(raw)
        except (ValueError, TypeError):
            continue
        if isinstance(stored, list):
            hosts.update(str(item).strip().lower() for item in stored if str(item).strip())
    return hosts


#: Validated referrer-relation selector for :func:`referrer_404_targets`.
#: ``"all"`` returns internal and external referrers together (labelled
#: per row); ``"internal"``/``"external"`` filter in SQL against the
#: configured own hosts/aliases with matching totals.
ReferrerRelation = Literal["all", "internal", "external"]


def referrer_404_targets(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    classifier: Classifier | None,
    own_hosts: set[str] | None = None,
    *,
    relation: ReferrerRelation = "all",
) -> tuple[list[dict[str, object]], int]:
    """Referrer-path -> target-404 report over sanitized fields.

    Covers internal AND external referrers together (each row is
    labelled; see ``relation`` to narrow). Keys use ONLY the minimized
    stored referrer (lowercase host without port/userinfo,
    ``http``/``https`` scheme or ``None``, secret-masked path without
    query values) plus the normalized target path. Rows whose referrer
    host is a configured own host/alias are labelled internal;
    everything else is external. Dangerous schemes can never appear
    (only ``http``/``https``/``None`` are stored), and no query values,
    userinfo or secrets are emitted. Totals come from an exact grouped
    subquery (no delimiter-collision tuple encoding); every grouping
    key participates in the stable order (requests DESC, host ASC,
    scheme NULLS LAST, referrer-path NULLS LAST, target ASC), so tied
    groups page deterministically. Ordinary host-level reports are
    untouched.
    """
    if relation not in ("all", "internal", "external"):
        raise ValueError(f"unknown referrer relation: {relation!r}")
    hosts = own_hosts if own_hosts is not None else own_hosts_for_scope(conn, filt)
    lowered = sorted({h.lower() for h in hosts if h})
    where, params = _where(filt, classifier)
    scoped = f"{where} AND status = 404 AND referer_host IS NOT NULL"
    relation_params: list[object] = []
    if relation != "all":
        if lowered:
            in_list = ", ".join("?" for _ in lowered)
            if relation == "internal":
                scoped += f" AND lower(referer_host) IN ({in_list})"
            else:
                scoped += f" AND lower(referer_host) NOT IN ({in_list})"
            relation_params = [*lowered]
        elif relation == "internal":
            return [], 0
    total = int(
        conn.execute(
            "SELECT COUNT(*) FROM (SELECT 1"
            f" FROM requests WHERE {scoped}"
            " GROUP BY referer_host, referer_scheme, referer_path, path)",
            [*params, *relation_params],
        ).fetchone()[0]
    )
    rows = conn.execute(
        "SELECT referer_host, referer_scheme, referer_path, path, COUNT(*) AS requests"
        f" FROM requests WHERE {scoped}"
        " GROUP BY referer_host, referer_scheme, referer_path, path"
        " ORDER BY requests DESC, referer_host ASC,"
        " referer_scheme ASC NULLS LAST, referer_path ASC NULLS LAST, path ASC"
        " LIMIT ? OFFSET ?",
        [*params, *relation_params, filt.limit, filt.offset],
    ).fetchall()
    lowered_set = set(lowered)
    return (
        [
            {
                "referer_host": host,
                "referer_scheme": scheme,
                "referer_path": ref_path,
                "target_path": target,
                "requests": int(count),
                "internal": str(host).lower() in lowered_set,
            }
            for host, scheme, ref_path, target, count in rows
        ],
        total,
    )
