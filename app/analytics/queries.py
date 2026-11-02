"""Parameterized analytics repositories (T4).

Every query is a fixed SQL string with bound parameters; sort orders
come from allowlisted contract literals, never from input. Large
cardinality scans (distinct agents/paths) are bounded with explicit
truncation flags so reads never load the whole database into memory.
"""

import hashlib
import math
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
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
    JourneyQuery,
    JourneyTimelineQuery,
    SlowEndpointsQuery,
    TopPathsQuery,
    TopReferrersQuery,
)
from app.analytics.rules import Rule
from app.db.importer import sanitize_error_summary
from app.ingestion.geoip import COUNTRY_CODE_RE, UNKNOWN_COUNTRY

MAX_DISTINCT_SCAN = 5000

#: Unix epoch as an aware datetime: the anchor for exact integer
#: microsecond arithmetic in :func:`epoch_micros`.
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def epoch_micros(value: str) -> int:
    """Exact integer epoch microseconds for one ISO-8601 instant.

    Fractional seconds keep full microsecond precision and any
    explicit UTC offset (positive or negative) normalizes exactly
    through datetime arithmetic — no float, no julianday rounding,
    no guessing. Naive (timezone-free) values raise ``ValueError``
    instead of being silently assumed UTC.
    """
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("timestamps must carry a timezone")
    delta = parsed - _EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def sqlite_epoch_micros(value: object) -> int | None:
    """Deterministic SQLite scalar wrapping :func:`epoch_micros`.

    ``NULL`` maps to ``NULL``; any other value must be a parseable
    aware ISO-8601 instant (stored events and validated window
    bounds always are). Unparseable values raise instead of
    silently comparing as equal.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"epoch_micros needs ISO-8601 text, got {type(value).__name__}")
    return epoch_micros(value)


#: Split-half byte aggregates. SQLite raises ``integer overflow``
#: once a plain ``SUM(bytes)`` exceeds int64, so byte totals aggregate
#: the high/low 32-bit halves instead: each half-sum fits for any
#: importable dataset (overflowing one half needs exabytes of logged
#: response bytes), and :func:`combine_bytes_total` joins them into
#: one exact Python integer — never via float, never raising, never
#: silently truncated.
_SUM_BYTES_HALVES = "COALESCE(SUM((bytes) >> 32), 0), COALESCE(SUM((bytes) & 4294967295), 0)"


def combine_bytes_total(hi: object, lo: object) -> int | None:
    """Exact integer byte total from split-half aggregates.

    ``None`` halves (an all-``NULL`` group, never an overflow) stay
    ``None``: no known bytes. Anything else combines with exact
    integer arithmetic — ordinary and extreme totals alike, including
    sums far above int64 that a plain ``SUM`` could never return.
    """
    if hi is None or lo is None:
        return None
    return int(hi) * 4294967296 + int(lo)


def register_time_functions(conn: sqlite3.Connection) -> None:
    """Register the exact-time scalars on one DB-API connection."""
    conn.create_function("epoch_micros", 1, sqlite_epoch_micros, deterministic=True)


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


def _base_where(filt: AnalyticsFilter) -> tuple[str, list[object]]:
    """Authorized event scope: site, optional source, UTC window only.

    Journey boundaries and coverage always derive from this scope
    BEFORE any content/method/status/traffic matcher, so narrow
    filters can hide rows but never invent new journey starts or
    widen the authorized history.
    """
    clauses = ["site_id = ?", "ts_utc >= ?", "ts_utc < ?"]
    params: list[object] = [
        filt.site_id,
        filt.window.time_from.isoformat(),
        filt.window.time_to.isoformat(),
    ]
    if filt.source_id is not None:
        clauses.append("source_id = ?")
        params.append(filt.source_id)
    return " AND ".join(clauses), params


def _matcher_clauses(
    filt: AnalyticsFilter, classifier: Classifier | None = None
) -> tuple[list[str], list[object]]:
    """Content/matcher predicates applied AFTER scope segmentation.

    Every clause here narrows which rows are shown/counted; none of
    them may redefine journey boundaries (those come from
    :func:`_base_where` alone).
    """
    clauses: list[str] = []
    params: list[object] = []
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
    if filt.client is not None:
        # Exact client equality: ONE stable HMAC pseudonym, parameterized.
        # Independent of (and intersecting with) the widening text search
        # below: embedding the HMAC in a UA/path never matches here.
        clauses.append("client_pseudonym = ?")
        params.append(filt.client)
    if filt.country is not None:
        # T5a offline-country selector (PAR-09): the contract already
        # normalized the value through the shared allowlist. The
        # explicit UNKNOWN selector matches every row with no known
        # country (NULL code: unknown lookups, unavailable lookups and
        # never-looked-up legacy rows alike); ISO codes match exactly.
        # An empty value never arrives here (transports map it to no
        # filter or reject), so Unknown is never silently selected.
        if filt.country == UNKNOWN_COUNTRY:
            clauses.append("country_code IS NULL")
        else:
            clauses.append("country_code = ?")
            params.append(filt.country)
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
    return clauses, params


def _where(filt: AnalyticsFilter, classifier: Classifier | None = None) -> tuple[str, list[object]]:
    """Full filtered scope: authorized base plus content matchers."""
    base_where, base_params = _base_where(filt)
    matcher_clauses, matcher_params = _matcher_clauses(filt, classifier)
    if matcher_clauses:
        return base_where + " AND " + " AND ".join(matcher_clauses), [
            *base_params,
            *matcher_params,
        ]
    return base_where, base_params


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
        f" {_SUM_BYTES_HALVES},"
        " COUNT(bytes)"
        f" FROM requests WHERE {where}",
        params,
    ).fetchone()
    total = combine_bytes_total(row[3], row[4])
    assert total is not None  # COALESCE halves never yield NULL
    return {
        "requests": row[0],
        "errors_4xx": row[1],
        "errors_5xx": row[2],
        "bytes_total": total,
        "bytes_measured": row[5],
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

    Method/status/status-class/country narrowing is lifted so the
    dropdown can always offer every value in the current scope (the
    current selection is retained separately); everything else still
    narrows honestly.
    """
    return filt.model_copy(
        update={
            "method": None,
            "status": None,
            "status_class": None,
            "country": None,
            "limit": 1,
            "offset": 0,
        }
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
    # Split-half ordering matches exact-total ordering only after the
    # low-half carry is normalized: the true total is
    # ``bytes_hi * 2**32 + bytes_lo`` and the raw low sum can exceed one
    # word (cross-carry), so ordering compares the normalized high word
    # ``bytes_hi + (bytes_lo >> 32)`` first and the normalized low word
    # ``bytes_lo & 4294967295`` second. Both operands stay int64 for any
    # importable dataset (overflowing one half needs exabytes of logged
    # response bytes); no REAL cast, no Python regrouping, no page-only
    # ranking. Audited 2026-11-02: this is the only grouped byte ranking
    # that orders by split halves; every other byte aggregate only sums
    # (exact ``combine_bytes_total``) or orders by request counts.
    "bytes_desc": "(bytes_hi + (bytes_lo >> 32)) DESC, (bytes_lo & 4294967295) DESC,"
    " requests DESC, path ASC, method ASC",
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
        " COALESCE(SUM((bytes) >> 32), 0) AS bytes_hi,"
        " COALESCE(SUM((bytes) & 4294967295), 0) AS bytes_lo"
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
                "bytes_total": combine_bytes_total(hi, lo),
            }
            for path, method, count, errors, hi, lo in rows
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
        f" {_SUM_BYTES_HALVES}"
        f" FROM requests WHERE {where} GROUP BY substr(ts_utc, 1, {width})",
        params,
    ).fetchall()
    by_key = {
        key: {"requests": count, "errors": errors, "bytes_total": combine_bytes_total(hi, lo)}
        for key, count, errors, hi, lo in rows
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


def _sample_paths_scoped(
    conn: sqlite3.Connection,
    where: str,
    params: list[object],
    client_pseudonyms: list[str],
    *,
    limit: int,
) -> dict[str, list[dict[str, object]]]:
    """Batched top-``limit`` (path, status, hits) rows per client pseudonym.

    One parameterized query over the caller's already-scoped ``where``
    predicate: per-client groups are ranked with ``ROW_NUMBER()``
    partitioned by client, ordered by hits DESC, path ASC, status ASC
    — the same order as :func:`sample_paths_for_client`. The result
    maps each requested pseudonym to its sample list (missing clients
    map to ``[]``). An empty request list returns without touching
    the database, so the SELECT count stays constant no matter how
    many offenders are shown.
    """
    wanted = [p for p in dict.fromkeys(client_pseudonyms) if p][:MAX_SAMPLE_CLIENTS]
    if not wanted or limit < 1:
        return {p: [] for p in dict.fromkeys(client_pseudonyms) if p}
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
    where, params = _where(filt, classifier)
    return _sample_paths_scoped(conn, where, params, client_pseudonyms, limit=limit)


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
    imports_truncated = False
    if source_ids:
        placeholders = ", ".join("?" for _ in source_ids)
        # Exact aggregates come from bounded SQL SUM, never from the
        # capped sample below, so follow generations and archive
        # attempts stay fully counted however long the history grows.
        totals = conn.execute(
            "SELECT COALESCE(SUM(lines_total), 0), COALESCE(SUM(lines_accepted), 0),"
            " COALESCE(SUM(lines_rejected), 0), COALESCE(SUM(records_replayed), 0),"
            f" COUNT(*) FROM imports WHERE source_id IN ({placeholders})",
            source_ids,
        ).fetchone()
        attempts = {
            "lines_total": int(totals[0]),
            "lines_accepted": int(totals[1]),
            "lines_rejected": int(totals[2]),
            "records_replayed": int(totals[3]),
        }
        sample = conn.execute(
            "SELECT id, source_id, file_fingerprint, lines_total, lines_accepted,"
            " lines_rejected, records_inserted, records_replayed, status, error_summary"
            f" FROM imports WHERE source_id IN ({placeholders}) ORDER BY id"
            f" LIMIT {IMPORT_HISTORY_SAMPLE_LIMIT}",
            source_ids,
        ).fetchall()
        imports_truncated = int(totals[4]) > len(sample)
        for imp in sample:
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
    return {
        "unique_events": row[0],
        "observed_min": row[1],
        "observed_max": row[2],
        "sources": sources,
        "imports": imports,
        "imports_truncated": imports_truncated,
        "import_attempts": attempts,
    }


#: Bound on the import-history sample served inside coverage: history
#: grows with every batch/generation/archive attempt, so a long-lived
#: source must never force an unbounded ``fetchall`` into responses.
#: Exact aggregate accounting always comes from bounded SQL ``SUM``
#: queries; only the displayed sample is capped, with an explicit flag.
IMPORT_HISTORY_SAMPLE_LIMIT = 200


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
        f" {_SUM_BYTES_HALVES}"
        f" FROM requests WHERE {where} GROUP BY {case}",
        [*case_params, *params, *case_params],
    ).fetchall()
    return [
        {
            "traffic": traffic,
            "requests": count,
            "errors_4xx": e4,
            "errors_5xx": e5,
            "bytes_total": combine_bytes_total(hi, lo),
        }
        for traffic, count, e4, e5, hi, lo in rows
    ]


def country_breakdown(
    conn: sqlite3.Connection, filt: AnalyticsFilter, classifier: Classifier | None = None
) -> list[dict[str, object]]:
    """Exact per-country request/error/byte totals, Unknown included.

    One ``GROUP BY`` over the filtered scope: every row lands in
    exactly one group (its ISO code, or ``Unknown`` for a NULL code),
    so group totals sum exactly. Stable order is requests descending,
    then the display label ascending.
    """
    where, params = _where(filt, classifier)
    rows = conn.execute(
        "SELECT COALESCE(country_code, 'Unknown') AS country, COUNT(*),"
        " COUNT(CASE WHEN status BETWEEN 400 AND 499 THEN 1 END),"
        " COUNT(CASE WHEN status BETWEEN 500 AND 599 THEN 1 END),"
        f" {_SUM_BYTES_HALVES}"
        " FROM requests WHERE"
        f" {where} GROUP BY country ORDER BY COUNT(*) DESC, country ASC",
        params,
    ).fetchall()
    return [
        {
            "country": country,
            "requests": int(count),
            "errors_4xx": int(e4),
            "errors_5xx": int(e5),
            "bytes_total": combine_bytes_total(hi, lo),
        }
        for country, count, e4, e5, hi, lo in rows
    ]


def geo_coverage(
    conn: sqlite3.Connection, filt: AnalyticsFilter, classifier: Classifier | None = None
) -> dict[str, object]:
    """Honest lookup coverage over the filtered scope (safe fields only).

    ``with_country`` rows carry a looked-up ISO code; ``unknown`` rows
    ran the lookup (or an equivalent eligibility decision) without a
    country; ``unavailable`` rows were stored while no database could
    be read; ``legacy`` rows predate the lookup columns entirely.
    Distinct observed sources/releases describe which databases the
    rows came from; no address, path or exception text is exposed.
    """
    where, params = _where(filt, classifier)
    row = conn.execute(
        "SELECT COUNT(*),"
        " COUNT(CASE WHEN country_code IS NOT NULL THEN 1 END),"
        " COUNT(CASE WHEN country_code IS NULL AND geo_status = 'unknown' THEN 1 END),"
        " COUNT(CASE WHEN geo_status = 'unavailable' THEN 1 END),"
        " COUNT(CASE WHEN geo_status IS NULL THEN 1 END)"
        f" FROM requests WHERE {where}",
        params,
    ).fetchone()
    sources = [
        r[0]
        for r in conn.execute(
            "SELECT DISTINCT geo_source FROM requests"
            f" WHERE {where} AND geo_source IS NOT NULL ORDER BY geo_source LIMIT 16",
            params,
        ).fetchall()
        if isinstance(r[0], str)
    ]
    releases = [
        r[0]
        for r in conn.execute(
            "SELECT DISTINCT geo_release FROM requests"
            f" WHERE {where} AND geo_release IS NOT NULL ORDER BY geo_release LIMIT 16",
            params,
        ).fetchall()
        if isinstance(r[0], str)
    ]
    return {
        "requests": int(row[0]),
        "with_country": int(row[1]),
        "unknown": int(row[2]),
        "unavailable": int(row[3]),
        "legacy": int(row[4]),
        "sources": sources,
        "releases": releases,
    }


def distinct_countries(
    conn: sqlite3.Connection, filt: AnalyticsFilter, classifier: Classifier | None = None
) -> list[str]:
    """Observed ISO country codes in scope; parameterized, bounded, safe."""
    scope = _option_scope(filt)
    where, params = _where(scope, classifier)
    rows = conn.execute(
        "SELECT DISTINCT country_code FROM requests"
        f" WHERE {where} AND country_code IS NOT NULL"
        " ORDER BY country_code LIMIT 249",
        params,
    ).fetchall()
    codes = [row[0] for row in rows if isinstance(row[0], str)]
    return [code for code in codes if COUNTRY_CODE_RE.match(code)]


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
        f" {_SUM_BYTES_HALVES},"
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
            "bytes_total": combine_bytes_total(hi, lo),
            "distinct_agents": agents,
            "distinct_paths": paths,
        }
        for idx, count, e4, e5, hi, lo, agents, paths in rows
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
        f" {_SUM_BYTES_HALVES}, COUNT(DISTINCT user_agent)"
        f" FROM requests WHERE {where} AND {_MATCH} = ?",
        [*params, classifier.spec, index],
    ).fetchone()
    total = combine_bytes_total(row[3], row[4])
    assert total is not None  # COALESCE halves never yield NULL
    return {
        "requests": row[0],
        "errors_4xx": row[1],
        "errors_5xx": row[2],
        "bytes_total": total,
        "distinct_agents": row[5],
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


#: Explicit allowlisted export columns in stable order (PAR-07): the
#: sanitized explorer projection plus approved SAFE enrichment. Never
#: the private original-IP table, raw lines, query values, keys,
#: exception text or stored diagnostics — even when an admin display
#: mode is full.
EXPORT_COLUMNS: tuple[str, ...] = (
    "ts_utc",
    "method",
    "path",
    "status",
    "bytes",
    "referer_scheme",
    "referer_host",
    "referer_path",
    "server_host",
    "http_version",
    "mime_type",
    "cache_status",
    "tls_protocol",
    "request_time_ms",
    "upstream_time_ms",
    "upstream_count",
    "format_id",
    "policy_version",
    "country_code",
    "geo_source",
    "geo_release",
    "geo_status",
    "user_agent",
    "ua_truncated",
    "client_pseudonym",
    "traffic",
    "rule_id",
    "conflict",
    "timing_available",
    "upstream_available",
)

#: Bounded streaming chunk: one ``fetchmany`` per chunk crosses into
#: Python, never a ``fetchall`` of the whole result.
EXPORT_CHUNK_ROWS = 1000


def _explorer_select(
    filt: AnalyticsFilter, classifier: Classifier, sort: str
) -> tuple[str, list[object]]:
    """Shared sanitized row SELECT for paging and full-result export.

    Sort comes from the allowlisted ``_EXPLORER_ORDER`` literals only;
    unknown sorts raise ``ValueError``. The projection is exactly
    :data:`EXPORT_COLUMNS` (truncated 200-char agent plus flag, derived
    booleans, no original-IP join).
    """
    where, params = _where(filt, classifier)
    traffic_case, traffic_params = traffic_case_sql(classifier)
    rule_case, rule_params = rule_id_case_sql(classifier)
    try:
        order = _EXPLORER_ORDER[sort]
    except KeyError as exc:
        raise ValueError(f"unknown explorer sort: {sort!r}") from exc
    sql = (
        "SELECT ts_utc, method, path, status, bytes, referer_scheme, referer_host,"
        " referer_path, server_host, http_version, mime_type, cache_status, tls_protocol,"
        " request_time_ms, upstream_time_ms, upstream_count, format_id, policy_version,"
        " country_code, geo_source, geo_release, geo_status,"
        " substr(user_agent, 1, 200),"
        " CASE WHEN user_agent IS NOT NULL AND LENGTH(user_agent) > 200 THEN 1 ELSE 0 END,"
        " client_pseudonym,"
        f" {traffic_case} AS traffic, {rule_case} AS rule_id,"
        f" {_CONFLICT} AS conflict"
        f" FROM requests WHERE {where} ORDER BY {order}"
    )
    return sql, [*traffic_params, *rule_params, *params]


def export_row_to_dict(row: tuple) -> dict[str, object]:
    """Map one SELECT tuple onto :data:`EXPORT_COLUMNS` with derived flags."""
    (
        ts,
        method,
        path,
        status,
        nbytes,
        referer_scheme,
        host,
        referer_path,
        server_host,
        http_version,
        mime_type,
        cache_status,
        tls_protocol,
        request_time_ms,
        upstream_time_ms,
        upstream_count,
        format_id,
        policy_version,
        country_code,
        geo_source,
        geo_release,
        geo_status,
        agent,
        truncated,
        pseudonym,
        traffic,
        rule_id,
        conflict,
    ) = row
    return {
        "ts_utc": ts,
        "method": method,
        "path": path,
        "status": status,
        "bytes": nbytes,
        "referer_scheme": referer_scheme,
        "referer_host": host,
        "referer_path": referer_path,
        "server_host": server_host,
        "http_version": http_version,
        "mime_type": mime_type,
        "tls_protocol": tls_protocol,
        "request_time_ms": request_time_ms,
        "upstream_time_ms": upstream_time_ms,
        "upstream_count": upstream_count,
        "format_id": format_id,
        "policy_version": policy_version,
        # Safe offline-country outcome (PAR-09): ISO code or None for
        # Unknown, plus lookup provenance. Never an original address.
        "country_code": country_code,
        "geo_source": geo_source,
        "geo_release": geo_release,
        "geo_status": geo_status,
        "user_agent": agent,
        "ua_truncated": bool(truncated),
        "client_pseudonym": pseudonym,
        "traffic": traffic,
        "rule_id": rule_id,
        "conflict": bool(conflict),
        "cache_status": cache_status,
        "timing_available": request_time_ms is not None,
        "upstream_available": upstream_time_ms is not None,
    }


def count_export_rows(
    conn: sqlite3.Connection, filt: AnalyticsFilter, classifier: Classifier
) -> int:
    """Exact full-result row count for the export scope (never a capped scan)."""
    where, params = _where(filt, classifier)
    return int(conn.execute(f"SELECT COUNT(*) FROM requests WHERE {where}", params).fetchone()[0])


def export_cursor(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    classifier: Classifier,
    sort: str,
) -> sqlite3.Cursor:
    """Open the full-result export SELECT cursor (stable order).

    Sort comes from the allowlisted ``_EXPLORER_ORDER`` literals
    only; unknown sorts raise ``ValueError`` before any row is
    read. The caller owns the cursor (and its ``close``) and must
    hold the read snapshot for the stream duration.
    """
    sql, params = _explorer_select(filt, classifier, sort)
    return conn.execute(sql, params)


def iter_export_rows(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    classifier: Classifier,
    sort: str,
    *,
    chunk: int = EXPORT_CHUNK_ROWS,
) -> Iterator[dict[str, object]]:
    """Stream full-result export rows in bounded chunks (stable order).

    A server-side cursor with ``fetchmany`` materializes at most
    ``chunk`` rows at a time — never a ``fetchall`` of the whole
    result and never page-size slicing with silently capped totals.
    The caller holds the read snapshot for the stream duration.
    """
    cursor = export_cursor(conn, filt, classifier, sort)
    try:
        while True:
            batch = cursor.fetchmany(chunk)
            if not batch:
                return
            for row in batch:
                yield export_row_to_dict(row)
    finally:
        cursor.close()


#: Backwards-compatible alias (internal callers renamed to public).
_export_row_to_dict = export_row_to_dict


def request_rows(
    conn: sqlite3.Connection, query: ExplorerQuery, classifier: Classifier
) -> tuple[list[dict[str, object]], int]:
    """Sanitized paginated request rows in one allowlisted server sort.

    Exposes only minimized fields: no raw lines, original IPs, query
    values or full user agents (truncated to 200 chars with an explicit
    truncation flag). The conflict flag is a derived boolean computed
    from the full stored sanitized agent — the full value itself never
    leaves the database. Approved SAFE enrichment travels alongside
    (format/policy provenance, sanitized referrer scheme/host/path,
    logged host, HTTP version, measured request/upstream timing,
    cache status, logged MIME, TLS); Combined-only/old absent values
    stay ``None``. No private original-IP join or field participates.
    """
    filt = query.filt
    sql, params = _explorer_select(filt, classifier, query.sort)
    total = count_export_rows(conn, filt, classifier)
    rows = conn.execute(f"{sql} LIMIT ? OFFSET ?", [*params, filt.limit, filt.offset]).fetchall()
    return [export_row_to_dict(row) for row in rows], total


def request_rows_with_ids(
    conn: sqlite3.Connection, query: ExplorerQuery, classifier: Classifier
) -> tuple[list[tuple[int, dict[str, object]]], int]:
    """Sanitized page rows paired with their internal request identity.

    Runs the SAME ``_explorer_select`` scope/order as :func:`request_rows`
    (same snapshot, same ``ORDER BY``, same page slice) but projects the
    internal ``requests.id`` alongside so a session-gated private reader
    can bind each displayed row to its own encrypted original by primary
    key — never by timestamp/path/pseudonym or row ordinal, so
    legitimate duplicate rows each resolve to their own event. The IDs
    are internal-only: web callers must never serialize them into API
    responses, exports, model tools, errors or shared DTOs.
    """
    filt = query.filt
    sql, params = _explorer_select(filt, classifier, query.sort)
    total = count_export_rows(conn, filt, classifier)
    id_sql = sql.replace("SELECT ts_utc,", "SELECT id, ts_utc,", 1)
    rows = conn.execute(f"{id_sql} LIMIT ? OFFSET ?", [*params, filt.limit, filt.offset]).fetchall()
    paired: list[tuple[int, dict[str, object]]] = []
    for row in rows:
        paired.append((int(row[0]), export_row_to_dict(tuple(row[1:]))))
    return paired, total


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
        f" COUNT(CASE WHEN status >= 400 THEN 1 END), {_SUM_BYTES_HALVES}"
        f" FROM requests WHERE {where} GROUP BY kind ORDER BY COUNT(*) DESC, kind ASC",
        params,
    ).fetchall()
    return [
        {
            "kind": kind,
            "requests": count,
            "errors": errors,
            "bytes_total": combine_bytes_total(hi, lo),
        }
        for kind, count, errors, hi, lo in rows
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
        " COALESCE(SUM(((CASE"
        f" WHEN {cand_sql} THEN bytes ELSE 0 END)) >> 32), 0),"
        " COALESCE(SUM(((CASE"
        f" WHEN {cand_sql} THEN bytes ELSE 0 END)) & 4294967295), 0),"
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
    for path, count, hi, lo, raw_indexes in rows:
        indexes = sorted({int(part) for part in str(raw_indexes).split(",") if part.strip()})
        rules = [index_to_id[i] for i in indexes if i in index_to_id]
        providers = sorted({by_id[r].provider for r in rules if by_id[r].provider})
        ai_total = combine_bytes_total(hi, lo)
        assert ai_total is not None  # COALESCE halves never yield NULL
        items.append(
            {
                "path": path,
                "ai_requests": int(count),
                "ai_bytes": ai_total,
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
        f" {rule_case} AS rule_id, COUNT(*) AS requests,"
        " COALESCE(SUM((bytes) >> 32), 0), COALESCE(SUM((bytes) & 4294967295), 0)"
        f" FROM requests WHERE {match_scoped}"
        " GROUP BY path, rule_id ORDER BY requests DESC, path ASC, rule_id ASC"
        " LIMIT ? OFFSET ?",
        [*rule_params, *match_params, filt.limit, filt.offset],
    ).fetchall()
    by_id = {rule_id: rule for rule_id, rule in zip(classifier.rule_ids, classifier.rules)}
    items: list[dict[str, object]] = []
    for path, rule_id, count, hi, lo in rows:
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
                "bytes_total": combine_bytes_total(hi, lo),
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


def referrer_urls(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    classifier: Classifier | None,
    own_hosts: set[str] | None = None,
    *,
    relation: ReferrerRelation = "all",
) -> tuple[list[dict[str, object]], int]:
    """All sanitized referrer source URLs over the filtered scope.

    Every request carrying a stored referrer contributes, regardless
    of status (2xx/3xx/304/4xx/5xx unless the caller filters): this
    fills the LogWerk ``renderRefererUrls`` gap that a 404-only page
    leaves. Keys use ONLY the minimized stored referrer (lowercase
    host without port/userinfo, ``http``/``https`` scheme or ``None``,
    secret-masked path without query values). Rows whose referrer
    host is a configured own host/alias are labelled internal;
    everything else is external. Missing scheme/path stays ``None``
    (rendered as Unknown, never an invented URL or direct-traffic
    claim). Totals come from an exact grouped subquery; the stable
    order (requests DESC, host ASC, scheme NULLS LAST, path NULLS
    LAST) pages deterministically. ``requests`` counts all rows,
    ``errors`` counts 4xx/5xx rows, ``bytes_total`` sums known bytes
    (``None`` when no row carries bytes) and ``bytes_known`` counts
    rows with known bytes.
    """
    if relation not in ("all", "internal", "external"):
        raise ValueError(f"unknown referrer relation: {relation!r}")
    hosts = own_hosts if own_hosts is not None else own_hosts_for_scope(conn, filt)
    lowered = sorted({h.lower() for h in hosts if h})
    where, params = _where(filt, classifier)
    scoped = f"{where} AND referer_host IS NOT NULL"
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
            " GROUP BY referer_host, referer_scheme, referer_path)",
            [*params, *relation_params],
        ).fetchone()[0]
    )
    # Un-COALESCEd halves preserve the all-NULL contract: a group
    # with no known bytes yields NULL halves, combined to None.
    rows = conn.execute(
        "SELECT referer_host, referer_scheme, referer_path, COUNT(*) AS requests,"
        " SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) AS errors,"
        " SUM((bytes) >> 32), SUM((bytes) & 4294967295), COUNT(bytes) AS bytes_known"
        f" FROM requests WHERE {scoped}"
        " GROUP BY referer_host, referer_scheme, referer_path"
        " ORDER BY requests DESC, referer_host ASC,"
        " referer_scheme ASC NULLS LAST, referer_path ASC NULLS LAST"
        " LIMIT ? OFFSET ?",
        [*params, *relation_params, filt.limit, filt.offset],
    ).fetchall()
    lowered_set = set(lowered)
    items: list[dict[str, object]] = []
    for host, scheme, ref_path, count, errors, hi, lo, known in rows:
        items.append(
            {
                "referer_host": host,
                "referer_scheme": scheme,
                "referer_path": ref_path,
                "requests": int(count),
                "errors": int(errors or 0),
                "bytes_total": combine_bytes_total(hi, lo),
                "bytes_known": int(known or 0),
                "internal": str(host).lower() in lowered_set,
            }
        )
    return items, total


#: Request-journey inactivity threshold (seconds). A gap STRICTLY
#: greater than this between two consecutive events of one
#: (client pseudonym, sanitized User-Agent) key starts a new journey;
#: a gap of exactly 1800 s continues the same journey. Journeys are
#: technical groupings, never visitors, people, sessions or clicks.
JOURNEY_GAP_SECONDS = 1800

#: Same threshold in integer epoch microseconds for the exact SQL
#: comparisons (:func:`epoch_micros` differences). Fractional gaps
#: split precisely: 1800.000000 s continues, 1800.000001 s starts new.
JOURNEY_GAP_MICROS = JOURNEY_GAP_SECONDS * 1_000_000

#: Bounded journey reads: only the requested page crosses into Python.
JOURNEY_SAMPLE_PATHS = 20
JOURNEY_MAX_OFFENDERS = 100


def journey_id_for(
    site_id: str,
    source_id: str | None,
    client_pseudonym: str,
    user_agent: str | None,
    start_ts: str,
) -> str:
    """Stable journey identity for one grouping key and start instant.

    SHA-256 over the site/source scope, the HMAC pseudonym, the
    sanitized User-Agent (``None`` marked explicitly so it can never
    collide with a stored agent) and the ISO start instant. No
    plaintext address or tracking cookie ever participates.
    """
    digest = hashlib.sha256()
    ua_part = "\x00null" if user_agent is None else "S:" + user_agent
    for part in (site_id, source_id or "", client_pseudonym, ua_part, start_ts):
        digest.update(b"\x1f")
        digest.update(part.encode("utf-8"))
    return digest.hexdigest()


def _journey_segments(
    filt: AnalyticsFilter, classifier: Classifier | None = None
) -> tuple[str, list[object], str, list[object]]:
    """Segmented journey CTE over the authorized base scope.

    Boundaries derive from the site/source/window event stream BEFORE
    any content matcher: the ``shown`` conditional aggregate applies
    the caller's matchers afterwards, so a filter that hides the
    first or a middle request shrinks ``shown`` but never invents a
    new start. Returns the CTE text, its bound params, the ``shown``
    predicate (with its own params) and the window ISO bounds.

    The base projection carries every stored column the shared
    matchers can reference (host, HTTP version, MIME, cache, TLS,
    measured/upstream timing, offline country) alongside the grouping
    keys, so a metadata filter narrows ``shown`` exactly like
    everywhere else instead of failing with an unknown column. Gap
    and edge comparisons use exact integer epoch microseconds
    (:func:`epoch_micros`), so fractional instants split journeys
    precisely at the 1800-second boundary.
    """
    base_where, base_params = _base_where(filt)
    matcher_clauses, matcher_params = _matcher_clauses(filt, classifier)
    if matcher_clauses:
        shown_cond = " AND ".join(f"({clause})" for clause in matcher_clauses)
    else:
        shown_cond = "1 = 1"
    cte = (
        "WITH base AS ("
        " SELECT id, ts_utc, method, path, status, bytes, referer_host,"
        " user_agent, client_pseudonym,"
        " server_host, http_version, mime_type, cache_status, tls_protocol,"
        " request_time_ms, upstream_time_ms, country_code,"
        " geo_source, geo_release, geo_status"
        f" FROM requests WHERE {base_where}"
        "), prev AS ("
        " SELECT base.*,"
        " LAG(ts_utc) OVER (PARTITION BY client_pseudonym, user_agent"
        " ORDER BY ts_utc ASC, id ASC) AS prev_ts"
        " FROM base"
        "), marked AS ("
        " SELECT prev.*, CASE WHEN prev_ts IS NULL THEN 1"
        f" WHEN epoch_micros(ts_utc) - epoch_micros(prev_ts) > {JOURNEY_GAP_MICROS} THEN 1"
        " ELSE 0 END AS is_start FROM prev"
        "), numbered AS ("
        " SELECT marked.*, SUM(is_start) OVER (PARTITION BY client_pseudonym,"
        " user_agent ORDER BY ts_utc ASC, id ASC ROWS UNBOUNDED PRECEDING) AS jseq"
        " FROM marked"
        "), keyed AS ("
        " SELECT numbered.*, MAX(jseq) OVER (PARTITION BY client_pseudonym,"
        " user_agent) AS jmax,"
        " FIRST_VALUE(path) OVER (PARTITION BY client_pseudonym, user_agent,"
        " jseq ORDER BY ts_utc ASC, id ASC) AS entry_path"
        " FROM numbered"
        "), journeys AS ("
        " SELECT client_pseudonym, user_agent,"
        " MIN(ts_utc) AS start_ts, MAX(ts_utc) AS end_ts,"
        " COUNT(*) AS total,"
        f" SUM(CASE WHEN {shown_cond} THEN 1 ELSE 0 END) AS shown,"
        " MIN(jseq) AS jseq, MAX(jmax) AS jmax, MAX(entry_path) AS entry_path"
        " FROM keyed GROUP BY client_pseudonym, user_agent, jseq"
        ")"
    )
    return cte, base_params, shown_cond, matcher_params


def _journey_edge_columns(window_from: str, window_to: str) -> tuple[str, list[object]]:
    """Window-edge truncation flags for one journey row.

    The window is half-open ``[from, to)`` and the edges are
    deliberately asymmetric. A first-of-key journey is
    left-truncated only when an unseen predecessor could still join
    it (``start - from < gap``): an excluded predecessor stands
    strictly before ``from``, so at exactly the gap distance its gap
    would strictly exceed the limit and start its own journey. A
    last-of-key journey is right-truncated when
    ``to - end <= gap``: an unseen successor may sit exactly on the
    excluded ``to`` edge, and a gap of exactly 1800 seconds
    continues the journey. All differences are exact integer epoch
    microseconds. No read outside the authorized window ever
    happens: uncertainty is flagged, not resolved by widening.
    """
    sql = (
        "CASE WHEN jseq = 1 AND epoch_micros(start_ts) - epoch_micros(?) <"
        f" {JOURNEY_GAP_MICROS} THEN 1 ELSE 0 END AS left_truncated,"
        " CASE WHEN jseq = jmax AND epoch_micros(?) - epoch_micros(end_ts) <="
        f" {JOURNEY_GAP_MICROS} THEN 1 ELSE 0 END AS right_truncated"
    )
    return sql, [window_from, window_to]


_JOURNEY_ORDER: dict[str, str] = {
    "requests_desc": (
        "shown DESC, start_ts ASC, client_pseudonym ASC,"
        " jseq ASC, COALESCE(user_agent, CHAR(0)) ASC"
    ),
    "start_asc": (
        "start_ts ASC, client_pseudonym ASC, jseq ASC, COALESCE(user_agent, CHAR(0)) ASC"
    ),
    "start_desc": (
        "start_ts DESC, client_pseudonym ASC, jseq ASC, COALESCE(user_agent, CHAR(0)) ASC"
    ),
    "duration_desc": (
        "(epoch_micros(end_ts) - epoch_micros(start_ts)) DESC, start_ts ASC,"
        " client_pseudonym ASC, jseq ASC, COALESCE(user_agent, CHAR(0)) ASC"
    ),
}


def journey_list(
    conn: sqlite3.Connection, query: JourneyQuery, classifier: Classifier | None = None
) -> tuple[list[dict[str, object]], int]:
    """Paginated request journeys with exact totals and edge honesty.

    ``total`` counts eligible journeys (at least ``min_requests``
    filtered/shown requests) exactly — never a capped distinct scan,
    never a silent truncation. Each row carries the unfiltered
    ``requests_total`` alongside the filtered ``requests_shown``
    count, the stable journey ID, the base-scope entry path and
    explicit window-edge flags. Elapsed time travels as float
    ``duration_s`` with the exact integer-microsecond
    ``duration_us`` companion (same epoch-micros arithmetic as the
    grouping/sort). Only the requested page crosses into
    Python — never a ``fetchall`` of every event.
    """
    filt = query.filt
    cte, cte_params, _shown_cond, matcher_params = _journey_segments(filt, classifier)
    edge_sql, edge_params = _journey_edge_columns(
        filt.window.time_from.isoformat(), filt.window.time_to.isoformat()
    )
    eligible = (
        f"{cte}, eligible AS (SELECT client_pseudonym, user_agent, start_ts, end_ts,"
        f" total, shown, jseq, jmax, entry_path, {edge_sql} FROM journeys WHERE shown >= ?)"
    )
    base_args: list[object] = [*cte_params, *matcher_params, *edge_params, query.min_requests]
    total = int(conn.execute(f"{eligible} SELECT COUNT(*) FROM eligible", base_args).fetchone()[0])
    try:
        order = _JOURNEY_ORDER[query.sort]
    except KeyError as exc:
        raise ValueError(f"unknown journey sort: {query.sort!r}") from exc
    rows = conn.execute(
        f"{eligible} SELECT client_pseudonym, user_agent, start_ts, end_ts, total, shown,"
        " jseq, jmax, entry_path, left_truncated, right_truncated"
        f" FROM eligible ORDER BY {order} LIMIT ? OFFSET ?",
        [*base_args, filt.limit, filt.offset],
    ).fetchall()
    items = []
    for client, agent, start, end, total_n, shown_n, _jseq, _jmax, entry, left, right in rows:
        left_flag = bool(left)
        right_flag = bool(right)
        if left_flag and right_flag:
            completeness = "partial-both"
        elif left_flag:
            completeness = "partial-left"
        elif right_flag:
            completeness = "partial-right"
        else:
            completeness = "complete"
        # Exact elapsed microseconds (the same epoch-micros
        # arithmetic the grouping/sort uses): float seconds for
        # display plus the exact integer companion, so a 1us
        # journey reads 1us instead of a floored 0.
        duration_us = epoch_micros(str(end)) - epoch_micros(str(start))
        items.append(
            {
                "journey_id": journey_id_for(
                    filt.site_id, filt.source_id, str(client), agent, str(start)
                ),
                "client_pseudonym": client,
                "requests_total": int(total_n),
                "requests_shown": int(shown_n),
                "started_at": start,
                "ended_at": end,
                "duration_s": duration_us / 1_000_000,
                "duration_us": duration_us,
                "entry_path": entry,
                "left_truncated": left_flag,
                "right_truncated": right_flag,
                "completeness": completeness,
            }
        )
    return items, total


def unixepoch_seconds(value: str) -> int:
    """Whole-second epoch for an ISO instant (testable pure helper).

    Kept for source compatibility: new grouping, duration, edge and
    comparison logic uses exact :func:`epoch_micros` instead, so
    fractional instants no longer truncate at the 1800-second
    boundary.
    """

    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return int(parsed.timestamp())


def _journey_timeline_for_key(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    client_pseudonym: str,
    user_agent: str | None,
    start_iso: str,
    classifier: Classifier | None = None,
) -> dict[str, object]:
    """Shared bounded timeline for one resolved journey key.

    ``start_iso`` is the canonical stored start instant; callers
    either supply it directly (:func:`journey_timeline`) or resolve
    it from an opaque journey ID first
    (:func:`journey_timeline_by_id`).
    """
    cte, cte_params, shown_cond, matcher_params = _journey_segments(filt, classifier)
    key_args: list[object] = [client_pseudonym, user_agent]
    target = conn.execute(
        f"{cte} SELECT jseq, total, shown, start_ts, end_ts, entry_path FROM journeys"
        " WHERE client_pseudonym = ? AND COALESCE(user_agent, CHAR(0)) = COALESCE(?, CHAR(0))"
        " AND start_ts = ?",
        [*cte_params, *matcher_params, *key_args, start_iso],
    ).fetchone()
    if target is None:
        raise KeyError("unknown journey: no journey starts there for that client")
    jseq, total_n, _shown_all, start_ts, end_ts, entry_path = target
    shown_total = int(
        conn.execute(
            f"{cte}, keyed_rows AS (SELECT * FROM keyed"
            " WHERE client_pseudonym = ?"
            " AND COALESCE(user_agent, CHAR(0)) = COALESCE(?, CHAR(0)) AND jseq = ?)"
            f" SELECT COUNT(*) FROM keyed_rows WHERE {shown_cond}",
            [*cte_params, *matcher_params, *key_args, jseq, *matcher_params],
        ).fetchone()[0]
    )
    rows = conn.execute(
        f"{cte}, keyed_rows AS (SELECT * FROM keyed"
        " WHERE client_pseudonym = ?"
        " AND COALESCE(user_agent, CHAR(0)) = COALESCE(?, CHAR(0)) AND jseq = ?)"
        " SELECT ts_utc, method, path, status, bytes, referer_host,"
        " substr(user_agent, 1, 200),"
        " CASE WHEN user_agent IS NOT NULL AND LENGTH(user_agent) > 200 THEN 1 ELSE 0 END,"
        " country_code, geo_status"
        f" FROM keyed_rows WHERE {shown_cond}"
        " ORDER BY ts_utc ASC, id ASC LIMIT ? OFFSET ?",
        [
            *cte_params,
            *matcher_params,
            *key_args,
            jseq,
            *matcher_params,
            filt.limit,
            filt.offset,
        ],
    ).fetchall()
    edge_sql, edge_params = _journey_edge_columns(
        filt.window.time_from.isoformat(), filt.window.time_to.isoformat()
    )
    edge = conn.execute(
        f"{cte} SELECT {edge_sql} FROM journeys"
        " WHERE client_pseudonym = ? AND COALESCE(user_agent, CHAR(0)) = COALESCE(?, CHAR(0))"
        " AND start_ts = ?",
        [*cte_params, *matcher_params, *edge_params, *key_args, start_iso],
    ).fetchone()
    assert edge is not None
    left_flag, right_flag = bool(edge[0]), bool(edge[1])
    items = [
        {
            "ts_utc": ts,
            "method": method,
            "path": path,
            "status": status,
            "bytes": nbytes,
            "referer_host": host,
            "user_agent": agent,
            "ua_truncated": bool(truncated),
            "country_code": country,
            "geo_status": geo_status,
        }
        for ts, method, path, status, nbytes, host, agent, truncated, country, geo_status in rows
    ]
    return {
        "journey_id": journey_id_for(
            filt.site_id, filt.source_id, client_pseudonym, user_agent, str(start_ts)
        ),
        "client_pseudonym": client_pseudonym,
        "started_at": start_ts,
        "ended_at": end_ts,
        "entry_path": entry_path,
        "requests_total": int(total_n),
        "requests_shown": shown_total,
        "left_truncated": left_flag,
        "right_truncated": right_flag,
        "items": items,
        "shown": len(items),
        "total": shown_total,
        "truncated": shown_total > filt.offset + len(items),
        "limit": filt.limit,
        "offset": filt.offset,
    }


def journey_timeline(
    conn: sqlite3.Connection, query: JourneyTimelineQuery, classifier: Classifier | None = None
) -> dict[str, object]:
    """Bounded chronological timeline for one journey key.

    The journey is re-derived with the same gap rule over the same
    authorized scope, then the caller's matchers select the shown
    rows: ``shown``/``total`` stay explicit even when filters hide the
    entry request. Raises ``KeyError`` for an unknown journey key.
    """
    return _journey_timeline_for_key(
        conn,
        query.filt,
        query.client_pseudonym,
        query.user_agent,
        query.journey_start.isoformat(),
        classifier,
    )


def journey_key_for_id(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    *,
    client_pseudonym: str,
    journey_start: datetime,
    journey_id: str,
    classifier: Classifier | None = None,
) -> tuple[str | None, str]:
    """Resolve an opaque journey ID to its grouping key in scope.

    Only the validated site/source/window event stream is read: every
    journey start for the client whose instant exactly equals the
    requested one (compared as integer epoch microseconds, so
    equivalent UTC offsets match) is re-hashed with
    :func:`journey_id_for` and the ID must match exactly. Distinct
    User-Agents sharing one client and start instant (including
    ``None`` versus empty string) hash distinctly, so at most one
    key matches; zero matches raise ``KeyError``. Rows stream
    through a bounded cursor one at a time (no ``fetchall``, no
    cap): high-cardinality same-client/same-start UA sets resolve
    with O(1) memory and a late match is never dropped. The full
    stored agent is never returned here — only handed to the
    timeline builder — and no original address participates.
    """
    wanted_us = epoch_micros(journey_start.isoformat())
    cte, cte_params, _shown_cond, matcher_params = _journey_segments(filt, classifier)
    # Streaming bounded cursor: rows are hashed one at a time and the
    # scan stops at the first exact ID match, so memory stays O(1) no
    # matter how many User-Agents share one client/start instant. No
    # LIMIT/cap is applied: a valid match near the end is still found.
    cursor = conn.execute(
        f"{cte} SELECT user_agent, start_ts FROM journeys"
        " WHERE client_pseudonym = ? AND epoch_micros(start_ts) = ?",
        [*cte_params, *matcher_params, client_pseudonym, wanted_us],
    )
    try:
        for agent, start_ts in cursor:
            candidate = journey_id_for(
                filt.site_id, filt.source_id, client_pseudonym, agent, str(start_ts)
            )
            if candidate == journey_id:
                return agent, str(start_ts)
    finally:
        cursor.close()
    raise KeyError("unknown journey: no journey in scope matches that ID")


def journey_timeline_by_id(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    *,
    client_pseudonym: str,
    journey_start: datetime,
    journey_id: str,
    classifier: Classifier | None = None,
) -> dict[str, object]:
    """Bounded timeline for one opaque journey ID (same shape as timeline).

    Resolves the key strictly inside the validated scope via
    :func:`journey_key_for_id`, then serves the identical bounded
    timeline — callers never guess a full User-Agent from a
    truncated display field.
    """
    user_agent, start_iso = journey_key_for_id(
        conn,
        filt,
        client_pseudonym=client_pseudonym,
        journey_start=journey_start,
        journey_id=journey_id,
        classifier=classifier,
    )
    return _journey_timeline_for_key(
        conn, filt, client_pseudonym, user_agent, start_iso, classifier
    )


def journey_entry_paths(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    classifier: Classifier | None = None,
    *,
    min_requests: int = 1,
) -> tuple[list[dict[str, object]], int]:
    """Entry-path aggregation over eligible journeys.

    The entry is always the journey's base-scope first request, so a
    filter hiding it cannot move the entry. Journeys qualify with at
    least ``min_requests`` filtered rows; complete and window-edge
    partial journeys aggregate together with both shares reported and
    the partial caveat carried by callers.
    """
    if min_requests < 1:
        raise ValueError("min_requests must be >= 1")
    cte, cte_params, _shown_cond, matcher_params = _journey_segments(filt, classifier)
    edge_sql, edge_params = _journey_edge_columns(
        filt.window.time_from.isoformat(), filt.window.time_to.isoformat()
    )
    scoped = f"{cte}, eligible AS (SELECT entry_path, {edge_sql} FROM journeys WHERE shown >= ?)"
    args: list[object] = [*cte_params, *matcher_params, *edge_params, min_requests]
    total = int(
        conn.execute(f"{scoped} SELECT COUNT(DISTINCT entry_path) FROM eligible", args).fetchone()[
            0
        ]
    )
    rows = conn.execute(
        f"{scoped} SELECT entry_path, COUNT(*) AS journeys,"
        " SUM(CASE WHEN left_truncated = 0 AND right_truncated = 0 THEN 1 ELSE 0 END)"
        " AS complete_journeys,"
        " SUM(CASE WHEN left_truncated = 1 OR right_truncated = 1 THEN 1 ELSE 0 END)"
        " AS partial_journeys"
        " FROM eligible GROUP BY entry_path"
        " ORDER BY journeys DESC, entry_path ASC LIMIT ? OFFSET ?",
        [*args, filt.limit, filt.offset],
    ).fetchall()
    return (
        [
            {
                "entry_path": path,
                "journeys": int(count),
                "complete_journeys": int(complete),
                "partial_journeys": int(partial),
            }
            for path, count, complete, partial in rows
        ],
        total,
    )


def _rule_row_condition(rule: Rule) -> tuple[str, list[object]]:
    """Conjunction of stored-field matchers for one security rule.

    ``path_contains`` matches the stored sanitized (query-stripped,
    secret-masked) path as a case-insensitive substring; ``%``/``_``
    in fragments are LIKE-escaped so they match literally, never as
    wildcards. No percent-decoding is performed at ingest or here, so
    an encoded spelling (``%2e``) matches only the literal stored
    spelling — the wire encoding it implies is documented per rule,
    never decoded. ``status_in`` matches the stored origin status.
    Rejected lines and raw bytes never participate.
    """
    clauses: list[str] = []
    params: list[object] = []
    if rule.path_contains:
        fragments = []
        for fragment in rule.path_contains:
            fragments.append("lower(path) LIKE ? ESCAPE '\\'")
            params.append("%" + _like_escape(fragment.lower()) + "%")
        clauses.append("(" + " OR ".join(fragments) + ")")
    if rule.status_in:
        placeholders = ", ".join("?" for _ in rule.status_in)
        clauses.append(f"status IN ({placeholders})")
        params.extend(rule.status_in)
    if not clauses:
        return "1 = 1", []
    return " AND ".join(clauses), params


def security_rule_totals(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    rule: Rule,
    classifier: Classifier | None = None,
) -> dict[str, int]:
    """Exact whole-scope totals for one aggregate security rule.

    A single ``GROUP BY``-free SQL aggregation over every matching
    row: totals stay exact no matter how many distinct paths exist.
    Only the bounded sample (see :func:`security_rule_sample`) pages.
    """
    where, params = _where(filt, classifier)
    cond, cond_params = _rule_row_condition(rule)
    row = conn.execute(
        f"SELECT COUNT(*), COUNT(DISTINCT path) FROM requests WHERE {where} AND ({cond})",
        [*params, *cond_params],
    ).fetchone()
    return {"requests": int(row[0]), "distinct_paths": int(row[1])}


def security_rule_sample(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    rule: Rule,
    classifier: Classifier | None = None,
    *,
    limit: int = JOURNEY_SAMPLE_PATHS,
) -> tuple[list[dict[str, object]], int]:
    """Bounded top path/status rows for one rule plus the exact group total.

    ``errors`` counts every stored error status (4xx AND 5xx) in the
    group — a ``/.env`` probe returning 500 is an error exactly like a
    404 — with the ``errors_4xx``/``errors_5xx`` split alongside so
    2xx/304 validation rows stay visibly non-errors.
    """
    where, params = _where(filt, classifier)
    cond, cond_params = _rule_row_condition(rule)
    total = int(
        conn.execute(
            "SELECT COUNT(*) FROM (SELECT 1 FROM requests"
            f" WHERE {where} AND ({cond}) GROUP BY path, status)",
            [*params, *cond_params],
        ).fetchone()[0]
    )
    rows = conn.execute(
        "SELECT path, status, COUNT(*) AS requests,"
        " COUNT(CASE WHEN status >= 400 THEN 1 END) AS errors,"
        " COUNT(CASE WHEN status BETWEEN 400 AND 499 THEN 1 END) AS errors_4xx,"
        " COUNT(CASE WHEN status BETWEEN 500 AND 599 THEN 1 END) AS errors_5xx"
        f" FROM requests WHERE {where} AND ({cond})"
        " GROUP BY path, status ORDER BY requests DESC, path ASC, status ASC LIMIT ?",
        [*params, *cond_params, limit],
    ).fetchall()
    return (
        [
            {
                "path": path,
                "status": status,
                "requests": int(count),
                "errors": int(errors),
                "errors_4xx": int(errors_4xx),
                "errors_5xx": int(errors_5xx),
            }
            for path, status, count, errors, errors_4xx, errors_5xx in rows
        ],
        total,
    )


#: Cap for per-pseudonym offender pages: only the top slice crosses
#: into Python, with shown/total/truncated reported explicitly.
SECURITY_MAX_OFFENDERS = JOURNEY_MAX_OFFENDERS
SECURITY_OFFENDER_PATHS = 5

#: Bounded chronological path-sequence rows per offender (F tempo
#: evidence): an ordered sample with exact totals, never a fetchall.
SECURITY_SEQUENCE_PER_OFFENDER = 10


def offender_sample_stats(
    conn: sqlite3.Connection,
    sample_where: str,
    sample_params: list[object],
    client_pseudonyms: list[str],
) -> dict[str, dict[str, int]]:
    """Exact per-client sample-scope stats in ONE grouped query.

    For every requested pseudonym returns the exact row count
    (``scope_rows``), the distinct-path count (``distinct_paths``)
    and the exact (path, status) group count (``groups_total``) in
    the sample scope. Groups and paths differ as soon as one path
    carries several statuses, so both travel together and samples
    can never claim a shown slice larger than its total. An empty
    request list returns without touching the database.
    """
    wanted = [p for p in dict.fromkeys(client_pseudonyms) if p][:MAX_SAMPLE_CLIENTS]
    if not wanted:
        return {}
    placeholders = ", ".join("?" for _ in wanted)
    rows = conn.execute(
        "SELECT client_pseudonym, COUNT(*) AS rows,"
        " COUNT(DISTINCT path) AS paths,"
        " COUNT(DISTINCT path || '\x1f' || status) AS groups"
        f" FROM requests WHERE {sample_where} AND client_pseudonym IN ({placeholders})"
        " GROUP BY client_pseudonym",
        [*sample_params, *wanted],
    ).fetchall()
    stats = {
        client: {"scope_rows": n, "distinct_paths": p, "groups_total": g}
        for client, n, p, g in rows
    }
    for requested in wanted:
        stats.setdefault(requested, {"scope_rows": 0, "distinct_paths": 0, "groups_total": 0})
    return stats


def offender_minute_peaks(
    conn: sqlite3.Connection,
    sample_where: str,
    sample_params: list[object],
    client_pseudonyms: list[str],
) -> dict[str, dict[str, object]]:
    """Peak whole-UTC-minute burst per client, ranked in SQL.

    Stored timestamps are UTC-normalized ISO text, so
    ``substr(ts_utc, 1, 16)`` buckets whole UTC minutes exactly;
    fractional rows fall into their truncated minute (documented,
    never interpolated). Ranking happens in SQL with
    ``ROW_NUMBER()`` partitioned by client ordered by hits DESC,
    minute ASC (exact earliest tie), so at most ONE row per
    requested client crosses into Python no matter how many minute
    buckets exist (never up to ``100*366*1440`` groups). Missing
    clients map to a zero peak. An empty request list returns
    without touching the database.
    """
    wanted = [p for p in dict.fromkeys(client_pseudonyms) if p][:MAX_SAMPLE_CLIENTS]
    if not wanted:
        return {}
    placeholders = ", ".join("?" for _ in wanted)
    rows = conn.execute(
        "SELECT client_pseudonym, minute, hits FROM ("
        " SELECT client_pseudonym, substr(ts_utc, 1, 16) AS minute,"
        " COUNT(*) AS hits,"
        " ROW_NUMBER() OVER (PARTITION BY client_pseudonym"
        " ORDER BY COUNT(*) DESC, substr(ts_utc, 1, 16) ASC) AS rn"
        f" FROM requests WHERE {sample_where} AND client_pseudonym IN ({placeholders})"
        " GROUP BY client_pseudonym, minute"
        ") WHERE rn = 1",
        [*sample_params, *wanted],
    ).fetchall()
    peaks: dict[str, dict[str, object]] = {
        p: {"peak_minute_requests": 0, "peak_minute": None} for p in wanted
    }
    for client, minute, hits in rows:
        peaks[str(client)] = {"peak_minute_requests": int(hits), "peak_minute": minute}
    return peaks


def offender_sequences(
    conn: sqlite3.Connection,
    sample_where: str,
    sample_params: list[object],
    client_pseudonyms: list[str],
    *,
    limit: int = SECURITY_SEQUENCE_PER_OFFENDER,
) -> dict[str, list[dict[str, object]]]:
    """First chronological (ts, path, status) rows per client, batched.

    ONE ``ROW_NUMBER()`` query partitioned by client, ordered by
    ``ts_utc`` ASC and row id ASC (identical instants keep a stable
    order). Gaps between consecutive sampled rows are exact integer
    epoch microseconds floored to whole seconds (``gap_prev_s``,
    ``None`` for the first row). Missing clients map to ``[]``; an
    empty request list returns without touching the database.
    """
    wanted = [p for p in dict.fromkeys(client_pseudonyms) if p][:MAX_SAMPLE_CLIENTS]
    if not wanted or limit < 1:
        return {p: [] for p in dict.fromkeys(client_pseudonyms) if p}
    placeholders = ", ".join("?" for _ in wanted)
    rows = conn.execute(
        "SELECT client_pseudonym, ts_utc, path, status FROM ("
        " SELECT client_pseudonym, ts_utc, path, status,"
        " ROW_NUMBER() OVER (PARTITION BY client_pseudonym"
        " ORDER BY ts_utc ASC, id ASC) AS rn"
        f" FROM requests WHERE {sample_where} AND client_pseudonym IN ({placeholders})"
        ") WHERE rn <= ? ORDER BY client_pseudonym ASC, rn ASC",
        [*sample_params, *wanted, limit],
    ).fetchall()
    grouped: dict[str, list[dict[str, object]]] = {p: [] for p in wanted}
    prev_us: dict[str, int] = {}
    for client, ts, path, status in rows:
        try:
            moment_us = epoch_micros(str(ts))
        except ValueError:
            moment_us = 0
        gap = None if client not in prev_us else (moment_us - prev_us[client]) // 1_000_000
        prev_us[client] = moment_us
        if len(grouped[client]) < limit:
            grouped[client].append(
                {"ts_utc": ts, "path": path, "status": status, "gap_prev_s": gap}
            )
    for requested in dict.fromkeys(client_pseudonyms):
        grouped.setdefault(requested, [])
    return grouped


def security_offenders(
    conn: sqlite3.Connection,
    filt: AnalyticsFilter,
    rule: Rule,
    classifier: Classifier | None = None,
) -> tuple[list[dict[str, object]], int]:
    """Per-pseudonym rate/breadth offenders for one threshold rule.

    ``min_client_errors`` keeps the legacy 4xx meaning (any stored
    4xx counts). ``min_client_requests`` counts matching rows after
    the rule's own ``path_contains``/``status_in`` narrowing;
    ``min_client_distinct_paths`` additionally requires that many
    distinct matching paths (probe-sweep candidate). Thresholds
    combine by conjunction. Exact offender total via a grouped
    subquery; only the top page (requests DESC, pseudonym ASC) plus
    constant bounded batched reads cross into Python: one grouped
    path sample (:func:`_sample_paths_scoped`), one exact
    per-client stats query (:func:`offender_sample_stats`), one
    whole-minute burst query (:func:`offender_minute_peaks`) and one
    chronological sequence query (:func:`offender_sequences`). The
    SELECT count is therefore constant no matter how many offenders
    are shown. The sample spans the offender's narrowed scope,
    except for the legacy un-narrowed 4xx rule, which keeps its
    historic all-status sample. Rejected lines never count: only
    stored events aggregate here.
    """
    where, params = _where(filt, classifier)
    cond, cond_params = _rule_row_condition(rule)
    predicates = [f"({cond})"]
    having: list[str] = []
    if rule.min_client_errors is not None:
        predicates.append("status BETWEEN 400 AND 499")
        having.append(f"COUNT(*) >= {int(rule.min_client_errors)}")
    if rule.min_client_requests is not None:
        having.append(f"COUNT(*) >= {int(rule.min_client_requests)}")
    if rule.min_client_distinct_paths is not None:
        having.append(f"COUNT(DISTINCT path) >= {int(rule.min_client_distinct_paths)}")
    if not having:
        raise ValueError(f"rule {rule.id} sets no per-client threshold")
    scoped = f"{where} AND {' AND '.join(predicates)}"
    args: list[object] = [*params, *cond_params]
    total = int(
        conn.execute(
            f"SELECT COUNT(*) FROM (SELECT 1 FROM requests WHERE {scoped}"
            f" GROUP BY client_pseudonym HAVING {' AND '.join(having)})",
            args,
        ).fetchone()[0]
    )
    rows = conn.execute(
        "SELECT client_pseudonym, COUNT(*) AS hits, COUNT(DISTINCT path) AS paths"
        f" FROM requests WHERE {scoped} GROUP BY client_pseudonym"
        f" HAVING {' AND '.join(having)}"
        " ORDER BY hits DESC, client_pseudonym ASC LIMIT ?",
        [*args, SECURITY_MAX_OFFENDERS + 1],
    ).fetchall()
    # The legacy 4xx rule (no row narrowing) keeps its historic
    # all-status sample: selection counts 4xx only, the sample shows
    # the offender's other rows too. Narrowed rules (path/status
    # selectors) sample within their own scope instead. Peaks ALWAYS
    # use the rule-matching scope (``scoped``): the peak numerator
    # matches the average numerator (stored 4xx for the legacy rule,
    # rule-matching rows otherwise), so the two tempo figures compare
    # identical traffic. The historic all-status context stays
    # available separately via the path/sequence samples.
    if rule.path_contains or rule.status_in:
        sample_where, sample_params = scoped, args
    else:
        sample_where, sample_params = where, params
    if rule.min_client_errors is not None:
        peak_numerator = "stored 4xx errors"
    else:
        peak_numerator = "rule-matching requests"
    shown = [str(ident) for ident, _hits, _paths in rows[:SECURITY_MAX_OFFENDERS]]
    samples = _sample_paths_scoped(
        conn, sample_where, sample_params, shown, limit=SECURITY_OFFENDER_PATHS
    )
    stats = offender_sample_stats(conn, sample_where, sample_params, shown)
    peaks = offender_minute_peaks(conn, scoped, args, shown)
    sequences = offender_sequences(conn, sample_where, sample_params, shown)
    window_from = filt.window.time_from
    window_to = filt.window.time_to
    offenders = []
    for ident, hits, paths in rows[:SECURITY_MAX_OFFENDERS]:
        key = str(ident)
        stat = stats[key]
        peak = peaks[key]
        minute = peak["peak_minute"]
        if isinstance(minute, str):
            interval_start = f"{minute}:00+00:00"
            try:
                bucket_from = datetime.fromisoformat(interval_start)
                bucket_to = bucket_from + timedelta(seconds=60)
                partial = bucket_from < window_from or bucket_to > window_to
                interval = f"{bucket_from.isoformat()}/{bucket_to.isoformat()}"
            except ValueError:
                partial = True
                interval = f"{interval_start}/+60s"
        else:
            partial = False
            interval = None
        offenders.append(
            {
                "client_pseudonym": ident,
                "hits": int(hits),
                "distinct_paths": int(paths),
                "sample_paths": samples[key],
                # Exact (path, status) groups in the sample scope
                # (differs from distinct paths once one path carries
                # several statuses); shown never exceeds this total.
                "sample_groups_total": stat["groups_total"],
                "sample_scope_requests": stat["scope_rows"],
                "sample_distinct_paths": stat["distinct_paths"],
                "peak_minute_requests": peak["peak_minute_requests"],
                "peak_minute": peak["peak_minute"],
                # Unambiguous tempo scope: peak and average share the
                # same rule-matching numerator (never compared as
                # identical traffic with the all-status samples).
                "peak_minute_scope": "rule_matching",
                "peak_minute_numerator": peak_numerator,
                # Whole-UTC-minute honesty: buckets intersecting a
                # partial query window edge are lower-bound counts
                # over the exact interval below, never a fully
                # observed 60s burst.
                "peak_minute_interval": interval,
                "peak_minute_partial": partial,
                "path_sequence": sequences[key],
                "path_sequence_total": stat["scope_rows"],
            }
        )
    return offenders, total
