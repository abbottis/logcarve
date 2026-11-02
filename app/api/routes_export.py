"""Full-result CSV/JSON export transport (PAR-07).

Exports the ENTIRE selected filtered request result with stable
ordering through ONE owned read snapshot and bounded ``fetchmany``
chunks — never page-size rows, ``fetchall`` or silently capped
totals. Only the allowlisted :data:`app.analytics.queries.EXPORT_COLUMNS`
travel (stable HMAC pseudonyms; never the private original-IP
table, raw lines, query values, keys, exception text or stored
diagnostics), even when an admin display mode is full.

Snapshot ownership (:class:`ExportStream`): the endpoint thread
opens ONE dedicated read-only snapshot and runs the row-cap
pre-count, the metadata queries AND the row-cursor open plus
first-chunk prime BEFORE any byte streams, so store/query failures
map to safe envelopes (503/413/400 with ``request_id``) instead of
a 200 prefix, and a writer committing between preparation and
streaming can neither inflate rows past the cap nor split
count/metadata/rows across generations. The same snapshot stays
open across Starlette's streaming worker threads (a documented
sequential handoff on this one owned handle — never a global
thread-safety switch, never ``fetchall``). The streaming response
itself (:class:`ExportStreamingResponse`) releases the snapshot in
an unconditional ASGI-``__call__`` ``finally`` — normal EOF,
renderer error, task cancellation, older-protocol disconnect and a
send failure before the first body byte all close cursor and
snapshot deterministically, without waiting for GC and without
relying on the row generator's ``finally`` (an unstarted generator
has no executing ``finally``) or the background task (skipped
when the superclass streaming raises). A post-header read failure
aborts the body — never a ``complete: true`` footer.

A caller that prepares an export but never sends its response owns
the same deterministic contract explicitly: close
``info["stream"]`` (via :func:`close_prepared` or
:meth:`ExportStream.close`, or the ``with`` statement) instead of
dropping the prepared handle.

Execution limits (documented, never silent truncation):

- ``EXPORT_MAX_ROWS``: scopes above this reject BEFORE streaming
  with a safe ``export_too_large`` envelope (HTTP 413). Narrow the
  window or filters instead.
- ``EXPORT_CHUNK_ROWS``: rows materialized per chunk while streaming.
- A failed or incomplete stream never masquerades as complete: the
  JSON envelope closes with ``"complete": true`` only on success
  (an aborted body does not parse), and a CSV abort truncates the
  chunked body mid-stream instead of delivering a whole file.
"""

import csv
import io
import json
import math
import re
import sqlite3
import unicodedata
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal, Self

from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask

from app.analytics import queries, service
from app.analytics.contracts import ExplorerSort
from app.analytics.queries import EXPORT_CHUNK_ROWS, EXPORT_COLUMNS
from app.api.deps import StoreUnavailable
from app.api.errors import error_response
from app.api.routes_analytics import (
    BotParam,
    CacheStatus,
    CategoryParam,
    ClientParam,
    CountryParam,
    HttpVersion,
    Method,
    MimeType,
    PathExact,
    PathPrefix,
    ProviderParam,
    PurposeParam,
    RefererHost,
    SearchParam,
    ServerHost,
    SiteId,
    SourceId,
    Status,
    StatusClassParam,
    TimeFrom,
    TimeTo,
    Timezone,
    TimingAvailable,
    TimingMax,
    TimingMin,
    TlsProtocol,
    TrafficParam,
    UpstreamAvailable,
    _deny,
    _params,
    _prepare,
)
from app.db.database import connect

EXPORT_SCHEMA_VERSION = service.EXPORT_SCHEMA_VERSION
EXPORT_PRIVACY_LABEL = service.EXPORT_PRIVACY_LABEL

#: Scopes above this row count reject before streaming (HTTP 413 with
#: a safe envelope). Narrow the window or filters instead: exports
#: never truncate silently.
EXPORT_MAX_ROWS = 250_000

ExportFormat = Annotated[Literal["csv", "json"], Query()]
ExportSort = Annotated[ExplorerSort, Query()]

_CSV_MEDIA_TYPE = "text/csv; charset=utf-8"
_JSON_MEDIA_TYPE = "application/json"

#: Dangerous spreadsheet formula leads. A cell whose first meaningful
#: character is one of these gains a neutralizing single-quote prefix.
_FORMULA_LEADS = ("=", "+", "-", "@")

#: Unicode categories skipped when looking for the first meaningful
#: character (check only — the stored value is always preserved
#: verbatim behind the neutralizing prefix):
#:
#: - ``Cc``: NUL and ASCII controls (``\x00``-``\x1f``, ``\x7f``),
#: - ``Cf``: format bytes (BOM ``U+FEFF``, zero-width ``U+200B`` …),
#: - ``Zl``/``Zp``: line/paragraph separators (``U+2028``/``U+2029``).
#:
#: Plain separators (``Zs``: space, NBSP, …) and the remaining ASCII
#: whitespace arrive via :meth:`str.isspace`. Together this covers
#: every leading byte that could push a formula lead out of a naive
#: ASCII-only check's sight.
_FORMULA_SKIP_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})


def _formula_triggered(text: str) -> bool:
    """True when the first meaningful character starts a formula.

    Leading Unicode whitespace, control and format bytes are skipped
    for the check only; the caller's text is never modified here.
    """
    for char in text:
        if char.isspace() or unicodedata.category(char) in _FORMULA_SKIP_CATEGORIES:
            continue
        return char in _FORMULA_LEADS
    return False


router = APIRouter(prefix="/api/v1")


def csv_cell(value: object) -> object:
    """Neutralize spreadsheet formula injection in one CSV cell.

    Untrusted string cells whose first meaningful character (after
    leading Unicode whitespace, control and format bytes) is ``=``,
    ``+``, ``-`` or ``@`` gain a leading single-quote prefix; the
    original text is preserved verbatim behind that prefix. Quoting
    and newline escaping stay with the ``csv`` writer. ``None`` maps
    to empty (safe-null: missing is never a formula), booleans to
    lowercase literals, and meaningful numerics pass through as
    numbers so they stay unquoted numeric cells. No spreadsheet is
    launched and no formula is ever evaluated here.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        return ""
    text = str(value)
    if _formula_triggered(text):
        return "'" + text
    return text


def safe_filename(site_id: str, time_from: datetime, time_to: datetime, ext: str) -> str:
    """ASCII-safe download filename carrying site and window (no secrets)."""
    safe_site = re.sub(r"[^A-Za-z0-9_.-]", "_", site_id)[:64] or "site"

    def compact(moment: datetime) -> str:
        return moment.strftime("%Y%m%dT%H%M%SZ")

    return f"logcarve-export-{safe_site}-{compact(time_from)}-{compact(time_to)}.{ext}"


#: Per-import entries carried in the CSV coverage header before the
#: explicit truncation flag engages (documented, never silent: the
#: flag travels in the same header value).
_IMPORTS_HEADER_CAP = 50


def _compact_filters(metadata: dict[str, object]) -> dict[str, object]:
    """Non-default validated filters for the CSV header (bounded).

    Only the site plus selectors that actually narrow the scope
    travel (``traffic: all`` and every ``None`` stay out), so the
    header stays small: bounded by the validated contract maxima
    (paths <= 1024, search <= 128, hosts <= 253, ...), typically a
    few hundred bytes. The JSON envelope always carries the full
    validated filter set.
    """
    full = metadata["filters"]
    assert isinstance(full, dict)
    compact: dict[str, object] = {"site_id": full.get("site_id")}
    for key, value in full.items():
        if key == "site_id" or value is None:
            continue
        if key == "traffic" and value == "all":
            continue
        compact[key] = value
    return compact


def _coverage_header(metadata: dict[str, object]) -> dict[str, object]:
    """Coverage/quality summary for the CSV header (bounded, ASCII-safe).

    Scalars plus the per-import ``id``/``status`` list capped at
    :data:`_IMPORTS_HEADER_CAP` with an explicit
    ``imports_truncated`` flag — never silent truncation, never
    ``error_summary``, never originals. The JSON envelope always
    carries the complete list.
    """
    coverage = metadata["coverage"]
    quality = metadata["data_quality"]
    assert isinstance(coverage, dict) and isinstance(quality, dict)
    totals = quality["line_totals"]
    assert isinstance(totals, dict)
    imports = quality["imports"]
    assert isinstance(imports, list)
    return {
        "unique_events": coverage["unique_events"],
        "observed_min": coverage["observed_min"],
        "observed_max": coverage["observed_max"],
        "sources": coverage["sources"],
        "lines_total": totals["lines_total"],
        "lines_accepted": totals["lines_accepted"],
        "lines_rejected": totals["lines_rejected"],
        "records_replayed": totals["records_replayed"],
        "imports_total": len(imports),
        "imports": imports[:_IMPORTS_HEADER_CAP],
        "imports_truncated": len(imports) > _IMPORTS_HEADER_CAP,
    }


def metadata_headers(metadata: dict[str, object], filename: str) -> dict[str, str]:
    """ASCII-safe export metadata headers (JSON adds the full envelope).

    Transport for the CSV download, whose body stays plain
    interoperable CSV (header row plus records, no preamble): every
    value here is ASCII (compact JSON with ``ensure_ascii`` escapes
    free text and controls — never a raw CR/LF), bounded by the
    validated contract maxima plus the explicitly flagged imports
    cap. Carries schema, site/source, UTC window, display timezone,
    sort, generation time, exact count, coverage/quality and
    privacy on the CSV path exactly as the JSON envelope does.
    """
    window = metadata["time_range"]
    assert isinstance(window, dict)
    filters_ascii = json.dumps(_compact_filters(metadata), ensure_ascii=True, sort_keys=True)
    coverage_ascii = json.dumps(_coverage_header(metadata), ensure_ascii=True, sort_keys=True)
    source = metadata.get("source_id")
    return {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Logcarve-Export-Schema": str(metadata["schema_version"]),
        "X-Logcarve-Export-Rows": str(metadata["row_count"]),
        "X-Logcarve-Export-Site": re.sub(r"[^A-Za-z0-9_.-]", "_", str(metadata["site_id"]))[:64],
        "X-Logcarve-Export-Source": (
            re.sub(r"[^A-Za-z0-9_.-]", "_", str(source))[:64] if source else ""
        ),
        "X-Logcarve-Export-Window": f"{window['time_from']}/{window['time_to']}",
        "X-Logcarve-Export-Timezone": str(metadata["display_timezone"]),
        "X-Logcarve-Export-Sort": str(metadata["sort"]),
        "X-Logcarve-Export-Generated-At": str(metadata["generated_at"]),
        "X-Logcarve-Export-Filters": filters_ascii,
        "X-Logcarve-Export-Coverage": coverage_ascii,
        "X-Logcarve-Privacy": "pseudonymized; no original IPs, raw lines, query values or keys",
    }


def csv_chunks(rows) -> object:
    """Render the header plus one CSV record per row, chunk by chunk."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    writer.writerow(list(EXPORT_COLUMNS))
    yield buffer.getvalue()
    for row in rows:
        buffer.seek(0)
        buffer.truncate()
        writer.writerow([csv_cell(row.get(column)) for column in EXPORT_COLUMNS])
        yield buffer.getvalue()


def json_chunks(metadata: dict[str, object], rows) -> object:
    """Render the metadata envelope plus one JSON object per row."""
    yield '{"metadata": '
    yield json.dumps(metadata, ensure_ascii=False, default=str)
    yield ', "rows": ['
    first = True
    for row in rows:
        if not first:
            yield ", "
        first = False
        yield json.dumps(row, ensure_ascii=False, default=str)
    yield '], "complete": true}'


class ExportTooLarge(Exception):
    """The export scope exceeds ``EXPORT_MAX_ROWS`` (maps to HTTP 413)."""

    def __init__(self, total: int) -> None:
        super().__init__(f"export scope holds {total} rows")
        self.total = total


class ExportStream:
    """ONE owned read snapshot spanning preparation through streaming.

    Lifecycle (all in endpoint order, before any byte streams):

    1. :meth:`open` — dedicated read-only connection plus ``BEGIN``.
       Storage failures raise :class:`StoreUnavailable` (safe 503).
    2. :meth:`prepare` — row-cap pre-count, metadata queries AND the
       row-cursor open plus first-chunk prime on that SAME snapshot.
       Query/validation failures raise ``ValueError`` (safe 400) or
       :class:`StoreUnavailable`; an over-cap scope raises
       :class:`ExportTooLarge` (safe 413). Every failure path closes
       the snapshot before raising.
    3. :meth:`rows` — bounded ``fetchmany`` chunks from the SAME
       cursor/snapshot. A post-header read failure propagates (the
       body aborts without a ``complete`` footer); the snapshot
       still releases via the generator ``finally``.

    Threading: the endpoint thread runs :meth:`open`/``prepare``;
    Starlette consumes :meth:`rows` from worker threads, so the
    dedicated handle opts out of the same-thread check on THIS
    connection only (see :func:`app.db.database.connect`) — a
    sequential handoff, never concurrent use, never a global
    switch, never ``fetchall``. :meth:`close` is idempotent:
    normal EOF, renderer error, generator cancellation, an
    explicit close without consumption, and mid-stream disconnect
    all release cursor and connection without waiting for GC. The
    streaming response owns the same release in its ASGI
    ``__call__`` ``finally`` (:class:`ExportStreamingResponse`)
    and additionally carries :meth:`close` as its background
    safety net. Supports the context-manager protocol so a
    prepared-but-unsent export can release deterministically
    with ``with`` or :func:`close_prepared`.
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = Path(db_path)
        self._conn: sqlite3.Connection | None = None
        self._cursor: sqlite3.Cursor | None = None
        self._buffered: list[tuple] = []
        self._chunk = EXPORT_CHUNK_ROWS
        self._metadata: dict[str, object] | None = None
        self._total = 0
        self._closed = False

    @property
    def closed(self) -> bool:
        """True once cursor and connection are deterministically released."""
        return self._closed

    @property
    def total(self) -> int:
        """Pre-counted exact row total under the owned snapshot."""
        return self._total

    def open(self) -> "ExportStream":
        """Open the dedicated snapshot connection (endpoint thread)."""
        assert self._conn is None and not self._closed
        try:
            conn = connect(self._db_path, read_only=True, check_same_thread=False)
        except (sqlite3.Error, OSError) as exc:
            raise StoreUnavailable("data store unavailable") from exc
        try:
            conn.execute("BEGIN")
        except (sqlite3.Error, OSError) as exc:
            conn.close()
            raise StoreUnavailable("data store unavailable") from exc
        self._conn = conn
        return self

    def prepare(
        self,
        filt,
        rules,
        sort: str,
        *,
        max_rows: int,
        display_timezone: str,
        chunk: int = EXPORT_CHUNK_ROWS,
    ) -> dict[str, object]:
        """Count, cap-check, metadata and cursor prime — one snapshot."""
        assert self._conn is not None and not self._closed
        conn = self._conn
        self._chunk = chunk
        try:
            clf = service.classifier_for_filter(filt, rules)
        except ValueError:
            self.close()
            raise
        try:
            total = queries.count_export_rows(conn, filt, clf)
        except (sqlite3.Error, OSError) as exc:
            self.close()
            raise StoreUnavailable("data store unavailable") from exc
        if total > max_rows:
            self.close()
            raise ExportTooLarge(total)
        try:
            metadata = service.export_metadata(
                conn,
                filt,
                rules,
                row_count=total,
                sort=sort,
                display_timezone=display_timezone,
            )
            cursor = queries.export_cursor(conn, filt, clf, sort)
            try:
                first = cursor.fetchmany(chunk)
            except (sqlite3.Error, OSError):
                cursor.close()
                raise
        except ValueError:
            self.close()
            raise
        except (sqlite3.Error, OSError) as exc:
            self.close()
            raise StoreUnavailable("data store unavailable") from exc
        self._cursor = cursor
        self._buffered = first
        self._metadata = metadata
        self._total = total
        return metadata

    def rows(self) -> Iterator[dict[str, object]]:
        """Yield prepared rows in bounded chunks; always release."""
        cursor = self._cursor
        assert cursor is not None and self._metadata is not None
        try:
            for raw in self._buffered:
                yield queries.export_row_to_dict(raw)
            self._buffered = []
            while True:
                # A post-header read failure propagates: the body
                # aborts without a complete footer while the finally
                # below still releases the snapshot.
                batch = cursor.fetchmany(self._chunk)
                if not batch:
                    return
                for raw in batch:
                    yield queries.export_row_to_dict(raw)
        finally:
            self.close()

    def __enter__(self) -> Self:
        """Context-manager entry: the stream itself (already opened)."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Context-manager exit: always release cursor and snapshot."""
        self.close()

    def close(self) -> None:
        """Idempotent deterministic release of cursor and snapshot."""
        if self._closed:
            return
        self._closed = True
        cursor, self._cursor = self._cursor, None
        if cursor is not None:
            try:
                cursor.close()
            except sqlite3.Error:
                pass
        conn, self._conn = self._conn, None
        if conn is not None:
            try:
                conn.execute("COMMIT")
            except (sqlite3.Error, OSError):
                try:
                    conn.execute("ROLLBACK")
                except (sqlite3.Error, OSError):
                    pass
            finally:
                try:
                    conn.close()
                except (sqlite3.Error, OSError):
                    pass
        self._buffered = []


def prepare_export(request: Request, params: dict):
    """Central validation for both export entries (Bearer API + browser).

    Returns ``(filt, rules, sort, export_format, info)`` or
    ``(None, None, None, None, error_response)``. Auth, filter
    validation, token site/source bounds, the row-cap pre-count,
    metadata AND the row-cursor prime all happen BEFORE any byte
    streams on ONE owned snapshot (:class:`ExportStream`), so
    failures map to safe envelopes instead of a truncated download.
    No credential is ever read from the query string. Exports always
    cover the full result: paging parameters are not accepted (no
    ``limit``/``offset`` leaks into metadata or rows).
    """
    export_format = params.pop("export_format", "csv")
    sort = params.pop("sort", "oldest")
    display_timezone = params.pop("timezone", "UTC")
    _token, filt, err = _prepare(request, **params, timezone=display_timezone)
    if err is not None:
        return None, None, None, None, err
    assert filt is not None
    rules = request.app.state.rules
    stream = ExportStream(Path(request.app.state.db_path)).open()
    try:
        metadata = stream.prepare(
            filt,
            rules,
            sort,
            max_rows=EXPORT_MAX_ROWS,
            display_timezone=display_timezone,
        )
    except ExportTooLarge as exc:
        return (
            None,
            None,
            None,
            None,
            error_response(
                413,
                "export_too_large",
                f"The selected scope holds {exc.total} rows, above the export limit"
                f" of {EXPORT_MAX_ROWS}. Narrow the window or filters.",
                request.state.request_id,
            ),
        )
    except ValueError:
        return (
            None,
            None,
            None,
            None,
            _deny(
                request.state.request_id,
                "invalid_request",
                "Unknown or contradictory traffic/bot selector.",
            ),
        )
    info = {"metadata": metadata, "total": stream.total, "stream": stream}
    return filt, rules, sort, export_format, info


def prepare_session_export(
    *,
    filt,
    rules,
    sort: str,
    export_format: str,
    db_path: Path,
    display_timezone: str = "UTC",
):
    """Validation for the session-authenticated browser download entry.

    The caller authenticated via the admin session (Bearer tokens are
    never accepted here and no credential is read from the query
    string); site/source/window/selectors were already checked by the
    web filter layer against the same store. Count, cap, metadata
    and cursor prime share ONE owned snapshot (:class:`ExportStream`)
    BEFORE any byte streams. Storage-access failures surface as the
    narrow ``StoreUnavailable`` signal (safe 503); anything else
    propagates. Every failure path closes the snapshot.
    """
    stream = ExportStream(Path(db_path)).open()
    try:
        metadata = stream.prepare(
            filt,
            rules,
            sort,
            max_rows=EXPORT_MAX_ROWS,
            display_timezone=display_timezone,
        )
    except ExportTooLarge as exc:
        return None, ("too_large", exc.total)
    except ValueError:
        return None, "invalid"
    info = {"metadata": metadata, "total": stream.total, "stream": stream}
    return (filt, rules, sort, export_format, info), None


class ExportStreamingResponse(StreamingResponse):
    """Streaming download that always releases its owned export snapshot.

    Starlette's ``StreamingResponse.__call__`` skips its background
    task whenever the superclass streaming raises (for example an
    ``OSError`` from ``send`` at the first body byte becomes
    ``ClientDisconnect`` before the background runs), and an
    unstarted row generator has no executing ``finally`` — so
    neither the background task nor the generator ``finally`` can be
    the sole owner of the snapshot. This subclass releases the
    :class:`ExportStream` in an unconditional ASGI-``__call__``
    ``finally`` covering both wire protocols (current and older
    disconnect handling), task cancellation and renderer errors.
    The background re-close stays as an idempotent no-op safety net
    for paths that complete without raising.
    """

    def __init__(self, *args, stream: ExportStream, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._export_stream = stream

    async def __call__(self, scope, receive, send) -> None:  # type: ignore[no-untyped-def]
        try:
            await super().__call__(scope, receive, send)
        finally:
            self._export_stream.close()


def close_prepared(info: dict) -> None:
    """Deterministically release a prepared-but-unsent export.

    A caller that ran :func:`prepare_export` (or
    :func:`prepare_session_export`) and then decided not to send the
    response — for example a renderer that rejects the prepared
    handle before streaming — must call this (or close
    ``info["stream"]`` directly, or use the stream as a context
    manager) instead of dropping the handle: an unused prepared
    response holds its read snapshot open until closed.
    """
    info["stream"].close()


def export_response(prepared, filename: str) -> ExportStreamingResponse:
    """Build the streaming download from validated export preparation."""
    _, _, _, export_format, info = prepared
    stream = info["stream"]
    metadata = info["metadata"]
    assert info["total"] == metadata["row_count"]
    headers = metadata_headers(metadata, filename)
    if export_format == "csv":
        body = csv_chunks(stream.rows())
        media_type = _CSV_MEDIA_TYPE
    else:
        body = json_chunks(metadata, stream.rows())
        media_type = _JSON_MEDIA_TYPE
    # Ownership: ExportStreamingResponse.__call__ always releases the
    # snapshot (even when the superclass streaming raises before the
    # row generator starts or the background task runs); the row
    # generator's finally and the background re-close stay as
    # idempotent no-op layers for the paths they do cover.
    return ExportStreamingResponse(
        body,
        media_type=media_type,
        headers=headers,
        stream=stream,
        background=BackgroundTask(stream.close),
    )


def export_params(
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    timezone: Timezone = "UTC",
    export_format: ExportFormat = "csv",
    sort: ExportSort = "oldest",
) -> dict:
    """Shared export query surface for the Bearer API and the browser entry."""
    params = _params(
        site_id,
        time_from,
        time_to,
        source_id,
        method,
        status,
        status_class,
        path_prefix,
        referer_host,
        search,
        client,
        traffic,
        bot,
        category,
        provider,
        purpose,
        path_exact,
        server_host,
        http_version,
        mime_type,
        cache_status,
        tls_protocol,
        timing_available,
        upstream_available,
        timing_min_ms,
        timing_max_ms,
        country,
        100,
        0,
        timezone,
    )
    params["export_format"] = export_format
    params["sort"] = sort
    return params


@router.get("/exports/requests")
def export_requests(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    timezone: Timezone = "UTC",
    export_format: ExportFormat = "csv",
    sort: ExportSort = "oldest",
):
    """Download the ENTIRE filtered request result as CSV or JSON.

    Bearer ``analytics:read`` only; the token's site/source/time
    bounds apply exactly like every analytics read. No model client,
    key or network is needed. Failures before streaming answer with
    safe envelopes; the row cap rejects with ``export_too_large``
    instead of truncating.
    """
    prepared = prepare_export(
        request,
        export_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            timezone,
            export_format,
            sort,
        ),
    )
    if prepared[0] is None:
        return prepared[4]
    filt = prepared[0]
    assert filt is not None
    filename = safe_filename(
        filt.site_id,
        filt.window.time_from,
        filt.window.time_to,
        "csv" if prepared[3] == "csv" else "json",
    )
    return export_response(prepared, filename)
