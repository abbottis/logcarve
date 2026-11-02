#!/usr/bin/env python3
"""Reproducible external LogCarve analytics client (T5).

Calls the versioned read-only API over plain HTTPS/HTTP with a scoped
Bearer token taken from ``LOGCARVE_API_TOKEN`` or ``--token``. Standard
library only: no third-party dependencies, no model access, no imports.
Prints one JSON document per endpoint; ``--endpoint`` also selects
typed report operations (``performance``, ``slow-endpoints``,
``seo-bot-statuses``, ``journeys``, ``comparison``, ...) and the
bounded streaming full-export downloads ``export-csv``/``export-json``
(which need ``--out`` and verify the body against the response
metadata instead of trusting a truncated file).

Example:
    LOGCARVE_API_TOKEN=lc_... python clients/logcarve_api_client.py \\
        --base-url http://127.0.0.1:8080 --site default \\
        --from 2026-10-27T00:00:00+00:00 --to 2026-10-28T00:00:00+00:00
"""

import argparse
import codecs
import csv
import http.client
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

ENDPOINTS = ("summary", "crawlers", "findings")
#: Typed report operations over the versioned read-only API. Each name
#: maps to one deterministic route; the model-assistant ``report``
#: enum is a subset of these aggregates (timelines, raw rows and the
#: streaming export stay outside the tool surface).
REPORT_ENDPOINTS = {
    "performance": "performance",
    "performance-overview": "performance/overview",
    "slow-endpoints": "performance/slow-endpoints",
    "seo-bot-statuses": "seo/bot-statuses",
    "seo-ai-only-paths": "seo/ai-only-paths",
    "referrer-404-targets": "referrers/404-targets",
    "referrer-urls": "referrers/urls",
    "journeys": "journeys",
    "journey-entries": "journeys/entry-paths",
    "comparison": "comparison",
    "traffic-breakdown": "traffic/breakdown",
    "resources": "traffic/resources",
    "browsers": "traffic/browsers",
    "heatmap": "traffic/heatmap",
}
EXPORT_FORMATS = ("export-csv", "export-json")
TIMEOUT_S = 30
#: Bounded streaming download: refuse to buffer more than this on disk
#: so a hostile scope cannot fill the filesystem silently. The server
#: row cap (250k rows) bounds legitimate exports well below this.
EXPORT_MAX_BYTES = 512 * 1024 * 1024
EXPORT_SCHEMA_VERSION = "export/1"
#: Bounded local verification (stdlib only, documented here): files
#: stream in 64 KiB chunks and no verification step calls ``read()``
#: without an explicit bound; CSV intake uses only bounded
#: ``readline()`` (never handle iteration or unbounded reads). One
#: CSV record, one JSON envelope prefix/row or the metadata object
#: may not exceed 1 MiB; anything larger fails closed as oversized
#: BEFORE the ``csv`` reader or JSON decoder can preallocate it,
#: instead of buffering unboundedly. JSON must carry exactly the
#: ``export/1`` envelope (``metadata`` object with a compatible
#: ``schema_version`` and a non-bool integer ``row_count`` in
#: ``[0, 250000]`` matching the header count, ``rows`` array of
#: objects of matching length, ``complete`` exactly ``true``) with
#: strict grammar (no trailing commas, duplicate keys, non-finite
#: constants or trailing junk). CSV needs a valid nonempty unique
#: header and exact header width on EVERY data row under strict
#: quoting. Numeric, null and formula-prefix cell semantics are
#: preserved by parsing (numbers stay numbers, ``null`` stays null,
#: quoted formula text stays quoted text) — verification counts and
#: completes, never rewrites.
VERIFY_CHUNK_BYTES = 65536
VERIFY_MAX_RECORD_BYTES = 1024 * 1024


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse credential-bearing redirects outside one validated http(s) origin.

    Non-http(s) schemes, credential-bearing userinfo, malformed ports,
    host or port changes, downgrades and off-default upgrades are
    refused before forwarding (see the checks below).

    Same-origin redirects with a preserved or upgraded scheme keep
    the stdlib behavior (the ``Authorization`` header travels only
    within that validated origin). Any redirect to a different host
    or port, or a downgrade from ``https`` to ``http``, raises a
    safe ``HTTPError`` (no token, no body) instead of forwarding
    the bearer token to an unapproved origin.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            old = urllib.parse.urlsplit(req.full_url)
            new = urllib.parse.urlsplit(urllib.parse.urljoin(req.full_url, newurl))
        except ValueError:
            raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)
        if old.scheme not in ("http", "https") or new.scheme not in ("http", "https"):
            raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)
        try:
            new_userinfo = new.username is not None or new.password is not None
            old_port = old.port if old.port is not None else _default_port(old.scheme)
            new_port = new.port if new.port is not None else _default_port(new.scheme)
        except ValueError:
            raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)
        if new_userinfo:
            raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)
        if not old.hostname or not new.hostname:
            raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)
        if old.hostname.lower() != new.hostname.lower():
            raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)
        if new.scheme == old.scheme:
            if old_port != new_port:
                raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)
        elif old.scheme == "http" and new.scheme == "https":
            # Canonical upgrade only: effective default ports 80 -> 443.
            if old_port != 80 or new_port != 443:
                raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)
        else:
            raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _default_port(scheme: str) -> int | None:
    if scheme == "https":
        return 443
    if scheme == "http":
        return 80
    return None


def _build_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_SafeRedirectHandler)


def _token(args: argparse.Namespace) -> str:
    token = args.token or os.environ.get("LOGCARVE_API_TOKEN", "")
    if not token:
        print("error: provide --token or LOGCARVE_API_TOKEN", file=sys.stderr)
        raise SystemExit(2)
    return token


def _route_for(endpoint: str) -> str:
    if endpoint == "findings":
        return "security/findings"
    return REPORT_ENDPOINTS.get(endpoint, endpoint)


def fetch(
    base_url: str,
    token: str,
    endpoint: str,
    params: dict[str, str],
    *,
    opener: urllib.request.OpenerDirector | None = None,
) -> dict:
    query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    url = f"{base_url.rstrip('/')}/api/v1/{_route_for(endpoint)}?{query}"
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    active = opener or _build_opener()
    try:
        with active.open(request, timeout=TIMEOUT_S) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        # Safe message only: status without body, never the token.
        print(f"error: HTTP {exc.code} for {endpoint}", file=sys.stderr)
        raise SystemExit(1)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"error: request failed for {endpoint}: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(1)


def download_export(
    base_url: str,
    token: str,
    params: dict[str, str],
    export_format: str,
    dest: str,
    *,
    max_bytes: int = EXPORT_MAX_BYTES,
    opener: urllib.request.OpenerDirector | None = None,
) -> dict:
    """Stream a full-result export to disk with completeness checks.

    The body streams in bounded chunks (never buffered whole in
    memory) up to ``max_bytes``. Response metadata travels in headers
    only and is validated, never trusted blindly: the schema version
    must match, and the received body must be complete — a JSON
    envelope must parse incrementally with ``"complete": true`` and
    its row count must equal the header count, while a CSV body must
    carry the header row plus exactly the header row count (counted
    with the stdlib ``csv`` reader so quoted newlines never split
    rows). Verification streams from disk; it never calls ``read()``
    without a bound, never iterates a handle line-by-line, and never
    rereads the whole result into memory.

    Output ownership: a pre-existing ``dest`` (including a symlink)
    is refused without truncation; the new file is created
    exclusively (``O_EXCL``/``O_NOFOLLOW``) with mode ``0o600``; only
    this run's partial is removed on any failure (including
    ``http.client.IncompleteRead`` and timeouts). Unrelated files
    are never touched. All failure messages are safe (no token, no
    response or log content).
    """
    ext = "csv" if export_format == "export-csv" else "json"
    if os.path.lexists(dest):
        print(f"error: refusing to overwrite existing {dest!r}", file=sys.stderr)
        raise SystemExit(1)
    query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    url = f"{base_url.rstrip('/')}/api/v1/exports/requests?{query}&export_format={ext}"
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    active = opener or _build_opener()
    owned = False
    expected = 0
    try:
        with active.open(request, timeout=TIMEOUT_S) as response:
            headers = response.headers
            schema = headers.get("X-Logcarve-Export-Schema", "")
            expected_rows = headers.get("X-Logcarve-Export-Rows", "")
            if schema != EXPORT_SCHEMA_VERSION:
                print("error: unexpected export schema; refusing download", file=sys.stderr)
                raise SystemExit(1)
            try:
                expected = int(expected_rows)
            except ValueError:
                print(
                    "error: export row-count header is missing or invalid; refusing download",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            if expected < 0 or expected > 250_000:
                print("error: export row-count header is out of range", file=sys.stderr)
                raise SystemExit(1)
            fd = _exclusive_create(dest)
            owned = True
            received = 0
            try:
                with os.fdopen(fd, "wb") as handle:
                    while True:
                        chunk = response.read(VERIFY_CHUNK_BYTES)
                        if not chunk:
                            break
                        received += len(chunk)
                        if received > max_bytes:
                            raise _DownloadTooLarge
                        handle.write(chunk)
            except _DownloadTooLarge:
                _remove_owned(dest, owned)
                print(
                    "error: export exceeded the local size bound; partial file removed",
                    file=sys.stderr,
                )
                raise SystemExit(1)
    except urllib.error.HTTPError as exc:
        # Safe message only: status without body, never the token.
        _remove_owned(dest, owned)
        print(f"error: HTTP {exc.code} for export", file=sys.stderr)
        raise SystemExit(1)
    except SystemExit:
        raise
    except (
        urllib.error.URLError,
        TimeoutError,
        http.client.IncompleteRead,
        http.client.HTTPException,
        OSError,
    ):
        _remove_owned(dest, owned)
        print("error: request failed for export", file=sys.stderr)
        raise SystemExit(1)
    except Exception:  # noqa: BLE001 - every failure must drop the run-owned partial
        _remove_owned(dest, owned)
        print("error: request failed for export", file=sys.stderr)
        raise SystemExit(1)
    return _verify_export_file(dest, ext, expected)


class _DownloadTooLarge(Exception):
    """Local size bound exceeded while streaming one export body."""


def _exclusive_create(dest: str) -> int:
    """Create ``dest`` exclusively with mode 0600; refuse anything existing."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        flags |= nofollow
    try:
        return os.open(dest, flags, 0o600)
    except FileExistsError:
        print(f"error: refusing to overwrite existing {dest!r}", file=sys.stderr)
        raise SystemExit(1)
    except OSError:
        print("error: cannot create download target", file=sys.stderr)
        raise SystemExit(1)


def _remove_owned(dest: str, owned: bool) -> None:
    if not owned:
        return
    _remove_partial(dest)


def _remove_partial(dest: str) -> None:
    try:
        os.remove(dest)
    except OSError:
        pass


def _verify_export_file(dest: str, ext: str, expected: int) -> dict:
    """Check a downloaded export for completeness; fail loudly if short.

    Streams from disk in bounded chunks (never ``read()`` without a
    size, never bare handle iteration): CSV records stream through a
    bounded ``readline()`` record iterator into the strict stdlib
    ``csv`` reader (valid nonempty unique header plus exactly
    ``expected`` records at exact header width; quoted newlines and
    chunk-boundary escapes stay inside their record), and JSON
    validates incrementally with a bounded decoder buffer and
    per-row state — mandatory ``metadata`` object (compatible
    ``schema_version``, non-bool integer ``row_count`` matching the
    header count), ``rows`` array of objects of matching length and
    ``complete`` exactly ``true``, with ``null``/numbers/quoted
    formula text preserved by parsing, never rewritten. Any
    truncation, malformed JSON/CSV, missing component, count mismatch
    or oversized record removes the partial file and exits nonzero
    with a safe message (no token, no log content).
    """
    if expected < 0 or expected > 250_000:
        _remove_partial(dest)
        print("error: export row count is out of range; partial file removed", file=sys.stderr)
        raise SystemExit(1)
    try:
        if ext == "json":
            return _verify_json_stream(dest, expected)
        return _verify_csv_stream(dest, expected)
    except SystemExit:
        raise
    except (OSError, UnicodeDecodeError, csv.Error, ValueError):
        _remove_partial(dest)
        print("error: export body is truncated or malformed; partial file removed", file=sys.stderr)
        raise SystemExit(1)


#: Bounded CSV intake: one ``readline()`` call never reads more
#: than this many characters, and one record never spans more
#: physical lines than this. Both bounds are far above genuine
#: server rows (tens of short ``\r\n`` lines) while keeping hostile
#: input bounded.
_CSV_READLINE_CHARS = 65536
_CSV_MAX_LINES_PER_RECORD = 65536


class _CsvRecordReader:
    """Yield one raw CSV record at a time from a text handle.

    Only ``handle.readline(size)`` with an explicit bound is ever
    used — the handle is never iterated line-by-line and ``read()``
    is never called — so an unbounded physical line cannot hide
    behind the iterator protocol. Quote tracking is streaming: a
    record ends at the first newline outside quotes, so legitimate
    quoted multiline fields stay one record, while an unclosed quote
    at EOF fails closed instead of silently merging the tail. A
    record (measured in UTF-8 bytes) larger than
    ``VERIFY_MAX_RECORD_BYTES`` fails closed BEFORE the ``csv``
    reader ever sees it, so the reader cannot be handed an
    arbitrarily large preallocated record. The per-record physical
    line count is a work limit, not a row cap: ordinary rows use a
    handful of lines.
    """

    def __init__(self, handle) -> None:
        self._handle = handle

    def records(self) -> object:
        parts: list[str] = []
        record_bytes = 0
        lines = 0
        in_quotes = False
        prev_quote = False
        while True:
            line = self._handle.readline(_CSV_READLINE_CHARS)
            if line == "":
                if in_quotes:
                    raise csv.Error("unclosed quotation at end of file")
                # A trailing newline leaves no pending record: only a
                # truly unterminated tail (no closing newline) yields.
                if parts:
                    yield "".join(parts)
                return
            lines += 1
            if lines > _CSV_MAX_LINES_PER_RECORD:
                raise csv.Error("record spans too many physical lines")
            record_bytes += len(line.encode("utf-8"))
            if record_bytes > VERIFY_MAX_RECORD_BYTES:
                raise csv.Error("oversized record")
            for char in line:
                if char == '"':
                    # A quote following a quote while outside quotes is
                    # the second half of an escaped pair (``""``):
                    # re-enter quotes instead of toggling twice.
                    if prev_quote and not in_quotes:
                        in_quotes = True
                        prev_quote = False
                    else:
                        in_quotes = not in_quotes
                        prev_quote = True
                elif char == "\n" and not in_quotes:
                    prev_quote = False
                    text = "".join(parts).removesuffix("\r")
                    parts = []
                    record_bytes = 0
                    lines = 0
                    yield text
                    break
                else:
                    prev_quote = False
                parts.append(char)
            else:
                continue
            continue


def _verify_csv_stream(dest: str, expected: int) -> dict:
    """Count CSV records by streaming bounded records; fail closed on mismatch.

    The header must be valid (every cell nonempty, all cells unique)
    and EVERY data row must decode under strict quoting with exactly
    the header width: extra/missing columns, malformed or unclosed
    quoting and oversized records all fail closed before an
    unbounded allocation. Quoted multiline fields and multibyte text
    stay one record. Completeness is the header row plus exactly
    ``expected`` records.

    Honest limits: this proves the body is well-formed CSV with the
    promised row count — it cannot cryptographically detect a
    same-count shortening inside one valid final cell (e.g. bytes
    missing from the last field while the row/grammar stays valid).
    Truncation that drops rows, breaks grammar or aborts the stream
    is caught here; a mid-stream network abort is additionally caught
    by the ``IncompleteRead``/timeout cleanup in
    :func:`download_export`.
    """
    try:
        with open(dest, "r", encoding="utf-8", errors="strict", newline="") as handle:
            reader = _CsvRecordReader(handle)
            try:
                records = reader.records()
                try:
                    header_text = next(records)  # type: ignore[call-overload]
                except StopIteration:
                    _remove_partial(dest)
                    print(
                        "error: export body is incomplete (missing header); partial file removed",
                        file=sys.stderr,
                    )
                    raise SystemExit(1)
                parsed = list(csv.reader([header_text], strict=True))
                header = parsed[0] if parsed else []
                if (
                    not header
                    or any(not cell.strip() for cell in header)
                    or len(set(header)) != len(header)
                ):
                    _remove_partial(dest)
                    print(
                        "error: export body carries an invalid header; partial file removed",
                        file=sys.stderr,
                    )
                    raise SystemExit(1)
                width = len(header)
                count = 0
                for record_text in records:
                    rows = list(csv.reader([record_text], strict=True))
                    row = rows[0] if rows else []
                    if len(row) != width:
                        _remove_partial(dest)
                        print(
                            "error: export body holds a malformed row; partial file removed",
                            file=sys.stderr,
                        )
                        raise SystemExit(1)
                    count += 1
                    if count > expected:
                        break
            except csv.Error:
                _remove_partial(dest)
                print(
                    "error: export body is truncated or malformed; partial file removed",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            if count != expected:
                _remove_partial(dest)
                print(
                    f"error: export body holds {count} rows, expected {expected};"
                    " partial file removed",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            return {"path": dest, "format": "csv", "rows": expected, "complete": True}
    except OSError:
        print("error: cannot read downloaded export", file=sys.stderr)
        raise SystemExit(1)


#: Exact mandatory envelope of a real ``export/1`` JSON body: no
#: component may be missing and no unknown component is accepted.
_JSON_ENVELOPE_KEYS = frozenset({"metadata", "rows", "complete"})


def _checked_object(pairs: list[tuple[str, object]]) -> dict:
    """Build one JSON object, failing closed on duplicate keys.

    Used as ``object_pairs_hook`` so EVERY object (envelope,
    metadata, each row, nested values) rejects duplicate keys
    instead of silently keeping the last occurrence.
    """
    obj: dict = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate key")
        obj[key] = value
    return obj


def _reject_constant(text: str) -> object:
    """Fail closed on non-finite JSON constants (``NaN``/``Infinity``)."""
    raise ValueError(f"non-finite constant {text!r}")


def _verify_json_stream(dest: str, expected: int) -> dict:
    """Validate the JSON export envelope incrementally from disk.

    Envelope shape is exactly ``{"metadata": {...}, "rows": [{...},
    ...], "complete": true}``: all three components are mandatory,
    unknown top-level keys are rejected, ``metadata`` must be an
    object carrying ``schema_version == "export/1"`` and a non-bool
    integer ``row_count`` in ``[0, 250000]`` equal to the header
    count, ``rows`` must be an array of objects (scalars, arrays and
    ``null`` are rejected) whose length equals the header count, and
    ``complete`` must be exactly ``true``. Grammar is strict: no
    trailing commas (envelope or rows), no duplicate keys at any
    depth, no ``NaN``/``Infinity`` constants, no trailing junk.

    Bytes stream from disk in bounded chunks through an incremental
    UTF-8 decoder (multibyte characters and escapes split across
    chunks stay intact) into a bounded text buffer; the ``metadata``
    object and each row decode one at a time from that buffer and
    consumed input is dropped, so the whole file is never held at
    once and no call uses ``read()`` without a bound. Only the row
    count is retained — never the full row list. Arbitrary legitimate
    whitespace, UTF-8, escaped quotes/newlines, chunk boundaries and
    large row counts stay accepted. Numbers, ``null`` and quoted
    formula text survive parsing untouched; verification counts and
    completes, never rewrites.
    """
    stream = _JsonStream(dest)
    try:
        try:
            stream.expect_char("{")
            metadata: dict | None = None
            row_count: int | None = None
            complete: object = None
            seen_keys: set[str] = set()
            while True:
                char = stream.peek_non_ws()
                if char == "}":
                    stream.expect_char("}")
                    break
                key = stream.decode_value()
                if not isinstance(key, str):
                    raise TypeError("bad key")
                if key in seen_keys:
                    raise ValueError("duplicate key")
                if key not in _JSON_ENVELOPE_KEYS:
                    raise ValueError("unknown envelope key")
                seen_keys.add(key)
                stream.expect_char(":")
                if key == "metadata":
                    value = stream.decode_value()
                    if not isinstance(value, dict):
                        raise ValueError("bad metadata")
                    metadata = value
                elif key == "rows":
                    row_count = stream.decode_rows(expected)
                else:
                    complete = stream.decode_value()
                char = stream.peek_non_ws()
                if char == ",":
                    stream.expect_char(",")
                    if stream.peek_non_ws() == "}":
                        raise ValueError("trailing comma")
                    continue
                if char == "}":
                    stream.expect_char("}")
                    break
                raise ValueError("bad separator")
            stream.expect_eof()
        except (json.JSONDecodeError, ValueError, TypeError, IndexError, UnicodeDecodeError):
            _remove_partial(dest)
            print(
                "error: export body is truncated (not valid JSON); partial file removed",
                file=sys.stderr,
            )
            raise SystemExit(1)
    finally:
        stream.close()
    if seen_keys != set(_JSON_ENVELOPE_KEYS):
        _remove_partial(dest)
        print(
            "error: export body is incomplete (missing envelope component); partial file removed",
            file=sys.stderr,
        )
        raise SystemExit(1)
    assert metadata is not None and row_count is not None
    if complete is not True:
        _remove_partial(dest)
        print(
            "error: export body is incomplete (missing complete marker); partial file removed",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if metadata.get("schema_version") != EXPORT_SCHEMA_VERSION:
        _remove_partial(dest)
        print(
            "error: export body carries an incompatible schema version; partial file removed",
            file=sys.stderr,
        )
        raise SystemExit(1)
    meta_count = metadata.get("row_count")
    if (
        not isinstance(meta_count, int)
        or isinstance(meta_count, bool)
        or meta_count < 0
        or meta_count > 250_000
    ):
        _remove_partial(dest)
        print(
            "error: export body is incomplete (bad metadata row count); partial file removed",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if row_count != expected or meta_count != expected:
        _remove_partial(dest)
        print(
            f"error: export body holds {row_count} rows, expected {expected}; partial file removed",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return {"path": dest, "format": "json", "rows": row_count, "complete": True}


class _JsonStream:
    """Bounded incremental JSON cursor over one export file.

    Reads bytes only via ``read(VERIFY_CHUNK_BYTES)`` through an
    incremental UTF-8 decoder. Decoded text stays bounded: consumed
    input is dropped and any single buffered value larger than
    ``VERIFY_MAX_RECORD_BYTES`` (plus one chunk of slack) fails
    closed as oversized. ``raw_decode`` never sees the whole file.
    """

    def __init__(self, dest: str) -> None:
        try:
            self._handle = open(dest, "rb")  # noqa: SIM115 - handle lifetime owned by close()
        except OSError:
            print("error: cannot read downloaded export", file=sys.stderr)
            raise SystemExit(1)
        self._utf8 = codecs.getincrementaldecoder("utf-8")(errors="strict")
        self._text = ""
        self._pos = 0
        self._eof = False
        # Strict grammar everywhere: duplicate keys rejected at any
        # depth, non-finite constants rejected (``allow_nan`` only
        # governs encoding; decoding needs ``parse_constant``).
        self._decoder = json.JSONDecoder(
            object_pairs_hook=_checked_object, parse_constant=_reject_constant
        )

    def close(self) -> None:
        try:
            self._handle.close()
        except OSError:
            pass

    def _fill(self) -> bool:
        chunk = self._handle.read(VERIFY_CHUNK_BYTES)
        if not chunk:
            try:
                tail = self._utf8.decode(b"", final=True)
            except UnicodeDecodeError:
                raise ValueError("bad utf-8")
            if tail:
                self._text += tail
            self._eof = True
            return bool(tail)
        try:
            self._text += self._utf8.decode(chunk)
        except UnicodeDecodeError:
            raise ValueError("bad utf-8")
        if len(self._text) - self._pos > VERIFY_MAX_RECORD_BYTES + VERIFY_CHUNK_BYTES:
            raise ValueError("oversized buffered value")
        return True

    def _skip_ws_fill(self) -> None:
        while True:
            while self._pos < len(self._text) and self._text[self._pos] in " \t\n\r":
                self._pos += 1
            if self._pos < len(self._text):
                return
            if self._eof:
                return
            # Drop consumed prefix before growing the buffer.
            if self._pos:
                self._text = self._text[self._pos :]
                self._pos = 0
            if not self._fill():
                return

    def peek_non_ws(self) -> str:
        self._skip_ws_fill()
        if self._pos >= len(self._text):
            raise ValueError("truncated")
        return self._text[self._pos]

    def expect_char(self, char: str) -> None:
        self._skip_ws_fill()
        if self._pos >= len(self._text) or self._text[self._pos] != char:
            raise ValueError(f"expected {char!r}")
        self._pos += 1

    def decode_value(self):
        """Decode one JSON value, pulling chunks until it completes."""
        self._skip_ws_fill()
        start = self._pos
        while True:
            try:
                value, end = self._decoder.raw_decode(self._text, self._pos)
            except json.JSONDecodeError:
                if self._eof:
                    raise
                self._fill()
                continue
            if end - start > VERIFY_MAX_RECORD_BYTES:
                raise ValueError("oversized record")
            self._pos = end
            return value

    def decode_rows(self, expected: int) -> int:
        """Decode the ``rows`` array, returning its length only.

        Every element must be a JSON object within the per-record
        byte bound; scalars, arrays and ``null`` fail closed. A comma
        must always be followed by another row — never ``]``.
        """
        self.expect_char("[")
        count = 0
        first = True
        while True:
            char = self.peek_non_ws()
            if char == "]":
                self.expect_char("]")
                return count
            if not first:
                raise ValueError("bad rows separator")
            first = False
            start = self._pos
            while True:
                try:
                    row, end = self._decoder.raw_decode(self._text, self._pos)
                except json.JSONDecodeError:
                    if self._eof:
                        raise ValueError("truncated rows")
                    self._fill()
                    continue
                break
            if end - start > VERIFY_MAX_RECORD_BYTES:
                raise ValueError("oversized record")
            if not isinstance(row, dict):
                raise TypeError("row is not an object")
            self._pos = end
            count += 1
            if count > expected:
                raise ValueError("too many rows")
            char = self.peek_non_ws()
            if char == ",":
                self.expect_char(",")
                if self.peek_non_ws() == "]":
                    raise ValueError("trailing comma")
                first = True
                # Keep the buffer bounded as rows accumulate.
                if self._pos > VERIFY_CHUNK_BYTES:
                    self._text = self._text[self._pos :]
                    self._pos = 0
                continue
            if char == "]":
                self.expect_char("]")
                return count
            raise ValueError("bad rows separator")

    def expect_eof(self) -> None:
        self._skip_ws_fill()
        if self._pos < len(self._text):
            raise ValueError("trailing data")
        if not self._eof:
            # Drain any bytes beyond the envelope: only whitespace may follow.
            while not self._eof:
                self._text = self._text[self._pos :]
                self._pos = 0
                if not self._fill():
                    break
                self._skip_ws_fill()
                if self._pos < len(self._text):
                    raise ValueError("trailing data")


def _skip_ws(text: str, pos: int) -> int:
    while pos < len(text) and text[pos] in " \t\n\r":
        pos += 1
    return pos


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="External LogCarve analytics client")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--token", default=None)
    parser.add_argument("--site", required=True)
    parser.add_argument("--from", dest="time_from", required=True)
    parser.add_argument("--to", dest="time_to", required=True)
    parser.add_argument(
        "--endpoint",
        choices=[*ENDPOINTS, *REPORT_ENDPOINTS, *EXPORT_FORMATS, "all"],
        default="all",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Destination file for export-csv/export-json downloads.",
    )
    parser.add_argument(
        "--source",
        default=None,
        help="Optional source id narrowing every request (server scope-checked).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Page size for report endpoints that page (1..1000).",
    )
    parser.add_argument(
        "--offset",
        type=int,
        default=None,
        help="Page offset for report endpoints that page (>= 0).",
    )
    parser.add_argument(
        "--baseline-from",
        default=None,
        help="Baseline window start for --endpoint comparison (ISO datetime; needs --baseline-to).",
    )
    parser.add_argument(
        "--baseline-to",
        default=None,
        help="Baseline window end for --endpoint comparison (ISO datetime; needs --baseline-from).",
    )
    return parser


def _report_params(args: argparse.Namespace) -> dict[str, str]:
    """Validated selectors for report fetches; unknown scope fails locally."""
    params: dict[str, str] = {}
    if args.source is not None:
        if not args.source or len(args.source) > 128:
            print("error: --source must be 1..128 characters", file=sys.stderr)
            raise SystemExit(2)
        params["source_id"] = args.source
    if args.limit is not None:
        if args.limit < 1 or args.limit > 1000:
            print("error: --limit must be 1..1000", file=sys.stderr)
            raise SystemExit(2)
        params["limit"] = str(args.limit)
    if args.offset is not None:
        if args.offset < 0:
            print("error: --offset must be >= 0", file=sys.stderr)
            raise SystemExit(2)
        params["offset"] = str(args.offset)
    return params


def _baseline_params(args: argparse.Namespace) -> dict[str, str]:
    """Validated explicit baseline window for comparison requests."""
    if (args.baseline_from is None) != (args.baseline_to is None):
        print("error: --baseline-from and --baseline-to are required together", file=sys.stderr)
        raise SystemExit(2)
    if args.baseline_from is None:
        return {}
    from datetime import datetime

    try:
        start = datetime.fromisoformat(args.baseline_from)
        end = datetime.fromisoformat(args.baseline_to)
    except ValueError:
        print("error: baseline window must hold ISO datetimes", file=sys.stderr)
        raise SystemExit(2)
    if start.tzinfo is None or end.tzinfo is None:
        print("error: baseline window must carry a timezone offset", file=sys.stderr)
        raise SystemExit(2)
    if not start < end:
        print("error: --baseline-from must precede --baseline-to", file=sys.stderr)
        raise SystemExit(2)
    return {"baseline_from": args.baseline_from, "baseline_to": args.baseline_to}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    token = _token(args)
    params = {"site_id": args.site, "from": args.time_from, "to": args.time_to}
    if args.endpoint in EXPORT_FORMATS:
        if not args.out:
            print("error: provide --out for export downloads", file=sys.stderr)
            raise SystemExit(2)
        summary = download_export(args.base_url, token, params, args.endpoint, args.out)
        json.dump(summary, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    wants_baseline = args.baseline_from is not None or args.baseline_to is not None
    if args.endpoint == "all":
        if wants_baseline:
            print("error: baseline flags apply to --endpoint comparison only", file=sys.stderr)
            raise SystemExit(2)
        # Historical default: the three standalone baseline
        # documents. Derived reports (typed aggregates, comparison)
        # are explicit opt-in: comparison needs an authorized
        # baseline window and must never run on a silent default.
        wanted = ENDPOINTS
    else:
        wanted = (args.endpoint,)
    if args.endpoint == "comparison":
        baseline = _baseline_params(args)
        if not baseline:
            print(
                "error: --endpoint comparison needs --baseline-from and --baseline-to",
                file=sys.stderr,
            )
            raise SystemExit(2)
        params.update(baseline)
    elif wants_baseline:
        print("error: baseline flags apply to --endpoint comparison only", file=sys.stderr)
        raise SystemExit(2)
    selector_params = _report_params(args)
    documents = {}
    for name in wanted:
        request_params = dict(params)
        if name in REPORT_ENDPOINTS:
            request_params.update(selector_params)
        elif selector_params and name in ENDPOINTS and "source_id" in selector_params:
            request_params["source_id"] = selector_params["source_id"]
        documents[name] = fetch(args.base_url, token, name, request_params)
    output = documents if len(documents) > 1 else documents[wanted[0]]
    json.dump(output, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
