"""Streaming import with T1a gzip, autodetect and host filtering.

Lines are read in fixed-size chunks so a single oversized line can
never exhaust memory; the buffer never exceeds the configured line
limit plus one chunk. Every line yields a normalized record, a
rejection, or — for host-bearing lines outside the configured filter —
a foreign-host skip. The caller receives accurate accepted/rejected/
skipped counts with bounded, sanitized diagnostics. Identical adjacent
requests stay distinct: each record carries its source, file identity,
line number and byte offset for later replay handling. A running digest
of the exact logical bytes pulled from the stream (content, newlines,
rejected and skipped oversized data) lands on the report once EOF is
reached, so a fully consumed import can be checked against the file it
read from. For gzip sources the logical bytes are the decompressed
bytes: the same plaintext imported plain or gzipped carries one
identity, while offsets stay position-stable within that logical stream.
"""

import hashlib
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from app.ingestion.autodetect import DEFAULT_SAMPLE_LINES, MAX_SAMPLE_LINES
from app.ingestion.combined import (
    APACHE_COMBINED,
    AUTO,
    CUSTOM,
    NGINX_COMBINED,
    CombinedRecord,
    Limits,
    LineRejection,
    parse_line,
)
from app.ingestion.gzipio import (
    GzipLimits,
    LogicalFingerprint,
    has_gzip_magic,
    iter_decompressed_chunks,
    logical_fingerprint,
)
from app.ingestion.sources import FileIdentity, HostFilter, identify_file, open_source_log

_CHUNK_SIZE = 65536
# Consecutive per-line engine-timeout rejections that abort an import:
# a file that keeps timing the custom match out is adversarial input,
# not a slow file, and fails honestly instead of burning CPU line by line.
CUSTOM_TIMEOUT_ABORT_STREAK = 16
# Absolute per-import engine-timeout budget: alternating adversarial and
# valid lines reset the streak forever, so a second global bound is
# required. Either bound aborts the import with the same fixed
# ``custom_timeout`` code; accepted/rejected counts stay accurate and the
# EOF digest is simply left unset on interruption.
CUSTOM_TIMEOUT_ABORT_TOTAL = 32
# Wall-clock budget for cumulative custom-match time per import. The
# streak/total counters bound timeout *counts*; this bounds elapsed
# *matching* time for inputs that time out slowly without hitting the
# count quickly. No background threads: measured inline around matches.
CUSTOM_TIMEOUT_ABORT_MATCH_S = 30.0


@dataclass
class ImportReport:
    """Accepted/rejected/skipped accounting for one streamed file. Diagnostics are bounded."""

    source_id: str
    format_id: str
    file: FileIdentity | None = None
    lines_read: int = 0
    bytes_read: int = 0
    accepted: int = 0
    rejected: int = 0
    foreign_skipped: int = 0
    is_gzip: bool = False
    gzip_members: int = 0
    compressed_sha256: str | None = None
    rejected_by_reason: dict[str, int] = field(default_factory=dict)
    diagnostics: list[LineRejection] = field(default_factory=list)
    skipped_hosts: list["HostSkipped"] = field(default_factory=list)
    diagnostics_truncated: int = 0
    consumed_sha256: str | None = None

    def note_accepted(self, record: CombinedRecord) -> None:
        self.lines_read += 1
        self.accepted += 1

    def note_rejected(self, rejection: LineRejection, max_diagnostics: int) -> None:
        self.lines_read += 1
        self.rejected += 1
        self.rejected_by_reason[rejection.reason] = (
            self.rejected_by_reason.get(rejection.reason, 0) + 1
        )
        if len(self.diagnostics) + len(self.skipped_hosts) < max_diagnostics:
            self.diagnostics.append(rejection)
        else:
            self.diagnostics_truncated += 1

    def note_skipped(self, skipped: "HostSkipped", max_diagnostics: int) -> None:
        self.lines_read += 1
        self.foreign_skipped += 1
        if len(self.diagnostics) + len(self.skipped_hosts) < max_diagnostics:
            self.skipped_hosts.append(skipped)
        else:
            self.diagnostics_truncated += 1


#: Fixed marker for skipped foreign hosts. The configured host itself is
#: attacker-controlled log content (a foreign logged host can itself be an
#: address), so the raw value is never retained in diagnostics, reports,
#: errors or logs; counters plus line/offset positions keep the signal.
WITHHELD_HOST = "<withheld>"


@dataclass(frozen=True)
class HostSkipped:
    """A host-bearing line outside the configured filter: valid, not malformed.

    ``host`` is always the fixed :data:`WITHHELD_HOST` marker, never the
    raw foreign logged host, which could itself be an address. Host-filter
    accounting (counts plus line/offset positions) stays useful without
    retaining attacker-controlled bytes.
    """

    line_number: int
    byte_offset: int
    host: str = WITHHELD_HOST


@dataclass(frozen=True)
class RawLine:
    """One physical line: byte offset and bytes, or None when oversized."""

    offset: int
    data: bytes | None


def iter_raw_lines(
    stream: BinaryIO, *, max_line_bytes: int, hasher: "hashlib.HASH | None" = None
) -> Iterator[RawLine]:
    """Yield physical lines with their byte offsets, bounded memory.

    A line longer than ``max_line_bytes`` (no newline within the limit)
    yields a single oversized marker; its remainder is skipped without
    buffering. A final line without a trailing newline is still yielded.

    When ``hasher`` is given, every raw byte pulled from the stream —
    line content, newlines, rejected lines and skipped oversized data —
    is fed to it at chunk-read time, so the digest reflects exactly what
    the import consumed without retaining input or re-reading the file.
    """
    yield from iter_chunk_lines(_read_stream_chunks(stream, hasher), max_line_bytes=max_line_bytes)


def _read_stream_chunks(stream: BinaryIO, hasher: "hashlib.HASH | None" = None) -> Iterator[bytes]:
    while True:
        chunk = stream.read(_CHUNK_SIZE)
        if hasher is not None:
            hasher.update(chunk)
        if not chunk:
            return
        yield chunk


def iter_chunk_lines(chunks: Iterator[bytes], *, max_line_bytes: int) -> Iterator[RawLine]:
    """Split an arbitrary chunk iterator into bounded physical lines.

    Offsets count logical bytes yielded by the chunk source (raw file
    bytes for plain sources, decompressed bytes for gzip sources), so
    replay positions stay stable within one logical stream.
    """
    consumed = 0
    line_start = 0
    pending = bytearray()
    skipping = False
    skip_start = 0
    for chunk in chunks:
        pos = 0
        end = len(chunk)
        while pos < end:
            if skipping:
                newline = chunk.find(b"\n", pos)
                if newline == -1:
                    pos = end
                else:
                    pos = newline + 1
                    line_start = consumed + pos
                    skipping = False
                    yield RawLine(skip_start, None)
                continue
            newline = chunk.find(b"\n", pos)
            if newline == -1:
                pending += chunk[pos:]
                if len(pending) > max_line_bytes:
                    # Defer the marker until the line end (newline or EOF)
                    # so each physical line reports exactly once.
                    skip_start = line_start
                    pending = bytearray()
                    skipping = True
                pos = end
            else:
                pending += chunk[pos : newline + 1]
                content = bytes(pending[:-1])
                if content.endswith(b"\r"):
                    content = content[:-1]
                pending = bytearray()
                if len(content) > max_line_bytes:
                    skip_start = line_start
                    line_start = consumed + newline + 1
                    yield RawLine(skip_start, None)
                else:
                    start = line_start
                    line_start = consumed + newline + 1
                    yield RawLine(start, content)
                pos = newline + 1
        consumed += end
    if skipping:
        yield RawLine(skip_start, None)
    elif pending:
        yield RawLine(line_start, bytes(pending))


def fingerprint_source(path: Path, *, gzip_limits: GzipLimits | None = None) -> LogicalFingerprint:
    """Logical-domain fingerprint of a source (bounded streaming, no retain)."""
    return logical_fingerprint(path, limits=gzip_limits)


def _parse_item(
    raw: bytes | None,
    *,
    effective_format: str,
    source_id: str,
    hmac_key: bytes,
    line_number: int,
    byte_offset: int,
    identity: FileIdentity,
    limits: Limits,
    custom_format=None,
    capture_original: bool = False,
) -> tuple:
    """Parse one line, always returning ``(item, original_or_None)``.

    ``original`` is the validated client address text transiently
    captured from the same match the HMAC derives from, present only
    when ``capture_original`` is set and the line parsed. It must flow
    only into the encrypted private channel, never into routine fields.
    """
    from app.ingestion.custom import parse_custom_line

    if raw is None:
        return (
            LineRejection(
                line_number,
                byte_offset,
                "oversized_line",
                f"<line exceeds {limits.max_line_bytes} bytes>",
            ),
            None,
        )
    if custom_format is not None:
        parsed = parse_custom_line(
            raw,
            spec=custom_format,
            source_id=source_id,
            hmac_key=hmac_key,
            line_number=line_number,
            byte_offset=byte_offset,
            file_dev=identity.dev,
            file_ino=identity.ino,
            limits=limits,
            capture_original=capture_original,
        )
    else:
        parsed = parse_line(
            raw,
            source_id=source_id,
            format_id=effective_format,
            hmac_key=hmac_key,
            line_number=line_number,
            byte_offset=byte_offset,
            file_dev=identity.dev,
            file_ino=identity.ino,
            limits=limits,
            capture_original=capture_original,
        )
    if capture_original:
        item, original = parsed
        if not isinstance(item, CombinedRecord):
            # Never carry an original out with a rejection: only records
            # flow into the encrypted private channel.
            return item, None
        return item, original
    return parsed, None


def _check_sample_lines(sample_lines: int) -> None:
    """Reject non-integer or out-of-range autodetect sample sizes."""
    if (
        isinstance(sample_lines, bool)
        or not isinstance(sample_lines, int)
        or not 1 <= sample_lines <= MAX_SAMPLE_LINES
    ):
        raise ValueError(f"autodetect_sample_lines must be an integer in 1..{MAX_SAMPLE_LINES}")


def _abort_on_timeout_abuse(
    item,
    timeout_streak: int,
    timeout_total: int,
    timeout_match_s: float,
) -> tuple[int, int]:
    """Bound custom-match engine timeouts per import; abort abuse honestly.

    Returns the updated ``(streak, total)``. The consecutive streak
    catches sustained runs; the absolute total catches adversarial lines
    interleaved with valid requests (which reset the streak forever);
    the cumulative timed-out matching time catches slow timeouts before
    the count alone would. Any bound fails with the fixed
    ``custom_timeout`` code through :class:`CustomFormatError` instead of
    burning CPU. Accepted/rejected counts stay accurate and the EOF
    digest is left unset on interruption.
    """
    from app.ingestion.custom import CustomFormatError

    if isinstance(item, LineRejection) and item.reason == "custom_timeout":
        timeout_streak += 1
        timeout_total += 1
        if (
            timeout_streak >= CUSTOM_TIMEOUT_ABORT_STREAK
            or timeout_total >= CUSTOM_TIMEOUT_ABORT_TOTAL
            or timeout_match_s >= CUSTOM_TIMEOUT_ABORT_MATCH_S
        ):
            raise CustomFormatError("interrupted:custom_timeout")
        return timeout_streak, timeout_total
    return 0, timeout_total


def iter_records(
    path: Path,
    *,
    source_id: str,
    format_id: str,
    hmac_key: bytes,
    limits: Limits | None = None,
    report: ImportReport | None = None,
    host_filter: HostFilter | None = None,
    custom_format=None,
    gzip_limits: GzipLimits | None = None,
    autodetect_sample_lines: int = DEFAULT_SAMPLE_LINES,
    default_combined: str = NGINX_COMBINED,
    capture_original: bool = False,
) -> Iterator[CombinedRecord | LineRejection | HostSkipped | tuple]:
    """Stream one resolved source file, yielding records, rejections or skips.

    The file is opened read-only. Gzip sources are detected by magic bytes
    (never the extension) and decompressed within bounds. ``auto`` resolves
    per file through sampled detection and fails closed on ambiguity; the
    indistinguishable Combined twins resolve to ``default_combined`` (the
    configured server flavor). Host-bearing lines outside ``host_filter``
    yield :class:`HostSkipped` instead of records. With
    ``capture_original=True`` each yield is an ``(item, original_or_None)``
    pair; otherwise bare items are yielded and the default path stays
    compatible. ``report`` accumulates
    accounting as items are consumed; pass one in to inspect counts
    afterwards. Sustained custom-match engine timeouts abort the import
    with a fixed ``custom_timeout`` failure instead of burning CPU line
    by line: a consecutive streak, an absolute per-import total (so
    alternating adversarial/valid lines cannot reset the bound forever),
    and a cumulative timed-out matching-time budget.
    """
    from app.ingestion.autodetect import resolve_format

    _check_sample_lines(autodetect_sample_lines)
    if default_combined not in (NGINX_COMBINED, APACHE_COMBINED):
        raise ValueError(f"unknown default_combined: {default_combined!r}")
    limits = limits or Limits()
    gzip_limits = gzip_limits or GzipLimits()
    identity = identify_file(path)
    if report is not None:
        report.file = identity
        report.bytes_read = identity.size
    if format_id == CUSTOM and custom_format is None:
        raise ValueError("format_id 'custom' requires a validated custom_format")
    effective_format = format_id
    if custom_format is not None:
        effective_format = custom_format.format_id
    elif format_id == AUTO:
        effective_format = resolve_format(
            format_id,
            path,
            limits=limits,
            sample_lines=autodetect_sample_lines,
            default_combined=default_combined,
            gzip_limits=gzip_limits,
        )
    if effective_format in (AUTO, CUSTOM):
        raise ValueError(f"unresolved format_id: {effective_format!r}")
    if report is not None:
        report.format_id = effective_format
    hasher = hashlib.sha256()
    line_number = 0
    is_gzip = has_gzip_magic(path)
    if report is not None:
        report.is_gzip = is_gzip
    if is_gzip:
        chunks, stats = iter_decompressed_chunks(path, limits=gzip_limits)
        if report is not None:
            report.gzip_members = stats["members"]

        def _hashed_chunks() -> Iterator[bytes]:
            for data in chunks:
                hasher.update(data)
                yield data
            if report is not None:
                report.gzip_members = stats["members"]

        line_iter = iter_chunk_lines(_hashed_chunks(), max_line_bytes=limits.max_line_bytes)
        timeout_streak = 0
        timeout_total = 0
        timeout_match_s = 0.0
        for raw in line_iter:
            line_number += 1
            match_start = time.monotonic() if custom_format is not None else 0.0
            item, original = _parse_item(
                raw.data,
                effective_format=effective_format,
                source_id=source_id,
                hmac_key=hmac_key,
                line_number=line_number,
                byte_offset=raw.offset,
                identity=identity,
                limits=limits,
                custom_format=custom_format,
                capture_original=capture_original,
            )
            if (
                custom_format is not None
                and isinstance(item, LineRejection)
                and item.reason == "custom_timeout"
            ):
                timeout_match_s += time.monotonic() - match_start
            # The terminal timed-out line is accounted exactly once
            # BEFORE the fixed interruption: _account runs first so the
            # physical line lands in lines_total/rejected, while the EOF
            # digest below is still left unset on interruption.
            accounted = _account(item, report, limits, host_filter, line_number, raw.offset)
            timeout_streak, timeout_total = _abort_on_timeout_abuse(
                item, timeout_streak, timeout_total, timeout_match_s
            )
            # No original ever leaves with a skip or rejection: only
            # accepted records flow into the encrypted private channel.
            kept = original if isinstance(accounted, CombinedRecord) else None
            yield (accounted, kept) if capture_original else accounted
        if report is not None:
            report.consumed_sha256 = hasher.hexdigest()
        return
    with open_source_log(path) as stream:
        timeout_streak = 0
        timeout_total = 0
        timeout_match_s = 0.0
        for raw in iter_raw_lines(stream, max_line_bytes=limits.max_line_bytes, hasher=hasher):
            line_number += 1
            match_start = time.monotonic() if custom_format is not None else 0.0
            item, original = _parse_item(
                raw.data,
                effective_format=effective_format,
                source_id=source_id,
                hmac_key=hmac_key,
                line_number=line_number,
                byte_offset=raw.offset,
                identity=identity,
                limits=limits,
                custom_format=custom_format,
                capture_original=capture_original,
            )
            if (
                custom_format is not None
                and isinstance(item, LineRejection)
                and item.reason == "custom_timeout"
            ):
                timeout_match_s += time.monotonic() - match_start
            # Accounted before the abort (see the gzip path above): the
            # terminal timed-out physical line counts exactly once.
            accounted = _account(item, report, limits, host_filter, line_number, raw.offset)
            timeout_streak, timeout_total = _abort_on_timeout_abuse(
                item, timeout_streak, timeout_total, timeout_match_s
            )
            # No original ever leaves with a skip or rejection (see above).
            kept = original if isinstance(accounted, CombinedRecord) else None
            yield (accounted, kept) if capture_original else accounted
    # Reached only when the stream was consumed to EOF: the digest then
    # covers exactly the bytes this import read. Interruptions propagate
    # before this point and leave ``consumed_sha256`` unset.
    if report is not None:
        report.consumed_sha256 = hasher.hexdigest()


def _account(item, report: ImportReport | None, limits: Limits, host_filter, line_number, offset):
    if isinstance(item, CombinedRecord) and host_filter is not None:
        host = item.extra.server_host if item.extra is not None else None
        if host is not None and not host_filter.matches(host):
            skipped = HostSkipped(line_number, offset)
            if report is not None:
                report.note_skipped(skipped, limits.max_diagnostics)
            return skipped
    if report is not None:
        if isinstance(item, CombinedRecord):
            report.note_accepted(item)
        elif isinstance(item, HostSkipped):
            report.note_skipped(item, limits.max_diagnostics)
        else:
            report.note_rejected(item, limits.max_diagnostics)
    return item


def collect_records(
    path: Path,
    *,
    source_id: str,
    format_id: str,
    hmac_key: bytes,
    limits: Limits | None = None,
    host_filter: HostFilter | None = None,
    custom_format=None,
    gzip_limits: GzipLimits | None = None,
    autodetect_sample_lines: int = DEFAULT_SAMPLE_LINES,
    default_combined: str = NGINX_COMBINED,
) -> tuple[list[CombinedRecord], ImportReport]:
    """Read a small source file fully; convenience wrapper for tests and previews.

    Production-scale imports must consume :func:`iter_records` in batches
    instead of materializing every record.
    """
    report = ImportReport(source_id=source_id, format_id=format_id)
    records = [
        item
        for item in iter_records(
            path,
            source_id=source_id,
            format_id=format_id,
            hmac_key=hmac_key,
            limits=limits,
            report=report,
            host_filter=host_filter,
            custom_format=custom_format,
            gzip_limits=gzip_limits,
            autodetect_sample_lines=autodetect_sample_lines,
            default_combined=default_combined,
        )
        if isinstance(item, CombinedRecord)
    ]
    return records, report
