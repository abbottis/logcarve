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
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from app.ingestion.autodetect import DEFAULT_SAMPLE_LINES
from app.ingestion.combined import (
    AUTO,
    CUSTOM,
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


@dataclass(frozen=True)
class HostSkipped:
    """A host-bearing line outside the configured filter: valid, not malformed."""

    line_number: int
    byte_offset: int
    host: str


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
):
    from app.ingestion.custom import parse_custom_line

    if raw is None:
        return LineRejection(
            line_number,
            byte_offset,
            "oversized_line",
            f"<line exceeds {limits.max_line_bytes} bytes>",
        )
    if custom_format is not None:
        return parse_custom_line(
            raw,
            spec=custom_format,
            source_id=source_id,
            hmac_key=hmac_key,
            line_number=line_number,
            byte_offset=byte_offset,
            file_dev=identity.dev,
            file_ino=identity.ino,
            limits=limits,
        )
    return parse_line(
        raw,
        source_id=source_id,
        format_id=effective_format,
        hmac_key=hmac_key,
        line_number=line_number,
        byte_offset=byte_offset,
        file_dev=identity.dev,
        file_ino=identity.ino,
        limits=limits,
    )


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
) -> Iterator[CombinedRecord | LineRejection | HostSkipped]:
    """Stream one resolved source file, yielding records, rejections or skips.

    The file is opened read-only. Gzip sources are detected by magic bytes
    (never the extension) and decompressed within bounds. ``auto`` resolves
    per file through sampled detection and fails closed on ambiguity.
    Host-bearing lines outside ``host_filter`` yield :class:`HostSkipped`
    instead of records. ``report`` accumulates accounting as items are
    consumed; pass one in to inspect counts afterwards.
    """
    from app.ingestion.autodetect import resolve_format

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
        for raw in line_iter:
            line_number += 1
            item = _parse_item(
                raw.data,
                effective_format=effective_format,
                source_id=source_id,
                hmac_key=hmac_key,
                line_number=line_number,
                byte_offset=raw.offset,
                identity=identity,
                limits=limits,
                custom_format=custom_format,
            )
            yield _account(item, report, limits, host_filter, line_number, raw.offset)
        if report is not None:
            report.consumed_sha256 = hasher.hexdigest()
        return
    with open_source_log(path) as stream:
        for raw in iter_raw_lines(stream, max_line_bytes=limits.max_line_bytes, hasher=hasher):
            line_number += 1
            item = _parse_item(
                raw.data,
                effective_format=effective_format,
                source_id=source_id,
                hmac_key=hmac_key,
                line_number=line_number,
                byte_offset=raw.offset,
                identity=identity,
                limits=limits,
                custom_format=custom_format,
            )
            yield _account(item, report, limits, host_filter, line_number, raw.offset)
    # Reached only when the stream was consumed to EOF: the digest then
    # covers exactly the bytes this import read. Interruptions propagate
    # before this point and leave ``consumed_sha256`` unset.
    if report is not None:
        report.consumed_sha256 = hasher.hexdigest()


def _account(item, report: ImportReport | None, limits: Limits, host_filter, line_number, offset):
    if isinstance(item, CombinedRecord) and host_filter is not None:
        host = item.extra.server_host if item.extra is not None else None
        if host is not None and not host_filter.matches(host):
            skipped = HostSkipped(line_number, offset, host[:253])
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
        )
        if isinstance(item, CombinedRecord)
    ]
    return records, report
