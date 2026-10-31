"""Streaming Combined import with bounded memory (T2).

Lines are read in fixed-size chunks so a single oversized line can
never exhaust memory; the buffer never exceeds the configured line
limit plus one chunk. Every line yields either a normalized record or
a rejection, and the caller receives accurate accepted/rejected counts
with bounded, sanitized diagnostics. Identical adjacent requests stay
distinct: each record carries its source, file identity, line number
and byte offset for later replay handling. A running digest of the
exact bytes pulled from the stream (content, newlines, rejected and
skipped oversized data) lands on the report once EOF is reached, so a
fully consumed import can be checked against the file it read from.
"""

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from app.ingestion.combined import (
    CombinedRecord,
    Limits,
    LineRejection,
    parse_line,
)
from app.ingestion.sources import FileIdentity, identify_file, open_source_log

_CHUNK_SIZE = 65536


@dataclass
class ImportReport:
    """Accepted/rejected accounting for one streamed file. Diagnostics are bounded."""

    source_id: str
    format_id: str
    file: FileIdentity | None = None
    lines_read: int = 0
    bytes_read: int = 0
    accepted: int = 0
    rejected: int = 0
    rejected_by_reason: dict[str, int] = field(default_factory=dict)
    diagnostics: list[LineRejection] = field(default_factory=list)
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
        if len(self.diagnostics) < max_diagnostics:
            self.diagnostics.append(rejection)
        else:
            self.diagnostics_truncated += 1


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
    consumed = 0
    line_start = 0
    pending = bytearray()
    skipping = False
    skip_start = 0
    while True:
        chunk = stream.read(_CHUNK_SIZE)
        if hasher is not None:
            hasher.update(chunk)
        if not chunk:
            if skipping:
                yield RawLine(skip_start, None)
            elif pending:
                yield RawLine(line_start, bytes(pending))
            return
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


def iter_records(
    path: Path,
    *,
    source_id: str,
    format_id: str,
    hmac_key: bytes,
    limits: Limits | None = None,
    report: ImportReport | None = None,
) -> Iterator[CombinedRecord | LineRejection]:
    """Stream one resolved source file, yielding records or rejections.

    The file is opened read-only. ``report`` accumulates accounting as
    items are consumed; pass one in to inspect counts afterwards.
    """
    limits = limits or Limits()
    identity = identify_file(path)
    if report is not None:
        report.file = identity
        report.bytes_read = identity.size
    hasher = hashlib.sha256()
    line_number = 0
    with open_source_log(path) as stream:
        for raw in iter_raw_lines(stream, max_line_bytes=limits.max_line_bytes, hasher=hasher):
            line_number += 1
            if raw.data is None:
                rejection = LineRejection(
                    line_number,
                    raw.offset,
                    "oversized_line",
                    f"<line exceeds {limits.max_line_bytes} bytes>",
                )
            else:
                item = parse_line(
                    raw.data,
                    source_id=source_id,
                    format_id=format_id,
                    hmac_key=hmac_key,
                    line_number=line_number,
                    byte_offset=raw.offset,
                    file_dev=identity.dev,
                    file_ino=identity.ino,
                    limits=limits,
                )
                rejection = None if isinstance(item, CombinedRecord) else item
            if report is not None:
                if rejection is None:
                    report.note_accepted(item)  # type: ignore[arg-type]
                else:
                    report.note_rejected(rejection, limits.max_diagnostics)
            yield item if rejection is None else rejection
    # Reached only when the stream was consumed to EOF: the digest then
    # covers exactly the bytes this import read. Interruptions propagate
    # before this point and leave ``consumed_sha256`` unset.
    if report is not None:
        report.consumed_sha256 = hasher.hexdigest()


def collect_records(
    path: Path,
    *,
    source_id: str,
    format_id: str,
    hmac_key: bytes,
    limits: Limits | None = None,
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
        )
        if isinstance(item, CombinedRecord)
    ]
    return records, report
