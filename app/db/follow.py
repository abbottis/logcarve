"""Opt-in CLI follow/watch with durable checkpoints and rotation handling (T5b2, PAR-08).

A bounded ``follow`` run tails one approved read-only source file across a
finite number of polls and commits each batch atomically with its
checkpoint progress: event rows, the ``follow_batches`` accounting row,
the generation checkpoint AND the running attempt counters land in ONE
writer transaction, so a cancel/restart can never meet a
commit-before-checkpoint duplicate window and a long active generation
reports real imported lines while it runs. Empty polls write nothing:
no import/job rows are created per idle tick, so a long-lived follow
never grows history.

Within a run the read cursor (pulled bytes) is separate from the
durable complete-line checkpoint: partial lines are carried in memory
once and never re-fed, so offsets and the running digest cover every
pulled byte exactly once with bounded per-poll memory. Concurrent
followers serialize on a checkpoint compare-and-swap inside the writer
transaction: stale work refuses with ``follow:stale_generation``
before any write, never rewinding progress.

Generations: every rotation, copytruncate shrink or replacement starts
a new generation with its own identity. A generation fingerprint
(``follow:v1:<source>:<seq>``) is honestly a generation label, never a
full-file content hash; batch logical-SHA/offset replay identity is
untouched, and no growing prefix is ever whole-file re-hashed per
appended line. A restart re-reads the consumed span once for validation
and digest resumption; a mismatch taints the generation and refuses
further adoption with safe guidance instead of silently duplicating.

Checkpoints persist offsets, digests, generation identity and aggregate
counts ONLY: never pending raw line bytes, chunks, URLs, User-Agents,
original addresses or keys. Unfinished partial lines stay in memory
within a run and are re-read from the checkpointed offset after a
restart. An unfinished OVERSIZED line additionally persists a minimal
discard marker (a flag plus the physical line start offset, no bytes):
the restart restores splitter drop mode from it so the completing
suffix can never be mistaken for a fresh line, and the marker clears
when the line ends or seals. The live path refuses gzip sources (replay
a gzip archive via ``replay_archive`` instead); per-poll memory is
bounded and an oversized partial line yields exactly one rejection at
completion.

Known polling limits (documented, not silently claimed): a rotation
between polls can lose lines written after the last poll; a same-inode
same-size rewrite is invisible until restart validation; a replacement
file that repeats already-ingested content starts a new generation
rather than a replay. Rotated archives keep full provenance through
``replay_archive``, which validates the sealed prefix before ingesting
only the new tail under the same generation identity.
"""

import hashlib
import os
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from app.db import repositories
from app.db.database import WriterBusy, connect, writer_transaction
from app.db.importer import (
    SOURCE_CONTENT_MISMATCH_CODE,
    _batch_core,
    _event_row,
    failure_code,
)
from app.db.migrations_runner import migrate
from app.ingestion.autodetect import AmbiguousFormat, UnmatchedFormat, resolve_format
from app.ingestion.combined import (
    APACHE_COMBINED,
    APACHE_VHOST_COMBINED,
    AUTO,
    CUSTOM,
    NGINX_COMBINED,
    NGINX_EXTENDED,
    CapturedOriginal,
    CombinedRecord,
    Limits,
    enrichment_policy,
)
from app.ingestion.custom import CustomFormat, CustomFormatError
from app.ingestion.geoip import (
    GEO_STATUS_UNKNOWN,
    CountryInfo,
    CountryLookup,
    GeoipError,
)
from app.ingestion.gzipio import (
    GzipError,
    GzipLimits,
    has_gzip_magic,
    iter_decompressed_chunks,
)
from app.ingestion.sources import (
    FileIdentity,
    HostFilter,
    SourceConfig,
    SourceError,
    resolve_source_path,
)

# Deliberate reuse of the streaming parser internals: follow must parse,
# account and bound custom-timeout abuse EXACTLY like batch import, so
# privacy/GeoIP/enrichment behavior stays identical across modes.
from app.ingestion.stream import (
    _abort_on_timeout_abuse,
    _parse_item,
)

#: Generation fingerprint label prefix. Honestly NOT a content hash: it
#: names the consuming follow generation (source + sequence). Batch
#: logical-SHA identity is never mixed into this label.
FOLLOW_FINGERPRINT_PREFIX = "follow:v1"

#: Live generation states. ``rotated`` also covers sealed-by-truncation
#: and sealed-by-replacement; ``tainted`` refuses further adoption.
STATUS_ACTIVE = "active"
STATUS_ROTATED = "rotated"
STATUS_TAINTED = "tainted"

#: Fixed follow diagnostic codes. Stored detail fields and served
#: payloads carry only these segments; never paths, raw bytes, secrets
#: or exception text.
FOLLOW_GZIP_UNSUPPORTED = "follow:live_gzip_unsupported"
AMBIGUOUS_PREFIX_ADOPTION = "follow:ambiguous_prefix_adoption"
ARCHIVE_PREFIX_MISMATCH = "follow:archive_prefix_mismatch"
PREFIX_TAINTED = "follow:prefix_mismatch"
ROTATION_TARGET_MISSING = "follow:rotation_target_missing"
STALE_GENERATION_CODE = "follow:stale_generation"
WRITER_BUSY_CODE = "interrupted:writer_busy"
IO_ERROR_CODE = "interrupted:io_error"

_FOLLOW_DETAIL_CODES = frozenset(
    (
        FOLLOW_GZIP_UNSUPPORTED,
        AMBIGUOUS_PREFIX_ADOPTION,
        ARCHIVE_PREFIX_MISMATCH,
        PREFIX_TAINTED,
        ROTATION_TARGET_MISSING,
        STALE_GENERATION_CODE,
        WRITER_BUSY_CODE,
        IO_ERROR_CODE,
    )
)

#: Poll bound defaults: finite polls, short sleeps, bounded reads.
DEFAULT_MAX_POLLS = 60
DEFAULT_POLL_INTERVAL_S = 1.0
DEFAULT_MAX_BYTES_PER_POLL = 8 * 1024 * 1024
DEFAULT_MAX_WRITER_RETRIES = 5

#: Re-validation window for the latest committed bytes (per poll, bounded).
#: A same-inode truncation followed by fast regrowth past the old size is
#: invisible to size checks, so every normal poll re-reads at most this
#: many trailing committed bytes and compares them to the window digest
#: captured at commit time. Older bytes are covered by the once-per-
#: restart full-span validation; a window mismatch seals the generation
#: and starts a new one, exactly like a detected shrink.
TAIL_WINDOW_BYTES = 65536

_HASH_CHUNK = 1024 * 1024


#: Refusal when no sealed generation exists for an archive replay.
ARCHIVE_NO_SEALED_GENERATION = "follow:archive_no_sealed_generation"


class FollowRefused(Exception):
    """Ambiguous adoption: refuse with safe guidance, never duplicate."""

    def __init__(self, code: str, guidance: str) -> None:
        super().__init__(code)
        self.code = code
        self.guidance = guidance


def generation_fingerprint(source_id: str, seq: int) -> str:
    """Honestly-labeled generation identity (not a content hash)."""
    return f"{FOLLOW_FINGERPRINT_PREFIX}:{source_id}:{seq}"


def generation_id(source_id: str, seq: int, identity: FileIdentity, start: int) -> str:
    """Durable human-meaningful generation label (identity, not content)."""
    return f"{source_id}:gen{seq}:{identity.dev:x}i{identity.ino:x}@{start}"


@dataclass
class FollowResult:
    """Bounded accounting of one follow run (counts and fixed codes only)."""

    source_id: str
    status: str = "completed"
    error_summary: str | None = None
    guidance: str | None = None
    polls: int = 0
    empty_polls: int = 0
    generations_started: int = 0
    lines_accepted: int = 0
    lines_rejected: int = 0
    lines_skipped_foreign: int = 0
    records_inserted: int = 0
    records_replayed: int = 0
    originals_captured: int = 0
    originals_skipped_mismatch: int = 0
    sealed_generations: list[int] = field(default_factory=list)
    active_generation: int | None = None
    drain_truncated: bool = False
    rejected_by_reason: dict[str, int] = field(default_factory=dict)


@dataclass
class ArchiveResult:
    """Accounting of one archive replay (counts and fixed codes only)."""

    source_id: str
    archive_path: str = ""
    generation_seq: int = 0
    status: str = "completed"
    error_summary: str | None = None
    guidance: str | None = None
    lines_accepted: int = 0
    lines_rejected: int = 0
    lines_skipped_foreign: int = 0
    records_inserted: int = 0
    records_replayed: int = 0
    originals_captured: int = 0
    originals_skipped_mismatch: int = 0
    rejected_by_reason: dict[str, int] = field(default_factory=dict)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _check_source_binding(db_path: Path, *, source_id: str, site_id: str) -> None:
    """Reject a source id already bound to another site before any write."""
    probe = connect(db_path, read_only=True)
    try:
        registered = repositories.fetch_source(probe, source_id=source_id)
    finally:
        probe.close()
    if registered is not None and str(registered["site_id"]) != site_id:
        raise repositories.SourceBindingError()


def _load_generation(conn: sqlite3.Connection, *, source_id: str, seq: int):
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT source_id, site_id, generation_seq, generation_id,"
            " file_dev, file_ino, gen_start_offset, next_offset,"
            " next_line_number, oversized_active, oversized_start,"
            " consumed_sha256, file_size, file_mtime_ns,"
            " adopted_prefix_sha, adopted_import_id, fresh_start, import_id,"
            " status, detail, updated_at FROM follow_generations"
            " WHERE source_id = ? AND generation_seq = ?",
            (source_id, seq),
        ).fetchone()
    finally:
        conn.row_factory = None


def _latest_generation(conn: sqlite3.Connection, *, source_id: str):
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT source_id, site_id, generation_seq, generation_id,"
            " file_dev, file_ino, gen_start_offset, next_offset,"
            " next_line_number, oversized_active, oversized_start,"
            " consumed_sha256, file_size, file_mtime_ns,"
            " adopted_prefix_sha, adopted_import_id, fresh_start, import_id,"
            " status, detail, updated_at FROM follow_generations"
            " WHERE source_id = ? ORDER BY generation_seq DESC LIMIT 1",
            (source_id,),
        ).fetchone()
    finally:
        conn.row_factory = None


def _store_generation(conn: sqlite3.Connection, *, row: dict) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO follow_generations (source_id, site_id,"
        " generation_seq, generation_id, file_dev, file_ino,"
        " gen_start_offset, next_offset, next_line_number, oversized_active,"
        " oversized_start, consumed_sha256,"
        " file_size, file_mtime_ns, adopted_prefix_sha, adopted_import_id,"
        " fresh_start, import_id, status, detail, updated_at)"
        " VALUES (:source_id, :site_id, :generation_seq, :generation_id,"
        " :file_dev, :file_ino, :gen_start_offset, :next_offset,"
        " :next_line_number, :oversized_active, :oversized_start,"
        " :consumed_sha256, :file_size, :file_mtime_ns,"
        " :adopted_prefix_sha, :adopted_import_id, :fresh_start, :import_id,"
        " :status, :detail, :updated_at)",
        row,
    )


def _ensure_follow_progress_columns(db_path: Path) -> None:
    """Backfill the discard-marker columns on pre-fix migration-8 stores.

    Migration 0008 is unreleased (live stays schema 4, candidates torn
    down), so its text now carries the columns for fresh stores; this
    idempotent step only heals a store created by the earlier 0008 text.
    Progress metadata only: a flag plus one integer offset, never bytes.
    A concurrent backfill loses harmlessly (duplicate-column error).
    """
    conn = sqlite3.connect(db_path)
    try:
        have = {info[1] for info in conn.execute("PRAGMA table_info(follow_generations)")}
        missing = {
            "oversized_active": "ALTER TABLE follow_generations ADD COLUMN oversized_active INTEGER NOT NULL DEFAULT 0",
            "oversized_start": "ALTER TABLE follow_generations ADD COLUMN oversized_start INTEGER",
        }
        for name, ddl in missing.items():
            if name not in have:
                try:
                    conn.execute(ddl)
                except sqlite3.OperationalError as exc:
                    if "duplicate column" not in str(exc).lower():
                        raise
        conn.commit()
    finally:
        conn.close()


def _record_follow_batch(
    conn: sqlite3.Connection,
    *,
    source_id: str,
    seq: int,
    start_offset: int,
    end_offset: int,
    accepted: int,
    rejected: int,
    skipped_foreign: int,
    inserted: int,
    replayed: int,
    consumed_sha256: str,
) -> None:
    conn.execute(
        "INSERT INTO follow_batches (source_id, generation_seq,"
        " start_offset, end_offset, lines_accepted, lines_rejected,"
        " lines_skipped_foreign, records_inserted, records_replayed,"
        " consumed_sha256, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            source_id,
            seq,
            start_offset,
            end_offset,
            accepted,
            rejected,
            skipped_foreign,
            inserted,
            replayed,
            consumed_sha256,
            _now(),
        ),
    )


def _tail_window(
    path: Path, start: int, end: int, *, gzip_limits: GzipLimits | None = None
) -> tuple[int, str]:
    """Digest of the latest committed logical window ``[max(start, end-N), end)``.

    Returns ``(window_start, hex)``; an empty span yields ``(start, "")``
    and is never checked. Logical bytes are hashed, so gzip archives
    validate against the same digest chain the commits extend. Only
    offsets and digests leave this helper.
    """
    window_start = max(start, end - TAIL_WINDOW_BYTES)
    if window_start >= end:
        return start, ""
    return window_start, _hash_logical_span(path, window_start, end, gzip_limits=gzip_limits)


def _hash_span(path: Path, start: int, end: int) -> str:
    """SHA-256 over raw file bytes ``[start, end)`` (streamed, bounded memory)."""
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        stream.seek(start)
        remaining = end - start
        while remaining > 0:
            chunk = stream.read(min(_HASH_CHUNK, remaining))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def _hash_logical_span(
    path: Path, start: int, end: int, *, gzip_limits: GzipLimits | None = None
) -> str:
    """SHA-256 over logical stream bytes ``[start, end)``.

    Plain files hash raw bytes; gzip members hash decompressed bytes so
    the same plaintext validates identically in either mode. The span is
    streamed with bounded memory; the prefix before ``start`` is
    decompressed and discarded (one bounded validation pass).
    """
    if not has_gzip_magic(path):
        return _hash_span(path, start, end)
    limits = gzip_limits or GzipLimits()
    digest = hashlib.sha256()
    position = 0
    for piece in iter_decompressed_chunks(path, limits=limits)[0]:
        if position + len(piece) <= start:
            position += len(piece)
            continue
        low = max(0, start - position)
        high = min(len(piece), end - position)
        if high > low:
            digest.update(piece[low:high])
        position += len(piece)
        if position >= end:
            break
    return digest.hexdigest()


def _iter_logical_pieces(path: Path, start: int, *, gzip_limits: GzipLimits | None = None):
    """Yield ``(abs_offset, bytes)`` of a logical stream from ``start``.

    Plain files seek and stream raw bytes; gzip members stream
    decompressed bytes with the prefix before ``start`` discarded. One
    bounded forward pass; the caller hashes and splits lines.
    """
    if not has_gzip_magic(path):
        with open(path, "rb") as stream:
            stream.seek(start)
            position = start
            while True:
                chunk = stream.read(_HASH_CHUNK)
                if not chunk:
                    return
                yield position, chunk
                position += len(chunk)
        return
    limits = gzip_limits or GzipLimits()
    position = 0
    for piece in iter_decompressed_chunks(path, limits=limits)[0]:
        if position + len(piece) <= start:
            position += len(piece)
            continue
        low = max(0, start - position)
        if low < len(piece):
            yield position + low, piece[low:]
        position += len(piece)


class _LineFollower:
    """Split bounded poll reads into complete physical lines with offsets.

    Trailing unterminated bytes stay pending in memory (never
    persisted); the caller keeps the checkpoint at the partial start so
    a restart re-reads them. Memory stays bounded: a pending line past
    the limit switches to skip mode and yields exactly one oversized
    marker at the next newline (or at seal). ``\\r`` before ``\\n`` is
    stripped, mirroring the batch splitter.
    """

    def __init__(self, max_line_bytes: int) -> None:
        self._max = max_line_bytes
        self.pending = bytearray()
        self.pending_start = 0
        self.skipping = False
        self.skip_start = 0

    def feed(
        self, data: bytes, base_offset: int
    ) -> tuple[list[tuple[int, bytes | None, int]], list[tuple[int, int]]]:
        """Consume new bytes; return completed lines plus dropped spans.

        Returns ``(items, dropped)`` where ``items`` are
        ``(offset, line|None, end)`` completes (``None`` data marks one
        oversized line; ``end`` is just past the newline) and
        ``dropped`` lists absolute ``(start, end)`` spans of oversized
        bytes that left memory without becoming an item: skip-mode
        bytes before a newline, a whole still-skipping chunk, or the
        tail that newly trips skip mode. The caller hashes ``dropped``
        in offset order at commit time; the trailing partial (if any)
        stays pending and unhashed until it completes.
        """
        out: list[tuple[int, bytes | None, int]] = []
        dropped: list[tuple[int, int]] = []
        if self.skipping:
            newline = data.find(b"\n")
            if newline == -1:
                dropped.append((base_offset, base_offset + len(data)))
                return out, dropped
            dropped.append((base_offset, base_offset + newline + 1))
            out.append((self.skip_start, None, base_offset + newline + 1))
            self.skipping = False
            base_offset += newline + 1
            data = data[newline + 1 :]
            if not data:
                return out, dropped
        if self.pending:
            start = self.pending_start
            buf = bytes(self.pending) + data
            self.pending = bytearray()
            base_offset = start
        else:
            buf = data
        pos = 0
        line_start = base_offset
        while True:
            newline = buf.find(b"\n", pos)
            if newline == -1:
                break
            content = buf[pos:newline]
            if content.endswith(b"\r"):
                content = content[:-1]
            line_end = base_offset + newline + 1
            if len(content) > self._max:
                # Mirror the batch splitter: an oversized physical line
                # reports exactly once (here, at its newline).
                out.append((line_start, None, line_end))
            else:
                out.append((line_start, content, line_end))
            pos = newline + 1
            line_start = base_offset + pos
        rest = buf[pos:]
        if rest:
            if len(rest) > self._max:
                self.skipping = True
                self.skip_start = line_start
                dropped.append((line_start, base_offset + len(buf)))
            else:
                self.pending = bytearray(rest)
                self.pending_start = line_start
        return out, dropped

    def seal(self, pulled_end: int) -> list[tuple[int, bytes | None, int]]:
        """Close a sealed generation: exactly one item per leftover.

        A skipping tail yields its oversized marker (``None``) spanning
        to ``pulled_end``: every skipped byte was already hashed (and
        checkpointed) by per-feed dropped-span commits, so the marker
        batch hash covers nothing new while the checkpoint honestly
        lands past the consumed tail. A non-empty pending partial is a
        real final line — the sealed file is complete, so batch EOF
        semantics apply and the bytes are consumed, never discarded.
        """
        out: list[tuple[int, bytes | None, int]] = []
        if self.skipping:
            out.append((self.skip_start, None, max(pulled_end, self.skip_start)))
            self.skipping = False
        elif self.pending:
            data = bytes(self.pending)
            self.pending = bytearray()
            out.append((self.pending_start, data, self.pending_start + len(data)))
        return out


@dataclass
class _RunContext:
    """Validated follow inputs shared by every poll and batch."""

    source: SourceConfig
    site_id: str
    site_name: str
    site_hostname: str
    server_type: str
    path_alias: str
    hmac_key: bytes
    batch_size: int
    effective_filter: HostFilter | None
    custom_format: CustomFormat | None
    default_combined: str
    limits: Limits
    gzip_limits: GzipLimits
    capture_originals: bool
    private_key: bytes | None
    lookup: CountryLookup
    policy: str
    lock_timeout_s: float
    max_writer_retries: int


def _fd_identity(fd: int) -> FileIdentity:
    stat = os.fstat(fd)
    return FileIdentity(
        dev=stat.st_dev, ino=stat.st_ino, size=stat.st_size, mtime_ns=stat.st_mtime_ns
    )


def _gen_row(
    *,
    source_id: str,
    site_id: str,
    seq: int,
    gen_id: str,
    identity: FileIdentity,
    gen_start: int,
    next_line: int,
    digest: str,
    adopted_prefix_sha: str | None,
    adopted_import_id: int | None,
    fresh_start: bool,
    import_id: int | None,
    status: str,
    detail: str | None,
) -> dict:
    return {
        "source_id": source_id,
        "site_id": site_id,
        "generation_seq": seq,
        "generation_id": gen_id,
        "file_dev": identity.dev,
        "file_ino": identity.ino,
        "gen_start_offset": gen_start,
        "next_offset": gen_start,
        "next_line_number": next_line,
        "oversized_active": 0,
        "oversized_start": None,
        "consumed_sha256": digest,
        "file_size": identity.size,
        "file_mtime_ns": identity.mtime_ns,
        "adopted_prefix_sha": adopted_prefix_sha,
        "adopted_import_id": adopted_import_id,
        "fresh_start": 1 if fresh_start else 0,
        "import_id": import_id,
        "status": status,
        "detail": detail,
        "updated_at": _now(),
    }


def _start_generation(
    conn: sqlite3.Connection,
    ctx: _RunContext,
    *,
    seq: int,
    identity: FileIdentity,
    gen_start: int,
    adopted_prefix_sha: str | None,
    adopted_import_id: int | None,
    fresh_start: bool,
) -> dict:
    """Register site/source, open the generation attempt row and checkpoint.

    All three land in the caller's writer transaction: a generation
    never exists without its attempt row and checkpoint.
    """
    repositories.ensure_site(
        conn,
        site_id=ctx.site_id,
        name=ctx.site_name,
        hostname=ctx.site_hostname,
        created_at=_now(),
    )
    repositories.ensure_source_locked(
        conn,
        source_id=ctx.source.source_id,
        site_id=ctx.site_id,
        server_type=ctx.server_type,
        format_id=ctx.source.format_id,
        path_alias=ctx.path_alias,
        allowed_hosts=(
            sorted(ctx.effective_filter.hosts) if ctx.effective_filter is not None else None
        ),
    )
    if ctx.effective_filter is not None:
        repositories.update_source_hosts(
            conn,
            source_id=ctx.source.source_id,
            site_id=ctx.site_id,
            allowed_hosts=sorted(ctx.effective_filter.hosts),
        )
    fingerprint = generation_fingerprint(ctx.source.source_id, seq)
    import_id = repositories.create_import(
        conn,
        source_id=ctx.source.source_id,
        file_fingerprint=fingerprint,
        file_size=identity.size,
        started_at=_now(),
    )
    row = _gen_row(
        source_id=ctx.source.source_id,
        site_id=ctx.site_id,
        seq=seq,
        gen_id=generation_id(ctx.source.source_id, seq, identity, gen_start),
        identity=identity,
        gen_start=gen_start,
        next_line=1,
        digest=hashlib.sha256().hexdigest() if gen_start == 0 else "",
        adopted_prefix_sha=adopted_prefix_sha,
        adopted_import_id=adopted_import_id,
        fresh_start=fresh_start,
        import_id=import_id,
        status=STATUS_ACTIVE,
        detail=None,
    )
    if gen_start > 0:
        # An adopted prefix is proven by hash before this point; the
        # resumption digest covers the consumed span only, rebuilt by
        # the caller through the same validation read.
        row["consumed_sha256"] = ""
    _store_generation(conn, row=row)
    row["import_id"] = import_id
    return row


def _adopt_or_begin(
    conn: sqlite3.Connection,
    ctx: _RunContext,
    *,
    resolved: Path,
    fresh_start: bool,
) -> tuple[dict, bool]:
    """First generation for a source: adopt a proven batch prefix or refuse.

    Returns ``(gen_row, adopted)``. Starting from offset zero with
    unrelated stored events would silently duplicate them under a new
    generation label, so that case refuses with safe guidance unless
    the operator explicitly passes ``fresh_start``.
    """
    stat = resolved.stat()
    identity = FileIdentity(
        dev=stat.st_dev, ino=stat.st_ino, size=stat.st_size, mtime_ns=stat.st_mtime_ns
    )
    events = repositories.count_events(conn, source_id=ctx.source.source_id)
    if events == 0:
        row = _start_generation(
            conn,
            ctx,
            seq=1,
            identity=identity,
            gen_start=0,
            adopted_prefix_sha=None,
            adopted_import_id=None,
            fresh_start=fresh_start,
        )
        return row, False
    completed = conn.execute(
        "SELECT id, file_fingerprint, file_size, error_summary FROM imports"
        " WHERE source_id = ? AND status = 'completed' ORDER BY id DESC LIMIT 5",
        (ctx.source.source_id,),
    ).fetchall()
    for import_id, fingerprint, file_size, error_summary in completed:
        summary = str(error_summary or "")
        if "source_changed" in summary or "source_content_mismatch" in summary:
            continue
        if file_size is None or int(file_size) > identity.size:
            continue
        if _hash_span(resolved, 0, int(file_size)) != str(fingerprint):
            continue
        row = _start_generation(
            conn,
            ctx,
            seq=1,
            identity=identity,
            gen_start=int(file_size),
            adopted_prefix_sha=str(fingerprint),
            adopted_import_id=int(import_id),
            fresh_start=fresh_start,
        )
        return row, True
    if not fresh_start:
        raise FollowRefused(
            AMBIGUOUS_PREFIX_ADOPTION,
            "follow refuses to start from offset 0: this source already has"
            " stored events but the current file prefix matches no completed"
            " clean batch import. Re-run with --fresh-start to follow from"
            " offset 0 anyway (duplicates existing events under a new"
            " generation label), or batch-import the file first and follow"
            " the grown tail.",
        )
    row = _start_generation(
        conn,
        ctx,
        seq=1,
        identity=identity,
        gen_start=0,
        adopted_prefix_sha=None,
        adopted_import_id=None,
        fresh_start=True,
    )
    return row, False


def _check_fresh_for_write(conn: sqlite3.Connection, gen: dict) -> None:
    """Compare-and-swap guard: refuse a batch/seal on a stale generation.

    The caller runs inside the writer transaction; the persisted
    identity, status and ``next_offset`` must still equal the in-memory
    checkpoint this batch started from. A concurrent follower that
    already advanced, sealed or replaced the generation makes this work
    stale: raise :class:`FollowFailed` with the fixed stale code before
    any event, batch or checkpoint write, so no progress is rewound and
    no duplicate accounting is recorded. Never retried: the loser of
    the race aborts exactly once.
    """
    current = _load_generation(
        conn, source_id=str(gen["source_id"]), seq=int(gen["generation_seq"])
    )
    if (
        current is None
        or str(current["generation_id"]) != str(gen["generation_id"])
        or str(current["status"]) != str(gen["status"])
        or int(current["next_offset"]) != int(gen["next_offset"])
    ):
        raise FollowFailed(STALE_GENERATION_CODE)


def _commit_follow_batch(
    conn: sqlite3.Connection,
    ctx: _RunContext,
    gen: dict,
    *,
    batch: list[tuple],
    batch_private: list[tuple[int, object]],
    batch_start: int,
    batch_end: int,
    accepted: int,
    rejected: int,
    skipped_foreign: int,
    span_digest: str,
    file_size: int,
    file_mtime_ns: int,
) -> tuple[int, int, int, int]:
    """Atomically commit one follow batch with its checkpoint progress.

    Event rows, the ``follow_batches`` accounting row, the generation
    checkpoint AND the running attempt counters commit in ONE writer
    transaction: a crash between commit and checkpoint is impossible by
    construction, and a long active generation reports its durable
    attempt totals (not zero) while it is still running. The generation
    keeps exactly one attempt row; idle polls write nothing. A stale
    in-memory checkpoint (another follower moved the generation first)
    is refused before any write via :func:`_check_fresh_for_write`.
    """
    _check_fresh_for_write(conn, gen)
    fingerprint = generation_fingerprint(ctx.source.source_id, int(gen["generation_seq"]))
    mismatched: set[int] = set()
    if ctx.capture_originals and batch_private:
        mismatched = repositories.find_core_mismatches(
            conn,
            source_id=ctx.source.source_id,
            file_fingerprint=fingerprint,
            cores={int(row[4]): _batch_core(row) for row in batch},
        )
    inserted = repositories.insert_events(conn, batch)
    originals_captured = 0
    originals_skipped = 0
    if ctx.capture_originals and batch_private and ctx.private_key is not None and batch:
        from app.db import private as _private

        placeholders = ",".join(["?"] * len(batch))
        id_rows = conn.execute(
            "SELECT id, byte_offset FROM requests WHERE source_id = ?"
            " AND file_fingerprint = ? AND byte_offset IN (" + placeholders + ")",
            (ctx.source.source_id, fingerprint, *[row[4] for row in batch]),
        ).fetchall()
        id_by_offset = {int(offset): int(row_id) for row_id, offset in id_rows}
        for offset, captured in batch_private:
            request_id = id_by_offset.get(int(offset))
            if request_id is None:
                continue
            if int(offset) in mismatched:
                originals_skipped += 1
                continue
            aad = _private.build_aad(
                site_id=ctx.site_id,
                source_id=ctx.source.source_id,
                file_fingerprint=fingerprint,
                byte_offset=int(offset),
            )
            nonce, ciphertext = _private.encrypt_captured(captured, key=ctx.private_key, aad=aad)
            if _private.store_private_ip(
                conn, request_id=request_id, nonce=nonce, ciphertext=ciphertext
            ):
                originals_captured += 1
    _record_follow_batch(
        conn,
        source_id=ctx.source.source_id,
        seq=int(gen["generation_seq"]),
        start_offset=batch_start,
        end_offset=batch_end,
        accepted=accepted,
        rejected=rejected,
        skipped_foreign=skipped_foreign,
        inserted=inserted,
        replayed=len(batch) - inserted,
        consumed_sha256=span_digest,
    )
    gen["next_offset"] = batch_end
    gen["consumed_sha256"] = span_digest
    gen["file_size"] = file_size
    gen["file_mtime_ns"] = file_mtime_ns
    gen["updated_at"] = _now()
    _store_generation(conn, row=gen)
    # Durable attempt counters advance in the SAME transaction: a long
    # active generation reports real imported lines from coverage (not
    # zero until seal), while idle polls still write nothing. Exactly
    # one attempt row per generation; replay attempts update their own
    # attempt row honestly through the same path.
    accepted_total, rejected_total, _skip_t, inserted_total, replayed_total = _gen_totals(
        conn,
        source_id=ctx.source.source_id,
        seq=int(gen["generation_seq"]),
    )
    conn.execute(
        "UPDATE imports SET lines_total = ?, lines_accepted = ?, lines_rejected = ?,"
        " records_inserted = ?, records_replayed = ? WHERE id = ?",
        (
            accepted_total + rejected_total,
            accepted_total,
            rejected_total,
            inserted_total,
            replayed_total,
            int(gen["import_id"]),
        ),
    )
    return inserted, len(batch) - inserted, originals_captured, originals_skipped


def _resolve_effective(ctx: _RunContext, resolved: Path) -> str:
    """Effective parser format for one file, mirroring batch import."""
    if ctx.custom_format is not None:
        return ctx.custom_format.format_id
    if ctx.source.format_id == AUTO:
        return resolve_format(
            AUTO,
            resolved,
            limits=ctx.limits,
            sample_lines=32,
            default_combined=ctx.default_combined,
            gzip_limits=ctx.gzip_limits,
        )
    return ctx.source.format_id


@dataclass
class _GenState:
    """In-run mutable state of the generation being consumed."""

    gen: dict
    hasher: object
    splitter: _LineFollower
    identity: FileIdentity
    effective_format: str
    line_number: int
    # Read source for bounded tail re-validation (live path or archive).
    path: Path | None = None
    # Offsets below ``hash_floor`` already feed the running digest
    # (replay: the validated sealed prefix, hashed once during the
    # prefix check and never re-hashed by tail commits). Live runs keep
    # ``0``: every pulled byte is hashed exactly once, in order.
    hash_floor: int = 0
    # Furthest pulled offset (read cursor, not the durable checkpoint).
    # Only complete-line bytes advance the checkpoint; the cursor also
    # covers pending tails so a skipping seal can land past them.
    read_end: int = 0
    # Latest committed window: ``(start, digest)`` over at most
    # TAIL_WINDOW_BYTES. In-memory only, refreshed at every commit from
    # a bounded re-read; empty (``""`` digest) until the first commit.
    tail_start: int = 0
    tail_sha: str = ""
    timeout_streak: int = 0
    timeout_total: int = 0
    timeout_match_s: float = 0.0
    accepted: int = 0
    rejected: int = 0
    skipped_foreign: int = 0
    inserted: int = 0
    replayed: int = 0


@dataclass
class _Accum:
    """One pending batch: rows plus the accounting of its lines."""

    rows: list = field(default_factory=list)
    private: list = field(default_factory=list)
    start: int | None = None
    accepted: int = 0
    rejected: int = 0
    skipped_foreign: int = 0
    reasons: dict = field(default_factory=dict)
    # Oversized spans dropped from memory by this feed (absolute
    # ``(start, end)``). Committed in offset order with the lines by
    # the same flush; bytes already hashed by earlier commits (before
    # the view start or below the replay floor) are clamped out.
    dropped: list = field(default_factory=list)


def _with_writer_retry(ctx: _RunContext, work: Callable[[], object]) -> object:
    """Run ``work`` in retries over a busy writer with bounded backoff."""
    attempt = 0
    while True:
        try:
            return work()
        except WriterBusy:
            if attempt >= ctx.max_writer_retries:
                raise
            attempt += 1
            time.sleep(min(0.05 * attempt, 0.5))


def _flush_accum(
    db_path: Path,
    ctx: _RunContext,
    state: _GenState,
    accum: _Accum,
    *,
    view: bytes,
    view_start: int,
    batch_end: int,
    result: FollowResult | ArchiveResult,
) -> None:
    """Commit one full batch (or seal batch) with digest and accounting.

    The running digest advances in strict offset order over the
    committed span ``[max(start, view_start, floor), batch_end)``: in
    one bounded slice, never retaining raw bytes and never re-hashing
    the floor prefix (replay) or already-committed earlier views.
    Dropped oversized spans inside the view hash as part of the same
    ordered slice; earlier-chunk portions were committed by their own
    per-feed flushes, so clamping keeps every pulled byte at exactly
    one hash.
    """
    if (
        not accum.rows
        and accum.accepted + accum.rejected + accum.skipped_foreign == 0
        and not accum.dropped
    ):
        return
    assert accum.start is not None
    lo = max(int(accum.start), view_start, int(state.hash_floor))
    piece_hasher = state.hasher.copy()  # type: ignore[attr-defined]
    if batch_end > lo:
        # Python slicing truncates past the view end (seal marker over
        # an empty view): only in-view bytes hash here, earlier-chunk
        # bytes were committed by their own per-feed flushes.
        piece_hasher.update(view[lo - view_start : batch_end - view_start])
    span_digest = piece_hasher.hexdigest()
    # Durable discard marker for an unfinished oversized line: a flag
    # plus the physical line start offset ONLY (never bytes). The same
    # atomic commit that advances the checkpoint records whether the
    # splitter is still dropping, so a restart restores drop mode and
    # the completing suffix cannot be mistaken for a fresh line. A
    # completed line already cleared splitter skipping in feed()/seal(),
    # so the marker clears with it in the same commit.
    if state.splitter.skipping:
        state.gen["oversized_active"] = 1
        state.gen["oversized_start"] = int(state.splitter.skip_start)
    else:
        state.gen["oversized_active"] = 0
        state.gen["oversized_start"] = None
    stat_size = state.identity.size
    stat_mtime = state.identity.mtime_ns

    def _work():
        with writer_transaction(db_path, lock_timeout_s=ctx.lock_timeout_s) as conn:
            return _commit_follow_batch(
                conn,
                ctx,
                state.gen,
                batch=accum.rows,
                batch_private=accum.private,
                batch_start=accum.start,
                batch_end=batch_end,
                accepted=accum.accepted,
                rejected=accum.rejected,
                skipped_foreign=accum.skipped_foreign,
                span_digest=span_digest,
                file_size=stat_size,
                file_mtime_ns=stat_mtime,
            )

    try:
        inserted, replayed, captured, skipped = _with_writer_retry(ctx, _work)
    except WriterBusy:
        raise FollowFailed(WRITER_BUSY_CODE)
    except FollowFailed:
        # Stale checkpoints refuse before any write: the running digest
        # stays exactly at the last committed span, never rewound.
        raise
    if batch_end > lo:
        state.hasher.update(view[lo - view_start : batch_end - view_start])
    if state.path is not None:
        # Refresh the re-validation window from a bounded re-read of the
        # just-committed tail (page-cache hot: these bytes were read
        # moments ago). Skipped/oversized spans are included: the window
        # covers raw committed bytes, never parsed outcomes.
        state.tail_start, state.tail_sha = _tail_window(
            state.path,
            int(state.gen["gen_start_offset"]),
            batch_end,
            gzip_limits=ctx.gzip_limits,
        )
    state.inserted += inserted
    state.replayed += replayed
    result.records_inserted += inserted
    result.records_replayed += replayed
    result.lines_accepted += accum.accepted
    result.lines_rejected += accum.rejected
    result.lines_skipped_foreign += accum.skipped_foreign
    result.originals_captured += captured
    result.originals_skipped_mismatch += skipped
    for reason, count in accum.reasons.items():
        result.rejected_by_reason[reason] = result.rejected_by_reason.get(reason, 0) + count
    state.accepted += accum.accepted
    state.rejected += accum.rejected
    state.skipped_foreign += accum.skipped_foreign
    accum.rows.clear()
    accum.private.clear()
    accum.start = None
    accum.accepted = accum.rejected = accum.skipped_foreign = 0
    accum.reasons.clear()
    # Keep the not-yet-covered tail of dropped oversized spans (a
    # trailing skip-rest past this batch end): the final flush of the
    # same feed extends over it in offset order. Fully covered spans
    # are gone; nothing is ever hashed twice.
    kept = [(max(start, batch_end), end) for start, end in accum.dropped if end > batch_end]
    accum.dropped.clear()
    accum.dropped.extend(kept)
    if accum.start is None and kept:
        accum.start = min(start for start, _end in kept)


class FollowFailed(Exception):
    """A follow run aborts with a fixed code; committed progress is kept."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _process_items(
    db_path: Path,
    ctx: _RunContext,
    state: _GenState,
    items: list[tuple[int, bytes | None, int]],
    *,
    view: bytes,
    view_start: int,
    dropped: list[tuple[int, int]] | None = None,
    result: FollowResult | ArchiveResult,
) -> None:
    """Parse complete lines and commit full batches incrementally.

    ``dropped`` oversized spans from the same feed commit with the
    lines in offset order (the final flush extends past the last item
    when the feed's dropped tail runs further); a dropped-only feed
    still commits its span so every pulled byte is checkpointed and
    hashed exactly once.
    """
    from app.ingestion.combined import LineRejection

    accum = _Accum()
    if dropped:
        accum.dropped.extend(dropped)
        accum.start = min(start for start, _end in dropped)
    for offset, data, end in items:
        if accum.start is None or offset < accum.start:
            # Items can precede the feed's dropped spans (a complete
            # line before a tail that newly trips skip mode): the
            # committed span always starts at the true minimum so no
            # byte escapes the ordered digest slice.
            accum.start = offset
        line_number = state.line_number
        state.line_number += 1
        if data is None:
            rejection = LineRejection(
                line_number,
                offset,
                "oversized_line",
                f"<line exceeds {ctx.limits.max_line_bytes} bytes>",
            )
            item, original = rejection, None
        else:
            match_start = time.monotonic() if ctx.custom_format is not None else 0.0
            item, original = _parse_item(
                data,
                effective_format=state.effective_format,
                source_id=ctx.source.source_id,
                hmac_key=ctx.hmac_key,
                line_number=line_number,
                byte_offset=offset,
                identity=state.identity,
                limits=ctx.limits,
                custom_format=ctx.custom_format,
                capture_original=True,
            )
            if ctx.custom_format is not None:
                state.timeout_match_s += time.monotonic() - match_start
            state.timeout_streak, state.timeout_total = _abort_on_timeout_abuse(
                item, state.timeout_streak, state.timeout_total, state.timeout_match_s
            )
        if isinstance(item, CombinedRecord) and ctx.effective_filter is not None:
            host = item.extra.server_host if item.extra is not None else None
            if host is not None and not ctx.effective_filter.matches(host):
                # Foreign-host skips are valid non-events: they count and
                # advance the committed span (position-only batches flush
                # through the same atomic path) but store no row.
                if accum.start is None:
                    accum.start = offset
                accum.skipped_foreign += 1
                if len(accum.rows) >= ctx.batch_size:
                    _flush_accum(
                        db_path,
                        ctx,
                        state,
                        accum,
                        view=view,
                        view_start=view_start,
                        batch_end=end,
                        result=result,
                    )
                continue
            kept = original
        elif isinstance(item, CombinedRecord):
            kept = original
        else:
            kept = None
        if isinstance(item, CombinedRecord):
            if accum.start is None:
                accum.start = offset
            if isinstance(kept, CapturedOriginal):
                country = ctx.lookup.lookup(kept.reveal())
            else:
                country = CountryInfo(None, GEO_STATUS_UNKNOWN, None, None)
            accum.rows.append(
                _event_row(
                    item,
                    import_id=int(state.gen["import_id"]),
                    site_id=ctx.site_id,
                    file_fingerprint=generation_fingerprint(
                        ctx.source.source_id, int(state.gen["generation_seq"])
                    ),
                    policy=ctx.policy,
                    country=country,
                )
            )
            if ctx.capture_originals and isinstance(kept, CapturedOriginal):
                accum.private.append((offset, kept))
            accum.accepted += 1
        else:
            if accum.start is None:
                accum.start = offset
            accum.rejected += 1
            reason = getattr(item, "reason", "invalid")
            accum.reasons[str(reason)] = accum.reasons.get(str(reason), 0) + 1
        if len(accum.rows) >= ctx.batch_size:
            _flush_accum(
                db_path,
                ctx,
                state,
                accum,
                view=view,
                view_start=view_start,
                batch_end=end,
                result=result,
            )
    if accum.rows or accum.accepted or accum.rejected or accum.skipped_foreign or accum.dropped:
        batch_end = items[-1][2] if items else int(accum.start or view_start)
        for _start, _end in accum.dropped:
            if _end > batch_end and _start < view_start + len(view):
                # A dropped oversized tail past the last complete line
                # (same view): the checkpoint honestly advances past
                # the consumed bytes it already hashed in order.
                batch_end = max(batch_end, min(_end, view_start + len(view)))
        _flush_accum(
            db_path,
            ctx,
            state,
            accum,
            view=view,
            view_start=view_start,
            batch_end=batch_end,
            result=result,
        )


def _row_dict(row) -> dict | None:
    if row is None:
        return None
    # sqlite3.Row iterates values, so zip keys explicitly.
    return dict(zip(row.keys(), row))


def _feed_view(
    state: _GenState, piece: bytes, piece_start: int
) -> tuple[list[tuple[int, bytes | None, int]], bytes, int, list[tuple[int, int]]]:
    """Feed one contiguous NEW piece; return ``(items, view, view_start, dropped)``.

    The caller passes only bytes never fed before (a separate read
    cursor tracks pulled bytes; the durable checkpoint still trails at
    the last complete line). The digest view prepends the carried
    pending bytes so every batch span slices exactly the consumed file
    bytes once: contiguity (``piece_start`` meets the pending tail) is
    required, re-reads never happen inside a run.
    """
    splitter = state.splitter
    if splitter.pending:
        assert piece_start == splitter.pending_start + len(splitter.pending), (
            "follow must feed only contiguous new bytes"
        )
    carry = bytes(splitter.pending)
    view = carry + piece
    view_start = splitter.pending_start if carry else piece_start
    items, dropped = splitter.feed(piece, piece_start)
    return items, view, view_start, dropped


def _gen_totals(
    conn: sqlite3.Connection, *, source_id: str, seq: int
) -> tuple[int, int, int, int, int]:
    """Bounded aggregate accounting of one generation (SQL SUM, no fetchall)."""
    row = conn.execute(
        "SELECT COALESCE(SUM(lines_accepted), 0), COALESCE(SUM(lines_rejected), 0),"
        " COALESCE(SUM(lines_skipped_foreign), 0), COALESCE(SUM(records_inserted), 0),"
        " COALESCE(SUM(records_replayed), 0) FROM follow_batches"
        " WHERE source_id = ? AND generation_seq = ?",
        (source_id, seq),
    ).fetchone()
    return (int(row[0]), int(row[1]), int(row[2]), int(row[3]), int(row[4]))


def _seal_state(
    db_path: Path,
    ctx: _RunContext,
    state: _GenState,
    *,
    status: str,
    detail: str | None,
    finish_status: str,
    error_summary: str | None,
    result: FollowResult,
) -> None:
    """Seal one generation: commit seal leftovers, close its attempt row.

    Seal leftovers (a final unterminated line or one oversized marker)
    commit through the same atomic batch path before the status flips.
    A skipping marker spans to the furthest pulled offset so the
    checkpoint lands past the consumed tail it already hashed.
    """
    markers = state.splitter.seal(int(state.read_end))
    if markers:
        # A final line carries its bytes as the digest view (the sealed
        # file is complete, so the span must cover them exactly); an
        # oversized marker spans to the pulled end over an empty view
        # (its bytes were committed per-feed) and changes nothing.
        offset, data, _end = markers[0]
        if data is None:
            seal_view, seal_start = b"", offset
        else:
            seal_view, seal_start = data, offset
        _process_items(
            db_path,
            ctx,
            state,
            markers,
            view=seal_view,
            view_start=seal_start,
            result=result,
        )

    def _work():
        with writer_transaction(db_path, lock_timeout_s=ctx.lock_timeout_s) as conn:
            _check_fresh_for_write(conn, state.gen)
            # Attempt totals come from the bounded SQL aggregate, never
            # from run-local memory: generations span many runs.
            accepted, rejected, _skipped, inserted, replayed = _gen_totals(
                conn,
                source_id=ctx.source.source_id,
                seq=int(state.gen["generation_seq"]),
            )
            state.gen["status"] = status
            state.gen["detail"] = detail
            state.gen["updated_at"] = _now()
            _store_generation(conn, row=state.gen)
            repositories.finish_import(
                conn,
                import_id=int(state.gen["import_id"]),
                finished_at=_now(),
                status=finish_status,
                counts=_repos_counts(accepted, rejected, inserted, replayed),
                error_summary=error_summary,
            )

    try:
        _with_writer_retry(ctx, _work)
    except WriterBusy:
        raise FollowFailed(WRITER_BUSY_CODE)
    result.sealed_generations.append(int(state.gen["generation_seq"]))


def _repos_counts(accepted: int, rejected: int, inserted: int, replayed: int):
    return repositories.ImportCounts(
        lines_total=accepted + rejected,
        lines_accepted=accepted,
        lines_rejected=rejected,
        records_inserted=inserted,
        records_replayed=replayed,
    )


def _begin_next_gen(
    db_path: Path,
    ctx: _RunContext,
    *,
    seq: int,
    identity: FileIdentity,
    fresh_start: bool,
) -> dict:
    """Start the generation after a sealed one (new inode or truncation).

    The previous file is gone or truncated away, so no prefix can be
    adopted; the operator contract is that rotated-in content never
    repeats already-ingested bytes (a repeated-content replacement is
    an operator error, documented, not a silent rule). A concurrent
    follower that already registered this sequence refuses the loser
    with the fixed stale code instead of silently replacing state.
    """

    def _work():
        with writer_transaction(db_path, lock_timeout_s=ctx.lock_timeout_s) as conn:
            latest = _row_dict(_latest_generation(conn, source_id=ctx.source.source_id))
            if latest is not None and int(latest["generation_seq"]) >= seq:
                raise FollowFailed(STALE_GENERATION_CODE)
            return _start_generation(
                conn,
                ctx,
                seq=seq,
                identity=identity,
                gen_start=0,
                adopted_prefix_sha=None,
                adopted_import_id=None,
                fresh_start=fresh_start,
            )

    try:
        return _with_writer_retry(ctx, _work)
    except WriterBusy:
        raise FollowFailed(WRITER_BUSY_CODE)


def _build_context(
    *,
    source: SourceConfig,
    site_id: str,
    site_name: str,
    site_hostname: str,
    server_type: str,
    path_alias: str,
    hmac_key: bytes,
    batch_size: int,
    host_filter: HostFilter | None,
    custom_format: CustomFormat | None,
    limits: Limits | None,
    gzip_limits: GzipLimits | None,
    capture_originals: bool,
    ip_key: object,
    country_lookup: CountryLookup | None,
    lock_timeout_s: float,
    max_writer_retries: int,
) -> _RunContext:
    if not hmac_key:
        raise ValueError("hmac_key must be non-empty")
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")
    if max_writer_retries < 0:
        raise ValueError("max_writer_retries must be non-negative")
    if source.format_id == CUSTOM and custom_format is None:
        raise CustomFormatError("interrupted:custom_invalid")
    if custom_format is not None and source.format_id not in (CUSTOM, custom_format.format_id):
        raise CustomFormatError("interrupted:custom_invalid")
    lookup = country_lookup if country_lookup is not None else CountryLookup.unavailable()
    from app.db import private as _private

    private_key: bytes | None = None
    if capture_originals:
        private_key = _private.require_ip_key(ip_key)
        _private.decrypt_ip(
            *_private.encrypt_ip(
                "127.0.0.1",
                key=private_key,
                aad=_private.build_aad(
                    site_id="self-test",
                    source_id="self-test",
                    file_fingerprint="self-test",
                    byte_offset=0,
                ),
            ),
            key=private_key,
            aad=_private.build_aad(
                site_id="self-test",
                source_id="self-test",
                file_fingerprint="self-test",
                byte_offset=0,
            ),
        )
    effective_filter = host_filter if host_filter is not None else source.host_filter()
    has_custom_vhost = custom_format is not None and "vhost" in custom_format.pattern.groupindex
    if effective_filter is None and (
        source.format_id in (APACHE_VHOST_COMBINED, NGINX_EXTENDED, AUTO) or has_custom_vhost
    ):
        effective_filter = HostFilter([site_hostname])
    return _RunContext(
        source=source,
        site_id=site_id,
        site_name=site_name,
        site_hostname=site_hostname,
        server_type=server_type,
        path_alias=path_alias,
        hmac_key=hmac_key,
        batch_size=batch_size,
        effective_filter=effective_filter,
        custom_format=custom_format,
        default_combined=(
            APACHE_COMBINED if server_type.strip().lower() == "apache" else NGINX_COMBINED
        ),
        limits=limits or Limits(),
        gzip_limits=gzip_limits or GzipLimits(),
        capture_originals=capture_originals,
        private_key=private_key,
        lookup=lookup,
        policy=enrichment_policy(source.format_id, custom_format),
        lock_timeout_s=lock_timeout_s,
        max_writer_retries=max_writer_retries,
    )


def _taint_and_refuse(
    db_path: Path,
    ctx: _RunContext,
    state: _GenState,
) -> FollowRefused:
    """Mark a generation tainted after restart validation failed."""

    def _work():
        with writer_transaction(db_path, lock_timeout_s=ctx.lock_timeout_s) as conn:
            accepted, rejected, _skipped, inserted, replayed = _gen_totals(
                conn,
                source_id=ctx.source.source_id,
                seq=int(state.gen["generation_seq"]),
            )
            state.gen["status"] = STATUS_TAINTED
            state.gen["detail"] = PREFIX_TAINTED
            state.gen["updated_at"] = _now()
            _store_generation(conn, row=state.gen)
            repositories.finish_import(
                conn,
                import_id=int(state.gen["import_id"]),
                finished_at=_now(),
                status="failed",
                counts=_repos_counts(accepted, rejected, inserted, replayed),
                error_summary=SOURCE_CONTENT_MISMATCH_CODE,
            )

    try:
        _with_writer_retry(ctx, _work)
    except WriterBusy:
        raise FollowFailed(WRITER_BUSY_CODE)
    return FollowRefused(
        PREFIX_TAINTED,
        "follow restarts re-read the consumed span once: the bytes changed"
        " under a live checkpoint, so the generation is tainted and refuses"
        " further adoption. Seal the file (rotate it away) and start a new"
        " generation, or batch-import the changed file as new rows.",
    )


def _rebuild_hasher(resolved: Path, start: int, end: int) -> "hashlib._Hash":
    """Re-read one consumed span into a fresh hasher (restart validation).

    The same read both validates the span and resumes the digest chain,
    so a restart costs exactly one bounded validation pass.
    """
    hasher = hashlib.sha256()
    with open(resolved, "rb") as stream:
        stream.seek(start)
        remaining = end - start
        while remaining > 0:
            chunk = stream.read(min(_HASH_CHUNK, remaining))
            if not chunk:
                break
            hasher.update(chunk)
            remaining -= len(chunk)
    return hasher


def _resume_or_begin(
    db_path: Path,
    ctx: _RunContext,
    *,
    resolved: Path,
    fresh_start: bool,
) -> tuple[dict, _GenState, bool]:
    """Load the latest generation: resume it or start the next one.

    Returns ``(gen, state, started)`` where ``started`` tells whether
    this call began a new generation. Raises :class:`FollowRefused`
    for tainted generations and ambiguous first starts.
    """
    probe = connect(db_path, read_only=True)
    try:
        latest = _row_dict(_latest_generation(probe, source_id=ctx.source.source_id))
    finally:
        probe.close()
    if latest is None:

        def _init():
            with writer_transaction(db_path, lock_timeout_s=ctx.lock_timeout_s) as conn:
                # A concurrent first registration wins; the loser
                # refuses with the fixed stale code, never silently
                # replacing fresh state.
                if _latest_generation(conn, source_id=ctx.source.source_id) is not None:
                    raise FollowFailed(STALE_GENERATION_CODE)
                gen_row, _adopted = _adopt_or_begin(
                    conn, ctx, resolved=resolved, fresh_start=fresh_start
                )
                return gen_row

        try:
            gen = _with_writer_retry(ctx, _init)
        except WriterBusy:
            raise FollowFailed(WRITER_BUSY_CODE)
        adopted_span = int(gen["gen_start_offset"])
        hasher = hashlib.sha256()
        if adopted_span > 0:
            # Adopted prefix: the resumption digest covers the consumed
            # span only; nothing before gen_start is ever hashed.
            hasher = _rebuild_hasher(resolved, adopted_span, adopted_span)
        return (
            gen,
            _GenState(
                gen=gen,
                hasher=hasher,
                splitter=_LineFollower(ctx.limits.max_line_bytes),
                identity=FileIdentity(
                    dev=int(gen["file_dev"]),
                    ino=int(gen["file_ino"]),
                    size=int(gen["file_size"]),
                    mtime_ns=int(gen["file_mtime_ns"]),
                ),
                effective_format=_resolve_effective(ctx, resolved),
                line_number=int(gen["next_line_number"]),
                path=resolved,
                tail_start=adopted_span,
                tail_sha="",
                read_end=int(gen["next_offset"]),
            ),
            True,
        )
    if str(latest["status"]) == STATUS_TAINTED and not fresh_start:
        raise FollowRefused(
            PREFIX_TAINTED,
            "the latest generation is tainted (a restart once saw its"
            " consumed bytes change). Re-run with --fresh-start to abandon"
            " it and follow from offset 0 of the current file.",
        )
    if str(latest["status"]) != STATUS_ACTIVE:
        stat = resolved.stat()
        identity = FileIdentity(
            dev=stat.st_dev, ino=stat.st_ino, size=stat.st_size, mtime_ns=stat.st_mtime_ns
        )
        gen = _begin_next_gen(
            db_path,
            ctx,
            seq=int(latest["generation_seq"]) + 1,
            identity=identity,
            fresh_start=fresh_start,
        )
        return (
            gen,
            _GenState(
                gen=gen,
                hasher=hashlib.sha256(),
                splitter=_LineFollower(ctx.limits.max_line_bytes),
                identity=identity,
                effective_format=_resolve_effective(ctx, resolved),
                line_number=1,
                path=resolved,
                tail_start=0,
                tail_sha="",
                read_end=0,
            ),
            True,
        )
    # Resume an active generation: same file and size first.
    stat = resolved.stat()
    if (stat.st_dev, stat.st_ino) != (int(latest["file_dev"]), int(latest["file_ino"])):
        # Rotation/replacement across restarts: the old file is gone, so
        # its unread tail cannot be drained. Seal it unvalidated (honest:
        # the loss, if any, is reported as a rotation) and continue with
        # a new generation under the operator contract.
        orphan = dict(latest)
        orphan_state = _GenState(
            gen=orphan,
            hasher=hashlib.sha256(),
            splitter=_LineFollower(ctx.limits.max_line_bytes),
            identity=FileIdentity(
                dev=int(orphan["file_dev"]),
                ino=int(orphan["file_ino"]),
                size=int(orphan["file_size"]),
                mtime_ns=int(orphan["file_mtime_ns"]),
            ),
            effective_format=_resolve_effective(ctx, resolved),
            line_number=int(orphan["next_line_number"]),
        )
        raise _RotationSealed(orphan_state)
    if stat.st_size < int(latest["next_offset"]):
        # Copytruncate across restarts: same file, smaller now.
        orphan_state = _GenState(
            gen=dict(latest),
            hasher=hashlib.sha256(),
            splitter=_LineFollower(ctx.limits.max_line_bytes),
            identity=FileIdentity(
                dev=stat.st_dev,
                ino=stat.st_ino,
                size=stat.st_size,
                mtime_ns=stat.st_mtime_ns,
            ),
            effective_format=_resolve_effective(ctx, resolved),
            line_number=int(latest["next_line_number"]),
        )
        raise _RotationSealed(orphan_state)
    gen_start = int(latest["gen_start_offset"])
    next_offset = int(latest["next_offset"])
    hasher = _rebuild_hasher(resolved, gen_start, next_offset)
    if hasher.hexdigest() != str(latest["consumed_sha256"]):
        holding = _GenState(
            gen=dict(latest),
            hasher=hasher,
            splitter=_LineFollower(ctx.limits.max_line_bytes),
            identity=FileIdentity(
                dev=stat.st_dev,
                ino=stat.st_ino,
                size=stat.st_size,
                mtime_ns=stat.st_mtime_ns,
            ),
            effective_format=_resolve_effective(ctx, resolved),
            line_number=int(latest["next_line_number"]),
        )
        raise _taint_and_refuse(db_path, ctx, holding)
    gen = dict(latest)
    gen["file_size"] = stat.st_size
    gen["file_mtime_ns"] = stat.st_mtime_ns
    tail_start, tail_sha = _tail_window(
        resolved, gen_start, next_offset, gzip_limits=ctx.gzip_limits
    )
    # Restore an unfinished oversized line's drop mode from the durable
    # discard marker (flag plus physical line start offset, never bytes).
    # Without this the completing suffix would parse as a fresh line; a
    # corrupt marker fails closed through the same taint path as a
    # mutated consumed span, never through silent adoption.
    oversized_active = int(gen.get("oversized_active", 0) or 0)
    oversized_start = gen.get("oversized_start")
    splitter = _LineFollower(ctx.limits.max_line_bytes)
    if oversized_active:
        if not (
            isinstance(oversized_start, int) and gen_start <= int(oversized_start) < next_offset
        ):
            holding = _GenState(
                gen=dict(latest),
                hasher=hasher,
                splitter=_LineFollower(ctx.limits.max_line_bytes),
                identity=FileIdentity(
                    dev=stat.st_dev,
                    ino=stat.st_ino,
                    size=stat.st_size,
                    mtime_ns=stat.st_mtime_ns,
                ),
                effective_format=_resolve_effective(ctx, resolved),
                line_number=int(latest["next_line_number"]),
            )
            raise _taint_and_refuse(db_path, ctx, holding)
        splitter.skipping = True
        splitter.skip_start = int(oversized_start)
    state = _GenState(
        gen=gen,
        hasher=hasher,
        splitter=splitter,
        identity=FileIdentity(
            dev=stat.st_dev,
            ino=stat.st_ino,
            size=stat.st_size,
            mtime_ns=stat.st_mtime_ns,
        ),
        effective_format=_resolve_effective(ctx, resolved),
        line_number=int(gen["next_line_number"]),
        path=resolved,
        tail_start=tail_start,
        tail_sha=tail_sha,
        read_end=next_offset,
    )

    def _touch():
        with writer_transaction(db_path, lock_timeout_s=ctx.lock_timeout_s) as conn:
            gen["updated_at"] = _now()
            _store_generation(conn, row=gen)

    try:
        _with_writer_retry(ctx, _touch)
    except WriterBusy:
        raise FollowFailed(WRITER_BUSY_CODE)
    return gen, state, False


class _RotationSealed(Exception):
    """Internal signal: the active generation sealed across restarts."""

    def __init__(self, orphan_state: _GenState) -> None:
        super().__init__("rotation sealed")
        self.orphan_state = orphan_state


def _open_live(resolved: Path) -> int:
    """Open a resolved source read-only; never creates or modifies it."""
    return os.open(resolved, os.O_RDONLY)


def _drain_fd(
    db_path: Path,
    ctx: _RunContext,
    state: _GenState,
    fd: int,
    *,
    result: FollowResult,
    max_rounds: int = 32,
) -> None:
    """Drain a rotated-away descriptor to EOF in bounded reads.

    The old file is complete, so every drained byte is consumed under
    the sealing generation; a still-growing descriptor stops after
    ``max_rounds`` bounded reads and the seal records what was drained.
    """
    # The drained descriptor may no longer match the path (rotation):
    # digest views stay in memory while the tail window pauses. A
    # dedicated drain cursor (not the durable checkpoint) feeds only
    # contiguous new bytes, mirroring the main poll loop.
    saved_path, state.path = state.path, None
    dpos = int(state.read_end)
    try:
        for _round in range(max_rounds):
            try:
                chunk = os.read(fd, DEFAULT_MAX_BYTES_PER_POLL)
            except OSError:
                raise FollowFailed(IO_ERROR_CODE)
            if not chunk:
                return
            items, view, view_start, dropped = _feed_view(state, chunk, dpos)
            dpos += len(chunk)
            state.read_end = dpos
            try:
                stat = os.fstat(fd)
            except OSError:
                raise FollowFailed(IO_ERROR_CODE)
            state.identity = FileIdentity(
                dev=stat.st_dev,
                ino=stat.st_ino,
                size=stat.st_size,
                mtime_ns=stat.st_mtime_ns,
            )
            if items or dropped:
                _process_items(
                    db_path,
                    ctx,
                    state,
                    items,
                    view=view,
                    view_start=view_start,
                    dropped=dropped,
                    result=result,
                )
        result.drain_truncated = True
    finally:
        state.path = saved_path


def run_follow(
    db_path: Path,
    *,
    source: SourceConfig,
    site_id: str,
    site_name: str,
    site_hostname: str,
    server_type: str,
    path_alias: str,
    hmac_key: bytes,
    batch_size: int = 1000,
    max_polls: int = DEFAULT_MAX_POLLS,
    poll_interval_s: float = DEFAULT_POLL_INTERVAL_S,
    max_bytes_per_poll: int = DEFAULT_MAX_BYTES_PER_POLL,
    capture_originals: bool = False,
    ip_key: object = None,
    country_lookup: CountryLookup | None = None,
    geoip_required: bool = False,
    host_filter: HostFilter | None = None,
    custom_format: CustomFormat | None = None,
    limits: Limits | None = None,
    gzip_limits: GzipLimits | None = None,
    lock_timeout_s: float = 30.0,
    max_writer_retries: int = DEFAULT_MAX_WRITER_RETRIES,
    fresh_start: bool = False,
    after_poll: Callable[[int, FollowResult], None] | None = None,
) -> FollowResult:
    """Tail one source across a bounded number of polls with checkpoints.

    Each poll reads only new bytes; event batches commit atomically
    with their checkpoint progress, so cancel/restart never meets a
    commit-before-checkpoint window. Empty polls write nothing. Held
    file descriptors let a within-run rotation drain the old tail
    before the new generation starts; restarts re-validate the consumed
    span once and taint the generation on mismatch instead of silently
    duplicating.
    """
    result = FollowResult(source_id=source.source_id)
    if (
        isinstance(max_polls, bool)
        or not isinstance(max_polls, int)
        or not 1 <= max_polls <= 100000
    ):
        raise ValueError("max_polls must be an integer in 1..100000")
    if not 0 <= float(poll_interval_s) <= 3600:
        raise ValueError("poll_interval_s must be within 0..3600")
    if (
        isinstance(max_bytes_per_poll, bool)
        or not isinstance(max_bytes_per_poll, int)
        or not 1024 <= max_bytes_per_poll <= 1024**3
    ):
        raise ValueError("max_bytes_per_poll must be an integer in 1024..2**30")
    ctx = _build_context(
        source=source,
        site_id=site_id,
        site_name=site_name,
        site_hostname=site_hostname,
        server_type=server_type,
        path_alias=path_alias,
        hmac_key=hmac_key,
        batch_size=batch_size,
        host_filter=host_filter,
        custom_format=custom_format,
        limits=limits,
        gzip_limits=gzip_limits,
        capture_originals=capture_originals,
        ip_key=ip_key,
        country_lookup=country_lookup,
        lock_timeout_s=lock_timeout_s,
        max_writer_retries=max_writer_retries,
    )
    if geoip_required and not ctx.lookup.available:
        raise GeoipError()
    migrate(db_path)
    _ensure_follow_progress_columns(db_path)
    _check_source_binding(db_path, source_id=source.source_id, site_id=site_id)
    resolved = resolve_source_path(source)
    if has_gzip_magic(resolved):
        raise FollowRefused(
            FOLLOW_GZIP_UNSUPPORTED,
            "follow tails plain log files only: a gzip source cannot be"
            " tailed by logical offset without re-decompressing the whole"
            " file per poll. Replay the gzip file via replay-archive.",
        )
    started = False
    try:
        current, state, started = _resume_or_begin(
            db_path, ctx, resolved=resolved, fresh_start=fresh_start
        )
    except FollowRefused as early:
        result.status = "refused"
        result.error_summary = early.code
        result.guidance = early.guidance
        return result
    except _RotationSealed as sealed:
        _seal_state(
            db_path,
            ctx,
            sealed.orphan_state,
            status=STATUS_ROTATED,
            detail=None,
            finish_status="completed",
            error_summary=None,
            result=result,
        )
        stat = resolved.stat()
        identity = FileIdentity(
            dev=stat.st_dev,
            ino=stat.st_ino,
            size=stat.st_size,
            mtime_ns=stat.st_mtime_ns,
        )
        current = _begin_next_gen(
            db_path,
            ctx,
            seq=int(sealed.orphan_state.gen["generation_seq"]) + 1,
            identity=identity,
            fresh_start=fresh_start,
        )
        state = _GenState(
            gen=current,
            hasher=hashlib.sha256(),
            splitter=_LineFollower(ctx.limits.max_line_bytes),
            identity=identity,
            effective_format=_resolve_effective(ctx, resolved),
            line_number=1,
            path=resolved,
            tail_start=0,
            tail_sha="",
        )
        result.generations_started += 1
    if started:
        result.generations_started += 1
    result.active_generation = int(current["generation_seq"])

    fd = -1
    try:
        fd = _open_live(resolved)
    except OSError:
        raise FollowFailed(IO_ERROR_CODE)
    # In-run read cursor, separate from the durable complete-line
    # checkpoint: partial-line bytes stay in splitter memory and are
    # NEVER re-read inside a run (a restart re-reads from the
    # checkpoint). Feeding already-read bytes again would duplicate
    # the partial prefix and corrupt the offset/digest chain.
    read_offset = int(state.gen["next_offset"])
    try:
        os.lseek(fd, read_offset, os.SEEK_SET)
        for poll in range(1, max_polls + 1):
            result.polls += 1
            try:
                cur = resolved.stat()
            except OSError:
                cur = None
            try:
                live = os.fstat(fd)
            except OSError:
                raise FollowFailed(IO_ERROR_CODE)
            if cur is None or (cur.st_dev, cur.st_ino) != (live.st_dev, live.st_ino):
                _drain_fd(db_path, ctx, state, fd, result=result)
                _seal_state(
                    db_path,
                    ctx,
                    state,
                    status=STATUS_ROTATED,
                    detail=None,
                    finish_status="completed",
                    error_summary=None,
                    result=result,
                )
                os.close(fd)
                fd = -1
                if cur is None:
                    result.error_summary = ROTATION_TARGET_MISSING
                    result.guidance = (
                        "the followed file vanished mid-run: its drained tail"
                        " is sealed. Re-run follow once the path exists again."
                    )
                    break
                # Revalidate the approved root/symlink boundary on every
                # rotation: the replacement must still resolve inside
                # the configured root, never an escaped symlink target.
                try:
                    resolved = resolve_source_path(ctx.source)
                except (SourceError, OSError):
                    raise FollowFailed(IO_ERROR_CODE)
                if has_gzip_magic(resolved):
                    raise FollowRefused(
                        FOLLOW_GZIP_UNSUPPORTED,
                        "the rotated-in file is gzip-compressed: replay it"
                        " via replay-archive instead of tailing it.",
                    )
                cur = resolved.stat()
                identity = FileIdentity(
                    dev=cur.st_dev,
                    ino=cur.st_ino,
                    size=cur.st_size,
                    mtime_ns=cur.st_mtime_ns,
                )
                current = _begin_next_gen(
                    db_path,
                    ctx,
                    seq=int(state.gen["generation_seq"]) + 1,
                    identity=identity,
                    fresh_start=fresh_start,
                )
                state = _GenState(
                    gen=current,
                    hasher=hashlib.sha256(),
                    splitter=_LineFollower(ctx.limits.max_line_bytes),
                    identity=identity,
                    effective_format=_resolve_effective(ctx, resolved),
                    line_number=1,
                    path=resolved,
                    tail_start=0,
                    tail_sha="",
                    read_end=0,
                )
                result.generations_started += 1
                result.active_generation = int(current["generation_seq"])
                fd = _open_live(resolved)
                os.lseek(fd, 0, os.SEEK_SET)
                read_offset = 0
            elif cur.st_size < int(state.gen["next_offset"]):
                _seal_state(
                    db_path,
                    ctx,
                    state,
                    status=STATUS_ROTATED,
                    detail=None,
                    finish_status="completed",
                    error_summary=None,
                    result=result,
                )
                # Same-inode truncation: revalidate the boundary before
                # reopening at zero (a swapped symlink must not escape).
                try:
                    resolved = resolve_source_path(ctx.source)
                except (SourceError, OSError):
                    raise FollowFailed(IO_ERROR_CODE)
                cur = resolved.stat()
                identity = FileIdentity(
                    dev=cur.st_dev,
                    ino=cur.st_ino,
                    size=cur.st_size,
                    mtime_ns=cur.st_mtime_ns,
                )
                current = _begin_next_gen(
                    db_path,
                    ctx,
                    seq=int(state.gen["generation_seq"]) + 1,
                    identity=identity,
                    fresh_start=fresh_start,
                )
                state = _GenState(
                    gen=current,
                    hasher=hashlib.sha256(),
                    splitter=_LineFollower(ctx.limits.max_line_bytes),
                    identity=identity,
                    effective_format=_resolve_effective(ctx, resolved),
                    line_number=1,
                    path=resolved,
                    tail_start=0,
                    tail_sha="",
                    read_end=0,
                )
                result.generations_started += 1
                result.active_generation = int(current["generation_seq"])
                os.lseek(fd, 0, os.SEEK_SET)
                read_offset = 0
            else:
                if (
                    state.tail_sha
                    and _hash_logical_span(
                        resolved,
                        state.tail_start,
                        int(state.gen["next_offset"]),
                        gzip_limits=ctx.gzip_limits,
                    )
                    != state.tail_sha
                ):
                    # Same-inode regrowth over truncated bytes: the
                    # committed tail changed without a size signal, so
                    # seal and start a new generation like a shrink.
                    _seal_state(
                        db_path,
                        ctx,
                        state,
                        status=STATUS_ROTATED,
                        detail=None,
                        finish_status="completed",
                        error_summary=None,
                        result=result,
                    )
                    identity = FileIdentity(
                        dev=cur.st_dev,
                        ino=cur.st_ino,
                        size=cur.st_size,
                        mtime_ns=cur.st_mtime_ns,
                    )
                    current = _begin_next_gen(
                        db_path,
                        ctx,
                        seq=int(state.gen["generation_seq"]) + 1,
                        identity=identity,
                        fresh_start=fresh_start,
                    )
                    state = _GenState(
                        gen=current,
                        hasher=hashlib.sha256(),
                        splitter=_LineFollower(ctx.limits.max_line_bytes),
                        identity=identity,
                        effective_format=_resolve_effective(ctx, resolved),
                        line_number=1,
                        path=resolved,
                        tail_start=0,
                        tail_sha="",
                        read_end=0,
                    )
                    result.generations_started += 1
                    result.active_generation = int(current["generation_seq"])
                    os.lseek(fd, 0, os.SEEK_SET)
                    read_offset = 0
                # Normal poll: read only NEW bytes from the read cursor.
                # The durable checkpoint trails at the last complete
                # line; seeking back to it here would re-feed the
                # retained partial prefix and duplicate it.
                try:
                    chunk = os.read(fd, max_bytes_per_poll)
                except OSError:
                    raise FollowFailed(IO_ERROR_CODE)
                if not chunk:
                    result.empty_polls += 1
                else:
                    position = read_offset
                    items, view, view_start, dropped = _feed_view(state, chunk, position)
                    read_offset += len(chunk)
                    state.read_end = read_offset
                    try:
                        fresh = os.fstat(fd)
                    except OSError:
                        raise FollowFailed(IO_ERROR_CODE)
                    state.identity = FileIdentity(
                        dev=fresh.st_dev,
                        ino=fresh.st_ino,
                        size=max(fresh.st_size, view_start + len(view)),
                        mtime_ns=fresh.st_mtime_ns,
                    )
                    if items or dropped:
                        try:
                            _process_items(
                                db_path,
                                ctx,
                                state,
                                items,
                                view=view,
                                view_start=view_start,
                                dropped=dropped,
                                result=result,
                            )
                        except (CustomFormatError, AmbiguousFormat, UnmatchedFormat) as exc:
                            _fail_active_import(db_path, ctx, state, failure_code(exc))
                            result.status = "failed"
                            result.error_summary = failure_code(exc)
                            break
            if after_poll is not None:
                after_poll(poll, result)
            if poll < max_polls and float(poll_interval_s) > 0:
                time.sleep(float(poll_interval_s))
    except FollowRefused as refused:
        try:
            if fd >= 0:
                os.close(fd)
        except OSError:
            pass
        result.status = "refused"
        result.error_summary = refused.code
        result.guidance = refused.guidance
        return result
    except FollowFailed as failed:
        try:
            if fd >= 0:
                os.close(fd)
        except OSError:
            pass
        result.status = "failed"
        result.error_summary = failed.code
        return result
    except KeyboardInterrupt:
        try:
            if fd >= 0:
                os.close(fd)
        except OSError:
            pass
        result.status = "cancelled"
        return result
    try:
        if fd >= 0:
            os.close(fd)
    except OSError:
        pass
    result.active_generation = int(state.gen["generation_seq"])
    return result


def _fail_active_import(db_path: Path, ctx: _RunContext, state: _GenState, code: str) -> None:
    """Finish the active generation attempt as failed; it stays resumable.

    A stale checkpoint refuses instead of overwriting a generation a
    concurrent follower already moved.
    """

    def _work():
        with writer_transaction(db_path, lock_timeout_s=ctx.lock_timeout_s) as conn:
            _check_fresh_for_write(conn, state.gen)
            accepted, rejected, _skipped, inserted, replayed = _gen_totals(
                conn,
                source_id=ctx.source.source_id,
                seq=int(state.gen["generation_seq"]),
            )
            repositories.finish_import(
                conn,
                import_id=int(state.gen["import_id"]),
                finished_at=_now(),
                status="failed",
                counts=_repos_counts(accepted, rejected, inserted, replayed),
                error_summary=code,
            )
            state.gen["updated_at"] = _now()
            _store_generation(conn, row=state.gen)

    try:
        _with_writer_retry(ctx, _work)
    except WriterBusy:
        raise FollowFailed(WRITER_BUSY_CODE)


def replay_archive(
    db_path: Path,
    *,
    archive: SourceConfig,
    site_id: str,
    site_name: str,
    site_hostname: str,
    server_type: str,
    path_alias: str,
    hmac_key: bytes,
    batch_size: int = 1000,
    generation_seq: int | None = None,
    capture_originals: bool = False,
    ip_key: object = None,
    country_lookup: CountryLookup | None = None,
    geoip_required: bool = False,
    host_filter: HostFilter | None = None,
    custom_format: CustomFormat | None = None,
    limits: Limits | None = None,
    gzip_limits: GzipLimits | None = None,
    lock_timeout_s: float = 30.0,
    max_writer_retries: int = DEFAULT_MAX_WRITER_RETRIES,
) -> ArchiveResult:
    """Replay a rotated archive under its sealed generation identity.

    The archive's consumed span is validated against the sealed running
    digest first (plain and gzip archives carrying the same logical
    bytes validate identically); only the new tail is then ingested, so
    a full-archive replay inserts nothing and replays everything. A
    prefix mismatch refuses with safe guidance and writes no events.
    """
    result = ArchiveResult(source_id=archive.source_id)
    ctx = _build_context(
        source=archive,
        site_id=site_id,
        site_name=site_name,
        site_hostname=site_hostname,
        server_type=server_type,
        path_alias=path_alias,
        hmac_key=hmac_key,
        batch_size=batch_size,
        host_filter=host_filter,
        custom_format=custom_format,
        limits=limits,
        gzip_limits=gzip_limits,
        capture_originals=capture_originals,
        ip_key=ip_key,
        country_lookup=country_lookup,
        lock_timeout_s=lock_timeout_s,
        max_writer_retries=max_writer_retries,
    )
    if geoip_required and not ctx.lookup.available:
        raise GeoipError()
    migrate(db_path)
    _ensure_follow_progress_columns(db_path)
    _check_source_binding(db_path, source_id=archive.source_id, site_id=site_id)
    resolved = resolve_source_path(archive)
    result.archive_path = str(archive.relative_path)
    probe = connect(db_path, read_only=True)
    try:
        if generation_seq is not None:
            gen = _row_dict(
                _load_generation(probe, source_id=archive.source_id, seq=generation_seq)
            )
        else:
            # The latest sealed generation, not the latest overall: a
            # rotation drain usually leaves a fresh active generation on
            # the live path while the archive belongs to its sealed
            # predecessor.
            probe.row_factory = sqlite3.Row
            try:
                sealed = probe.execute(
                    "SELECT source_id, site_id, generation_seq, generation_id,"
                    " file_dev, file_ino, gen_start_offset, next_offset,"
                    " next_line_number, oversized_active, oversized_start,"
                    " consumed_sha256, file_size, file_mtime_ns,"
                    " adopted_prefix_sha, adopted_import_id, fresh_start, import_id,"
                    " status, detail, updated_at FROM follow_generations"
                    " WHERE source_id = ? AND status = ?"
                    " ORDER BY generation_seq DESC LIMIT 1",
                    (archive.source_id, STATUS_ROTATED),
                ).fetchone()
            finally:
                probe.row_factory = None
            gen = _row_dict(sealed)
    finally:
        probe.close()
    if gen is None or str(gen["status"]) == STATUS_ACTIVE:
        result.status = "refused"
        result.error_summary = ARCHIVE_NO_SEALED_GENERATION
        result.guidance = (
            "no sealed follow generation exists for this source: rotate the"
            " live file first (follow seals the drained generation), then"
            " replay the archived file."
        )
        return result
    if str(gen["status"]) == STATUS_TAINTED:
        result.status = "refused"
        result.error_summary = PREFIX_TAINTED
        result.guidance = (
            "the sealed generation is tainted: its consumed bytes changed"
            " under a live checkpoint. Batch-import the archive as new rows"
            " instead of replaying it."
        )
        return result
    result.generation_seq = int(gen["generation_seq"])
    gen_start = int(gen["gen_start_offset"])
    sealed_end = int(gen["next_offset"])
    # Validation + digest seeding in one bounded read: the archive must
    # still carry exactly the sealed consumed span.
    hasher = hashlib.sha256()
    try:
        for piece_offset, piece in _iter_logical_pieces(
            resolved, gen_start, gzip_limits=ctx.gzip_limits
        ):
            if piece_offset >= sealed_end:
                break
            hasher.update(piece[: sealed_end - piece_offset])
    except GzipError as exc:
        return _failed_archive_attempt(db_path, ctx, gen, result, failure_code(exc))
    if hasher.hexdigest() != str(gen["consumed_sha256"]):
        result.status = "refused"
        result.error_summary = ARCHIVE_PREFIX_MISMATCH
        result.guidance = (
            "the archive prefix does not match the sealed generation digest:"
            " it is a different file (or a different compression of different"
            " bytes). Replaying it would silently duplicate or misattribute"
            " events. Batch-import the archive as new rows instead."
        )
        return result

    def _create_attempt():
        with writer_transaction(db_path, lock_timeout_s=ctx.lock_timeout_s) as conn:
            return repositories.create_import(
                conn,
                source_id=archive.source_id,
                file_fingerprint=generation_fingerprint(
                    archive.source_id, int(gen["generation_seq"])
                ),
                file_size=resolved.stat().st_size,
                started_at=_now(),
            )

    try:
        attempt_id = _with_writer_retry(ctx, _create_attempt)
    except WriterBusy:
        result.status = "failed"
        result.error_summary = WRITER_BUSY_CODE
        return result
    work = dict(gen)
    work["import_id"] = attempt_id
    tail_start, tail_sha = _tail_window(
        resolved, gen_start, sealed_end, gzip_limits=ctx.gzip_limits
    )
    state = _GenState(
        gen=work,
        hasher=hasher,
        splitter=_LineFollower(ctx.limits.max_line_bytes),
        identity=FileIdentity(
            dev=int(gen["file_dev"]),
            ino=int(gen["file_ino"]),
            size=int(gen["file_size"]),
            mtime_ns=int(gen["file_mtime_ns"]),
        ),
        effective_format=_resolve_effective(ctx, resolved),
        line_number=1,
        path=resolved,
        tail_start=tail_start,
        tail_sha=tail_sha,
        # The sealed prefix is already in the digest (seeded by the
        # validation read above): the replay loop must hash only the
        # NEW tail, never the consumed bytes again. Without this floor
        # a second identical replay would hash the prefix twice and
        # refuse its own committed state as a mismatch.
        hash_floor=sealed_end,
        read_end=sealed_end,
    )

    new_end = sealed_end
    try:
        for piece_offset, piece in _iter_logical_pieces(
            resolved, gen_start, gzip_limits=ctx.gzip_limits
        ):
            new_end = max(new_end, piece_offset + len(piece))
            state.read_end = max(int(state.read_end), piece_offset + len(piece))
            items, view, view_start, dropped = _feed_view(state, piece, piece_offset)
            if items or dropped:
                _process_items(
                    db_path,
                    ctx,
                    state,
                    items,
                    view=view,
                    view_start=view_start,
                    dropped=dropped,
                    result=result,
                )
        # Archive EOF terminates the stream (batch parity): a trailing
        # partial is a real final line, a skipping tail one rejection.
        tail = state.splitter.seal(int(state.read_end))
        if tail:
            offset, data, _end = tail[0]
            if data is None:
                tail_view, tail_start = b"", offset
            else:
                tail_view, tail_start = data, offset
                new_end = max(new_end, offset + len(data))
            _process_items(
                db_path,
                ctx,
                state,
                tail,
                view=tail_view,
                view_start=tail_start,
                result=result,
            )
    except (CustomFormatError, AmbiguousFormat, UnmatchedFormat, GzipError) as exc:
        return _failed_archive_attempt(
            db_path, ctx, gen, result, failure_code(exc), attempt_id=attempt_id
        )
    except WriterBusy:
        return _failed_archive_attempt(
            db_path, ctx, gen, result, WRITER_BUSY_CODE, attempt_id=attempt_id
        )
    except FollowFailed as failed:
        return _failed_archive_attempt(
            db_path, ctx, gen, result, failed.code, attempt_id=attempt_id
        )
    stat = resolved.stat()

    def _finish():
        with writer_transaction(db_path, lock_timeout_s=ctx.lock_timeout_s) as conn:
            gen["next_offset"] = new_end
            gen["consumed_sha256"] = state.hasher.hexdigest()
            gen["next_line_number"] = state.line_number
            gen["file_size"] = stat.st_size
            gen["file_mtime_ns"] = stat.st_mtime_ns
            gen["updated_at"] = _now()
            _store_generation(conn, row=gen)
            repositories.finish_import(
                conn,
                import_id=attempt_id,
                finished_at=_now(),
                status="completed",
                counts=repositories.ImportCounts(
                    lines_total=result.lines_accepted + result.lines_rejected,
                    lines_accepted=result.lines_accepted,
                    lines_rejected=result.lines_rejected,
                    records_inserted=result.records_inserted,
                    records_replayed=result.records_replayed,
                ),
                error_summary=None,
            )

    try:
        _with_writer_retry(ctx, _finish)
    except WriterBusy:
        return _failed_archive_attempt(
            db_path, ctx, gen, result, WRITER_BUSY_CODE, attempt_id=attempt_id
        )
    return result


def _failed_archive_attempt(
    db_path: Path,
    ctx: _RunContext,
    gen: dict,
    result: ArchiveResult,
    code: str,
    *,
    attempt_id: int | None = None,
) -> ArchiveResult:
    """Finish a failed archive attempt with a fixed code (no events added)."""
    if attempt_id is not None:

        def _work():
            with writer_transaction(db_path, lock_timeout_s=ctx.lock_timeout_s) as conn:
                repositories.finish_import(
                    conn,
                    import_id=attempt_id,
                    finished_at=_now(),
                    status="failed",
                    counts=repositories.ImportCounts(
                        lines_total=result.lines_accepted + result.lines_rejected,
                        lines_accepted=result.lines_accepted,
                        lines_rejected=result.lines_rejected,
                        records_inserted=result.records_inserted,
                        records_replayed=result.records_replayed,
                    ),
                    error_summary=code,
                )

        try:
            _with_writer_retry(ctx, _work)
        except WriterBusy:
            pass
    result.status = "failed"
    result.error_summary = code
    return result
