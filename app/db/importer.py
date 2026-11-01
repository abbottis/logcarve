"""Repeatable batch import over the T2 streaming parser (T3).

Replay identity is ``(source_id, file fingerprint, record byte offset)``:
re-importing the same file inserts nothing new, while legitimate
identical requests (distinct positions) insert distinct rows. Identity
never relies on inode/mtime and never on normalized event content.

Each batch commits in its own bounded transaction, so an interrupted
import keeps committed batches and a re-run completes it without
duplicates. A size change of the source file during import is reported
as ``source_changed``; a changed file carries a new fingerprint and
imports as new rows.

Source consistency: the import reader computes a running digest of the
exact bytes it pulls from the stream (line content, newlines, rejected
and skipped oversized data) with bounded memory and no input retained.
For a fully consumed import this consumed-bytes digest is compared
against both the pre-import fingerprint and a fresh final digest; an
interrupted import performs no comparison. An open descriptor alone
cannot prevent in-place writes, so it is this reader-produced digest —
never a substitute re-reading pass — that proves what was consumed. Any
size or content change flags the import (``source_changed`` with
``source_changed_during_import`` and, for content, an additional
``source_content_mismatch`` code), including a transient same-size
rewrite that is restored before the final hash: the consumed bytes still
differ from both digests. Committed batches are kept and stay queryable,
completion is never reported clean on mismatch, and the codes surface
through analytics quality warnings. A later re-import of the changed
file carries the new fingerprint and imports as new rows; flagged rows
remain attributed to the fingerprint recorded at import time.
Diagnostics use allowlisted codes only; exception text is never
persisted.
"""

import hashlib
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from app.db import repositories
from app.db.database import WriterBusy, writer_transaction
from app.db.migrations_runner import migrate
from app.ingestion.autodetect import AmbiguousFormat, UnmatchedFormat
from app.ingestion.combined import (
    APACHE_VHOST_COMBINED,
    AUTO,
    CUSTOM,
    NGINX_EXTENDED,
    CombinedRecord,
    Limits,
    LineRejection,
)
from app.ingestion.custom import CustomFormat, CustomFormatError
from app.ingestion.gzipio import GzipError, GzipLimits
from app.ingestion.sources import HostFilter, SourceConfig, resolve_source_path
from app.ingestion.stream import HostSkipped, ImportReport, fingerprint_source, iter_records

_FINGERPRINT_CHUNK = 1024 * 1024


def sha256_file(path: Path) -> str:
    """Stable content fingerprint of a source file (streamed, bounded memory)."""
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(_FINGERPRINT_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


# Allowlisted import diagnostic codes. Stored and served summaries use
# only these segments so exception text (paths, raw bytes, secrets) can
# never persist into the database or leak through analytics responses.
SOURCE_CHANGED_CODE = "source_changed_during_import"
SOURCE_CONTENT_MISMATCH_CODE = "source_content_mismatch"
FAILURE_CODES = (
    "interrupted:io_error",
    "interrupted:storage_error",
    "interrupted:writer_busy",
    "interrupted:import_failed",
    "interrupted:gzip_crc_error",
    "interrupted:gzip_truncated",
    "interrupted:gzip_too_large",
    "interrupted:gzip_ratio_exceeded",
    "interrupted:gzip_member_limit",
    "interrupted:gzip_invalid",
    "interrupted:format_ambiguous",
    "interrupted:format_unmatched",
    "interrupted:custom_invalid",
)
_ALLOWED_SUMMARY_SEGMENTS = frozenset(
    (SOURCE_CHANGED_CODE, SOURCE_CONTENT_MISMATCH_CODE, *FAILURE_CODES)
)
LEGACY_WITHHELD = "diagnostic_withheld:legacy_format"


def failure_code(exc: BaseException) -> str:
    """Map an import failure to an allowlisted code; never persist repr(exc)."""
    if isinstance(exc, WriterBusy):
        return "interrupted:writer_busy"
    if isinstance(exc, (GzipError, CustomFormatError, AmbiguousFormat, UnmatchedFormat)):
        code = getattr(exc, "code", "interrupted:import_failed")
        if code in FAILURE_CODES:
            return code
        return "interrupted:import_failed"
    if isinstance(exc, OSError):
        return "interrupted:io_error"
    if isinstance(exc, sqlite3.Error):
        return "interrupted:storage_error"
    return "interrupted:import_failed"


def sanitize_error_summary(value: str | None) -> str | None:
    """Keep only allowlisted diagnostic segments from a stored summary.

    Summaries written before allowlisting (free-text ``repr`` output) are
    replaced with a fixed marker instead of leaking through analytics.
    """
    if not value:
        return None
    kept = [segment for segment in value.split("; ") if segment in _ALLOWED_SUMMARY_SEGMENTS]
    if kept:
        return "; ".join(kept)
    return LEGACY_WITHHELD


@dataclass
class ImportResult:
    import_id: int
    source_id: str
    file_fingerprint: str
    lines_total: int = 0
    lines_accepted: int = 0
    lines_rejected: int = 0
    records_inserted: int = 0
    records_replayed: int = 0
    records_skipped_foreign: int = 0
    is_gzip: bool = False
    gzip_members: int = 0
    status: str = "completed"
    error_summary: str | None = None
    source_changed: bool = False
    consumed_sha256: str | None = None
    rejected_by_reason: dict[str, int] = field(default_factory=dict)


def _event_row(
    record: CombinedRecord,
    *,
    import_id: int,
    site_id: str,
    file_fingerprint: str,
) -> tuple:
    return (
        import_id,
        site_id,
        record.source_id,
        file_fingerprint,
        record.byte_offset,
        record.line_number,
        record.timestamp_utc.isoformat(),
        record.request.method,
        record.request.target_path,
        record.status,
        record.bytes_sent,
        record.referer_host,
        record.user_agent,
        record.client_pseudonym,
        record.duration_ms,
    )


def run_import(
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
    limits: Limits | None = None,
    clock: Callable[[], datetime] | None = None,
    after_batch: Callable[[int], None] | None = None,
    lock_timeout_s: float = 30.0,
    host_filter: HostFilter | None = None,
    custom_format: CustomFormat | None = None,
    gzip_limits: GzipLimits | None = None,
    autodetect_sample_lines: int = 32,
) -> ImportResult:
    """Import one resolved source file; repeatable and interruption-safe.

    Identity is the logical-byte fingerprint (decompressed bytes for gzip,
    raw bytes for plain files) plus the record byte offset, so the same
    plaintext imported plain or gzipped replays instead of duplicating,
    while legitimate identical requests (distinct positions) stay distinct.
    """
    if not hmac_key:
        raise ValueError("hmac_key must be non-empty")
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")
    if source.format_id == CUSTOM and custom_format is None:
        raise CustomFormatError("interrupted:custom_invalid")
    if custom_format is not None and source.format_id not in (CUSTOM, custom_format.format_id):
        raise CustomFormatError("interrupted:custom_invalid")
    effective_filter = host_filter if host_filter is not None else source.host_filter()
    if effective_filter is None and source.format_id in (
        APACHE_VHOST_COMBINED,
        NGINX_EXTENDED,
        AUTO,
    ):
        # Host-bearing lines must never be silently attributed to this site:
        # without an explicit rule the configured site hostname is the filter.
        # Plain presets carry no host, so they pass through unaffected.
        effective_filter = HostFilter([site_hostname])
    now = clock or (lambda: datetime.now(UTC))
    migrate(db_path)

    resolved = resolve_source_path(source)
    try:
        logical = fingerprint_source(resolved, gzip_limits=gzip_limits)
    except GzipError as exc:
        return _failed_pre_import(
            db_path,
            source=source,
            site_id=site_id,
            site_name=site_name,
            site_hostname=site_hostname,
            server_type=server_type,
            path_alias=path_alias,
            now=now,
            failure=exc,
        )
    fingerprint = logical.logical_sha256
    size_before = resolved.stat().st_size

    with writer_transaction(db_path, lock_timeout_s=lock_timeout_s) as conn:
        started = now().isoformat()
        repositories.ensure_site(
            conn,
            site_id=site_id,
            name=site_name,
            hostname=site_hostname,
            created_at=started,
        )
        repositories.ensure_source(
            conn,
            source_id=source.source_id,
            site_id=site_id,
            server_type=server_type,
            format_id=source.format_id,
            path_alias=path_alias,
        )
        import_id = repositories.create_import(
            conn,
            source_id=source.source_id,
            file_fingerprint=fingerprint,
            file_size=size_before,
            started_at=started,
        )

    stream_report = ImportReport(source_id=source.source_id, format_id=source.format_id)
    inserted = 0
    batch: list[tuple] = []
    batch_index = 0
    failure: Exception | None = None
    try:
        for item in iter_records(
            resolved,
            source_id=source.source_id,
            format_id=source.format_id,
            hmac_key=hmac_key,
            limits=limits,
            report=stream_report,
            host_filter=effective_filter,
            custom_format=custom_format,
            gzip_limits=gzip_limits,
            autodetect_sample_lines=autodetect_sample_lines,
        ):
            if isinstance(item, (LineRejection, HostSkipped)):
                continue
            batch.append(
                _event_row(item, import_id=import_id, site_id=site_id, file_fingerprint=fingerprint)
            )
            if len(batch) >= batch_size:
                batch_index += 1
                with writer_transaction(db_path, lock_timeout_s=lock_timeout_s) as conn:
                    inserted += repositories.insert_events(conn, batch)
                batch.clear()
                if after_batch is not None:
                    after_batch(batch_index)
        if batch:
            batch_index += 1
            with writer_transaction(db_path, lock_timeout_s=lock_timeout_s) as conn:
                inserted += repositories.insert_events(conn, batch)
            batch.clear()
            if after_batch is not None:
                after_batch(batch_index)
    except Exception as exc:  # noqa: BLE001 - recorded on the import row, then re-raised
        failure = exc

    rejected_total = sum(stream_report.rejected_by_reason.values())
    skipped_foreign = stream_report.foreign_skipped
    accepted = stream_report.lines_read - rejected_total - skipped_foreign
    consumed = stream_report.consumed_sha256
    try:
        size_after = resolved.stat().st_size
    except OSError:
        size_after = None
    size_changed = size_after is None or size_after != size_before
    content_mismatch = False
    if failure is None and consumed is not None:
        # The consumed-bytes digest comes from the import reader itself:
        # every logical byte the import actually read (lines, newlines,
        # rejected and skipped oversized data; decompressed bytes for
        # gzip). It is compared against both the pre-import logical
        # fingerprint and a fresh final logical digest, so even a
        # transient same-size change that is restored before this point
        # is detected: the consumed bytes still differ from both. A
        # change that lands after the reader finished leaves the
        # consumed bytes matching but moves the file; that is flagged
        # as a source change with correctly attributed rows.
        try:
            final_digest: str | None = fingerprint_source(
                resolved, gzip_limits=gzip_limits
            ).logical_sha256
        except (OSError, GzipError):
            final_digest = None
        if consumed != fingerprint or (final_digest is not None and consumed != final_digest):
            content_mismatch = True
        elif final_digest is None or final_digest != fingerprint:
            size_changed = True
    source_changed = size_changed or content_mismatch
    warnings: list[str] = []
    if source_changed:
        warnings.append(SOURCE_CHANGED_CODE)
    if content_mismatch:
        warnings.append(SOURCE_CONTENT_MISMATCH_CODE)
    if failure is not None:
        status = "failed"
        warnings.append(failure_code(failure))
    else:
        status = "completed"
    counts = repositories.ImportCounts(
        lines_total=stream_report.lines_read,
        lines_accepted=accepted,
        lines_rejected=rejected_total,
        records_inserted=inserted,
        records_replayed=accepted - inserted,
    )
    with writer_transaction(db_path, lock_timeout_s=lock_timeout_s) as conn:
        repositories.finish_import(
            conn,
            import_id=import_id,
            finished_at=now().isoformat(),
            status=status,
            counts=counts,
            error_summary="; ".join(warnings) or None,
        )
    if failure is not None:
        raise failure
    return ImportResult(
        import_id=import_id,
        source_id=source.source_id,
        file_fingerprint=fingerprint,
        lines_total=counts.lines_total,
        lines_accepted=counts.lines_accepted,
        lines_rejected=counts.lines_rejected,
        records_inserted=counts.records_inserted,
        records_replayed=accepted - inserted,
        records_skipped_foreign=skipped_foreign,
        is_gzip=logical.is_gzip,
        gzip_members=stream_report.gzip_members,
        status=status,
        error_summary="; ".join(warnings) or None,
        source_changed=source_changed,
        consumed_sha256=consumed,
        rejected_by_reason=dict(stream_report.rejected_by_reason),
    )


def _failed_pre_import(
    db_path: Path,
    *,
    source: SourceConfig,
    site_id: str,
    site_name: str,
    site_hostname: str,
    server_type: str,
    path_alias: str,
    now,
    failure: Exception,
) -> ImportResult:
    """Record a fixed-code failure when the source cannot even be fingerprinted.

    No event rows exist yet, so there is nothing to keep; the import row
    records the interruption with an allowlisted code only.
    """
    migrate(db_path)
    with writer_transaction(db_path) as conn:
        started = now().isoformat()
        repositories.ensure_site(
            conn,
            site_id=site_id,
            name=site_name,
            hostname=site_hostname,
            created_at=started,
        )
        repositories.ensure_source(
            conn,
            source_id=source.source_id,
            site_id=site_id,
            server_type=server_type,
            format_id=source.format_id,
            path_alias=path_alias,
        )
        import_id = repositories.create_import(
            conn,
            source_id=source.source_id,
            file_fingerprint="unavailable:pre_import_failed",
            file_size=0,
            started_at=started,
        )
        counts = repositories.ImportCounts(
            lines_total=0,
            lines_accepted=0,
            lines_rejected=0,
            records_inserted=0,
            records_replayed=0,
        )
        repositories.finish_import(
            conn,
            import_id=import_id,
            finished_at=now().isoformat(),
            status="failed",
            counts=counts,
            error_summary=failure_code(failure),
        )
    return ImportResult(
        import_id=import_id,
        source_id=source.source_id,
        file_fingerprint="unavailable:pre_import_failed",
        status="failed",
        error_summary=failure_code(failure),
        source_changed=False,
    )
