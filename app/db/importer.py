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
from app.db.database import WriterBusy, connect, writer_transaction
from app.db.migrations_runner import migrate
from app.ingestion.autodetect import AmbiguousFormat, UnmatchedFormat
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
    LineRejection,
    enrichment_policy,
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
    "interrupted:custom_timeout",
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
    originals_captured: int = 0


def _check_source_binding(db_path: Path, *, source_id: str, site_id: str) -> None:
    """Reject a source id already bound to another site before any write.

    ``ensure_source`` uses ``ON CONFLICT DO NOTHING``, so without this
    check a replayed other-site source id would silently reuse the
    foreign row (and attach replayed other-site originals to it).
    Raises :class:`SourceBindingError` with the fixed
    ``source_site_mismatch`` code, leaving core/metadata/private/auth/
    usage state unchanged and creating no site.
    """
    probe = connect(db_path, read_only=True)
    try:
        registered = repositories.fetch_source(probe, source_id=source_id)
    finally:
        probe.close()
    if registered is not None and str(registered["site_id"]) != site_id:
        raise repositories.SourceBindingError()


def _event_row(
    record: CombinedRecord,
    *,
    import_id: int,
    site_id: str,
    file_fingerprint: str,
    policy: str,
) -> tuple:
    """Legacy core columns plus nullable T1b enrichment metadata.

    ``duration_ms`` stays legacy (always ``None`` from the parser: Combined
    never supplies timing). Measured timings land in
    ``request_time_ms``/``upstream_time_ms``/``upstream_count`` with
    ``None`` meaning absent; ``policy`` tags the parser policy.
    """
    extra = record.extra
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
        record.format_id,
        record.request.http_version,
        extra.server_host if extra is not None else None,
        extra.referer_scheme if extra is not None else None,
        extra.referer_path if extra is not None else None,
        extra.cache_status if extra is not None else None,
        extra.mime_type if extra is not None else None,
        extra.tls_protocol if extra is not None else None,
        extra.request_time_ms if extra is not None else None,
        extra.upstream_time_ms if extra is not None else None,
        extra.upstream_count if extra is not None else None,
        policy,
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
    capture_originals: bool = False,
    ip_key: object = None,
) -> ImportResult:
    """Import one resolved source file; repeatable and interruption-safe.

    Identity is the logical-byte fingerprint (decompressed bytes for gzip,
    raw bytes for plain files) plus the record byte offset, so the same
    plaintext imported plain or gzipped replays instead of duplicating,
    while legitimate identical requests (distinct positions) stay distinct.

    With ``capture_originals=True`` the validated client address of each
    accepted record is additionally stored encrypted (AESGCM, separate
    server key, per-event AAD). Capture without a valid configured key
    fails before any write. Routine rows, reports and payloads never carry
    originals regardless of this flag.
    """
    if not hmac_key:
        raise ValueError("hmac_key must be non-empty")
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")
    if (
        isinstance(autodetect_sample_lines, bool)
        or not isinstance(autodetect_sample_lines, int)
        or not 1 <= autodetect_sample_lines <= 1024
    ):
        raise ValueError("autodetect_sample_lines must be an integer in 1..1024")
    if source.format_id == CUSTOM and custom_format is None:
        raise CustomFormatError("interrupted:custom_invalid")
    if custom_format is not None and source.format_id not in (CUSTOM, custom_format.format_id):
        raise CustomFormatError("interrupted:custom_invalid")
    from app.db import private as _private

    private_key: bytes | None = None
    if capture_originals:
        # Fail before any write when no valid key is configured; a
        # roundtrip self-test proves the key operates without storing it.
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
        # Host-bearing lines must never be silently attributed to this site:
        # without an explicit rule the configured site hostname is the filter.
        # Plain presets carry no host, so they pass through unaffected.
        # Custom vhost mappings default the same way when applicable.
        effective_filter = HostFilter([site_hostname])
    # The configured server flavor decides indistinguishable Combined twins.
    default_combined = (
        APACHE_COMBINED if server_type.strip().lower() == "apache" else NGINX_COMBINED
    )
    now = clock or (lambda: datetime.now(UTC))
    migrate(db_path)
    _check_source_binding(db_path, source_id=source.source_id, site_id=site_id)

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
    policy = enrichment_policy(source.format_id, custom_format)

    with writer_transaction(db_path, lock_timeout_s=lock_timeout_s) as conn:
        started = now().isoformat()
        repositories.ensure_site(
            conn,
            site_id=site_id,
            name=site_name,
            hostname=site_hostname,
            created_at=started,
        )
        # Same-lock immutable binding: the pre-lock read check above
        # cannot see a concurrent first registration, so the guard
        # inside this transaction re-reads the stored site under the
        # write lock and rolls the whole transaction back on mismatch.
        repositories.ensure_source_locked(
            conn,
            source_id=source.source_id,
            site_id=site_id,
            server_type=server_type,
            format_id=source.format_id,
            path_alias=path_alias,
            allowed_hosts=(
                sorted(effective_filter.hosts) if effective_filter is not None else None
            ),
        )
        # Persist alias metadata for already-bound sources: their row
        # predates the allowed_hosts column (ON CONFLICT ignores it), so
        # without this later internal/external referrer reports would
        # keep using stale aliases. Core/site/auth/ledger fields stay
        # untouched; only the validated alias column is rewritten.
        if effective_filter is not None:
            repositories.update_source_hosts(
                conn,
                source_id=source.source_id,
                site_id=site_id,
                allowed_hosts=sorted(effective_filter.hosts),
            )
        import_id = repositories.create_import(
            conn,
            source_id=source.source_id,
            file_fingerprint=fingerprint,
            file_size=size_before,
            started_at=started,
        )

    def _flush_batch(conn) -> None:
        """Insert one batch and store captured originals encrypted (same transaction)."""
        nonlocal inserted, originals_captured
        inserted += repositories.insert_events(conn, batch)
        if capture_originals and batch_private and private_key is not None:
            placeholders = ",".join(["?"] * len(batch))
            id_rows = conn.execute(
                "SELECT id, byte_offset FROM requests WHERE source_id = ?"
                " AND file_fingerprint = ? AND byte_offset IN (" + placeholders + ")",
                (source.source_id, fingerprint, *[row[4] for row in batch]),
            ).fetchall()
            id_by_offset = {int(offset): int(row_id) for row_id, offset in id_rows}
            for offset, captured in batch_private:
                request_id = id_by_offset.get(offset)
                if request_id is None:
                    continue
                aad = _private.build_aad(
                    site_id=site_id,
                    source_id=source.source_id,
                    file_fingerprint=fingerprint,
                    byte_offset=offset,
                )
                nonce, ciphertext = _private.encrypt_captured(captured, key=private_key, aad=aad)
                if _private.store_private_ip(
                    conn, request_id=request_id, nonce=nonce, ciphertext=ciphertext
                ):
                    originals_captured += 1

    stream_report = ImportReport(source_id=source.source_id, format_id=source.format_id)
    inserted = 0
    originals_captured = 0
    batch: list[tuple] = []
    batch_private: list[tuple[int, CapturedOriginal]] = []
    batch_index = 0
    failure: Exception | None = None
    try:
        for yielded in iter_records(
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
            default_combined=default_combined,
            capture_original=capture_originals,
        ):
            if capture_originals:
                item, original = yielded
            else:
                item, original = yielded, None
            if isinstance(item, (LineRejection, HostSkipped)):
                continue
            batch.append(
                _event_row(
                    item,
                    import_id=import_id,
                    site_id=site_id,
                    file_fingerprint=fingerprint,
                    policy=policy,
                )
            )
            if capture_originals and isinstance(original, CapturedOriginal):
                batch_private.append((item.byte_offset, original))
            if len(batch) >= batch_size:
                batch_index += 1
                with writer_transaction(db_path, lock_timeout_s=lock_timeout_s) as conn:
                    _flush_batch(conn)
                batch.clear()
                batch_private.clear()
                if after_batch is not None:
                    after_batch(batch_index)
        if batch:
            batch_index += 1
            with writer_transaction(db_path, lock_timeout_s=lock_timeout_s) as conn:
                _flush_batch(conn)
            batch.clear()
            batch_private.clear()
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
        originals_captured=originals_captured,
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
    _check_source_binding(db_path, source_id=source.source_id, site_id=site_id)
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
