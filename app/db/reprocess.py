"""Read-only-source reprocess/enrichment (T1b, PAR-02).

Old rows keep new fields nullable until an explicit reprocess enriches
them: the original approved source file is read again (never written,
moved or deleted) and each stored event is matched by its replay
identity ``(source_id, file_fingerprint, byte_offset)``. Before touching
a row, the freshly parsed record must reproduce the stored normalized
core (timestamp, method, path, status, bytes, referrer host, user agent,
HMAC pseudonym, legacy duration) exactly; only then are the new
nullable metadata columns (and, optionally, the encrypted private
original) written. Core columns are never rewritten, nothing is
duplicated, a changed file never lands under an old fingerprint, and
the run never resets unrelated state.

Batch commits keep partial progress honest and recoverable: an
interruption raises after committing finished batches, and a re-run
re-verifies every row (already-enriched rows compare equal, already
stored originals are kept, so two runs are idempotent). Records whose
approved source is gone match nothing and stay untouched -- HMAC
pseudonyms cannot reconstruct original addresses or referrer paths.
Source changes and mismatches surface as fixed codes only.
"""

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from app.db import private as _private
from app.db import repositories
from app.db.database import connect, writer_transaction
from app.db.importer import (
    _ALLOWED_SUMMARY_SEGMENTS,
    SOURCE_CONTENT_MISMATCH_CODE,
    failure_code,
)
from app.db.migrations_runner import migrate
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
from app.ingestion.gzipio import GzipError, GzipLimits
from app.ingestion.sources import HostFilter, SourceConfig, resolve_source_path
from app.ingestion.stream import HostSkipped, ImportReport, fingerprint_source, iter_records

REPROCESS_NO_ROWS = "reprocess_unavailable:no_matching_rows"
REPROCESS_NO_SOURCE = "reprocess_unavailable:source_missing"
REPROCESS_SOURCE_CHANGED = "source_changed_during_reprocess"
REPROCESS_MISMATCH = "reprocess_mismatch:core_changed"
REPROCESS_REJECTED_STATUS = "rejected"

_ALLOWED_REPROCESS_SEGMENTS = frozenset(
    {
        *_ALLOWED_SUMMARY_SEGMENTS,
        REPROCESS_NO_ROWS,
        REPROCESS_NO_SOURCE,
        REPROCESS_SOURCE_CHANGED,
        REPROCESS_MISMATCH,
        repositories.SOURCE_SITE_MISMATCH_CODE,
    }
)


def _sanitize_reprocess_summary(value: str | None) -> str | None:
    if not value:
        return None
    kept = [segment for segment in value.split("; ") if segment in _ALLOWED_REPROCESS_SEGMENTS]
    if kept:
        return "; ".join(kept)
    return "diagnostic_withheld:legacy_format"


@dataclass
class ReprocessResult:
    source_id: str
    file_fingerprint: str
    rows_matched: int = 0
    rows_verified: int = 0
    rows_enriched: int = 0
    rows_mismatched: int = 0
    rows_unparseable: int = 0
    rows_skipped_foreign: int = 0
    originals_captured: int = 0
    status: str = "completed"
    error_summary: str | None = None
    source_changed: bool = False
    consumed_sha256: str | None = None
    mismatch_by_reason: dict[str, int] = field(default_factory=dict)


def _core_tuple(record: CombinedRecord) -> tuple:
    """Normalized core identity a reparse must reproduce exactly."""
    return (
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


def _metadata_tuple(record: CombinedRecord, policy: str) -> tuple:
    """New nullable enrichment metadata, in repository column order."""
    extra = record.extra
    return (
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


def run_reprocess(
    db_path: Path,
    *,
    source: SourceConfig,
    site_id: str,
    site_hostname: str,
    server_type: str,
    hmac_key: bytes,
    batch_size: int = 1000,
    limits: Limits | None = None,
    after_batch: Callable[[int], None] | None = None,
    lock_timeout_s: float = 30.0,
    host_filter: HostFilter | None = None,
    custom_format: CustomFormat | None = None,
    gzip_limits: GzipLimits | None = None,
    autodetect_sample_lines: int = 32,
    capture_originals: bool = False,
    ip_key: object = None,
) -> ReprocessResult:
    """Enrich stored rows from their approved read-only source file.

    ``source.format_id`` selects the enrichment grammar (for example an
    extended preset with measured timings). Capture without a valid
    configured key fails before any write.
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
    default_combined = (
        APACHE_COMBINED if server_type.strip().lower() == "apache" else NGINX_COMBINED
    )
    migrate(db_path)

    try:
        resolved = resolve_source_path(source)
    except (OSError, ValueError):
        return ReprocessResult(
            source_id=source.source_id,
            file_fingerprint="unavailable:source_missing",
            status="unavailable",
            error_summary=REPROCESS_NO_SOURCE,
        )
    try:
        logical = fingerprint_source(resolved, gzip_limits=gzip_limits)
    except GzipError as exc:
        return ReprocessResult(
            source_id=source.source_id,
            file_fingerprint="unavailable:pre_reprocess_failed",
            status="failed",
            error_summary=failure_code(exc),
        )
    fingerprint = logical.logical_sha256
    try:
        size_before = resolved.stat().st_size
    except OSError:
        return ReprocessResult(
            source_id=source.source_id,
            file_fingerprint=fingerprint,
            status="unavailable",
            error_summary=REPROCESS_NO_SOURCE,
        )

    # Immutable source/site binding, checked BEFORE any write. A source
    # id registered to another site, or stored rows for this file owned
    # by another site, reject with a fixed code and leave every table
    # untouched: no cross-site enrichment, no replayed other-site
    # originals, no new site creation.
    probe = connect(db_path, read_only=True)
    try:
        registered = repositories.fetch_source(probe, source_id=source.source_id)
        if registered is not None and str(registered["site_id"]) != site_id:
            return ReprocessResult(
                source_id=source.source_id,
                file_fingerprint=fingerprint,
                status=REPROCESS_REJECTED_STATUS,
                error_summary=repositories.SOURCE_SITE_MISMATCH_CODE,
            )
        rows_mine = repositories.count_reprocess_rows(
            probe,
            source_id=source.source_id,
            file_fingerprint=fingerprint,
            site_id=site_id,
        )
        if rows_mine == 0:
            rows_any_site = repositories.count_reprocess_rows(
                probe, source_id=source.source_id, file_fingerprint=fingerprint
            )
            if rows_any_site > 0:
                return ReprocessResult(
                    source_id=source.source_id,
                    file_fingerprint=fingerprint,
                    status=REPROCESS_REJECTED_STATUS,
                    error_summary=repositories.SOURCE_SITE_MISMATCH_CODE,
                )
            return ReprocessResult(
                source_id=source.source_id,
                file_fingerprint=fingerprint,
                status="unavailable",
                error_summary=REPROCESS_NO_ROWS,
            )
    finally:
        probe.close()

    # Same-lock binding recheck plus alias persistence: the probe above
    # runs without the writer lock, so a concurrent foreign registration
    # could land between probe and flush. Re-asserting inside a writer
    # transaction closes that race (mismatch rolls back, nothing is
    # written), and already-bound sources gain the new validated alias
    # metadata (core/site/auth/ledger fields untouched) so later
    # internal/external referrer reports classify correctly. Row writes
    # stay additionally guarded per row by stored identity.
    try:
        with writer_transaction(db_path, lock_timeout_s=lock_timeout_s) as guard_conn:
            # Read-only recheck under the write lock: no source row is
            # created here (the probe already proved our rows exist).
            repositories.check_source_binding_locked(
                guard_conn, source_id=source.source_id, site_id=site_id
            )
            if effective_filter is not None:
                repositories.update_source_hosts(
                    guard_conn,
                    source_id=source.source_id,
                    site_id=site_id,
                    allowed_hosts=sorted(effective_filter.hosts),
                )
    except repositories.SourceBindingError:
        return ReprocessResult(
            source_id=source.source_id,
            file_fingerprint=fingerprint,
            status=REPROCESS_REJECTED_STATUS,
            error_summary=repositories.SOURCE_SITE_MISMATCH_CODE,
        )

    policy = enrichment_policy(source.format_id, custom_format)
    page_limit = max(1, min(batch_size, repositories.REPROCESS_PAGE_MAX))
    # Keyset merge-join state: stored rows are paged in byte_offset
    # order through short read transactions (no long-lived snapshot
    # while writing) and the file streams in the same order, so at most
    # two pages are ever retained -- never an all-source dict.
    page: dict[int, sqlite3.Row] = {}
    page_ceiling = -1
    page_exhausted = False

    def _stored_at(offset: int) -> sqlite3.Row | None:
        nonlocal page, page_ceiling, page_exhausted
        if offset in page:
            return page[offset]
        while offset > page_ceiling and not page_exhausted:
            read_conn = connect(db_path, read_only=True)
            try:
                rows = repositories.fetch_reprocess_page(
                    read_conn,
                    source_id=source.source_id,
                    file_fingerprint=fingerprint,
                    site_id=site_id,
                    after_offset=page_ceiling,
                    limit=page_limit,
                )
            finally:
                read_conn.close()
            if not rows:
                page_exhausted = True
                break
            # The file streams in ascending offset order and the new
            # page starts past the old ceiling, so older entries can
            # never match again and are dropped: memory stays bounded.
            page = {}
            for row in rows:
                page[int(row["byte_offset"])] = row
            page_ceiling = max(page)
        return page.get(offset)

    result = ReprocessResult(
        source_id=source.source_id,
        file_fingerprint=fingerprint,
        rows_matched=rows_mine,
    )
    stream_report = ImportReport(source_id=source.source_id, format_id=source.format_id)
    pending_meta: list[tuple[int, str, str, str, tuple]] = []
    pending_private: list[tuple[int, bytes]] = []
    pending_captures: dict[int, CapturedOriginal] = {}
    batch_index = 0
    failure: Exception | None = None

    def _flush(conn) -> None:
        nonlocal result
        for request_id, row_site, row_source, row_fp, values in pending_meta:
            repositories.update_request_metadata_guarded(
                conn,
                request_id=request_id,
                site_id=row_site,
                source_id=row_source,
                file_fingerprint=row_fp,
                values=values,
            )
            result.rows_enriched += 1
        for request_id, aad in pending_private:
            assert private_key is not None
            nonce, ciphertext = _private.encrypt_captured(
                pending_captures[request_id], key=private_key, aad=aad
            )
            if _private.store_private_ip(
                conn, request_id=request_id, nonce=nonce, ciphertext=ciphertext
            ):
                result.originals_captured += 1
        pending_meta.clear()
        pending_private.clear()
        pending_captures.clear()

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
            offset = getattr(item, "byte_offset", None)
            stored = _stored_at(int(offset)) if offset is not None else None
            if isinstance(item, CombinedRecord) and stored is not None:
                if _core_tuple(item) != (
                    stored["ts_utc"],
                    stored["method"],
                    stored["path"],
                    stored["status"],
                    stored["bytes"],
                    stored["referer_host"],
                    stored["user_agent"],
                    stored["client_pseudonym"],
                    stored["duration_ms"],
                ):
                    result.rows_mismatched += 1
                    result.mismatch_by_reason[REPROCESS_MISMATCH] = (
                        result.mismatch_by_reason.get(REPROCESS_MISMATCH, 0) + 1
                    )
                    continue
                result.rows_verified += 1
                wanted = _metadata_tuple(item, policy)
                current = (
                    stored["format_id"],
                    stored["http_version"],
                    stored["server_host"],
                    stored["referer_scheme"],
                    stored["referer_path"],
                    stored["cache_status"],
                    stored["mime_type"],
                    stored["tls_protocol"],
                    stored["request_time_ms"],
                    stored["upstream_time_ms"],
                    stored["upstream_count"],
                    stored["policy_version"],
                )
                if wanted != current:
                    pending_meta.append(
                        (
                            int(stored["id"]),
                            str(stored["site_id"]),
                            str(stored["source_id"]),
                            str(stored["file_fingerprint"]),
                            wanted,
                        )
                    )
                if (
                    capture_originals
                    and isinstance(original, CapturedOriginal)
                    and private_key is not None
                ):
                    # The AAD comes from the validated STORED identity,
                    # never the caller-supplied site: ciphertext for one
                    # event/site cannot be attached to another.
                    aad = _private.build_aad(
                        site_id=str(stored["site_id"]),
                        source_id=str(stored["source_id"]),
                        file_fingerprint=str(stored["file_fingerprint"]),
                        byte_offset=int(stored["byte_offset"]),
                    )
                    pending_private.append((int(stored["id"]), aad))
                    pending_captures[int(stored["id"])] = original
                if len(pending_meta) + len(pending_private) >= batch_size:
                    batch_index += 1
                    with writer_transaction(db_path, lock_timeout_s=lock_timeout_s) as conn:
                        _flush(conn)
                    if after_batch is not None:
                        after_batch(batch_index)
            elif stored is not None:
                if isinstance(item, HostSkipped):
                    result.rows_skipped_foreign += 1
                else:
                    result.rows_unparseable += 1
        if pending_meta or pending_private:
            batch_index += 1
            with writer_transaction(db_path, lock_timeout_s=lock_timeout_s) as conn:
                _flush(conn)
            if after_batch is not None:
                after_batch(batch_index)
    except Exception as exc:  # noqa: BLE001 - partial batches stay, then re-raised
        failure = exc

    consumed = stream_report.consumed_sha256
    try:
        size_after = resolved.stat().st_size
    except OSError:
        size_after = None
    size_changed = size_after is None or size_after != size_before
    content_mismatch = False
    if failure is None and consumed is not None:
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
    result.source_changed = size_changed or content_mismatch
    result.consumed_sha256 = consumed
    warnings: list[str] = []
    if result.source_changed:
        warnings.append(REPROCESS_SOURCE_CHANGED)
    if content_mismatch:
        warnings.append(SOURCE_CONTENT_MISMATCH_CODE)
    if failure is not None:
        result.status = "failed"
        warnings.append(failure_code(failure))
    if result.status != REPROCESS_REJECTED_STATUS:
        result.error_summary = _sanitize_reprocess_summary("; ".join(warnings) or None)
    # A rejected run keeps the fixed mismatch code set at the binding
    # check: the operation never started, so there is nothing to warn.
    if failure is not None:
        raise failure
    return result
