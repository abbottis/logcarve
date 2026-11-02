"""Local administrative import CLI (T3).

All operations target explicitly configured source IDs and a local
database file. The HMAC key always comes from the ``HMAC_KEY``
environment variable, never from an argument or the shell history.
There are no HTTP routes, no model calls and no remote access here.
"""

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from app.db.backup import backup_database, restore_database, rotate_backups
from app.db.database import connect
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.db.reprocess import run_reprocess
from app.db.retention import apply_retention
from app.ingestion.combined import (
    APACHE_COMBINED,
    APACHE_VHOST_COMBINED,
    AUTO,
    COMMON,
    CUSTOM,
    NGINX_COMBINED,
    NGINX_EXTENDED,
    Limits,
)
from app.ingestion.custom import CustomFormatError, load_spec_file
from app.ingestion.gzipio import GzipLimits
from app.ingestion.sources import HostFilter, SourceConfig

_FORMAT_CHOICES = (
    NGINX_COMBINED,
    APACHE_COMBINED,
    COMMON,
    APACHE_VHOST_COMBINED,
    NGINX_EXTENDED,
    AUTO,
    CUSTOM,
)


def _hmac_key() -> bytes:
    key = os.environ.get("HMAC_KEY", "")
    if not key:
        raise SystemExit("error: HMAC_KEY environment variable must be set")
    return key.encode("utf-8")


def _utcnow() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _result_payload(result) -> dict:
    return {
        "import_id": result.import_id,
        "status": result.status,
        "lines_total": result.lines_total,
        "lines_accepted": result.lines_accepted,
        "lines_rejected": result.lines_rejected,
        "records_inserted": result.records_inserted,
        "records_replayed": result.records_replayed,
        "records_skipped_foreign": result.records_skipped_foreign,
        "is_gzip": result.is_gzip,
        "gzip_members": result.gzip_members,
        "source_changed": result.source_changed,
        "error_summary": result.error_summary,
        "originals_captured": result.originals_captured,
    }


def _split_hosts(values: list[str] | None) -> list[str]:
    hosts: list[str] = []
    for value in values or []:
        hosts.extend(part.strip() for part in value.split(",") if part.strip())
    return hosts


def _country_lookup(args: argparse.Namespace):
    """Country lookup for import/reprocess from flag or environment.

    ``--geoip-db`` wins; otherwise ``GEOIP_DB_PATH``; empty means
    unconfigured (fixed ``unavailable`` markers). The handle opens
    read-only and never downloads anything.
    """
    from app.ingestion.geoip import CountryLookup

    configured = args.geoip_db
    if configured is None:
        configured = os.environ.get("GEOIP_DB_PATH", "")
    configured = (configured or "").strip()
    if not configured:
        return CountryLookup.unavailable()
    return CountryLookup.open(configured)


def _resolve_explicit_hosts(
    *,
    site_hostname: str,
    host_filter: list[str] | None,
    host_alias: list[str] | None,
    vhost_bearing: bool,
) -> list[str]:
    """Combine ``--host-filter`` and ``--host-alias`` into one host set.

    ``--host-alias`` extends the configured primary (``site_hostname``);
    ``--host-filter`` explicitly supplies a replacement set, so the
    primary is NOT added then (aliases still append: every explicitly
    named host is honored). With neither flag, host-bearing formats
    (vhost/extended/auto, or a custom mapping with a ``vhost`` group)
    fall back to the site hostname so foreign hosts can never be
    silently counted as this site; plain formats stay unfiltered.
    Matching is case-insensitive upstream (``HostFilter`` normalizes),
    so duplicates fold here.
    """
    filters = _split_hosts(host_filter)
    aliases = _split_hosts(host_alias)
    if filters:
        seen: set[str] = set()
        explicit: list[str] = []
        for host in [*filters, *aliases]:
            key = host.lower()
            if key not in seen:
                seen.add(key)
                explicit.append(host)
        return explicit
    if aliases:
        combined = [site_hostname, *aliases]
        seen = set()
        deduped = []
        for host in combined:
            key = host.lower()
            if key not in seen:
                seen.add(key)
                deduped.append(host)
        return deduped
    if vhost_bearing:
        return [site_hostname]
    return []


def cmd_import(args: argparse.Namespace) -> int:
    custom_format = None
    if args.format == CUSTOM or args.format_config is not None:
        if args.format_config is None:
            print("error: --format custom requires --format-config", file=sys.stderr)
            return 2
        try:
            custom_format = load_spec_file(Path(args.format_config))
        except CustomFormatError as exc:
            print(f"error: invalid custom format ({exc.code})", file=sys.stderr)
            return 2
    has_custom_vhost = custom_format is not None and "vhost" in custom_format.pattern.groupindex
    explicit_hosts = _resolve_explicit_hosts(
        site_hostname=args.site_hostname,
        host_filter=args.host_filter,
        host_alias=args.host_alias,
        vhost_bearing=(
            args.format in (APACHE_VHOST_COMBINED, NGINX_EXTENDED, AUTO) or has_custom_vhost
        ),
    )
    host_filter: HostFilter | None = None
    if explicit_hosts:
        try:
            host_filter = HostFilter(explicit_hosts)
        except ValueError:
            print("error: invalid host filter", file=sys.stderr)
            return 2
    allowed_hosts = sorted(host_filter.hosts) if host_filter is not None else None
    try:
        limits = Limits(
            max_line_bytes=args.max_line_bytes,
            max_diagnostics=args.max_diagnostics,
        )
        gzip_limits = GzipLimits(
            max_compressed_bytes=args.max_compressed_bytes,
            max_uncompressed_bytes=args.max_uncompressed_bytes,
            max_compression_ratio=args.max_compression_ratio,
            max_gzip_members=args.max_gzip_members,
        )
    except ValueError:
        print("error: invalid resource limits", file=sys.stderr)
        return 2
    if (
        isinstance(args.batch_size, bool)
        or not isinstance(args.batch_size, int)
        or args.batch_size < 1
    ):
        print("error: invalid batch size", file=sys.stderr)
        return 2
    if (
        isinstance(args.autodetect_sample_lines, bool)
        or not isinstance(args.autodetect_sample_lines, int)
        or not 1 <= args.autodetect_sample_lines <= 1024
    ):
        print("error: invalid autodetect sample size", file=sys.stderr)
        return 2
    payloads: list[dict] = []
    overall = "completed"
    from app.db.private import PrivateUnavailable
    from app.db.repositories import SourceBindingError
    from app.ingestion.geoip import GeoipError

    with _country_lookup(args) as lookup:
        for index, relative in enumerate(args.path):
            try:
                source = SourceConfig(
                    source_id=args.source_id,
                    format_id=args.format,
                    allowed_root=Path(args.root),
                    relative_path=relative,
                    allowed_hosts=allowed_hosts,
                )
            except ValueError:
                print("error: invalid source configuration", file=sys.stderr)
                return 2
            try:
                result = run_import(
                    Path(args.db),
                    source=source,
                    site_id=args.site_id,
                    site_name=args.site_name,
                    site_hostname=args.site_hostname,
                    server_type=args.server_type,
                    path_alias=relative,
                    hmac_key=_hmac_key(),
                    batch_size=args.batch_size,
                    limits=limits,
                    host_filter=host_filter,
                    custom_format=custom_format,
                    gzip_limits=gzip_limits,
                    autodetect_sample_lines=args.autodetect_sample_lines,
                    capture_originals=args.capture_original_ips,
                    country_lookup=lookup,
                    geoip_required=args.geoip_required,
                )
            except PrivateUnavailable as exc:
                print(f"error: {exc.code}", file=sys.stderr)
                return 1
            except GeoipError as exc:
                print(f"error: {exc.code}", file=sys.stderr)
                return 1
            except SourceBindingError as exc:
                print(f"error: {exc.code}", file=sys.stderr)
                return 1
            entry = _result_payload(result)
            entry["file_index"] = index
            entry["format_id"] = (
                custom_format.format_id if custom_format is not None else args.format
            )
            entry["geoip_available"] = result.geoip_available
            entry["geoip_source"] = result.geoip_source
            entry["geoip_release"] = result.geoip_release
            payloads.append(entry)
            if result.status != "completed":
                overall = result.status
    if len(payloads) == 1:
        print(json.dumps(payloads[0]))
    else:
        print(json.dumps({"status": overall, "files": payloads}))
    return 0 if overall == "completed" else 1


def cmd_reprocess(args: argparse.Namespace) -> int:
    """Enrich stored rows from their approved read-only source files."""
    from app.db.private import PrivateUnavailable
    from app.ingestion.geoip import GeoipError

    custom_format = None
    if args.format == CUSTOM or args.format_config is not None:
        if args.format_config is None:
            print("error: --format custom requires --format-config", file=sys.stderr)
            return 2
        try:
            custom_format = load_spec_file(Path(args.format_config))
        except CustomFormatError as exc:
            print(f"error: invalid custom format ({exc.code})", file=sys.stderr)
            return 2
    has_custom_vhost = custom_format is not None and "vhost" in custom_format.pattern.groupindex
    explicit_hosts = _resolve_explicit_hosts(
        site_hostname=args.site_hostname,
        host_filter=args.host_filter,
        host_alias=args.host_alias,
        vhost_bearing=(
            args.format in (APACHE_VHOST_COMBINED, NGINX_EXTENDED, AUTO) or has_custom_vhost
        ),
    )
    host_filter: HostFilter | None = None
    if explicit_hosts:
        try:
            host_filter = HostFilter(explicit_hosts)
        except ValueError:
            print("error: invalid host filter", file=sys.stderr)
            return 2
    try:
        limits = Limits(
            max_line_bytes=args.max_line_bytes,
            max_diagnostics=args.max_diagnostics,
        )
        gzip_limits = GzipLimits(
            max_compressed_bytes=args.max_compressed_bytes,
            max_uncompressed_bytes=args.max_uncompressed_bytes,
            max_compression_ratio=args.max_compression_ratio,
            max_gzip_members=args.max_gzip_members,
        )
    except ValueError:
        print("error: invalid resource limits", file=sys.stderr)
        return 2
    if (
        isinstance(args.batch_size, bool)
        or not isinstance(args.batch_size, int)
        or args.batch_size < 1
    ):
        print("error: invalid batch size", file=sys.stderr)
        return 2
    if (
        isinstance(args.autodetect_sample_lines, bool)
        or not isinstance(args.autodetect_sample_lines, int)
        or not 1 <= args.autodetect_sample_lines <= 1024
    ):
        print("error: invalid autodetect sample size", file=sys.stderr)
        return 2
    payloads: list[dict] = []
    overall = "completed"
    with _country_lookup(args) as lookup:
        for index, relative in enumerate(args.path):
            try:
                source = SourceConfig(
                    source_id=args.source_id,
                    format_id=args.format,
                    allowed_root=Path(args.root),
                    relative_path=relative,
                    allowed_hosts=sorted(host_filter.hosts) if host_filter is not None else None,
                )
            except ValueError:
                print("error: invalid source configuration", file=sys.stderr)
                return 2
            try:
                result = run_reprocess(
                    Path(args.db),
                    source=source,
                    site_id=args.site_id,
                    site_hostname=args.site_hostname,
                    server_type=args.server_type,
                    hmac_key=_hmac_key(),
                    batch_size=args.batch_size,
                    limits=limits,
                    host_filter=host_filter,
                    custom_format=custom_format,
                    gzip_limits=gzip_limits,
                    autodetect_sample_lines=args.autodetect_sample_lines,
                    capture_originals=args.capture_original_ips,
                    country_lookup=lookup,
                    geoip_required=args.geoip_required,
                )
            except PrivateUnavailable as exc:
                print(f"error: {exc.code}", file=sys.stderr)
                return 1
            except GeoipError as exc:
                print(f"error: {exc.code}", file=sys.stderr)
                return 1
        entry = {
            "file_index": index,
            "status": result.status,
            "file_fingerprint": result.file_fingerprint,
            "rows_matched": result.rows_matched,
            "rows_verified": result.rows_verified,
            "rows_enriched": result.rows_enriched,
            "rows_mismatched": result.rows_mismatched,
            "rows_unparseable": result.rows_unparseable,
            "rows_skipped_foreign": result.rows_skipped_foreign,
            "originals_captured": result.originals_captured,
            "source_changed": result.source_changed,
            "error_summary": result.error_summary,
        }
        payloads.append(entry)
        if result.status != "completed":
            overall = result.status
    if len(payloads) == 1:
        print(json.dumps(payloads[0]))
    else:
        print(json.dumps({"status": overall, "files": payloads}))
    return 0 if overall == "completed" else 1


def _follow_payload(result) -> dict:
    """Follow JSON payload: counts and fixed codes only, never raw bytes."""
    return {
        "status": result.status,
        "source_id": result.source_id,
        "polls": result.polls,
        "empty_polls": result.empty_polls,
        "generations_started": result.generations_started,
        "active_generation": result.active_generation,
        "sealed_generations": result.sealed_generations,
        "drain_truncated": result.drain_truncated,
        "lines_accepted": result.lines_accepted,
        "lines_rejected": result.lines_rejected,
        "records_inserted": result.records_inserted,
        "records_replayed": result.records_replayed,
        "records_skipped_foreign": result.lines_skipped_foreign,
        "originals_captured": result.originals_captured,
        "originals_skipped_mismatch": result.originals_skipped_mismatch,
        "rejected_by_reason": result.rejected_by_reason,
        "error_summary": result.error_summary,
        "guidance": result.guidance,
    }


def _archive_payload(result) -> dict:
    """Archive-replay JSON payload: counts and fixed codes only."""
    return {
        "status": result.status,
        "source_id": result.source_id,
        "archive_path": result.archive_path,
        "generation_seq": result.generation_seq,
        "lines_accepted": result.lines_accepted,
        "lines_rejected": result.lines_rejected,
        "records_inserted": result.records_inserted,
        "records_replayed": result.records_replayed,
        "records_skipped_foreign": result.lines_skipped_foreign,
        "originals_captured": result.originals_captured,
        "originals_skipped_mismatch": result.originals_skipped_mismatch,
        "rejected_by_reason": result.rejected_by_reason,
        "error_summary": result.error_summary,
        "guidance": result.guidance,
    }


def _follow_source_args(parser) -> None:
    """Shared source/binding arguments for follow and replay-archive."""
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--format", required=True, choices=list(_FORMAT_CHOICES))
    parser.add_argument("--format-config", default=None, help="Validated custom-format JSON file")
    parser.add_argument("--root", required=True, help="Approved source root directory")
    parser.add_argument(
        "--host-filter",
        action="append",
        default=None,
        help="Explicit replacement host set (repeatable/comma-separated); --site-hostname is NOT added",
    )
    parser.add_argument(
        "--host-alias",
        action="append",
        default=None,
        help="Extra hosts extending --site-hostname (repeatable/comma-separated)",
    )
    parser.add_argument("--site-id", default="default")
    parser.add_argument("--site-name", default="Example site")
    parser.add_argument("--site-hostname", default="example.org")
    parser.add_argument("--server-type", default="nginx")
    parser.add_argument("--batch-size", type=int, default=1000)
    parser.add_argument("--max-line-bytes", type=int, default=65536)
    parser.add_argument("--max-diagnostics", type=int, default=20)
    parser.add_argument("--max-compressed-bytes", type=int, default=1073741824)
    parser.add_argument("--max-uncompressed-bytes", type=int, default=1073741824)
    parser.add_argument("--max-compression-ratio", type=float, default=100.0)
    parser.add_argument("--max-gzip-members", type=int, default=64)
    parser.add_argument("--autodetect-sample-lines", type=int, default=32)
    parser.add_argument(
        "--capture-original-ips",
        action="store_true",
        default=False,
        help="Store validated client addresses encrypted (requires ORIGINAL_IP_KEY)",
    )
    parser.add_argument(
        "--geoip-db",
        default=None,
        help="Mounted offline country database (DB-IP Country Lite MMDB);"
        " defaults to GEOIP_DB_PATH; empty stores unavailable markers",
    )
    parser.add_argument(
        "--geoip-required",
        action="store_true",
        default=False,
        help="Fail before any write when the country database is missing/unreadable",
    )


def _follow_common_kwargs(args: argparse.Namespace):
    """Validate shared follow flags; return kwargs or an exit code."""
    from app.db.follow import DEFAULT_MAX_BYTES_PER_POLL

    custom_format = None
    if args.format == CUSTOM or args.format_config is not None:
        if args.format_config is None:
            print("error: --format custom requires --format-config", file=sys.stderr)
            return 2, None
        try:
            custom_format = load_spec_file(Path(args.format_config))
        except CustomFormatError as exc:
            print(f"error: invalid custom format ({exc.code})", file=sys.stderr)
            return 2, None
    has_custom_vhost = custom_format is not None and "vhost" in custom_format.pattern.groupindex
    explicit_hosts = _resolve_explicit_hosts(
        site_hostname=args.site_hostname,
        host_filter=args.host_filter,
        host_alias=args.host_alias,
        vhost_bearing=(
            args.format in (APACHE_VHOST_COMBINED, NGINX_EXTENDED, AUTO) or has_custom_vhost
        ),
    )
    host_filter = None
    if explicit_hosts:
        try:
            host_filter = HostFilter(explicit_hosts)
        except ValueError:
            print("error: invalid host filter", file=sys.stderr)
            return 2, None
    try:
        limits = Limits(
            max_line_bytes=args.max_line_bytes,
            max_diagnostics=args.max_diagnostics,
        )
        gzip_limits = GzipLimits(
            max_compressed_bytes=args.max_compressed_bytes,
            max_uncompressed_bytes=args.max_uncompressed_bytes,
            max_compression_ratio=args.max_compression_ratio,
            max_gzip_members=args.max_gzip_members,
        )
    except ValueError:
        print("error: invalid resource limits", file=sys.stderr)
        return 2, None
    if (
        isinstance(args.batch_size, bool)
        or not isinstance(args.batch_size, int)
        or args.batch_size < 1
    ):
        print("error: invalid batch size", file=sys.stderr)
        return 2, None
    if (
        isinstance(args.autodetect_sample_lines, bool)
        or not isinstance(args.autodetect_sample_lines, int)
        or not 1 <= args.autodetect_sample_lines <= 1024
    ):
        print("error: invalid autodetect sample size", file=sys.stderr)
        return 2, None
    return 0, {
        "custom_format": custom_format,
        "host_filter": host_filter,
        "limits": limits,
        "gzip_limits": gzip_limits,
        "max_bytes_default": DEFAULT_MAX_BYTES_PER_POLL,
    }


def cmd_follow(args: argparse.Namespace) -> int:
    from app.db import follow as follow_mod
    from app.db.private import PrivateUnavailable
    from app.db.repositories import SourceBindingError
    from app.ingestion.geoip import GeoipError

    code, common = _follow_common_kwargs(args)
    if code != 0:
        return code
    if (
        isinstance(args.max_polls, bool)
        or not isinstance(args.max_polls, int)
        or not 1 <= args.max_polls <= 100000
    ):
        print("error: invalid max polls", file=sys.stderr)
        return 2
    try:
        poll_interval = float(args.poll_interval_s)
    except (TypeError, ValueError):
        print("error: invalid poll interval", file=sys.stderr)
        return 2
    if not 0 <= poll_interval <= 3600:
        print("error: invalid poll interval", file=sys.stderr)
        return 2
    if (
        isinstance(args.max_bytes_per_poll, bool)
        or not isinstance(args.max_bytes_per_poll, int)
        or not 1024 <= args.max_bytes_per_poll <= 1024**3
    ):
        print("error: invalid max bytes per poll", file=sys.stderr)
        return 2
    if (
        isinstance(args.max_writer_retries, bool)
        or not isinstance(args.max_writer_retries, int)
        or not 0 <= args.max_writer_retries <= 100
    ):
        print("error: invalid max writer retries", file=sys.stderr)
        return 2
    try:
        source = SourceConfig(
            source_id=args.source_id,
            format_id=args.format,
            allowed_root=Path(args.root),
            relative_path=args.path,
            allowed_hosts=(
                sorted(common["host_filter"].hosts) if common["host_filter"] is not None else None
            ),
        )
    except ValueError:
        print("error: invalid source configuration", file=sys.stderr)
        return 2
    try:
        with _country_lookup(args) as lookup:
            result = follow_mod.run_follow(
                Path(args.db),
                source=source,
                site_id=args.site_id,
                site_name=args.site_name,
                site_hostname=args.site_hostname,
                server_type=args.server_type,
                path_alias=args.path,
                hmac_key=_hmac_key(),
                batch_size=args.batch_size,
                max_polls=args.max_polls,
                poll_interval_s=poll_interval,
                max_bytes_per_poll=args.max_bytes_per_poll,
                capture_originals=args.capture_original_ips,
                country_lookup=lookup,
                geoip_required=args.geoip_required,
                host_filter=common["host_filter"],
                custom_format=common["custom_format"],
                limits=common["limits"],
                gzip_limits=common["gzip_limits"],
                max_writer_retries=args.max_writer_retries,
                fresh_start=args.fresh_start,
            )
    except follow_mod.FollowRefused as exc:
        print(f"error: {exc.code}: {exc.guidance}", file=sys.stderr)
        return 2
    except PrivateUnavailable as exc:
        print(f"error: {exc.code}", file=sys.stderr)
        return 1
    except GeoipError as exc:
        print(f"error: {exc.code}", file=sys.stderr)
        return 1
    except SourceBindingError as exc:
        print(f"error: {exc.code}", file=sys.stderr)
        return 1
    except (CustomFormatError, ValueError) as exc:
        print(f"error: invalid follow configuration ({exc})", file=sys.stderr)
        return 2
    print(json.dumps(_follow_payload(result)))
    return 0 if result.status in ("completed", "cancelled") else 1


def cmd_replay_archive(args: argparse.Namespace) -> int:
    from app.db import follow as follow_mod
    from app.db.private import PrivateUnavailable
    from app.db.repositories import SourceBindingError
    from app.ingestion.geoip import GeoipError

    code, common = _follow_common_kwargs(args)
    if code != 0:
        return code
    generation_seq = None
    if args.generation_seq is not None:
        if (
            isinstance(args.generation_seq, bool)
            or not isinstance(args.generation_seq, int)
            or args.generation_seq < 1
        ):
            print("error: invalid generation sequence", file=sys.stderr)
            return 2
        generation_seq = args.generation_seq
    try:
        # Validated for intent only: the replay reads the archive, while
        # --path names the live file the generation followed.
        _live_source = SourceConfig(
            source_id=args.source_id,
            format_id=args.format,
            allowed_root=Path(args.root),
            relative_path=args.path,
            allowed_hosts=(
                sorted(common["host_filter"].hosts) if common["host_filter"] is not None else None
            ),
        )
        archive = SourceConfig(
            source_id=args.source_id,
            format_id=args.format,
            allowed_root=Path(args.root),
            relative_path=args.archive_path,
            allowed_hosts=(
                sorted(common["host_filter"].hosts) if common["host_filter"] is not None else None
            ),
        )
    except ValueError:
        print("error: invalid source configuration", file=sys.stderr)
        return 2
    try:
        with _country_lookup(args) as lookup:
            result = follow_mod.replay_archive(
                Path(args.db),
                archive=archive,
                site_id=args.site_id,
                site_name=args.site_name,
                site_hostname=args.site_hostname,
                server_type=args.server_type,
                path_alias=args.archive_path,
                hmac_key=_hmac_key(),
                batch_size=args.batch_size,
                generation_seq=generation_seq,
                capture_originals=args.capture_original_ips,
                country_lookup=lookup,
                geoip_required=args.geoip_required,
                host_filter=common["host_filter"],
                custom_format=common["custom_format"],
                limits=common["limits"],
                gzip_limits=common["gzip_limits"],
            )
    except follow_mod.FollowRefused as exc:
        print(f"error: {exc.code}: {exc.guidance}", file=sys.stderr)
        return 2
    except PrivateUnavailable as exc:
        print(f"error: {exc.code}", file=sys.stderr)
        return 1
    except GeoipError as exc:
        print(f"error: {exc.code}", file=sys.stderr)
        return 1
    except SourceBindingError as exc:
        print(f"error: {exc.code}", file=sys.stderr)
        return 1
    except (CustomFormatError, ValueError) as exc:
        print(f"error: invalid replay configuration ({exc})", file=sys.stderr)
        return 2
    print(json.dumps(_archive_payload(result)))
    if result.status == "completed":
        return 0
    return 1 if result.status == "failed" else 2


def cmd_retention(args: argparse.Namespace) -> int:
    migrate(Path(args.db))
    conn = connect(Path(args.db))
    try:
        with conn:
            deleted = apply_retention(conn, days=args.days, now=datetime.now(UTC))
    finally:
        conn.close()
    print(json.dumps({"deleted": deleted, "days": args.days}))
    return 0


def cmd_backup(args: argparse.Namespace) -> int:
    dest = Path(args.dest_dir) / f"{Path(args.db).stem}-backup-{_utcnow()}.sqlite3"
    path = backup_database(Path(args.db), dest)
    removed: list[str] = []
    if args.keep is not None:
        removed = [
            str(p)
            for p in rotate_backups(Path(args.dest_dir), keep=args.keep, db_stem=Path(args.db).stem)
        ]
    print(json.dumps({"backup": str(path), "rotated_out": removed}))
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    path = restore_database(Path(args.backup), Path(args.dest))
    if args.retention_days is not None:
        conn = connect(path)
        try:
            with conn:
                deleted = apply_retention(conn, days=args.retention_days, now=datetime.now(UTC))
        finally:
            conn.close()
    else:
        deleted = 0
    print(json.dumps({"restored": str(path), "retention_reapplied_deleted": deleted}))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logcarve-import", description="Local administrative log import"
    )
    parser.add_argument("--db", required=True, help="SQLite database file")
    sub = parser.add_subparsers(dest="command", required=True)

    importer = sub.add_parser("import", help="Import configured source files in order")
    importer.add_argument("--source-id", required=True)
    importer.add_argument("--format", required=True, choices=list(_FORMAT_CHOICES))
    importer.add_argument("--format-config", default=None, help="Validated custom-format JSON file")
    importer.add_argument("--root", required=True, help="Approved source root directory")
    importer.add_argument(
        "--path",
        required=True,
        action="append",
        help="Relative path inside the approved root (repeatable file series)",
    )
    importer.add_argument(
        "--host-filter",
        action="append",
        default=None,
        help="Explicit replacement host set (repeatable/comma-separated); --site-hostname is NOT added",
    )
    importer.add_argument(
        "--host-alias",
        action="append",
        default=None,
        help="Extra hosts extending --site-hostname (repeatable/comma-separated)",
    )
    importer.add_argument("--site-id", default="default")
    importer.add_argument("--site-name", default="Example site")
    importer.add_argument("--site-hostname", default="example.org")
    importer.add_argument("--server-type", default="nginx")
    importer.add_argument("--batch-size", type=int, default=1000)
    importer.add_argument("--max-line-bytes", type=int, default=65536)
    importer.add_argument("--max-diagnostics", type=int, default=20)
    importer.add_argument("--max-compressed-bytes", type=int, default=1073741824)
    importer.add_argument("--max-uncompressed-bytes", type=int, default=1073741824)
    importer.add_argument("--max-compression-ratio", type=float, default=100.0)
    importer.add_argument("--max-gzip-members", type=int, default=64)
    importer.add_argument("--autodetect-sample-lines", type=int, default=32)
    importer.add_argument(
        "--capture-original-ips",
        action="store_true",
        default=False,
        help="Store validated client addresses encrypted (requires ORIGINAL_IP_KEY)",
    )
    importer.add_argument(
        "--geoip-db",
        default=None,
        help="Mounted offline country database (DB-IP Country Lite MMDB);"
        " defaults to GEOIP_DB_PATH; empty stores unavailable markers",
    )
    importer.add_argument(
        "--geoip-required",
        action="store_true",
        default=False,
        help="Fail before any write when the country database is missing/unreadable",
    )
    importer.set_defaults(func=cmd_import)

    reprocess = sub.add_parser(
        "reprocess", help="Enrich stored rows from approved read-only sources (no new rows)"
    )
    reprocess.add_argument("--source-id", required=True)
    reprocess.add_argument("--format", required=True, choices=list(_FORMAT_CHOICES))
    reprocess.add_argument(
        "--format-config", default=None, help="Validated custom-format JSON file"
    )
    reprocess.add_argument("--root", required=True, help="Approved source root directory")
    reprocess.add_argument(
        "--path",
        required=True,
        action="append",
        help="Relative path inside the approved root (repeatable file series)",
    )
    reprocess.add_argument(
        "--host-filter",
        action="append",
        default=None,
        help="Explicit replacement host set (repeatable/comma-separated); --site-hostname is NOT added",
    )
    reprocess.add_argument(
        "--host-alias",
        action="append",
        default=None,
        help="Extra hosts extending --site-hostname (repeatable/comma-separated)",
    )
    reprocess.add_argument("--site-id", default="default")
    reprocess.add_argument("--site-hostname", default="example.org")
    reprocess.add_argument("--server-type", default="nginx")
    reprocess.add_argument("--batch-size", type=int, default=1000)
    reprocess.add_argument("--max-line-bytes", type=int, default=65536)
    reprocess.add_argument("--max-diagnostics", type=int, default=20)
    reprocess.add_argument("--max-compressed-bytes", type=int, default=1073741824)
    reprocess.add_argument("--max-uncompressed-bytes", type=int, default=1073741824)
    reprocess.add_argument("--max-compression-ratio", type=float, default=100.0)
    reprocess.add_argument("--max-gzip-members", type=int, default=64)
    reprocess.add_argument("--autodetect-sample-lines", type=int, default=32)
    reprocess.add_argument(
        "--capture-original-ips",
        action="store_true",
        default=False,
        help="Store validated client addresses encrypted (requires ORIGINAL_IP_KEY)",
    )
    reprocess.add_argument(
        "--geoip-db",
        default=None,
        help="Mounted offline country database (DB-IP Country Lite MMDB);"
        " defaults to GEOIP_DB_PATH; empty stores unavailable markers",
    )
    reprocess.add_argument(
        "--geoip-required",
        action="store_true",
        default=False,
        help="Fail before any write when the country database is missing/unreadable",
    )
    reprocess.set_defaults(func=cmd_reprocess)

    follow = sub.add_parser(
        "follow",
        help="Opt-in tail of one source file with durable checkpoints (bounded polls)",
    )
    _follow_source_args(follow)
    follow.add_argument("--path", required=True, help="Relative path inside the approved root")
    follow.add_argument("--max-polls", type=int, default=60)
    follow.add_argument("--poll-interval-s", type=float, default=1.0)
    follow.add_argument("--max-bytes-per-poll", type=int, default=8388608)
    follow.add_argument("--max-writer-retries", type=int, default=5)
    follow.add_argument(
        "--fresh-start",
        action="store_true",
        default=False,
        help="Abandon taint/ambiguity guards and follow from offset 0 (may duplicate)",
    )
    follow.set_defaults(func=cmd_follow)

    replay_archive = sub.add_parser(
        "replay-archive",
        help="Replay a rotated archive under its sealed follow generation",
    )
    _follow_source_args(replay_archive)
    replay_archive.add_argument(
        "--path", required=True, help="Live relative path the generation followed"
    )
    replay_archive.add_argument(
        "--archive-path",
        required=True,
        help="Rotated archive relative path inside the approved root",
    )
    replay_archive.add_argument(
        "--generation-seq",
        type=int,
        default=None,
        help="Sealed generation (default: latest sealed)",
    )
    replay_archive.set_defaults(func=cmd_replay_archive)

    retention = sub.add_parser("retention", help="Delete owned events older than N days (UTC)")
    retention.add_argument("--days", type=int, default=30)
    retention.set_defaults(func=cmd_retention)

    backup = sub.add_parser("backup", help="Consistent online backup with 0600 permissions")
    backup.add_argument("--dest-dir", required=True)
    backup.add_argument("--keep", type=int, default=None, help="Rotate: keep newest N backups")
    backup.set_defaults(func=cmd_backup)

    restore = sub.add_parser("restore", help="Restore a backup into an isolated path")
    restore.add_argument("--backup", required=True)
    restore.add_argument("--dest", required=True, help="Isolated destination, never a live DB")
    restore.add_argument("--retention-days", type=int, default=None)
    restore.set_defaults(func=cmd_restore)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - top-level CLI boundary maps errors to exit 1
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
