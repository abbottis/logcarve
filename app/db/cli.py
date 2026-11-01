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
        from app.db.private import PrivateUnavailable
        from app.db.repositories import SourceBindingError

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
            )
        except PrivateUnavailable as exc:
            print(f"error: {exc.code}", file=sys.stderr)
            return 1
        except SourceBindingError as exc:
            print(f"error: {exc.code}", file=sys.stderr)
            return 1
        entry = _result_payload(result)
        entry["file_index"] = index
        entry["format_id"] = custom_format.format_id if custom_format is not None else args.format
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
            )
        except PrivateUnavailable as exc:
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
    reprocess.set_defaults(func=cmd_reprocess)

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
