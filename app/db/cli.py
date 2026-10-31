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
from app.db.retention import apply_retention
from app.ingestion.combined import Limits
from app.ingestion.sources import SourceConfig


def _hmac_key() -> bytes:
    key = os.environ.get("HMAC_KEY", "")
    if not key:
        raise SystemExit("error: HMAC_KEY environment variable must be set")
    return key.encode("utf-8")


def _utcnow() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def cmd_import(args: argparse.Namespace) -> int:
    source = SourceConfig(
        source_id=args.source_id,
        format_id=args.format,
        allowed_root=Path(args.root),
        relative_path=args.path,
    )
    result = run_import(
        Path(args.db),
        source=source,
        site_id=args.site_id,
        site_name=args.site_name,
        site_hostname=args.site_hostname,
        server_type=args.server_type,
        path_alias=args.path,
        hmac_key=_hmac_key(),
        batch_size=args.batch_size,
        limits=Limits(
            max_line_bytes=args.max_line_bytes,
            max_diagnostics=args.max_diagnostics,
        ),
    )
    print(
        json.dumps(
            {
                "import_id": result.import_id,
                "status": result.status,
                "lines_total": result.lines_total,
                "lines_accepted": result.lines_accepted,
                "lines_rejected": result.lines_rejected,
                "records_inserted": result.records_inserted,
                "records_replayed": result.records_replayed,
                "source_changed": result.source_changed,
                "error_summary": result.error_summary,
            }
        )
    )
    return 0 if result.status == "completed" else 1


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

    importer = sub.add_parser("import", help="Import one configured source file")
    importer.add_argument("--source-id", required=True)
    importer.add_argument("--format", required=True, choices=["nginx_combined", "apache_combined"])
    importer.add_argument("--root", required=True, help="Approved source root directory")
    importer.add_argument("--path", required=True, help="Relative path inside the approved root")
    importer.add_argument("--site-id", default="default")
    importer.add_argument("--site-name", default="Example site")
    importer.add_argument("--site-hostname", default="example.org")
    importer.add_argument("--server-type", default="nginx")
    importer.add_argument("--batch-size", type=int, default=1000)
    importer.add_argument("--max-line-bytes", type=int, default=65536)
    importer.add_argument("--max-diagnostics", type=int, default=20)
    importer.set_defaults(func=cmd_import)

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
