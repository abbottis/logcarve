#!/usr/bin/env python3
"""Coordinator-executed in-place demo upgrade with hash proofs (T5b3, PAR-08).

Upgrades a LogCarve SQLite store to the current schema WITHOUT resetting
or restoring model usage, spent allowance, auth, tokens or sessions:
only pending migrations apply, then an optional read-only-source
reprocess enriches the new nullable columns. Every step is proven by
hashes taken before and after; a mismatch aborts with a fixed reason
and the protected backup is left for inspection (never auto-restored:
restoring a whole backup would rewind the spent ledger and auth state).

The coordinator runs this (never Muse): all runtime inputs are explicit
flags or environment variables. Secrets are never printed, baked in,
or written anywhere by this helper.

Posture (fail closed before any backup or write):
- ``MODEL_API_KEY`` must be empty and AI disabled (``AI_ENABLED`` unset
  or false): the upgrade touches deterministic data only.
- Refuses euid 0 (run as the non-root image user).
- Source mounts and the GeoIP database must exist as regular files;
  sources are only ever read (never edited, truncated, moved or
  deleted).
- ``--capture-originals`` requires a valid ``ORIGINAL_IP_KEY`` supplied
  by the coordinator; without it the flag fails closed.
- Sources and the GeoIP database are opened read-only; the helper
  writes only to the database file and the backup directory (the
  read-only mount itself stays a deployment property).

Rollback is image-only by design: redeploy the previous image against
the migrated database (additions stay backward-readable where proven).
The backup is a protected recovery artifact, not an automatic
activation rollback.

Usage:
    python scripts/upgrade_demo.py --db /data/logcarve-demo.sqlite3 \\
        --backup-dir /data/upgrade-backups --source-root /logs \\
        --fixture demo-access.log --dry-run
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Tables whose rows must be byte-identical before and after (full-row
# hashes, ordered by rowid). Auth, sessions, tokens, model spend and the
# capped smoke allowance/ledger are never touched by an upgrade.
PRESERVED_TABLES = (
    "admin_users",
    "admin_sessions",
    "api_tokens",
    "ai_spend",
    "smoke_allowance",
    "smoke_holds",
)

# Immutable core of one event row: identity plus normalized request
# fields and the HMAC pseudonym. Enrichment columns (timings, country,
# policy) may change intentionally and are excluded on purpose.
CORE_EVENT_COLUMNS = (
    "id",
    "site_id",
    "source_id",
    "file_fingerprint",
    "byte_offset",
    "line_number",
    "ts_utc",
    "method",
    "path",
    "status",
    "bytes",
    "referer_host",
    "user_agent",
    "client_pseudonym",
    "duration_ms",
    "format_id",
)


def _fail(reason: str, detail: str = "") -> int:
    print(json.dumps({"verdict": "refused", "reason": reason, "detail": detail}))
    return 2


def _serialize(value: object) -> bytes:
    if value is None:
        return b"\x00"
    if isinstance(value, bytes):
        return b"B" + value
    return ("T" + str(value)).encode("utf-8")


def _hash_table(conn: sqlite3.Connection, table: str) -> tuple[str, int]:
    digest = hashlib.sha256()
    count = 0
    for row in conn.execute(f"SELECT * FROM {table} ORDER BY rowid"):
        for value in row:
            digest.update(_serialize(value))
            digest.update(b"\x01")
        digest.update(b"\x02")
        count += 1
    return digest.hexdigest(), count


def _hash_core_events(conn: sqlite3.Connection) -> tuple[str, int]:
    columns = ", ".join(CORE_EVENT_COLUMNS)
    digest = hashlib.sha256()
    count = 0
    for row in conn.execute(f"SELECT {columns} FROM requests ORDER BY id"):
        for value in row:
            digest.update(_serialize(value))
            digest.update(b"\x01")
        digest.update(b"\x02")
        count += 1
    return digest.hexdigest(), count


def _table_names(conn: sqlite3.Connection) -> set[str]:
    return {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    }


def _snapshot(conn: sqlite3.Connection) -> dict:
    tables = _table_names(conn)
    preserved = {}
    for table in PRESERVED_TABLES:
        if table in tables:
            digest, count = _hash_table(conn, table)
            preserved[table] = {"sha256": digest, "rows": count}
    core_sha, core_rows = _hash_core_events(conn)
    version = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
    return {
        "schema_version": version,
        "request_rows": core_rows,
        "core_events_sha256": core_sha,
        "preserved_tables": preserved,
    }


def _posture(args: argparse.Namespace) -> tuple[bool, str]:
    if os.environ.get("MODEL_API_KEY", "").strip():
        return False, "MODEL_API_KEY must be empty for the deterministic upgrade"
    ai_enabled = os.environ.get("AI_ENABLED", "").strip().lower()
    if ai_enabled not in ("", "0", "false", "no", "off"):
        return False, "AI_ENABLED must be off for the deterministic upgrade"
    try:
        if os.geteuid() == 0:
            return False, "refusing to run as root; use the non-root image user"
    except AttributeError:
        pass
    db = Path(args.db)
    if not db.is_file():
        return False, f"database is not a file: {args.db}"
    root = Path(args.source_root)
    if not root.is_dir():
        return False, f"source root is not a directory: {args.source_root}"
    for fixture in args.fixture:
        candidate = root / fixture
        if not candidate.is_file():
            return False, f"fixture is not a file: {fixture}"
    if args.geoip_db:
        geo = Path(args.geoip_db)
        if not geo.is_file():
            return False, f"GeoIP database is not a file: {args.geoip_db}"
    if args.capture_originals and not os.environ.get("ORIGINAL_IP_KEY", "").strip():
        return False, "ORIGINAL_IP_KEY is required with --capture-originals"
    return True, ""


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="In-place demo upgrade with hash proofs (coordinator-executed).",
    )
    parser.add_argument("--db", required=True, help="SQLite store file to upgrade")
    parser.add_argument("--backup-dir", required=True, help="Protected backup destination")
    parser.add_argument("--source-root", required=True, help="Approved read-only source root")
    parser.add_argument(
        "--fixture",
        action="append",
        default=[],
        help="Fixture relative path under --source-root (repeatable, for provenance)",
    )
    parser.add_argument("--source-id", default="example-combined")
    parser.add_argument("--site-id", default="default")
    parser.add_argument("--site-hostname", default="example.org")
    parser.add_argument("--geoip-db", default=None, help="Optional mounted MMDB for enrichment")
    parser.add_argument(
        "--capture-originals",
        action="store_true",
        default=False,
        help="Capture original IPs encrypted (requires ORIGINAL_IP_KEY)",
    )
    parser.add_argument(
        "--no-enrich",
        action="store_true",
        default=False,
        help="Skip the post-migration read-only reprocess enrichment",
    )
    parser.add_argument("--dry-run", action="store_true", default=False)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    ok, reason = _posture(args)
    if not ok:
        return _fail("posture", reason)

    from app.db.database import connect
    from app.db.migrations_runner import migrate

    db = Path(args.db)
    conn = connect(db, read_only=True)
    try:
        pre = _snapshot(conn)
        fixture_shas = {name: _sha_file(Path(args.source_root) / name) for name in args.fixture}
    finally:
        conn.close()
    pre["fixture_shas"] = fixture_shas

    if args.dry_run:
        print(
            json.dumps(
                {
                    "verdict": "dry-run",
                    "schema_version": pre["schema_version"],
                    "request_rows": pre["request_rows"],
                    "core_events_sha256": pre["core_events_sha256"],
                    "preserved_tables": pre["preserved_tables"],
                    "fixture_shas": fixture_shas,
                }
            )
        )
        return 0

    from app.db.backup import backup_database

    backup_dir = Path(args.backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup_path = backup_dir / f"{db.stem}-pre-upgrade-{stamp}.sqlite3"
    backup_database(db, backup_path)
    if not backup_path.is_file() or backup_path.stat().st_size == 0:
        return _fail("backup", "protected backup missing or empty after backup")

    result = migrate(db)
    applied = sorted(result.applied)

    if not args.no_enrich:
        hmac_key = os.environ.get("HMAC_KEY", "").encode()
        if not hmac_key:
            return _fail("posture", "HMAC_KEY is required for the enrichment reprocess")
        from app.db import private as _private
        from app.db.reprocess import run_reprocess
        from app.ingestion.combined import NGINX_COMBINED
        from app.ingestion.geoip import CountryLookup
        from app.ingestion.sources import SourceConfig

        ip_key: object = None
        if args.capture_originals:
            try:
                ip_key = _private.require_ip_key(os.environ.get("ORIGINAL_IP_KEY", ""))
            except _private.PrivateUnavailable as exc:
                return _fail("posture", f"ORIGINAL_IP_KEY invalid: {exc.code}")
        lookup = CountryLookup.open(args.geoip_db) if args.geoip_db else CountryLookup.unavailable()
        with lookup:
            for fixture in args.fixture:
                run_reprocess(
                    db,
                    source=SourceConfig(
                        source_id=args.source_id,
                        format_id=NGINX_COMBINED,
                        allowed_root=Path(args.source_root),
                        relative_path=fixture,
                    ),
                    site_id=args.site_id,
                    site_hostname=args.site_hostname,
                    server_type="nginx",
                    hmac_key=hmac_key,
                    capture_originals=args.capture_originals,
                    ip_key=ip_key,
                    country_lookup=lookup,
                )

    conn = connect(db, read_only=True)
    try:
        post = _snapshot(conn)
    finally:
        conn.close()

    errors: list[str] = []
    if post["request_rows"] != pre["request_rows"]:
        errors.append("request row count changed")
    if post["core_events_sha256"] != pre["core_events_sha256"]:
        errors.append("core event tuples changed")
    for table, proof in pre["preserved_tables"].items():
        after = post["preserved_tables"].get(table)
        if after is None or after["sha256"] != proof["sha256"]:
            errors.append(f"preserved table changed: {table}")
    if errors:
        print(
            json.dumps(
                {
                    "verdict": "failed",
                    "errors": errors,
                    "backup": str(backup_path),
                    "note": "backup retained for inspection; no automatic restore"
                    " (restoring would rewind the spent ledger and auth state)",
                }
            )
        )
        return 1
    print(
        json.dumps(
            {
                "verdict": "upgraded",
                "schema_version": post["schema_version"],
                "applied_migrations": sorted(applied),
                "request_rows": post["request_rows"],
                "core_events_sha256": post["core_events_sha256"],
                "preserved_tables": {k: v["rows"] for k, v in post["preserved_tables"].items()},
                "backup": str(backup_path),
                "rollback": "image-only: redeploy the previous image against"
                " the migrated database; never auto-restore the backup",
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
