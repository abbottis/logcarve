"""Verified-synthetic store probe for the T10 demo seeder (read-only).

Reads the database at ``DATABASE_PATH`` and the read-only fixture mount at
``/logs/demo-access.log`` without writing anything. Prints one JSON document
with a ``verdict``:

- FRESH: no database yet; safe to seed.
- PARTIAL: migrated demo-shaped store with missing pieces; safe to top up.
- SEEDED: exactly the known 30-row synthetic dataset; re-import must replay.
- FOREIGN: anything else (unknown sites/sources/rows, fingerprint drift,
  bad imports); the caller must refuse it untouched.

The fixture is pinned to the authoritative committed digest
``FIXTURE_SHA256`` (``tests/fixtures/combined/t8_smoke.txt`` at the T10
baseline), never to whatever bytes a mount happens to serve: aggregate row
counts alone do not prove a synthetic store, so every imports row must also
carry the authoritative fingerprint.
"""

import hashlib
import json
import os
from pathlib import Path

# Authoritative digest of tests/fixtures/combined/t8_smoke.txt (30 rows,
# 12/10/8 across 26/27/28 Oct 2026). Bump only with a reviewed fixture change.
FIXTURE_SHA256 = "d765393fb016cc147cf2359f9612b4bb6b6582a9caf1966fb1fe380daeebeb65"
EXPECTED_ROWS = 30


def main() -> int:
    db = Path(os.environ["DATABASE_PATH"])
    # Default is the demo container mount; smoke and tests point elsewhere.
    fixture = Path(os.environ.get("DEMO_FIXTURE_PATH", "/logs/demo-access.log"))
    try:
        mount_sha = hashlib.sha256(fixture.read_bytes()).hexdigest()
    except OSError:
        print(json.dumps({"verdict": "FOREIGN", "reason": "fixture unreadable"}))
        return 0
    if mount_sha != FIXTURE_SHA256:
        print(
            json.dumps(
                {
                    "verdict": "FOREIGN",
                    "reason": "fixture digest drift",
                    "mount_sha": mount_sha,
                }
            )
        )
        return 0

    if not db.exists() or db.stat().st_size == 0:
        print(json.dumps({"verdict": "FRESH", "fixture_sha": FIXTURE_SHA256}))
        return 0

    from app.db.database import connect

    conn = connect(db, read_only=True)
    try:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        if not {"sites", "log_sources", "imports", "requests"} <= tables:
            print(json.dumps({"verdict": "FOREIGN", "reason": "unrecognized schema"}))
            return 0
        sites = [row[0] for row in conn.execute("SELECT id FROM sites ORDER BY id").fetchall()]
        sources = [
            row[0]
            for row in conn.execute(
                "SELECT id FROM log_sources WHERE site_id = 'default' ORDER BY id"
            ).fetchall()
        ]
        other_sources = conn.execute(
            "SELECT COUNT(*) FROM log_sources WHERE site_id != 'default'"
        ).fetchone()[0]
        total = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
        foreign_rows = conn.execute(
            "SELECT COUNT(*) FROM requests WHERE site_id != 'default'"
            " OR source_id != 'example-combined'"
        ).fetchone()[0]
        users = (
            conn.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0]
            if "admin_users" in tables
            else 0
        )
        tokens = (
            conn.execute("SELECT COUNT(*) FROM api_tokens WHERE name = 'demo-client'").fetchone()[0]
            if "api_tokens" in tables
            else 0
        )
        fingerprints = [
            row[0]
            for row in conn.execute(
                "SELECT DISTINCT file_fingerprint FROM imports WHERE source_id = 'example-combined'"
            ).fetchall()
        ]
        bad_imports = conn.execute(
            "SELECT COUNT(*) FROM imports WHERE source_id = 'example-combined'"
            " AND (status != 'completed' OR (error_summary IS NOT NULL"
            " AND error_summary != ''))"
        ).fetchone()[0]
        foreign_imports = conn.execute(
            "SELECT COUNT(*) FROM imports WHERE source_id != 'example-combined'"
        ).fetchone()[0]
        info = {
            "sites": sites,
            "sources": sources,
            "rows": total,
            "users": users,
            "demo_token": tokens,
            "fixture_sha": FIXTURE_SHA256,
        }
        clean = not other_sources and not foreign_rows and not foreign_imports and not bad_imports
        empty = clean and sites == [] and sources == [] and total == 0 and not fingerprints
        exact = (
            clean
            and sites == ["default"]
            and sources == ["example-combined"]
            and total == EXPECTED_ROWS
            and fingerprints
            and all(fp == FIXTURE_SHA256 for fp in fingerprints)
        )
        if exact and users >= 1:
            info["verdict"] = "SEEDED"
        elif empty or exact:
            # Empty migrated store or half-seeded demo-shaped store: safe to
            # top up, since only authoritative fixture rows can land here.
            info["verdict"] = "PARTIAL"
        else:
            info["verdict"] = "FOREIGN"
        print(json.dumps(info))
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
