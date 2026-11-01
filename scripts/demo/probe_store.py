"""Verified-synthetic store probe for the demo seeder (read-only).

Reads the database at ``DATABASE_PATH`` and the read-only fixture mounts
without writing anything. Prints one JSON document with a ``verdict``:

- FRESH: no database yet; safe to seed.
- PARTIAL: migrated demo-shaped store with missing pieces; safe to top up.
  This covers the empty store, the legacy T8-only store (Slice C upgrade
  path), a rich-only store, rows without an admin, and an interrupted
  import whose fingerprints are all known (re-import converges
  idempotently; nothing is deleted).
- SEEDED: exactly the known combined synthetic dataset (30 T8 rows plus
  90 rich rows); re-import must replay.
- FOREIGN: anything else (unknown sites/sources/rows/fingerprints,
  fixture drift, bad imports with unknown provenance); the caller must
  refuse it untouched.

Both fixtures are pinned to their authoritative committed digests
(``tests/fixtures/combined/t8_smoke.txt`` at the T10 baseline and
``tests/fixtures/combined/demo_rich_29_31oct.txt`` at the Slice C
baseline), never to whatever bytes a mount happens to serve: aggregate
row counts alone do not prove a synthetic store, so every imports row
must also carry an authoritative fingerprint.
"""

import hashlib
import json
import os
from pathlib import Path

# Authoritative digest of tests/fixtures/combined/t8_smoke.txt (30 rows,
# 12/10/8 across 26/27/28 Oct 2026). Bump only with a reviewed fixture change.
FIXTURE_SHA256 = "d765393fb016cc147cf2359f9612b4bb6b6582a9caf1966fb1fe380daeebeb65"
EXPECTED_ROWS = 30

# Authoritative digest of tests/fixtures/combined/demo_rich_29_31oct.txt
# (90 rows, 30/30/30 across 29/31 Oct 2026, outside the T8 window).
# Bump only with a reviewed fixture change.
RICH_SHA256 = "2c424fcf559e5d822db84102b15b9d0519b8a5b566977391fdfa9a1bf32e0d3f"
RICH_ROWS = 90

COMBINED_ROWS = EXPECTED_ROWS + RICH_ROWS
KNOWN_FINGERPRINTS = frozenset({FIXTURE_SHA256, RICH_SHA256})


def _digest(label: str, path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        print(json.dumps({"verdict": "FOREIGN", "reason": f"{label} unreadable"}))
        return None


def main() -> int:
    db = Path(os.environ["DATABASE_PATH"])
    # Defaults are the demo container mounts; smoke and tests point elsewhere.
    fixture = Path(os.environ.get("DEMO_FIXTURE_PATH", "/logs/demo-access.log"))
    rich = Path(os.environ.get("DEMO_RICH_FIXTURE_PATH", "/logs/demo-rich-access.log"))
    mount_sha = _digest("fixture", fixture)
    if mount_sha is None:
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
    rich_sha = _digest("rich fixture", rich)
    if rich_sha is None:
        return 0
    if rich_sha != RICH_SHA256:
        print(
            json.dumps(
                {
                    "verdict": "FOREIGN",
                    "reason": "rich fixture digest drift",
                    "mount_sha": rich_sha,
                }
            )
        )
        return 0

    if not db.exists() or db.stat().st_size == 0:
        print(
            json.dumps(
                {
                    "verdict": "FRESH",
                    "fixture_sha": FIXTURE_SHA256,
                    "rich_sha": RICH_SHA256,
                }
            )
        )
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
        all_sources = [
            row[0] for row in conn.execute("SELECT DISTINCT id FROM log_sources").fetchall()
        ]
        total = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
        foreign_rows = conn.execute(
            "SELECT COUNT(*) FROM requests WHERE site_id != 'default'"
            " OR source_id != 'example-combined'"
        ).fetchone()[0]
        unknown_fp_rows = conn.execute(
            "SELECT COUNT(*) FROM requests WHERE file_fingerprint != ? AND file_fingerprint != ?",
            (FIXTURE_SHA256, RICH_SHA256),
        ).fetchone()[0]
        t8_rows = conn.execute(
            "SELECT COUNT(*) FROM requests WHERE file_fingerprint = ?",
            (FIXTURE_SHA256,),
        ).fetchone()[0]
        rich_rows = conn.execute(
            "SELECT COUNT(*) FROM requests WHERE file_fingerprint = ?",
            (RICH_SHA256,),
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
        # A failed import attempt is superseded once a clean completed import
        # of the same source bytes exists: replay absorbs the partial rows,
        # so the store converges instead of staying failed forever. An
        # unresumed failure still blocks convergence below (PARTIAL/FOREIGN).
        _UNSUPERSEDED = (
            "SELECT COUNT(*) FROM imports bad WHERE source_id = 'example-combined'"
            " AND (bad.status != 'completed' OR (bad.error_summary IS NOT NULL"
            " AND bad.error_summary != ''))"
            " AND NOT EXISTS (SELECT 1 FROM imports good WHERE good.source_id = bad.source_id"
            " AND good.file_fingerprint = bad.file_fingerprint AND good.status = 'completed'"
            " AND (good.error_summary IS NULL OR good.error_summary = ''))"
        )
        _UNSUPERSEDED_FPS = _UNSUPERSEDED.replace(
            "SELECT COUNT(*)", "SELECT DISTINCT file_fingerprint"
        )
        bad_imports = conn.execute(_UNSUPERSEDED).fetchone()[0]
        bad_import_fps = [row[0] for row in conn.execute(_UNSUPERSEDED_FPS).fetchall()]
        foreign_imports = conn.execute(
            "SELECT COUNT(*) FROM imports WHERE source_id != 'example-combined'"
        ).fetchone()[0]
        info = {
            "sites": sites,
            "sources": sources,
            "rows": total,
            "t8_rows": t8_rows,
            "rich_rows": rich_rows,
            "users": users,
            "demo_token": tokens,
            "fixture_sha": FIXTURE_SHA256,
            "rich_sha": RICH_SHA256,
        }
        structural_clean = (
            not other_sources
            and not foreign_rows
            and not unknown_fp_rows
            and not foreign_imports
            and all(site == "default" for site in sites)
            and all(source == "example-combined" for source in all_sources)
            and all(fp in KNOWN_FINGERPRINTS for fp in fingerprints)
        )
        if not structural_clean:
            info["verdict"] = "FOREIGN"
        elif bad_imports and not all(fp in KNOWN_FINGERPRINTS for fp in bad_import_fps):
            # Failed imports of unknown provenance are refused untouched.
            info["verdict"] = "FOREIGN"
        else:
            exact = (
                sites == ["default"]
                and sources == ["example-combined"]
                and total == COMBINED_ROWS
                and t8_rows == EXPECTED_ROWS
                and rich_rows == RICH_ROWS
                and not bad_imports
            )
            if exact and users >= 1:
                info["verdict"] = "SEEDED"
            else:
                # Empty migrated store, legacy T8-only upgrade, rich-only
                # store, rows without an admin, or an interrupted import
                # with known fingerprints: only authoritative fixture rows
                # can land here, and re-import converges idempotently.
                info["verdict"] = "PARTIAL"
                if bad_imports:
                    info["interrupted"] = True
        print(json.dumps(info))
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
