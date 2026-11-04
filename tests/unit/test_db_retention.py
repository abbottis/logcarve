"""T3 retention tests: UTC cutoff, boundary rows and owned-data-only scope."""

from datetime import UTC, datetime

import pytest

from app.db import repositories
from app.db.database import connect
from app.db.migrations_runner import migrate
from app.db.retention import apply_retention, retention_cutoff_utc

NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)


def _seed(conn, day: str, hour: str = "12:00:00", offset: int = 0):
    conn.execute(
        "INSERT INTO requests (import_id, site_id, source_id, file_fingerprint,"
        " byte_offset, line_number, ts_utc, method, path, status, bytes,"
        " referer_host, user_agent, client_pseudonym, duration_ms)"
        " VALUES (1, 'default', 'example-combined', 'fp', ?, 1, ?, 'GET', '/x', 200, 1,"
        " NULL, NULL, 'pseudonym', NULL)",
        (offset, f"{day}T{hour}+00:00"),
    )


def test_retention_deletes_only_older_events(tmp_path):
    db = tmp_path / "retention.sqlite3"
    migrate(db)
    conn = connect(db)
    with conn:
        repositories.ensure_site(
            conn, site_id="default", name="s", hostname="example.org", created_at=NOW.isoformat()
        )
        repositories.ensure_source(
            conn,
            source_id="example-combined",
            site_id="default",
            server_type="nginx",
            format_id="nginx_combined",
            path_alias="access.log",
        )
        repositories.create_import(
            conn,
            source_id="example-combined",
            file_fingerprint="fp",
            file_size=10,
            started_at=NOW.isoformat(),
        )
        _seed(conn, "2026-09-01", offset=0)  # 58 days old: deleted
        _seed(conn, "2026-09-29", "11:59:59", offset=1)  # just past cutoff: deleted
        _seed(conn, "2026-09-29", "12:00:00", offset=2)  # exactly cutoff: kept
        _seed(conn, "2026-10-15", offset=3)  # recent: kept
    with conn:
        deleted = apply_retention(conn, days=30, now=NOW)
    assert deleted == 2
    remaining = conn.execute("SELECT ts_utc FROM requests ORDER BY ts_utc").fetchall()
    conn.close()
    assert [row[0] for row in remaining] == [
        "2026-09-29T12:00:00+00:00",
        "2026-10-15T12:00:00+00:00",
    ]


def test_retention_keeps_import_reports(tmp_path):
    db = tmp_path / "retention.sqlite3"
    migrate(db)
    conn = connect(db)
    with conn:
        repositories.ensure_site(
            conn, site_id="default", name="s", hostname="example.org", created_at=NOW.isoformat()
        )
        repositories.ensure_source(
            conn,
            source_id="example-combined",
            site_id="default",
            server_type="nginx",
            format_id="nginx_combined",
            path_alias="access.log",
        )
        conn.execute(
            "INSERT INTO imports (source_id, file_fingerprint, file_size, started_at,"
            " finished_at, status) VALUES ('example-combined', 'fp', 10,"
            " '2026-09-01T00:00:00+00:00', '2026-09-01T00:00:01+00:00', 'completed')"
        )
        _seed(conn, "2026-09-01")
    with conn:
        assert apply_retention(conn, days=30, now=NOW) == 1
        assert conn.execute("SELECT COUNT(*) FROM imports").fetchone()[0] == 1
    conn.close()


def test_retention_days_validated():
    with pytest.raises(ValueError):
        retention_cutoff_utc(0, now=NOW)
    assert retention_cutoff_utc(30, now=NOW) == "2026-09-29T12:00:00+00:00"
