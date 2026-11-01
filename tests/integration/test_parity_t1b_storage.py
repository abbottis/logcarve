"""T1b integration tests: encrypted originals, reprocess, retention, contracts.

End-to-end storage-foundation coverage on temporary synthetic databases:
upgrade of a schema-4 store, capture imports with ciphertext-only rest
state, fail-closed key handling with a still-working deterministic API,
two-run idempotent reprocess with interruption recovery, retention
cascades, and address-free API/analytics/model contracts. Synthetic
fixtures only; the 120-row fixture and goldens are untouched.
"""

import base64
import hashlib
import hmac
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user, issue_token
from app.db import migrations_runner, private, repositories
from app.db.database import connect, writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.db.private import PrivateUnavailable
from app.db.reprocess import run_reprocess
from app.db.retention import apply_retention
from app.ingestion.combined import NGINX_EXTENDED
from app.ingestion.sources import SourceConfig

ROOT = Path(__file__).resolve().parent.parent.parent
T1A = ROOT / "tests" / "fixtures" / "parity_t1a"
HMAC_KEY = b"parity-t1b-integration-key"
SITE = "site-t1b"

SENTINELS = ("203.0.113.20", "2001:db8::25", "198.51.100.7", "192.0.2.44", "hunter2")

NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC)


def _key_bytes(seed: int = 21) -> bytes:
    return bytes((seed * 37 + i) % 256 for i in range(32))


def _key_env(monkeypatch, seed: int = 21) -> bytes:
    key = _key_bytes(seed)
    monkeypatch.setenv("ORIGINAL_IP_KEY", base64.b64encode(key).decode())
    return key


def _copy_source(root: Path, name: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    target = root / name
    target.write_bytes((T1A / name).read_bytes())
    return target


def _source(root: Path, name: str, fmt: str, hosts=None) -> SourceConfig:
    return SourceConfig(
        source_id="t1b-source",
        format_id=fmt,
        allowed_root=root,
        relative_path=name,
        allowed_hosts=hosts,
    )


def _import(
    db: Path,
    root: Path,
    name: str,
    fmt: str = NGINX_EXTENDED,
    capture: bool = False,
    hosts=None,
    **overrides,
):
    return run_import(
        db,
        source=_source(root, name, fmt, hosts),
        site_id=SITE,
        site_name="T1b site",
        site_hostname="example.org",
        server_type="nginx",
        path_alias=name,
        hmac_key=HMAC_KEY,
        capture_originals=capture,
        **overrides,
    )


def _reprocess(db: Path, root: Path, name: str, fmt: str = NGINX_EXTENDED, capture=False, **kw):
    return run_reprocess(
        db,
        source=_source(root, name, fmt, ["example.org"]),
        site_id=SITE,
        site_hostname="example.org",
        server_type="nginx",
        hmac_key=HMAC_KEY,
        capture_originals=capture,
        **kw,
    )


def _db_bytes(db: Path) -> bytes:
    blob = bytearray(db.read_bytes())
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = db.parent / (db.name + suffix)
        if sidecar.exists():
            blob += sidecar.read_bytes()
    return bytes(blob)


def _routine_values(conn) -> str:
    rows = conn.execute(
        "SELECT id, import_id, site_id, source_id, file_fingerprint, byte_offset,"
        " line_number, ts_utc, method, path, status, bytes, referer_host,"
        " user_agent, client_pseudonym, duration_ms, format_id, http_version,"
        " server_host, referer_scheme, referer_path, cache_status, mime_type,"
        " tls_protocol, request_time_ms, upstream_time_ms, upstream_count,"
        " policy_version"
        " FROM requests ORDER BY id"
    ).fetchall()
    return json.dumps([list(row) for row in rows], default=str)


# --- Schema-4 upgrade ---


def test_upgrade_schema4_preserves_core_and_unrelated_tables(tmp_path, monkeypatch):
    staged = tmp_path / "migrations"
    staged.mkdir()
    real = Path(migrations_runner.MIGRATIONS_DIR)
    for name in (
        "0001_initial.sql",
        "0002_auth.sql",
        "0003_ai_budget.sql",
        "0004_smoke_allowance.sql",
    ):
        (staged / name).write_text((real / name).read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(migrations_runner, "MIGRATIONS_DIR", staged)
    db = tmp_path / "legacy.sqlite3"
    assert migrate(db).applied == (1, 2, 3, 4)
    conn = connect(db)
    try:
        with conn:
            repositories.ensure_site(
                conn, site_id="s", name="n", hostname="h", created_at=NOW.isoformat()
            )
            # Schema-4 shape: log_sources has no allowed_hosts column yet, so
            # the row is inserted with the legacy six-column statement.
            conn.execute(
                "INSERT INTO log_sources (id, site_id, server_type, format_id,"
                " path_alias, enabled) VALUES ('src', 's', 'nginx',"
                " 'nginx_combined', 'a.log', 1)"
            )
            import_id = repositories.create_import(
                conn, source_id="src", file_fingerprint="fp", file_size=10, started_at="x"
            )
            conn.executemany(
                "INSERT INTO requests (import_id, site_id, source_id, file_fingerprint,"
                " byte_offset, line_number, ts_utc, method, path, status, bytes,"
                " referer_host, user_agent, client_pseudonym, duration_ms)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        import_id,
                        "s",
                        "src",
                        "fp",
                        0,
                        1,
                        "2026-10-27T00:00:00+00:00",
                        "GET",
                        "/a",
                        200,
                        5,
                        None,
                        None,
                        "pseudo-a",
                        None,
                    ),
                    (
                        import_id,
                        "s",
                        "src",
                        "fp",
                        80,
                        2,
                        "2026-10-27T00:01:00+00:00",
                        "POST",
                        "/b",
                        404,
                        7,
                        "example.org",
                        "UA",
                        "pseudo-b",
                        None,
                    ),
                ],
            )
            create_admin_user(conn, username="admin", password_hash=hash_password("pw"))
            conn.execute(
                "INSERT INTO ai_spend (day, kind, amount_micro_usd, status, created_at)"
                " VALUES ('2026-11-01', 'probe', 5, 'active', '2026-11-01T00:00:00+00:00')"
            )
            conn.execute(
                "INSERT INTO smoke_allowance (id, version, max_investigations, max_requests,"
                " max_micro_usd, used_investigations, used_requests, used_micro_usd,"
                " held_micro_usd, updated_at)"
                " VALUES (1, 1, 3, 12, 1000000, 1, 2, 300, 0, '2026-11-01T00:00:00+00:00')"
            )
        before_ids = [row[0] for row in conn.execute("SELECT id FROM requests ORDER BY id")]
        before_core = conn.execute(
            "SELECT file_fingerprint, byte_offset, method, path, status, client_pseudonym"
            " FROM requests ORDER BY id"
        ).fetchall()
        before_count = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
        auth_before = conn.execute("SELECT username FROM admin_users").fetchall()
        spend_before = conn.execute("SELECT amount_micro_usd FROM ai_spend").fetchall()
        allowance_before = conn.execute("SELECT used_micro_usd FROM smoke_allowance").fetchone()[0]
    finally:
        conn.close()
    monkeypatch.setattr(migrations_runner, "MIGRATIONS_DIR", real)
    assert migrate(db).applied == (5,)
    assert migrate(db).applied == ()
    conn = connect(db, read_only=True)
    try:
        assert [row[0] for row in conn.execute("SELECT id FROM requests ORDER BY id")] == before_ids
        assert (
            conn.execute(
                "SELECT file_fingerprint, byte_offset, method, path, status, client_pseudonym"
                " FROM requests ORDER BY id"
            ).fetchall()
            == before_core
        )
        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == before_count
        enriched = conn.execute(
            "SELECT format_id, http_version, server_host, referer_scheme, referer_path,"
            " cache_status, mime_type, tls_protocol, request_time_ms, upstream_time_ms,"
            " upstream_count, policy_version, duration_ms FROM requests ORDER BY id"
        ).fetchall()
        for row in enriched:
            # Pre-existing rows keep every new enrichment field NULL --
            # including upstream_count (absent timing infers no count)
            # and the policy tag -- until an explicit reprocess.
            # Legacy duration_ms stays NULL: Combined never supplied it.
            assert tuple(row[:-1]) == (None,) * 12
            assert row[-1] is None
        assert conn.execute("SELECT username FROM admin_users").fetchall() == auth_before
        assert conn.execute("SELECT amount_micro_usd FROM ai_spend").fetchall() == spend_before
        assert conn.execute("SELECT used_micro_usd FROM smoke_allowance").fetchone()[0] == (
            allowance_before
        )
        assert conn.execute("SELECT COUNT(*) FROM request_original_ips").fetchone()[0] == 0
        assert private.get_ip_display_mode(conn) == "full"
    finally:
        conn.close()


def test_premigrate_backup_then_restore_round_trip(tmp_path, monkeypatch):
    staged = tmp_path / "migrations"
    staged.mkdir()
    real = Path(migrations_runner.MIGRATIONS_DIR)
    for name in (
        "0001_initial.sql",
        "0002_auth.sql",
        "0003_ai_budget.sql",
        "0004_smoke_allowance.sql",
    ):
        (staged / name).write_text((real / name).read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(migrations_runner, "MIGRATIONS_DIR", staged)
    db = tmp_path / "store.sqlite3"
    assert migrate(db).applied == (1, 2, 3, 4)
    conn = connect(db)
    try:
        with conn:
            repositories.ensure_site(
                conn, site_id="s", name="n", hostname="h", created_at=NOW.isoformat()
            )
            conn.execute(
                "INSERT INTO log_sources (id, site_id, server_type, format_id,"
                " path_alias, enabled) VALUES ('src', 's', 'nginx',"
                " 'nginx_combined', 'a.log', 1)"
            )
    finally:
        conn.close()
    monkeypatch.setattr(migrations_runner, "MIGRATIONS_DIR", real)
    backups = tmp_path / "backups"
    result = migrate(db, backup_dir=backups)
    assert result.applied == (5,)
    assert result.backup_path is not None and result.backup_path.is_file()
    import stat as statmod

    assert statmod.S_IMODE(result.backup_path.stat().st_mode) == 0o600
    probe = sqlite3.connect(str(result.backup_path))
    try:
        assert probe.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 4
    finally:
        probe.close()


# --- Capture import ---


def test_capture_import_stores_metadata_and_encrypted_originals(tmp_path, monkeypatch):
    key = _key_env(monkeypatch)
    root = tmp_path / "logs"
    _copy_source(root, "nginx_extended.txt")
    db = tmp_path / "t1b.sqlite3"
    result = _import(db, root, "nginx_extended.txt", capture=True)
    assert result.status == "completed"
    assert result.records_inserted == 3
    assert result.originals_captured == 3
    conn = connect(db, read_only=True)
    try:
        rows = conn.execute(
            "SELECT id, client_pseudonym, format_id, http_version, server_host,"
            " referer_scheme, referer_path, cache_status, mime_type, tls_protocol,"
            " request_time_ms, upstream_time_ms, upstream_count, duration_ms"
            " FROM requests ORDER BY id"
        ).fetchall()
        assert [row[2] for row in rows] == ["nginx_extended"] * 3
        assert rows[0][4] == "example.org" and rows[0][7] == "MISS"
        assert rows[0][8] == "text/html" and rows[0][9] == "TLSv1.3"
        assert rows[0][10] == pytest.approx(123.0) and rows[0][11] == pytest.approx(120.0)
        assert rows[0][12] == 2 and rows[0][13] is None
        assert rows[1][8] == "text/css" and rows[2][4] is None
        nonces = conn.execute(
            "SELECT nonce FROM request_original_ips ORDER BY request_id"
        ).fetchall()
        assert len(nonces) == 3 and len({bytes(n[0]) for n in nonces}) == 3
        for row in rows:
            assert private.read_original_ip(conn, request_id=row[0], key=key) in (
                "203.0.113.20",
                "2001:db8::25",
                "198.51.100.7",
            )
    finally:
        conn.close()
    blob = _db_bytes(db)
    for sentinel in SENTINELS:
        assert sentinel.encode() not in blob
    assert private.count_private_rows(connect(db, read_only=True)) == 3


def test_import_without_capture_stores_metadata_and_no_private_rows(tmp_path, monkeypatch):
    monkeypatch.delenv("ORIGINAL_IP_KEY", raising=False)
    root = tmp_path / "logs"
    _copy_source(root, "nginx_extended.txt")
    db = tmp_path / "plain.sqlite3"
    result = _import(db, root, "nginx_extended.txt")
    assert result.status == "completed" and result.originals_captured == 0
    conn = connect(db, read_only=True)
    try:
        assert conn.execute("SELECT COUNT(*) FROM request_original_ips").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 3
        assert conn.execute("SELECT request_time_ms FROM requests ORDER BY id").fetchall()[0][
            0
        ] == pytest.approx(123.0)
    finally:
        conn.close()


def test_private_reader_refuses_wrong_key_tamper_and_swap(tmp_path, monkeypatch):
    key = _key_env(monkeypatch)
    root = tmp_path / "logs"
    _copy_source(root, "nginx_extended.txt")
    db = tmp_path / "swap.sqlite3"
    _import(db, root, "nginx_extended.txt", capture=True)
    conn = connect(db, read_only=True)
    try:
        rows = conn.execute(
            "SELECT request_id, nonce, ciphertext FROM request_original_ips"
        ).fetchall()
        rid, nonce, ciphertext = rows[0][0], bytes(rows[0][1]), bytes(rows[0][2])
        other_id = rows[1][0]
        with pytest.raises(PrivateUnavailable) as excinfo:
            private.read_original_ip(conn, request_id=rid, key=_key_bytes(99))
        assert excinfo.value.code == "private_unavailable:decrypt_failed"
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0x01
        with pytest.raises(PrivateUnavailable):
            private.decrypt_ip(
                nonce,
                bytes(tampered),
                key=key,
                aad=private.build_aad(
                    site_id=SITE,
                    source_id="t1b-source",
                    file_fingerprint="fp",
                    byte_offset=0,
                ),
            )
        swapped = conn.execute(
            "SELECT nonce, ciphertext FROM request_original_ips WHERE request_id = ?", (other_id,)
        ).fetchone()
        with pytest.raises(PrivateUnavailable) as excinfo:
            private.decrypt_ip(
                bytes(swapped[0]),
                bytes(swapped[1]),
                key=key,
                aad=private.build_aad(
                    site_id=SITE,
                    source_id="t1b-source",
                    file_fingerprint="fp",
                    byte_offset=0,
                ),
            )
        assert excinfo.value.code == "private_unavailable:decrypt_failed"
    finally:
        conn.close()


def test_routine_rows_and_analytics_carry_no_originals(tmp_path, monkeypatch):
    _key_env(monkeypatch)
    root = tmp_path / "logs"
    _copy_source(root, "nginx_extended.txt")
    db = tmp_path / "routine.sqlite3"
    _import(db, root, "nginx_extended.txt", capture=True)
    from app.analytics import service as analytics_service
    from app.analytics.contracts import AnalyticsFilter, TimeWindow

    conn = connect(db, read_only=True)
    try:
        assert "original" not in {row[1] for row in conn.execute("PRAGMA table_info(requests)")}
        routine = _routine_values(conn)
        for sentinel in SENTINELS:
            assert sentinel not in routine
        filt = AnalyticsFilter(
            site_id=SITE,
            window=TimeWindow(
                time_from=datetime(2026, 10, 27, tzinfo=UTC),
                time_to=datetime(2026, 10, 28, tzinfo=UTC),
            ),
        )
        payload = json.dumps(analytics_service.summarize(conn, filt), default=str)
        for sentinel in SENTINELS:
            assert sentinel not in payload
    finally:
        conn.close()


def test_deterministic_api_works_without_key_and_stays_address_free(tmp_path, monkeypatch):
    monkeypatch.delenv("ORIGINAL_IP_KEY", raising=False)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    root = tmp_path / "logs"
    _copy_source(root, "nginx_extended.txt")
    db = tmp_path / "nokey.sqlite3"
    result = _import(db, root, "nginx_extended.txt")
    assert result.status == "completed"
    with writer_transaction(db) as conn:
        token = issue_token(conn, name="t", site_id=SITE)[1]
    from app.main import create_app

    client = TestClient(create_app(db_path=db, secure_cookies=False), raise_server_exceptions=False)
    response = client.get(
        "/api/v1/summary",
        params={
            "site_id": SITE,
            "from": "2026-10-27T00:00:00+00:00",
            "to": "2026-10-28T00:00:00+00:00",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    body = response.text
    for sentinel in SENTINELS:
        assert sentinel not in body


def test_capture_without_key_fails_before_writes(tmp_path, monkeypatch):
    monkeypatch.delenv("ORIGINAL_IP_KEY", raising=False)
    root = tmp_path / "logs"
    _copy_source(root, "nginx_extended.txt")
    db = tmp_path / "fail.sqlite3"
    with pytest.raises(PrivateUnavailable) as excinfo:
        _import(db, root, "nginx_extended.txt", capture=True)
    assert excinfo.value.code == "private_unavailable:no_key"
    # Failed before any write: the database file was never even created.
    assert not db.exists()


def test_capture_cli_without_key_fails_before_writes(tmp_path, monkeypatch):
    monkeypatch.delenv("ORIGINAL_IP_KEY", raising=False)
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    root = tmp_path / "logs"
    _copy_source(root, "nginx_extended.txt")
    db = tmp_path / "cli.sqlite3"
    from app.db.cli import main as cli_main

    code = cli_main(
        [
            "--db",
            str(db),
            "import",
            "--source-id",
            "t1b-source",
            "--format",
            "nginx_extended",
            "--root",
            str(root),
            "--path",
            "nginx_extended.txt",
            "--site-id",
            SITE,
            "--site-hostname",
            "example.org",
            "--capture-original-ips",
        ]
    )
    assert code == 1
    assert not db.exists()


# --- Reprocess ---


def test_reprocess_twice_adds_no_rows_and_preserves_identity(tmp_path, monkeypatch):
    key = _key_env(monkeypatch)
    root = tmp_path / "logs"
    target = _copy_source(root, "nginx_extended.txt")
    before_bytes = target.read_bytes()
    db = tmp_path / "repro.sqlite3"
    first = _import(db, root, "nginx_extended.txt")
    assert first.status == "completed"
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("pw"))
        issue_token(conn, name="t", site_id=SITE)
        conn.execute(
            "INSERT INTO ai_spend (day, kind, amount_micro_usd, status, created_at)"
            " VALUES ('2026-11-01', 'probe', 5, 'active', '2026-11-01T00:00:00+00:00')"
        )
    conn = connect(db, read_only=True)
    try:
        ids_before = [row[0] for row in conn.execute("SELECT id FROM requests ORDER BY id")]
        core_before = conn.execute(
            "SELECT file_fingerprint, byte_offset, ts_utc, method, path, status,"
            " client_pseudonym, duration_ms FROM requests ORDER BY id"
        ).fetchall()
        users_before = conn.execute("SELECT username FROM admin_users").fetchall()
        spend_before = conn.execute("SELECT amount_micro_usd FROM ai_spend").fetchall()
    finally:
        conn.close()
    one = _reprocess(db, root, "nginx_extended.txt", capture=True)
    assert one.status == "completed" and one.error_summary is None
    assert one.rows_matched == 3 and one.rows_verified == 3 and one.rows_mismatched == 0
    assert one.rows_enriched == 0 and one.originals_captured == 3
    two = _reprocess(db, root, "nginx_extended.txt", capture=True)
    assert two.status == "completed"
    assert two.rows_matched == 3 and two.rows_verified == 3
    assert two.rows_enriched == 0 and two.originals_captured == 0
    assert two.rows_mismatched == 0
    conn = connect(db, read_only=True)
    try:
        assert [row[0] for row in conn.execute("SELECT id FROM requests ORDER BY id")] == ids_before
        assert (
            conn.execute(
                "SELECT file_fingerprint, byte_offset, ts_utc, method, path, status,"
                " client_pseudonym, duration_ms FROM requests ORDER BY id"
            ).fetchall()
            == core_before
        )
        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 3
        assert conn.execute("SELECT username FROM admin_users").fetchall() == users_before
        assert conn.execute("SELECT amount_micro_usd FROM ai_spend").fetchall() == spend_before
        assert conn.execute("SELECT COUNT(*) FROM request_original_ips").fetchone()[0] == 3
        assert private.read_original_ip(conn, request_id=ids_before[0], key=key) == "203.0.113.20"
        expected_pseudonym = hmac.new(HMAC_KEY, b"203.0.113.20", hashlib.sha256).hexdigest()
        assert (
            conn.execute(
                "SELECT client_pseudonym FROM requests WHERE id = ?", (ids_before[0],)
            ).fetchone()[0]
            == expected_pseudonym
        )
    finally:
        conn.close()
    assert target.read_bytes() == before_bytes


def test_reprocess_recovers_after_interruption(tmp_path, monkeypatch):
    _key_env(monkeypatch)
    root = tmp_path / "logs"
    _copy_source(root, "nginx_extended.txt")
    db = tmp_path / "resume.sqlite3"
    _import(db, root, "nginx_extended.txt")

    def _boom(_index):
        raise KeyboardInterrupt("synthetic interruption")

    with pytest.raises(KeyboardInterrupt):
        _reprocess(db, root, "nginx_extended.txt", capture=True, batch_size=1, after_batch=_boom)
    done = _reprocess(db, root, "nginx_extended.txt", capture=True)
    assert done.status == "completed" and done.rows_verified == 3
    again = _reprocess(db, root, "nginx_extended.txt", capture=True)
    assert again.rows_enriched == 0 and again.originals_captured == 0
    conn = connect(db, read_only=True)
    try:
        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 3
    finally:
        conn.close()


def test_reprocess_without_approved_source_stays_unavailable(tmp_path, monkeypatch):
    _key_env(monkeypatch)
    root = tmp_path / "logs"
    _copy_source(root, "nginx_extended.txt")
    db = tmp_path / "gone.sqlite3"
    _import(db, root, "nginx_extended.txt")
    (root / "nginx_extended.txt").unlink()
    result = _reprocess(db, root, "nginx_extended.txt")
    assert result.status == "unavailable"
    assert result.error_summary == "reprocess_unavailable:source_missing"
    conn = connect(db, read_only=True)
    try:
        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 3
    finally:
        conn.close()


def test_reprocess_changed_file_does_not_land_under_old_fingerprint(tmp_path, monkeypatch):
    _key_env(monkeypatch)
    root = tmp_path / "logs"
    target = _copy_source(root, "nginx_extended.txt")
    db = tmp_path / "changed.sqlite3"
    first = _import(db, root, "nginx_extended.txt")
    assert first.status == "completed"
    target.write_bytes(
        b'198.51.100.9 - - [27/Oct/2026:12:00:00 +0000] "GET /other HTTP/1.1" 200 1 '
        b'"-" "-" example.org HIT 0.010 text/html TLSv1.3 "0.005"\n'
    )
    result = _reprocess(db, root, "nginx_extended.txt")
    assert result.status == "unavailable"
    assert result.error_summary == "reprocess_unavailable:no_matching_rows"
    conn = connect(db, read_only=True)
    try:
        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 3
        assert (
            conn.execute("SELECT DISTINCT file_fingerprint FROM requests").fetchone()[0]
            == first.file_fingerprint
        )
    finally:
        conn.close()


def test_reprocess_cannot_replace_original_with_different_client(tmp_path, monkeypatch):
    key = _key_env(monkeypatch)
    root = tmp_path / "logs"
    _copy_source(root, "nginx_extended.txt")
    db = tmp_path / "keep.sqlite3"
    _import(db, root, "nginx_extended.txt", capture=True)
    conn = connect(db)
    try:
        victim = conn.execute(
            "SELECT request_id FROM request_original_ips ORDER BY request_id"
        ).fetchone()[0]
        other_aad = private.build_aad(
            site_id="elsewhere", source_id="t1b-source", file_fingerprint="fp", byte_offset=0
        )
        nonce, ciphertext = private.encrypt_ip("192.0.2.1", key=key, aad=other_aad)
        with conn:
            inserted = private.store_private_ip(
                conn, request_id=victim, nonce=nonce, ciphertext=ciphertext
            )
        assert inserted is False
        assert private.read_original_ip(conn, request_id=victim, key=key) == "203.0.113.20"
    finally:
        conn.close()


def test_reprocess_keeps_host_isolation_and_source_hash(tmp_path, monkeypatch):
    _key_env(monkeypatch)
    root = tmp_path / "logs"
    shutil_copy = _copy_source(root, "apache_vhost.txt")
    before = shutil_copy.read_bytes()
    db = tmp_path / "vhost.sqlite3"
    from app.ingestion.combined import APACHE_VHOST_COMBINED

    result = run_import(
        db,
        source=_source(root, "apache_vhost.txt", APACHE_VHOST_COMBINED, ["example.org"]),
        site_id=SITE,
        site_name="T1b site",
        site_hostname="example.org",
        server_type="apache",
        path_alias="apache_vhost.txt",
        hmac_key=HMAC_KEY,
    )
    assert result.records_skipped_foreign == 1
    repro = run_reprocess(
        db,
        source=_source(root, "apache_vhost.txt", APACHE_VHOST_COMBINED, ["example.org"]),
        site_id=SITE,
        site_hostname="example.org",
        server_type="apache",
        hmac_key=HMAC_KEY,
    )
    assert repro.status == "completed"
    # The foreign line was never stored, so it is simply not ours to
    # verify; the two stored rows verify and the counts stay exact.
    assert repro.rows_verified == 2 and repro.rows_mismatched == 0
    assert repro.rows_skipped_foreign == 0
    conn = connect(db, read_only=True)
    try:
        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 2
        hosts = conn.execute("SELECT allowed_hosts FROM log_sources").fetchone()[0]
        assert json.loads(hosts) == ["example.org"]
    finally:
        conn.close()
    assert shutil_copy.read_bytes() == before


# --- Retention ---


def test_retention_cascades_private_rows_and_preserves_owned_tables(tmp_path, monkeypatch):
    _key_env(monkeypatch)
    root = tmp_path / "logs"
    _copy_source(root, "nginx_extended.txt")
    db = tmp_path / "retention.sqlite3"
    _import(db, root, "nginx_extended.txt", capture=True)
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("pw"))
        issue_token(conn, name="t", site_id=SITE)
        old_ts = "2020-01-01T00:00:00+00:00"
        conn.execute("UPDATE requests SET ts_utc = ? WHERE id = 1", (old_ts,))
    raw = connect(db)
    try:
        with raw:
            deleted = apply_retention(raw, days=30, now=NOW)
        assert deleted == 1
        assert raw.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 2
        assert raw.execute("SELECT COUNT(*) FROM request_original_ips").fetchone()[0] == 2
        assert raw.execute("SELECT username FROM admin_users").fetchall() == [("admin",)]
        assert raw.execute("SELECT COUNT(*) FROM api_tokens").fetchone()[0] == 1
        assert raw.execute("SELECT COUNT(*) FROM log_sources").fetchone()[0] == 1
        assert raw.execute("SELECT COUNT(*) FROM imports").fetchone()[0] == 1
    finally:
        raw.close()


# --- Bounded multi-batch reprocess ---


def _combined_log_lines(count: int) -> bytes:
    lines = []
    for index in range(count):
        lines.append(
            f"203.0.113.{20 + (index % 200)} - - [27/Oct/2026:10:{index % 60:02d}:{(index * 7) % 60:02d} +0000] "
            f'"GET /batch/{index} HTTP/1.1" 200 10 "-" "BatchAgent/{index}"\n'
        )
    return "".join(lines).encode()


def test_reprocess_multibatch_bounded_no_full_materialization(tmp_path, monkeypatch):
    """35 rows with batch 10: keyset pages, exact counts, idempotent rerun."""
    from app.ingestion.combined import NGINX_COMBINED

    key = _key_env(monkeypatch)
    root = tmp_path / "logs"
    root.mkdir(parents=True, exist_ok=True)
    (root / "batch.log").write_bytes(_combined_log_lines(35))
    db = tmp_path / "batch.sqlite3"
    imported = run_import(
        db,
        source=_source(root, "batch.log", NGINX_COMBINED),
        site_id=SITE,
        site_name="T1b site",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="batch.log",
        hmac_key=HMAC_KEY,
    )
    assert imported.status == "completed" and imported.records_inserted == 35
    # Regression tripwire: the unbounded all-source helper is gone and
    # every read of stored request rows goes through a LIMIT page. The
    # trace hook watches the read connections reprocess opens itself, so
    # a reintroduced full-materialization SELECT fails loudly here.
    import app.db.reprocess as reprocess_mod

    assert not hasattr(repositories, "fetch_requests_for_reprocess")
    real_connect = reprocess_mod.connect
    seen: list[str] = []

    def _traced_connect(*args, **kwargs):
        conn = real_connect(*args, **kwargs)
        conn.set_trace_callback(seen.append)
        return conn

    monkeypatch.setattr(reprocess_mod, "connect", _traced_connect)
    batches: list[int] = []
    first = run_reprocess(
        db,
        source=_source(root, "batch.log", NGINX_COMBINED),
        site_id=SITE,
        site_hostname="example.org",
        server_type="nginx",
        hmac_key=HMAC_KEY,
        batch_size=10,
        capture_originals=True,
        ip_key=key,
        after_batch=batches.append,
    )
    assert first.status == "completed", first.error_summary
    assert first.rows_matched == 35
    assert first.rows_verified == 35
    assert first.rows_mismatched == 0
    assert first.originals_captured == 35
    assert len(batches) >= 4
    request_reads = [sql for sql in seen if "FROM requests" in sql]
    assert request_reads, "expected traced request reads"
    # COUNT(*) aggregates return one row; every row-materializing read
    # must carry a LIMIT page bound.
    materializing = [sql for sql in request_reads if "COUNT(" not in sql.upper()]
    assert materializing, "expected traced page reads"
    assert all("LIMIT" in sql.upper() for sql in materializing), materializing
    monkeypatch.undo()
    # The page bound holds no matter what limit a caller requests.
    probe = connect(db, read_only=True)
    try:
        assert (
            repositories.count_reprocess_rows(
                probe,
                source_id="t1b-source",
                file_fingerprint=first.file_fingerprint,
                site_id=SITE,
            )
            == 35
        )
        oversized = repositories.fetch_reprocess_page(
            probe,
            source_id="t1b-source",
            file_fingerprint=first.file_fingerprint,
            site_id=SITE,
            after_offset=-1,
            limit=5000,
        )
        assert len(oversized) <= repositories.REPROCESS_PAGE_MAX
        assert [int(row["byte_offset"]) for row in oversized] == sorted(
            int(row["byte_offset"]) for row in oversized
        )
    finally:
        probe.close()
    # Idempotent rerun: zero new rows, same IDs/HMAC/core, kept originals.
    before = _routine_values(connect(db, read_only=True))
    second = run_reprocess(
        db,
        source=_source(root, "batch.log", NGINX_COMBINED),
        site_id=SITE,
        site_hostname="example.org",
        server_type="nginx",
        hmac_key=HMAC_KEY,
        batch_size=10,
        capture_originals=True,
        ip_key=key,
    )
    assert second.status == "completed", second.error_summary
    assert second.rows_verified == 35 and second.rows_enriched == 0
    assert second.originals_captured == 0
    assert second.rows_mismatched == 0
    after_conn = connect(db, read_only=True)
    try:
        assert _routine_values(after_conn) == before
        assert after_conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 35
        assert private.count_private_rows(after_conn) == 35
        assert private.read_original_ip(after_conn, request_id=1, key=key).startswith("203.0.113.")
    finally:
        after_conn.close()


# --- Source/site binding ---


def _state_snapshot(db: Path) -> dict:
    conn = connect(db, read_only=True)
    try:
        tables = (
            "sites",
            "log_sources",
            "imports",
            "requests",
            "request_original_ips",
            "admin_users",
            "api_tokens",
            "ai_spend",
            "smoke_allowance",
        )
        counts = {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in tables
        }
        counts["routine"] = _routine_values(conn)
        counts["private_blob"] = json.dumps(
            conn.execute(
                "SELECT request_id, length(nonce), length(ciphertext)"
                " FROM request_original_ips ORDER BY request_id"
            ).fetchall()
        )
        return counts
    finally:
        conn.close()


def test_wrong_site_import_and_reprocess_rejected_without_state_change(tmp_path, monkeypatch):
    """The confirmed cross-site probe: same source/file/HMAC under site-b."""
    from app.ingestion.combined import NGINX_COMBINED

    key_a = _key_env(monkeypatch)
    key_b = _key_bytes(77)
    root = tmp_path / "logs"
    root.mkdir(parents=True, exist_ok=True)
    (root / "scope.log").write_bytes(_combined_log_lines(3))
    db = tmp_path / "scope.sqlite3"

    def _run_import(site: str, **kw):
        return run_import(
            db,
            source=_source(root, "scope.log", NGINX_COMBINED),
            site_id=site,
            site_name=f"Site {site}",
            site_hostname="example.org",
            server_type="nginx",
            path_alias="scope.log",
            hmac_key=HMAC_KEY,
            **kw,
        )

    first = _run_import("site-a")
    assert first.status == "completed" and first.records_inserted == 3
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("pw"))
        issue_token(conn, name="t", site_id="site-a")
    before = _state_snapshot(db)
    # Wrong-site import of the same source/file: fixed safe error, and
    # no new site, import row, request or private row appears.
    with pytest.raises(repositories.SourceBindingError) as excinfo:
        _run_import("site-b", capture_originals=True, ip_key=key_b)
    assert excinfo.value.code == repositories.SOURCE_SITE_MISMATCH_CODE
    assert _state_snapshot(db) == before
    # Wrong-site reprocess with capture and a valid separate key: the
    # exact confirmed probe now rejects instead of storing site-b
    # ciphertext that the owning site could never decrypt.
    repro = run_reprocess(
        db,
        source=_source(root, "scope.log", NGINX_COMBINED),
        site_id="site-b",
        site_hostname="example.org",
        server_type="nginx",
        hmac_key=HMAC_KEY,
        capture_originals=True,
        ip_key=key_b,
    )
    assert repro.status == "rejected"
    assert repro.error_summary == repositories.SOURCE_SITE_MISMATCH_CODE
    assert repro.rows_verified == 0 and repro.originals_captured == 0
    assert _state_snapshot(db) == before
    # Owning-site reads still work; nothing was attached elsewhere.
    conn = connect(db, read_only=True)
    try:
        assert private.count_private_rows(conn) == 0
        assert conn.execute("SELECT COUNT(*) FROM sites").fetchone()[0] == 1
    finally:
        conn.close()
    # The owning site can still enrich and read its own originals.
    ok = run_reprocess(
        db,
        source=_source(root, "scope.log", NGINX_COMBINED),
        site_id="site-a",
        site_hostname="example.org",
        server_type="nginx",
        hmac_key=HMAC_KEY,
        capture_originals=True,
        ip_key=key_a,
    )
    assert ok.status == "completed", ok.error_summary
    assert ok.rows_verified == 3 and ok.originals_captured == 3
    check = connect(db, read_only=True)
    try:
        assert private.read_original_ip(check, request_id=1, key=key_a).startswith("203.0.113.")
        with pytest.raises(PrivateUnavailable):
            private.read_original_ip(check, request_id=1, key=key_b)
    finally:
        check.close()


# --- Nullable legacy semantics and policy tags ---


def test_absent_upstream_stays_null_and_policy_tagged(tmp_path, monkeypatch):
    from app.ingestion.combined import NGINX_COMBINED, PARSER_POLICY_VERSION

    monkeypatch.delenv("ORIGINAL_IP_KEY", raising=False)
    root = tmp_path / "logs"
    root.mkdir(parents=True, exist_ok=True)
    (root / "plain.log").write_bytes(_combined_log_lines(2))
    db = tmp_path / "policy.sqlite3"
    result = run_import(
        db,
        source=_source(root, "plain.log", NGINX_COMBINED),
        site_id=SITE,
        site_name="T1b site",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="plain.log",
        hmac_key=HMAC_KEY,
    )
    assert result.status == "completed"
    conn = connect(db, read_only=True)
    try:
        rows = conn.execute(
            "SELECT request_time_ms, upstream_time_ms, upstream_count, policy_version,"
            " duration_ms FROM requests ORDER BY id"
        ).fetchall()
        assert len(rows) == 2
        for row in rows:
            # Absent timing infers nothing: NULL count, NULL policy-free
            # legacy duration, and the explicit current policy tag.
            assert row[0] is None and row[1] is None and row[2] is None
            assert row[3] == PARSER_POLICY_VERSION == "t1b.1"
            assert row[4] is None
    finally:
        conn.close()
