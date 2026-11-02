"""T5b3 helpers (integration): upgrade proofs and benchmark harness.

Synthetic fixtures only. The upgrade helper rehearses a v7-to-v8
in-place upgrade on a synthetic store (events, auth and spent ledger
seeded, follow schema removed): core event hashes and preserved-table
hashes must match before and after, migration 8 applies, and a
protected backup is left behind. A true v4 rehearsal builds the store
from the original migrations 1..4 with parser-derived legacy rows and
proves a faithful schema-4-to-8 upgrade with actual enrichment. The
benchmark harness runs a small deterministic smoke (the coordinator
owns 100k/1M) with expected-equals-observed counts.
"""

import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user
from app.db.database import connect, writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.sources import SourceConfig

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
LINE = '203.0.113.10 - - [27/Oct/2026:09:15:32 +0000] "GET /a HTTP/1.1" 200 512 "-" "T/1.0"\n'


def _load_script(name: str):
    path = REPO_ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.replace(".py", ""), path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _nonroot(monkeypatch):
    if os.geteuid() == 0:
        monkeypatch.setattr(os, "geteuid", lambda: 1000)


def _seed_store(db: Path, root: Path) -> None:
    (root / "a.log").write_text(LINE * 3, encoding="utf-8")
    result = run_import(
        db,
        source=SourceConfig(
            source_id="example-combined",
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="a.log",
        ),
        site_id="default",
        site_name="Demo",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="a.log",
        hmac_key=b"t5b3-helper-hmac-key",
    )
    assert result.status == "completed", result.error_summary
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("pw"))
        conn.execute(
            "INSERT INTO ai_spend (day, kind, amount_micro_usd, status, created_at)"
            " VALUES ('2026-11-01', 'charge', 500000, 'active', '2026-11-01T00:00:00+00:00')"
        )
        conn.execute(
            "INSERT INTO smoke_allowance (id, version, max_investigations,"
            " max_requests, max_micro_usd, used_investigations, used_requests,"
            " used_micro_usd, held_micro_usd, updated_at)"
            " VALUES (1, 1, 10, 100, 1000000, 2, 5, 500000, 0,"
            " '2026-11-01T00:00:00+00:00')"
        )


def _downgrade_to_v7(db: Path) -> None:
    conn = sqlite3.connect(db)
    try:
        conn.execute("DROP TABLE follow_generations")
        conn.execute("DROP TABLE follow_batches")
        conn.execute("DELETE FROM schema_migrations WHERE version = 8")
        conn.commit()
        assert conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 7
    finally:
        conn.close()


def _run_upgrade(monkeypatch, db: Path, root: Path, *extra: str) -> tuple[int, dict]:
    upgrade = _load_script("upgrade_demo.py")
    monkeypatch.setenv("HMAC_KEY", "t5b3-helper-hmac-key")
    monkeypatch.setenv("AI_ENABLED", "false")
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    monkeypatch.delenv("ORIGINAL_IP_KEY", raising=False)
    _nonroot(monkeypatch)
    argv = [
        "--db",
        str(db),
        "--backup-dir",
        str(db.parent / "backups"),
        "--source-root",
        str(root),
        "--fixture",
        "a.log",
        *extra,
    ]
    code = upgrade.main(argv)
    return code, upgrade


def test_upgrade_dry_run_changes_nothing(tmp_path, monkeypatch, capsys):
    upgrade = _load_script("upgrade_demo.py")
    db = tmp_path / "demo.sqlite3"
    root = tmp_path / "logs"
    root.mkdir()
    migrate(db)
    _seed_store(db, root)
    _downgrade_to_v7(db)
    before = db.stat().st_size
    _nonroot(monkeypatch)
    monkeypatch.setenv("HMAC_KEY", "t5b3-helper-hmac-key")
    monkeypatch.setenv("AI_ENABLED", "false")
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    code = upgrade.main(
        [
            "--db",
            str(db),
            "--backup-dir",
            str(tmp_path / "b"),
            "--source-root",
            str(root),
            "--fixture",
            "a.log",
            "--dry-run",
        ]
    )
    assert code == 0
    body = json.loads(capsys.readouterr().out)
    assert body["verdict"] == "dry-run"
    assert body["schema_version"] == 7
    assert body["request_rows"] == 3
    assert db.stat().st_size == before
    assert not (tmp_path / "b").exists()


def test_upgrade_v7_to_v8_preserves_core_and_ledger(tmp_path, monkeypatch, capsys):
    db = tmp_path / "demo.sqlite3"
    root = tmp_path / "logs"
    root.mkdir()
    migrate(db)
    _seed_store(db, root)
    _downgrade_to_v7(db)
    conn = connect(db, read_only=True)
    try:
        before_events = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
        before_spend = conn.execute("SELECT amount_micro_usd FROM ai_spend").fetchone()[0]
        before_allow = conn.execute("SELECT used_micro_usd FROM smoke_allowance").fetchone()[0]
    finally:
        conn.close()
    code, _upgrade = _run_upgrade(monkeypatch, db, root, "--no-enrich")
    assert code == 0, capsys.readouterr().out
    body = json.loads(capsys.readouterr().out)
    assert body["verdict"] == "upgraded"
    assert body["applied_migrations"] == [8]
    assert body["schema_version"] == 8
    assert body["request_rows"] == before_events == 3
    assert Path(body["backup"]).is_file()
    conn = connect(db, read_only=True)
    try:
        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 3
        assert conn.execute("SELECT amount_micro_usd FROM ai_spend").fetchone()[0] == before_spend
        assert (
            conn.execute("SELECT used_micro_usd FROM smoke_allowance").fetchone()[0] == before_allow
        )
        admins = conn.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0]
        assert admins == 1
    finally:
        conn.close()


def test_upgrade_posture_refusals(tmp_path, monkeypatch, capsys):
    upgrade = _load_script("upgrade_demo.py")
    db = tmp_path / "demo.sqlite3"
    root = tmp_path / "logs"
    root.mkdir()
    migrate(db)
    _nonroot(monkeypatch)
    monkeypatch.setenv("HMAC_KEY", "x")
    monkeypatch.setenv("AI_ENABLED", "false")
    base = [
        "--db",
        str(db),
        "--backup-dir",
        str(tmp_path / "b"),
        "--source-root",
        str(root),
        "--dry-run",
    ]
    monkeypatch.setenv("MODEL_API_KEY", "some-key")
    assert upgrade.main(base) == 2
    assert json.loads(capsys.readouterr().out)["reason"] == "posture"
    monkeypatch.delenv("MODEL_API_KEY")
    assert upgrade.main([*base, "--capture-originals"]) == 2
    assert json.loads(capsys.readouterr().out)["reason"] == "posture"


def test_benchmark_small_smoke_matches(tmp_path):
    bench = _load_script("benchmark_synthetic.py")
    out = tmp_path / "bench.json"
    code = bench.main(["--rows", "2500", "--seed", "20261102", "--out", str(out)])
    assert code == 0
    body = json.loads(out.read_text(encoding="utf-8"))
    assert body["verdict"] == "match"
    assert body["expected"]["accepted"] == body["observed"]["records_inserted"] == 2498
    assert body["expected"]["rejected"] == body["observed"]["lines_rejected"] == 2
    assert body["expected"]["slow_ge_1000ms"] == body["observed"]["slow_ge_1000ms"]
    assert body["observed"]["records_replayed"] == 2498
    assert body["observed"]["export_rows"] == 2498
    assert body["observed"]["export_stream_proof"] == "cursor"
    probe = body["observed"]["export_413_probe"]
    assert probe["exercised"] is True
    assert probe["http_status"] == 413 and probe["code"] == "export_too_large"
    assert body["measurements"]["peak_rss_import_mib"] > 0
    assert body["measurements"]["peak_rss_overall_mib"] > 0
    assert body["environment"]["rss_unit"]
    assert body["environment"]["architecture"]
    assert body["fixture"]["sha256"]


V4_HMAC = b"t5b3-v4-rehearsal-hmac"
V4_LINES = (
    '203.0.113.10 - - [27/Oct/2026:09:15:32 +0000] "GET /a HTTP/1.1" 200 512 "-" "T/1.0"\n',
    '198.51.100.7 - - [27/Oct/2026:09:16:01 +0000] "POST /b HTTP/1.1" 404 128 "https://example.org/" "T/1.0"\n',
    '192.0.2.44 - - [27/Oct/2026:09:17:44 +0000] "GET /c HTTP/1.1" 200 64 "-" "Other/2.0"\n',
)


def _seed_true_v4(db: Path, root: Path, monkeypatch) -> None:
    """Build a genuine schema-4 store from the original migrations 1..4.

    Event rows are inserted in the legacy v4 column shape with values
    parsed from the real fixture by the product parser, so the later
    read-only reprocess matches and enriches exactly these rows.
    """
    from app.db import migrations_runner, repositories
    from app.ingestion.combined import NGINX_COMBINED, CombinedRecord
    from app.ingestion.stream import fingerprint_source, iter_records

    staged = root.parent / "migrations-v4"
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
    assert migrate(db).applied == (1, 2, 3, 4)
    fixture = root / "a.log"
    fixture.write_text("".join(V4_LINES), encoding="utf-8")
    parsed = []
    for yielded in iter_records(
        fixture,
        source_id="example-combined",
        format_id=NGINX_COMBINED,
        hmac_key=V4_HMAC,
        capture_original=True,
    ):
        item, _original = yielded
        assert isinstance(item, CombinedRecord)
        parsed.append(item)
    assert len(parsed) == len(V4_LINES)
    fingerprint = fingerprint_source(fixture).logical_sha256
    with writer_transaction(db) as conn:
        repositories.ensure_site(
            conn,
            site_id="default",
            name="Demo",
            hostname="example.org",
            created_at="2026-11-01T00:00:00+00:00",
        )
        conn.execute(
            "INSERT INTO log_sources (id, site_id, server_type, format_id,"
            " path_alias, enabled) VALUES ('example-combined', 'default',"
            " 'nginx', 'nginx_combined', 'a.log', 1)"
        )
        import_id = repositories.create_import(
            conn,
            source_id="example-combined",
            file_fingerprint=fingerprint,
            file_size=fixture.stat().st_size,
            started_at="2026-11-01T00:00:00+00:00",
        )
        conn.executemany(
            "INSERT INTO requests (import_id, site_id, source_id, file_fingerprint,"
            " byte_offset, line_number, ts_utc, method, path, status, bytes,"
            " referer_host, user_agent, client_pseudonym, duration_ms)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    import_id,
                    "default",
                    "example-combined",
                    fingerprint,
                    item.byte_offset,
                    item.line_number,
                    item.timestamp_utc.isoformat(),
                    item.request.method,
                    item.request.target_path,
                    item.status,
                    item.bytes_sent,
                    item.referer_host,
                    item.user_agent,
                    item.client_pseudonym,
                    item.duration_ms,
                )
                for item in parsed
            ],
        )
        create_admin_user(conn, username="admin", password_hash=hash_password("pw"))
        conn.execute(
            "INSERT INTO ai_spend (day, kind, amount_micro_usd, status, created_at)"
            " VALUES ('2026-11-01', 'charge', 500000, 'active', '2026-11-01T00:00:00+00:00')"
        )
        conn.execute(
            "INSERT INTO smoke_allowance (id, version, max_investigations,"
            " max_requests, max_micro_usd, used_investigations, used_requests,"
            " used_micro_usd, held_micro_usd, updated_at)"
            " VALUES (1, 1, 10, 100, 1000000, 2, 5, 500000, 0,"
            " '2026-11-01T00:00:00+00:00')"
        )
        conn.execute(
            "INSERT INTO smoke_holds (amount_micro_usd, status, created_at)"
            " VALUES (1000, 'active', '2026-11-01T00:00:00+00:00')"
        )
    monkeypatch.setattr(migrations_runner, "MIGRATIONS_DIR", real)
    probe = sqlite3.connect(db)
    try:
        assert probe.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 4
        assert probe.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 3
    finally:
        probe.close()


def _run_v4_upgrade(monkeypatch, db: Path, root: Path, *extra: str) -> tuple[int, dict]:
    upgrade = _load_script("upgrade_demo.py")
    monkeypatch.setenv("HMAC_KEY", V4_HMAC.decode())
    monkeypatch.setenv("AI_ENABLED", "false")
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    monkeypatch.delenv("ORIGINAL_IP_KEY", raising=False)
    _nonroot(monkeypatch)
    argv = [
        "--db",
        str(db),
        "--backup-dir",
        str(db.parent / "backups"),
        "--source-root",
        str(root),
        "--fixture",
        "a.log",
        *extra,
    ]
    return upgrade.main(argv), upgrade


def test_upgrade_v4_to_v8_with_actual_enrichment(tmp_path, monkeypatch, capsys):
    from app.ingestion.combined import PARSER_POLICY_VERSION

    db = tmp_path / "demo.sqlite3"
    root = tmp_path / "logs"
    root.mkdir()
    _seed_true_v4(db, root, monkeypatch)
    code, _upgrade = _run_v4_upgrade(monkeypatch, db, root)
    assert code == 0, capsys.readouterr().out
    body = json.loads(capsys.readouterr().out)
    assert body["verdict"] == "upgraded"
    assert body["schema_version"] == 8
    assert body["applied_migrations"] == [5, 6, 7, 8]
    assert body["request_rows"] == 3
    assert len(body["enrichment"]) == 1
    entry = body["enrichment"][0]
    assert entry["fixture"] == "a.log"
    assert entry["status"] == "completed"
    assert entry["rows_matched"] == entry["rows_enriched"] == 3
    assert entry["rows_mismatched"] == entry["rows_unparseable"] == 0
    assert entry["rows_skipped_foreign"] == 0
    assert Path(body["backup"]).is_file()
    import stat as statmod

    assert statmod.S_IMODE(Path(body["backup"]).stat().st_mode) == 0o600
    conn = connect(db, read_only=True)
    try:
        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 3
        enriched = conn.execute(
            "SELECT format_id, policy_version, duration_ms FROM requests ORDER BY id"
        ).fetchall()
        assert [(row[0], row[1]) for row in enriched] == [
            ("nginx_combined", PARSER_POLICY_VERSION)
        ] * 3
        assert [row[2] for row in enriched] == [None] * 3
        assert conn.execute("SELECT amount_micro_usd FROM ai_spend").fetchone()[0] == 500000
        assert conn.execute("SELECT used_micro_usd FROM smoke_allowance").fetchone()[0] == 500000
        assert conn.execute("SELECT COUNT(*) FROM smoke_holds").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0] == 1
    finally:
        conn.close()


def test_upgrade_changed_fixture_fails_loudly_without_restore(tmp_path, monkeypatch, capsys):
    db = tmp_path / "demo.sqlite3"
    root = tmp_path / "logs"
    root.mkdir()
    _seed_true_v4(db, root, monkeypatch)
    (root / "a.log").write_text("".join(line.replace("/a", "/zzz") for line in V4_LINES))
    code, _upgrade = _run_v4_upgrade(monkeypatch, db, root)
    assert code == 1
    body = json.loads(capsys.readouterr().out)
    assert body["verdict"] == "failed"
    assert any("enrichment" in error for error in body["errors"])
    assert body["enrichment"][0]["status"] in ("unavailable", "failed")
    assert Path(body["backup"]).is_file()
    live = connect(db, read_only=True)
    backup_conn = sqlite3.connect(str(Path(body["backup"])))
    try:
        assert live.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 8
        assert backup_conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 4
        assert live.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 3
        assert live.execute("SELECT amount_micro_usd FROM ai_spend").fetchone()[0] == 500000
    finally:
        live.close()
        backup_conn.close()


def test_upgrade_preflight_fails_before_any_write(tmp_path, monkeypatch, capsys):
    upgrade = _load_script("upgrade_demo.py")
    db = tmp_path / "demo.sqlite3"
    root = tmp_path / "logs"
    root.mkdir()
    _seed_true_v4(db, root, monkeypatch)
    _nonroot(monkeypatch)
    monkeypatch.setenv("HMAC_KEY", V4_HMAC.decode())
    monkeypatch.setenv("AI_ENABLED", "false")
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    monkeypatch.delenv("ORIGINAL_IP_KEY", raising=False)
    base = [
        "--db",
        str(db),
        "--backup-dir",
        str(tmp_path / "backups"),
        "--source-root",
        str(root),
        "--fixture",
        "a.log",
        "--capture-originals",
    ]
    assert upgrade.main([*base, "--dry-run"]) == 2
    assert json.loads(capsys.readouterr().out)["reason"] == "posture"
    assert not (tmp_path / "backups").exists()
    conn = connect(db, read_only=True)
    try:
        assert conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 4
    finally:
        conn.close()


def test_cli_follow_help_lists_bounds():
    code = subprocess.run(
        [sys.executable, "-m", "app.db.cli", "follow", "--help"],
        capture_output=True,
        check=False,
        cwd=REPO_ROOT,
    ).returncode
    assert code == 0
    replay = subprocess.run(
        [sys.executable, "-m", "app.db.cli", "replay-archive", "--help"],
        capture_output=True,
        check=False,
        cwd=REPO_ROOT,
    ).returncode
    assert replay == 0
