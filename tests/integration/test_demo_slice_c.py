"""Slice C additive demo dataset: safety, upgrade, replay, refusal (synthetic only).

The original 30-row T8 fixture stays byte-identical; the 90-row rich
fixture (29-31 Oct 2026, outside the T8 window) is additive under the
unchanged source identity ``example-combined``. Expectations come from
``tests/fixtures/expected/demo_slice_c.json`` (hand-derived with
awk/grep, never the product parser); the service/API assertions below
prove the product agrees with those independent counts.

Covers: fresh seed, legacy T8-only upgrade (T8 rows untouched),
restart persistence, repeat/replay-zero with preserved history,
deterministic partial interruption with convergence, foreign refusal
(mutated bytes, unknown provenance, foreign rows) leaving the store
untouched, and unchanged auth/session/token/usage state.
"""

import hashlib
import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.analytics import service as analytics_service
from app.analytics.contracts import AnalyticsFilter, ExplorerQuery, TimeWindow
from app.analytics.rules import load_rules
from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user, issue_token
from app.db.database import connect, writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.sources import SourceConfig

ROOT = Path(__file__).resolve().parent.parent.parent
T8 = ROOT / "tests" / "fixtures" / "combined" / "t8_smoke.txt"
RICH = ROOT / "tests" / "fixtures" / "combined" / "demo_rich_29_31oct.txt"
EXPECTED = json.loads((ROOT / "tests" / "fixtures" / "expected" / "demo_slice_c.json").read_text())
HMAC_KEY = b"synthetic-test-hmac-key"
COMBINED_WINDOW = TimeWindow(
    time_from=datetime(2026, 10, 26, tzinfo=UTC),
    time_to=datetime(2026, 11, 1, tzinfo=UTC),
)


def _load_probe():
    spec = importlib.util.spec_from_file_location(
        "probe_store", ROOT / "scripts" / "demo" / "probe_store.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _probe_verdict(monkeypatch, capsys, db):
    monkeypatch.setenv("DATABASE_PATH", str(db))
    monkeypatch.setenv("DEMO_FIXTURE_PATH", str(T8))
    monkeypatch.setenv("DEMO_RICH_FIXTURE_PATH", str(RICH))
    assert _load_probe().main() == 0
    return json.loads(capsys.readouterr().out)


def _write_logs(root: Path):
    root.mkdir(exist_ok=True)
    (root / "t8.log").write_bytes(T8.read_bytes())
    (root / "rich.log").write_bytes(RICH.read_bytes())
    return root


def _import(db, root, name, **kwargs):
    return run_import(
        db,
        source=SourceConfig(
            source_id="example-combined",
            format_id="nginx_combined",
            allowed_root=root,
            relative_path=name,
        ),
        site_id="default",
        site_name="s",
        site_hostname="example.org",
        server_type="nginx",
        path_alias=name,
        hmac_key=HMAC_KEY,
        **kwargs,
    )


def _seed_admin(db):
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))


def _counts(db):
    conn = connect(db, read_only=True)
    try:
        return {
            "rows": conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0],
            "imports": conn.execute("SELECT COUNT(*) FROM imports").fetchone()[0],
            "users": conn.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0],
            "tokens": conn.execute("SELECT COUNT(*) FROM api_tokens").fetchone()[0],
        }
    finally:
        conn.close()


def _rules():
    return list(load_rules(ROOT / "config" / "bot_rules.yaml").rules)


def test_fixtures_pinned_and_t8_untouched():
    assert T8.read_bytes()  # fails loudly if the mount is missing
    assert hashlib.sha256(T8.read_bytes()).hexdigest() == EXPECTED["provenance"]["t8"]["sha256"]
    assert hashlib.sha256(RICH.read_bytes()).hexdigest() == EXPECTED["provenance"]["rich"]["sha256"]
    assert len(T8.read_bytes().splitlines()) == 30
    assert len(RICH.read_bytes().splitlines()) == 90
    # Rich rows live strictly outside the T8 exclusive window (26/27/28 Oct).
    days = [line.split(b"[")[1].split(b"/")[0] for line in RICH.read_bytes().splitlines()]
    assert sorted(set(days)) == [b"29", b"30", b"31"]


def test_fresh_seed_converges_to_expected_totals(tmp_path, monkeypatch, capsys):
    root = _write_logs(tmp_path / "logs")
    db = tmp_path / "fresh.sqlite3"
    assert _probe_verdict(monkeypatch, capsys, db)["verdict"] == "FRESH"
    migrate(db)
    _seed_admin(db)
    t8_result = _import(db, root, "t8.log")
    rich_result = _import(db, root, "rich.log")
    assert (t8_result.status, t8_result.records_inserted) == ("completed", 30)
    assert (rich_result.status, rich_result.records_inserted) == ("completed", 90)
    verdict = _probe_verdict(monkeypatch, capsys, db)
    assert verdict["verdict"] == "SEEDED"
    assert verdict["rows"] == 120

    rules = _rules()
    conn = connect(db, read_only=True)
    try:
        summary = analytics_service.summarize(
            conn, AnalyticsFilter(site_id="default", window=COMBINED_WINDOW), rules
        )
    finally:
        conn.close()
    exp = EXPECTED["combined"]
    assert summary["totals"]["requests"] == exp["rows"] == 120
    assert summary["totals"]["bytes_total"] == exp["bytes_total"] == 127744
    assert {row["status"]: row["requests"] for row in summary["status_distribution"]} == {
        int(k): v for k, v in exp["status"].items()
    }


def test_rich_traffic_and_bot_counts_match_independent_expectations(tmp_path):
    root = _write_logs(tmp_path / "logs")
    db = tmp_path / "counts.sqlite3"
    migrate(db)
    _import(db, root, "t8.log")
    _import(db, root, "rich.log")
    rules = _rules()
    conn = connect(db, read_only=True)
    try:
        breakdown = analytics_service.traffic_breakdown(
            conn, AnalyticsFilter(site_id="default", window=COMBINED_WINDOW), rules
        )
        crawlers = analytics_service.crawler_claims(
            conn, AnalyticsFilter(site_id="default", window=COMBINED_WINDOW), rules
        )
    finally:
        conn.close()
    exp = EXPECTED["combined"]
    assert {row["traffic"]: row["requests"] for row in breakdown["buckets"]} == exp["traffic"]
    named = {finding.rule_id: finding.counts["requests"] for finding in crawlers}
    for rule_id, count in exp["named_bots"].items():
        assert named.get(rule_id) == count, rule_id
    # Rule-matched rows are exactly claimed_bot + other_automation; the
    # browser_like + unknown rows carry no rule id by design.
    assert sum(named.values()) == exp["traffic"]["claimed_bot"] + exp["traffic"]["other_automation"]


def test_legacy_t8_store_upgrades_additively(tmp_path, monkeypatch, capsys):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "t8.log").write_bytes(T8.read_bytes())
    (root / "rich.log").write_bytes(RICH.read_bytes())
    db = tmp_path / "legacy.sqlite3"
    migrate(db)
    _seed_admin(db)
    before_t8 = _import(db, root, "t8.log")
    assert (before_t8.status, before_t8.records_inserted) == ("completed", 30)
    conn = connect(db, read_only=True)
    try:
        t8_paths_before = conn.execute(
            "SELECT path, status, method FROM requests ORDER BY ts_utc, byte_offset"
        ).fetchall()
    finally:
        conn.close()
    verdict = _probe_verdict(monkeypatch, capsys, db)
    assert verdict["verdict"] == "PARTIAL"
    assert verdict["t8_rows"] == 30 and verdict["rich_rows"] == 0

    rich_result = _import(db, root, "rich.log")
    assert (rich_result.status, rich_result.records_inserted) == ("completed", 90)
    conn = connect(db, read_only=True)
    try:
        t8_paths_after = conn.execute(
            "SELECT path, status, method FROM requests WHERE file_fingerprint = ?"
            " ORDER BY ts_utc, byte_offset",
            (EXPECTED["provenance"]["t8"]["sha256"],),
        ).fetchall()
    finally:
        conn.close()
    assert t8_paths_after == t8_paths_before
    verdict = _probe_verdict(monkeypatch, capsys, db)
    assert verdict["verdict"] == "SEEDED"
    assert verdict["rows"] == 120


def test_replay_zero_preserves_history(tmp_path, monkeypatch, capsys):
    root = _write_logs(tmp_path / "logs")
    db = tmp_path / "replay.sqlite3"
    migrate(db)
    _seed_admin(db)
    _import(db, root, "t8.log")
    _import(db, root, "rich.log")
    history_before = _counts(db)
    again_t8 = _import(db, root, "t8.log")
    again_rich = _import(db, root, "rich.log")
    assert (again_t8.records_inserted, again_t8.records_replayed) == (0, 30)
    assert (again_rich.records_inserted, again_rich.records_replayed) == (0, 90)
    assert _counts(db)["rows"] == history_before["rows"] == 120
    # Re-imports append import rows (audit history), never user/token rows.
    assert _counts(db)["imports"] == history_before["imports"] + 2
    assert _counts(db)["users"] == history_before["users"] == 1
    assert _probe_verdict(monkeypatch, capsys, db)["verdict"] == "SEEDED"


def test_restart_persistence(tmp_path):
    root = _write_logs(tmp_path / "logs")
    db = tmp_path / "restart.sqlite3"
    migrate(db)
    _import(db, root, "t8.log")
    _import(db, root, "rich.log")
    before = _counts(db)
    # A fresh process handle over the same file sees the same store.
    assert _counts(db) == before
    assert before["rows"] == 120


def test_partial_interruption_converges_without_duplicates(tmp_path, monkeypatch, capsys):
    root = _write_logs(tmp_path / "logs")
    db = tmp_path / "interrupted.sqlite3"
    migrate(db)
    _seed_admin(db)
    _import(db, root, "t8.log")

    def _crash_after_first_batch(batch_index):
        if batch_index >= 1:
            raise OSError("synthetic mid-import crash")

    with pytest.raises(IOError, match="synthetic mid-import crash"):
        _import(db, root, "rich.log", batch_size=10, after_batch=_crash_after_first_batch)
    verdict = _probe_verdict(monkeypatch, capsys, db)
    assert verdict["verdict"] == "PARTIAL"
    assert verdict.get("interrupted") is True
    partial_rows = verdict["rows"]
    assert 30 < partial_rows < 120

    resumed = _import(db, root, "rich.log")
    assert resumed.status == "completed"
    verdict = _probe_verdict(monkeypatch, capsys, db)
    assert verdict["verdict"] == "SEEDED"
    assert verdict["rows"] == 120
    # The superseded failed attempt leaves its audit row but no duplicates.
    conn = connect(db, read_only=True)
    try:
        failed = conn.execute(
            "SELECT COUNT(*) FROM imports WHERE status != 'completed'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert failed == 1


def test_mutated_rich_bytes_are_refused_untouched(tmp_path, monkeypatch, capsys):
    root = _write_logs(tmp_path / "logs")
    db = tmp_path / "mutated.sqlite3"
    migrate(db)
    _seed_admin(db)
    _import(db, root, "t8.log")
    (root / "rich.log").write_bytes(
        RICH.read_bytes().replace(b"GET /blog/ HTTP/1.1", b"GET /foreign-sentinel HTTP/1.1", 1)
    )
    mutated = _import(db, root, "rich.log")
    assert mutated.status == "completed"
    before = _counts(db)
    verdict = _probe_verdict(monkeypatch, capsys, db)
    # The probe pins the committed digest, not the drifted mount: the store
    # now carries unknown-provenance rows and must be refused untouched.
    assert verdict["verdict"] == "FOREIGN"
    assert _counts(db) == before


def test_foreign_rows_are_refused(tmp_path, monkeypatch, capsys):
    root = _write_logs(tmp_path / "logs")
    db = tmp_path / "foreign.sqlite3"
    migrate(db)
    _import(db, root, "t8.log")
    _import(db, root, "rich.log")
    before = _counts(db)
    run_import(
        db,
        source=SourceConfig(
            source_id="example-combined",
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="t8.log",
        ),
        site_id="elsewhere",
        site_name="s",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="t8.log",
        hmac_key=HMAC_KEY,
    )
    assert _probe_verdict(monkeypatch, capsys, db)["verdict"] == "FOREIGN"
    # Replay identity is site-agnostic, so the cross-site attempt inserts no
    # rows; the FOREIGN verdict (extra site) is what stops the seeder.
    assert _counts(db)["rows"] == before["rows"] == 120


def test_auth_token_and_usage_state_survive_upgrade(tmp_path, monkeypatch, capsys):
    from app.db.database import writer_transaction as _wt

    root = _write_logs(tmp_path / "logs")
    db = tmp_path / "state.sqlite3"
    migrate(db)
    # Seeder order: rows land before the token is issued (token site binding
    # requires the site row, and the upgrade must preserve all three).
    _import(db, root, "t8.log")
    with _wt(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
        _, token_before = issue_token(
            conn, name="demo-client", site_id="default", scopes=("analytics:read",)
        )
        admin_before = conn.execute("SELECT id, username FROM admin_users ORDER BY id").fetchall()
        token_row_before = conn.execute(
            "SELECT name, site_id, scopes FROM api_tokens ORDER BY id"
        ).fetchall()
        conn.execute(
            "INSERT INTO ai_spend (day, kind, amount_micro_usd, status, created_at)"
            " VALUES ('2026-10-29', 'charge', 1500000, 'charged', '2026-10-29T00:00:00+00:00')"
        )
        spend_before = conn.execute(
            "SELECT day, kind, amount_micro_usd, status FROM ai_spend"
        ).fetchall()
    # Legacy upgrade imports only the missing rich rows.
    upgrade = _import(db, root, "rich.log")
    assert (upgrade.status, upgrade.records_inserted) == ("completed", 90)
    with _wt(db) as conn:
        assert (
            conn.execute("SELECT id, username FROM admin_users ORDER BY id").fetchall()
            == admin_before
        )
        assert (
            conn.execute("SELECT name, site_id, scopes FROM api_tokens ORDER BY id").fetchall()
            == token_row_before
        )
        assert (
            conn.execute("SELECT day, kind, amount_micro_usd, status FROM ai_spend").fetchall()
            == spend_before
        )
    assert isinstance(token_before, str) and token_before
    assert _probe_verdict(monkeypatch, capsys, db)["verdict"] == "SEEDED"


def test_candidate_procedure_is_isolated_and_tracked(tmp_path):
    """The isolated candidate verification uses a unique project/port and
    tracked sources only: it must never address the persistent demo
    project, its secrets, or the Docker socket. No Docker here; this
    stages the export layout and checks the documented contract plus shell
    syntax (coordinator executes the script against real Docker)."""
    import shutil
    import subprocess

    export = tmp_path / "export"
    (export / "scripts" / "demo").mkdir(parents=True)
    for name in ("lib.sh", "init.sh", "seed.sh", "verify_candidate.sh", "probe_store.py"):
        shutil.copy(ROOT / "scripts" / "demo" / name, export / "scripts" / "demo" / name)
    fixture_dir = export / "tests" / "fixtures" / "combined"
    fixture_dir.mkdir(parents=True)
    shutil.copy(T8, fixture_dir / "t8_smoke.txt")
    shutil.copy(RICH, fixture_dir / "demo_rich_29_31oct.txt")
    candidate = (export / "scripts" / "demo" / "verify_candidate.sh").read_text()
    assert 'PROJECT="logcarve-demo-candidate"' in candidate
    assert '"8091"' in candidate or ":8091:" in candidate or "8091:8080" in candidate
    assert "git -C" in candidate and "archive HEAD" in candidate
    assert EXPECTED["provenance"]["t8"]["sha256"] in candidate
    assert EXPECTED["provenance"]["rich"]["sha256"] in candidate
    assert "0 30" in candidate and "0 90" in candidate
    assert 'AI_ENABLED: "false"' in candidate and 'MODEL_API_KEY: ""' in candidate
    # Never the persistent demo identity, its secrets, or the socket.
    assert "docker.sock" not in candidate
    assert "local-demo-secrets" not in candidate
    assert "-p logcarve-demo " not in candidate and "-p logcarve-demo\n" not in candidate
    assert "logcarve-demo:" not in candidate
    for name in ("seed.sh", "verify_candidate.sh"):
        result = subprocess.run(
            ["sh", "-n", str(export / "scripts" / "demo" / name)],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert result.returncode == 0, result.stderr


def test_no_raw_ips_or_lines_leak_through_combined_analytics(tmp_path):
    root = _write_logs(tmp_path / "logs")
    db = tmp_path / "leak.sqlite3"
    migrate(db)
    _import(db, root, "t8.log")
    _import(db, root, "rich.log")
    rules = _rules()
    conn = connect(db, read_only=True)
    try:
        explorer = analytics_service.request_explorer(
            conn,
            ExplorerQuery(
                filt=AnalyticsFilter(site_id="default", window=COMBINED_WINDOW, limit=120)
            ),
            rules,
        )
        findings = analytics_service.security_findings(
            conn, AnalyticsFilter(site_id="default", window=COMBINED_WINDOW), rules
        )
    finally:
        conn.close()
    assert explorer["total_rows"] == 120
    blob = json.dumps(
        {
            "explorer": explorer["items"],
            "findings": [
                {"rule_id": f.rule_id, "counts": f.counts, "evidence": f.evidence} for f in findings
            ],
        }
    )
    for raw in ("192.0.2.", "198.51.100.", "203.0.113."):
        assert raw not in blob
    assert "token=synthetic" not in blob
