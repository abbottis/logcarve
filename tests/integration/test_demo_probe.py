"""Unit tests for the demo store probe (synthetic data only).

The probe guards seed/reset: only FRESH/PARTIAL stores may be written,
SEEDED stores only re-import, FOREIGN stores are refused untouched. These
tests pin the verdicts, including the Slice C legacy upgrade (a T8-only
store is PARTIAL, never SEEDED) and recovery after an interrupted first
init (rows landed, admin present, token missing).
"""

import importlib.util
import json
from pathlib import Path

from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user
from app.db.database import writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.sources import SourceConfig

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "combined" / "t8_smoke.txt"
RICH = ROOT / "tests" / "fixtures" / "combined" / "demo_rich_29_31oct.txt"
HMAC_KEY = b"synthetic-test-hmac-key"


def _load_probe():
    spec = importlib.util.spec_from_file_location(
        "probe_store", ROOT / "scripts" / "demo" / "probe_store.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _point_probe(monkeypatch, db):
    monkeypatch.setenv("DATABASE_PATH", str(db))
    monkeypatch.setenv("DEMO_FIXTURE_PATH", str(FIXTURE))
    monkeypatch.setenv("DEMO_RICH_FIXTURE_PATH", str(RICH))


def _import_both(db, root, site_id="default"):
    for name, blob in (("t8.log", FIXTURE.read_bytes()), ("rich.log", RICH.read_bytes())):
        (root / name).write_bytes(blob)
        run_import(
            db,
            source=SourceConfig(
                source_id="example-combined",
                format_id="nginx_combined",
                allowed_root=root,
                relative_path=name,
            ),
            site_id=site_id,
            site_name="s",
            site_hostname="example.org",
            server_type="nginx",
            path_alias=name,
            hmac_key=HMAC_KEY,
        )


def _seed_rows(db, root, with_admin=True):
    migrate(db)
    root.mkdir(exist_ok=True)
    if with_admin:
        with writer_transaction(db) as conn:
            create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
    _import_both(db, root)


def test_probe_pins_authoritative_fixture_digests():
    probe = _load_probe()
    import hashlib

    assert probe.FIXTURE_SHA256 == hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    assert probe.EXPECTED_ROWS == 30
    assert probe.RICH_SHA256 == hashlib.sha256(RICH.read_bytes()).hexdigest()
    assert probe.RICH_ROWS == 90
    assert probe.COMBINED_ROWS == 120


def test_fresh_store_without_database(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "absent.sqlite3"))
    monkeypatch.setenv("DEMO_FIXTURE_PATH", str(FIXTURE))
    monkeypatch.setenv("DEMO_RICH_FIXTURE_PATH", str(RICH))
    assert _load_probe().main() == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "FRESH"


def test_fixture_drift_is_foreign(tmp_path, monkeypatch, capsys):
    other = tmp_path / "other.log"
    other.write_bytes(b"foreign bytes")
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "absent.sqlite3"))
    monkeypatch.setenv("DEMO_FIXTURE_PATH", str(other))
    monkeypatch.setenv("DEMO_RICH_FIXTURE_PATH", str(RICH))
    assert _load_probe().main() == 0
    verdict = json.loads(capsys.readouterr().out)
    assert verdict["verdict"] == "FOREIGN"
    assert verdict["reason"] == "fixture digest drift"


def test_rich_fixture_drift_is_foreign(tmp_path, monkeypatch, capsys):
    other = tmp_path / "other-rich.log"
    other.write_bytes(b"foreign bytes")
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "absent.sqlite3"))
    monkeypatch.setenv("DEMO_FIXTURE_PATH", str(FIXTURE))
    monkeypatch.setenv("DEMO_RICH_FIXTURE_PATH", str(other))
    assert _load_probe().main() == 0
    verdict = json.loads(capsys.readouterr().out)
    assert verdict["verdict"] == "FOREIGN"
    assert verdict["reason"] == "rich fixture digest drift"


def test_seeded_store_reports_token_presence(tmp_path, monkeypatch, capsys):
    root = tmp_path / "logs"
    db = tmp_path / "seeded.sqlite3"
    _seed_rows(db, root, with_admin=True)
    _point_probe(monkeypatch, db)
    assert _load_probe().main() == 0
    verdict = json.loads(capsys.readouterr().out)
    assert verdict["verdict"] == "SEEDED"
    assert verdict["rows"] == 120
    assert verdict["t8_rows"] == 30
    assert verdict["rich_rows"] == 90
    # Interrupted first init: rows + admin landed, demo-client token missing.
    assert verdict["demo_token"] == 0


def test_interrupted_rows_without_admin_are_partial(tmp_path, monkeypatch, capsys):
    root = tmp_path / "logs"
    db = tmp_path / "partial.sqlite3"
    _seed_rows(db, root, with_admin=False)
    _point_probe(monkeypatch, db)
    assert _load_probe().main() == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "PARTIAL"


def test_empty_migrated_store_is_partial(tmp_path, monkeypatch, capsys):
    db = tmp_path / "empty.sqlite3"
    migrate(db)
    _point_probe(monkeypatch, db)
    assert _load_probe().main() == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "PARTIAL"


def test_foreign_site_is_refused(tmp_path, monkeypatch, capsys):
    root = tmp_path / "logs"
    root.mkdir()
    db = tmp_path / "foreign.sqlite3"
    migrate(db)
    (root / "access.log").write_bytes(FIXTURE.read_bytes())
    run_import(
        db,
        source=SourceConfig(
            source_id="example-combined",
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="access.log",
        ),
        site_id="elsewhere",
        site_name="s",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="access.log",
        hmac_key=HMAC_KEY,
    )
    _point_probe(monkeypatch, db)
    assert _load_probe().main() == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "FOREIGN"
