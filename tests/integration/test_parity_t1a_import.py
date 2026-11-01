"""T1a import integration: gzip identity, series, isolation, auto/custom.

Synthetic data only, under pytest tmp dirs. The 120-row baseline and
legacy HMAC/replay expectations are untouched; plaintext T6 behavior
regressions are covered by the existing suite plus the clean-digest
assertion here.
"""

import gzip
import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.db import repositories
from app.db.database import connect
from app.db.importer import run_import
from app.ingestion.custom import load_spec_file
from app.ingestion.sources import HostFilter, SourceConfig

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
T1A = FIXTURES / "parity_t1a"
HMAC_KEY = b"parity-t1a-hmac-key"
NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)


def _source(root: Path, relative: str, fmt: str, **kwargs) -> SourceConfig:
    return SourceConfig(
        source_id="t1a-source", format_id=fmt, allowed_root=root, relative_path=relative, **kwargs
    )


def _run(db: Path, root: Path, relative: str, fmt: str, **kwargs):
    defaults = {
        "source": _source(root, relative, fmt),
        "site_id": "default",
        "site_name": "Example site",
        "site_hostname": "example.org",
        "server_type": "nginx",
        "path_alias": relative,
        "hmac_key": HMAC_KEY,
    }
    defaults.update(kwargs)
    return run_import(db, **defaults)


def _row_count(db: Path) -> int:
    conn = connect(db, read_only=True)
    try:
        return repositories.count_events(conn)
    finally:
        conn.close()


def test_gzip_replays_plain_without_duplicates(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    payload = (T1A / "common.txt").read_bytes()
    (root / "plain.log").write_bytes(payload)
    (root / "archived.log.gz").write_bytes(gzip.compress(payload, mtime=0))
    db = tmp_path / "t1a.sqlite3"
    first = _run(db, root, "plain.log", "common")
    assert (first.records_inserted, first.records_replayed) == (4, 0)
    assert first.is_gzip is False
    second = _run(db, root, "archived.log.gz", "common")
    # Same logical bytes at the same positions: full replay, no duplicates.
    assert second.is_gzip is True
    assert second.file_fingerprint == first.file_fingerprint
    assert (second.records_inserted, second.records_replayed) == (0, 4)
    assert _row_count(db) == 4
    # And the reverse order replays too.
    db2 = tmp_path / "t1b.sqlite3"
    _run(db2, root, "archived.log.gz", "common")
    again = _run(db2, root, "plain.log", "common")
    assert (again.records_inserted, again.records_replayed) == (0, 4)
    assert _row_count(db2) == 4


def test_gzip_clean_digest_matches_logical_bytes(tmp_path):
    from app.db.importer import sha256_file

    root = tmp_path / "logs"
    root.mkdir()
    payload = (T1A / "nginx_extended.txt").read_bytes()
    (root / "ext.gz").write_bytes(gzip.compress(payload, mtime=0))
    db = tmp_path / "t1a.sqlite3"
    result = _run(db, root, "ext.gz", "nginx_extended")
    assert result.status == "completed"
    assert result.source_changed is False
    assert result.error_summary is None
    assert result.consumed_sha256 == hashlib.sha256(payload).hexdigest()
    assert result.file_fingerprint == hashlib.sha256(payload).hexdigest()
    # Compressed bytes differ from logical bytes: the stored identity is
    # logical, never the compressed hash.
    assert sha256_file(root / "ext.gz") != result.file_fingerprint


def test_gzip_failure_records_fixed_code(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    blob = bytearray(gzip.compress((T1A / "common.txt").read_bytes(), mtime=0))
    (root / "cut.gz").write_bytes(bytes(blob[: len(blob) // 2]))
    db = tmp_path / "t1a.sqlite3"
    result = _run(db, root, "cut.gz", "common")
    assert result.status == "failed"
    assert result.error_summary == "interrupted:gzip_truncated"
    conn = connect(db, read_only=True)
    try:
        stored = conn.execute("SELECT status, error_summary FROM imports").fetchone()
    finally:
        conn.close()
    assert tuple(stored) == ("failed", "interrupted:gzip_truncated")


def test_host_isolation_end_to_end_with_counts(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "vhost.log").write_bytes((T1A / "apache_vhost.txt").read_bytes())
    db = tmp_path / "t1a.sqlite3"
    result = _run(
        db,
        root,
        "vhost.log",
        "apache_vhost_combined",
        host_filter=HostFilter(["example.org"]),
    )
    assert result.status == "completed"
    assert (result.records_inserted, result.records_skipped_foreign) == (2, 1)
    assert result.lines_total == 3
    conn = connect(db, read_only=True)
    try:
        paths = [row["path"] for row in repositories.fetch_events_by_path(conn, path="/foreign")]
    finally:
        conn.close()
    assert paths == []


def test_auto_format_and_custom_end_to_end(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "ext.log").write_bytes((T1A / "nginx_extended.txt").read_bytes())
    (root / "acme.log").write_bytes((T1A / "custom_acme.txt").read_bytes())
    db = tmp_path / "t1a.sqlite3"
    auto = _run(db, root, "ext.log", "auto")
    assert auto.status == "completed"
    assert auto.records_inserted == 3
    spec = load_spec_file(T1A / "custom_acme.json")
    custom = _run(db, root, "acme.log", spec.format_id, custom_format=spec)
    assert custom.status == "completed"
    assert custom.records_inserted == 2
    assert _row_count(db) == 5


def test_auto_vhost_defaults_to_site_hostname_filter(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "vhost.log").write_bytes((T1A / "apache_vhost.txt").read_bytes())
    db = tmp_path / "t1a.sqlite3"
    # No explicit filter: auto resolves to the vhost preset and the site
    # hostname becomes the filter, so the foreign host skips instead of
    # being silently counted as this site.
    result = _run(db, root, "vhost.log", "auto")
    assert result.status == "completed"
    assert (result.records_inserted, result.records_skipped_foreign) == (2, 1)


def test_ambiguous_auto_fails_with_fixed_code(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "twins.log").write_bytes(
        b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1" 200 10 "-" "-"\n'
        b'198.51.100.7 - - [27/Oct/2026:10:16:00 +0100] "GET /y HTTP/1.1" 200 5 "-" "-"\n'
    )
    db = tmp_path / "t1a.sqlite3"
    with pytest.raises(Exception) as excinfo:
        _run(db, root, "twins.log", "auto")
    assert getattr(excinfo.value, "code", "") == "interrupted:format_ambiguous"
    conn = connect(db, read_only=True)
    try:
        stored = conn.execute("SELECT status, error_summary FROM imports").fetchone()
    finally:
        conn.close()
    assert tuple(stored) == ("failed", "interrupted:format_ambiguous")


def test_file_series_cli_reports_per_file_outcomes(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "a.log").write_bytes((T1A / "common.txt").read_bytes())
    (root / "b.log.gz").write_bytes(gzip.compress((T1A / "common.txt").read_bytes(), mtime=0))
    db = tmp_path / "series.sqlite3"
    env = dict(os.environ)
    env["HMAC_KEY"] = "parity-t1a-hmac-key"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "app.db.cli",
            "--db",
            str(db),
            "import",
            "--source-id",
            "t1a-source",
            "--format",
            "common",
            "--root",
            str(root),
            "--path",
            "a.log",
            "--path",
            "b.log.gz",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    summary = json.loads(proc.stdout)
    assert summary["status"] == "completed"
    assert [entry["file_index"] for entry in summary["files"]] == [0, 1]
    assert summary["files"][0]["is_gzip"] is False
    assert summary["files"][1]["is_gzip"] is True
    # Same logical content: the gzipped series member replays the plain one.
    assert summary["files"][1]["records_inserted"] == 0
    assert summary["files"][1]["records_replayed"] == 4
    assert _row_count(db) == 4


def test_series_interruption_recovers_per_file(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "a.log").write_bytes((T1A / "common.txt").read_bytes())
    # Distinct content per series member: identical bytes under one source
    # would correctly replay instead of inserting (tested elsewhere).
    (root / "b.log").write_bytes(
        (T1A / "common.txt").read_bytes()
        + b'192.0.2.1 - - [28/Oct/2026:09:00:00 +0100] "GET /extra HTTP/1.1" 200 7\n'
    )
    db = tmp_path / "t1a.sqlite3"

    def crash_on_first_batch(index: int) -> None:
        if index == 1:
            raise RuntimeError("simulated crash")

    with pytest.raises(RuntimeError, match="simulated crash"):
        _run(db, root, "a.log", "common", batch_size=1, after_batch=crash_on_first_batch)
    # Committed batches survive; the second series member imports cleanly.
    second = _run(db, root, "b.log", "common")
    assert second.status == "completed"
    assert second.records_inserted == 5
    rerun = _run(db, root, "a.log", "common")
    assert rerun.status == "completed"
    assert _row_count(db) == 9


def test_source_bytes_unchanged_by_imports(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "vhost.log").write_bytes((T1A / "apache_vhost.txt").read_bytes())
    (root / "ext.gz").write_bytes(gzip.compress((T1A / "nginx_extended.txt").read_bytes()))
    before = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in ("vhost.log", "ext.gz")
    }
    db = tmp_path / "t1a.sqlite3"
    _run(db, root, "vhost.log", "apache_vhost_combined", host_filter=HostFilter(["example.org"]))
    _run(db, root, "ext.gz", "nginx_extended")
    after = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in before}
    assert after == before
