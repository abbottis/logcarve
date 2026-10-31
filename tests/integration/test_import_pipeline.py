"""T3 import pipeline tests: replay, interruption, recovery, retention,
backup/restore, CLI and the 100k generated-record benchmark.

All sources, databases and generated logs are synthetic and live under
pytest tmp dirs or the process environment. Nothing is committed.
"""

import json
import os
import random
import resource
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.db import repositories
from app.db.backup import backup_database, restore_database
from app.db.database import WriterBusy, connect, writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.db.retention import apply_retention
from app.ingestion.sources import SourceConfig

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
HMAC_KEY = b"synthetic-test-hmac-key"
NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)

HOSTS = [f"203.0.113.{i}" for i in range(1, 60)] + [f"198.51.100.{i}" for i in range(1, 60)]
METHODS = ["GET", "GET", "GET", "POST", "PUT", "DELETE", "OPTIONS"]
PATHS = ["/", "/index.html", "/style.css", "/app.js", "/api/events", "/search", "/old-page"]
PATHS += [f"/item/{i}" for i in range(30)]
STATUSES = [200] * 80 + [301, 302, 304, 400, 401, 403, 404, 404, 429, 500, 502]
UAS = ["Mozilla/5.0", "curl/8.0", "ExampleCrawler/1.0", "Googlebot/2.1", "health-check/1.0"]


def _source(root: Path, relative: str, source_id: str = "example-combined") -> SourceConfig:
    return SourceConfig(
        source_id=source_id, format_id="nginx_combined", allowed_root=root, relative_path=relative
    )


def write_synthetic_log(path: Path, count: int, *, seed: int, base: datetime) -> dict[str, int]:
    """Deterministic synthetic Combined log; returns accepted/rejected tallies."""
    rng = random.Random(seed)
    accepted = rejected = 0
    with open(path, "w", encoding="utf-8", newline="\n") as stream:
        for i in range(count):
            if i % 97 == 0:
                stream.write(f"malformed line number {i} without quotes\n")
                rejected += 1
                continue
            moment = base + timedelta(seconds=i)
            stamp = moment.strftime("%d/%b/%Y:%H:%M:%S +0100")
            query = f"?q={i}" if i % 5 == 0 else ""
            line = (
                f"{rng.choice(HOSTS)} - - [{stamp}]"
                f' "{rng.choice(METHODS)} {rng.choice(PATHS)}{query} HTTP/1.1"'
                f" {rng.choice(STATUSES)} {rng.randrange(0, 5000)}"
                f' "{rng.choice(["https://example.org/", "-"])}" "{rng.choice(UAS)}"\n'
            )
            stream.write(line)
            accepted += 1
    return {"accepted": accepted, "rejected": rejected}


def _run(db: Path, root: Path, relative: str, **kwargs) -> object:
    defaults = {
        "source": _source(root, relative),
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


def test_replay_same_file_inserts_nothing_new(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes((FIXTURES / "combined" / "nginx_combined.txt").read_bytes())
    db = tmp_path / "import.sqlite3"
    first = _run(db, root, "access.log")
    assert (first.records_inserted, first.records_replayed) == (10, 0)
    second = _run(db, root, "access.log")
    assert (second.records_inserted, second.records_replayed) == (0, 10)
    assert second.status == "completed"
    assert _row_count(db) == 10


def test_identical_content_new_path_replays_without_inode(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    data = (FIXTURES / "combined" / "nginx_combined.txt").read_bytes()
    (root / "a.log").write_bytes(data)
    (root / "b.log").write_bytes(data)
    db = tmp_path / "import.sqlite3"
    _run(db, root, "a.log")
    second = _run(db, root, "b.log")
    assert (second.records_inserted, second.records_replayed) == (0, 10)
    assert _row_count(db) == 10


def test_identical_adjacent_requests_have_distinct_positions(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes((FIXTURES / "combined" / "nginx_combined.txt").read_bytes())
    db = tmp_path / "import.sqlite3"
    _run(db, root, "access.log")
    conn = connect(db, read_only=True)
    try:
        rows = repositories.fetch_events_by_path(conn, path="/identical")
    finally:
        conn.close()
    assert len(rows) == 2
    assert rows[0]["byte_offset"] != rows[1]["byte_offset"]
    assert rows[0]["line_number"] != rows[1]["line_number"]


def test_interrupted_import_recovers_on_rerun(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    tallies = write_synthetic_log(
        root / "big.log", 50, seed=7, base=datetime(2026, 10, 1, tzinfo=UTC)
    )
    db = tmp_path / "import.sqlite3"

    def crash_after_two_batches(index: int) -> None:
        if index == 2:
            raise RuntimeError("simulated crash")

    with pytest.raises(RuntimeError, match="simulated crash"):
        _run(db, root, "big.log", batch_size=10, after_batch=crash_after_two_batches)
    assert _row_count(db) == 20
    conn = connect(db, read_only=True)
    try:
        status = conn.execute("SELECT status FROM imports ORDER BY id DESC LIMIT 1").fetchone()[0]
    finally:
        conn.close()
    assert status == "failed"

    result = _run(db, root, "big.log", batch_size=10)
    assert result.status == "completed"
    assert (result.records_inserted, result.records_replayed) == (tallies["accepted"] - 20, 20)
    assert _row_count(db) == tallies["accepted"]


def test_restart_persistence_across_connections(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes((FIXTURES / "combined" / "nginx_combined.txt").read_bytes())
    db = tmp_path / "import.sqlite3"
    _run(db, root, "access.log")
    assert _row_count(db) == 10
    assert _row_count(db) == 10


def test_same_size_source_change_is_flagged_with_mismatch_code(tmp_path):
    from app.db.importer import sha256_file

    root = tmp_path / "logs"
    root.mkdir()
    line = (
        b'203.0.113.7 - - [01/Oct/2026:00:00:%02d +0100] "GET /item HTTP/1.1" 200 9 "-" "t/1.0"\n'
    )
    (root / "swap.log").write_bytes(b"".join(line % i for i in range(4)))
    original = (root / "swap.log").read_bytes()
    db = tmp_path / "import.sqlite3"

    def rewrite_same_size_after_first_batch(index: int) -> None:
        if index == 1:
            swapped = original.replace(b"GET /item", b"GET /swap")
            assert len(swapped) == len(original)
            (root / "swap.log").write_bytes(swapped)

    result = _run(
        db, root, "swap.log", batch_size=2, after_batch=rewrite_same_size_after_first_batch
    )
    assert result.status == "completed"
    # The change must be explicit: never a silent clean completion.
    assert result.source_changed is True
    assert result.error_summary is not None
    assert "source_changed_during_import" in result.error_summary
    assert "source_content_mismatch" in result.error_summary
    # Committed batches are kept and stay queryable under the recorded fingerprint.
    assert _row_count(db) == 4
    assert sha256_file(root / "swap.log") != result.file_fingerprint
    # A re-import of the changed file carries the new fingerprint as new rows.
    rerun = _run(db, root, "swap.log", batch_size=2)
    assert rerun.file_fingerprint != result.file_fingerprint
    assert rerun.records_inserted == 4
    assert _row_count(db) == 8


def test_import_failure_uses_allowlisted_code_without_exception_text(tmp_path):
    from app.analytics import service
    from app.analytics.contracts import AnalyticsFilter, TimeWindow

    sentinel = "S3CR3T-sentinel-/secret/source/dir/token-abc123"
    root = tmp_path / "logs"
    root.mkdir()
    write_synthetic_log(root / "fail.log", 20, seed=23, base=datetime(2026, 10, 1, tzinfo=UTC))
    db = tmp_path / "import.sqlite3"

    def crash_with_sentinel(index: int) -> None:
        if index == 1:
            raise RuntimeError(f"boom {sentinel}")

    with pytest.raises(RuntimeError, match="boom"):
        _run(db, root, "fail.log", batch_size=10, after_batch=crash_with_sentinel)
    conn = connect(db, read_only=True)
    try:
        stored = conn.execute("SELECT status, error_summary FROM imports").fetchone()
    finally:
        conn.close()
    assert stored[0] == "failed"
    assert stored[1] == "interrupted:import_failed"
    assert sentinel not in stored[1]
    filt = AnalyticsFilter(
        site_id="default",
        window=TimeWindow(
            time_from=datetime(2026, 10, 1, tzinfo=UTC),
            time_to=datetime(2026, 10, 3, tzinfo=UTC),
        ),
    )
    conn = connect(db, read_only=True)
    try:
        covered = service.coverage_summary(conn, filt)
    finally:
        conn.close()
    assert covered["imports"][0]["error_summary"] == "interrupted:import_failed"
    assert sentinel not in json.dumps(covered)


def test_legacy_error_summary_scrubbed_at_analytics_boundary(tmp_path):
    from app.analytics import service
    from app.analytics.contracts import AnalyticsFilter, TimeWindow
    from app.db.importer import LEGACY_WITHHELD

    sentinel = "L3GACY-sentinel-/old/secret/path"
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes((FIXTURES / "combined" / "nginx_combined.txt").read_bytes())
    db = tmp_path / "import.sqlite3"
    _run(db, root, "access.log")
    conn = connect(db)
    try:
        with conn:
            conn.execute(
                "UPDATE imports SET error_summary = ?",
                (f"interrupted: RuntimeError('disk {sentinel}')",),
            )
    finally:
        conn.close()
    filt = AnalyticsFilter(
        site_id="default",
        window=TimeWindow(
            time_from=datetime(2026, 10, 27, tzinfo=UTC),
            time_to=datetime(2026, 10, 28, tzinfo=UTC),
        ),
    )
    conn = connect(db, read_only=True)
    try:
        covered = service.coverage_summary(conn, filt)
        summarized = service.summarize(conn, filt)
    finally:
        conn.close()
    assert covered["imports"][0]["error_summary"] == LEGACY_WITHHELD
    assert summarized["data_quality"]["imports"][0]["error_summary"] == LEGACY_WITHHELD
    assert sentinel not in json.dumps(covered)
    assert sentinel not in json.dumps(summarized)


def test_legacy_source_changed_segment_survives_scrub(tmp_path):
    from app.analytics import service
    from app.analytics.contracts import AnalyticsFilter, TimeWindow

    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes((FIXTURES / "combined" / "nginx_combined.txt").read_bytes())
    db = tmp_path / "import.sqlite3"
    _run(db, root, "access.log")
    conn = connect(db)
    try:
        with conn:
            conn.execute(
                "UPDATE imports SET error_summary = ?",
                ("source_changed_during_import",),
            )
    finally:
        conn.close()
    filt = AnalyticsFilter(
        site_id="default",
        window=TimeWindow(
            time_from=datetime(2026, 10, 27, tzinfo=UTC),
            time_to=datetime(2026, 10, 28, tzinfo=UTC),
        ),
    )
    conn = connect(db, read_only=True)
    try:
        covered = service.coverage_summary(conn, filt)
    finally:
        conn.close()
    assert covered["imports"][0]["error_summary"] == "source_changed_during_import"


def test_transient_rewrite_and_restore_is_detected(tmp_path):
    from app.db.importer import sha256_file

    root = tmp_path / "logs"
    root.mkdir()
    line = (
        b'203.0.113.7 - - [01/Oct/2026:00:00:%02d +0100] "GET /item HTTP/1.1" 200 9 "-" "t/1.0"\n'
    )
    (root / "swap.log").write_bytes(b"".join(line % (i % 60) for i in range(3000)))
    original = (root / "swap.log").read_bytes()
    db = tmp_path / "import.sqlite3"

    def rewrite_after_first_batch(index: int) -> None:
        if index == 1:
            swapped = original.replace(b"GET /item", b"GET /swap")
            assert len(swapped) == len(original)
            (root / "swap.log").write_bytes(swapped)

    def restore_after_fifteenth_batch(index: int) -> None:
        if index == 15:
            (root / "swap.log").write_bytes(original)

    def both_hooks(index: int) -> None:
        rewrite_after_first_batch(index)
        restore_after_fifteenth_batch(index)

    result = _run(db, root, "swap.log", batch_size=100, after_batch=both_hooks)
    assert result.status == "completed"
    # The file was restored before the final hash, so a pre/post-only
    # comparison would report clean: the reader digest must still flag it.
    assert sha256_file(root / "swap.log") == result.file_fingerprint
    assert result.source_changed is True
    assert result.error_summary is not None
    assert "source_changed_during_import" in result.error_summary
    assert "source_content_mismatch" in result.error_summary
    assert result.consumed_sha256 is not None
    assert result.consumed_sha256 != result.file_fingerprint
    # Committed batches are kept and stay queryable.
    assert _row_count(db) == 3000


def test_unchanged_input_reports_clean_with_matching_consumed_digest(tmp_path):
    from app.db.importer import sha256_file
    from app.ingestion.combined import Limits

    root = tmp_path / "logs"
    root.mkdir()
    line = b'203.0.113.7 - - [01/Oct/2026:00:00:07 +0100] "GET /item HTTP/1.1" 200 9 "-" "t/1.0"\n'
    body = b"".join(line for _ in range(50))
    body += b"malformed line without quotes\n"
    body += b"x" * 300 + b"\n"
    (root / "mixed.log").write_bytes(body)
    db = tmp_path / "import.sqlite3"
    result = _run(db, root, "mixed.log", limits=Limits(max_line_bytes=100))
    assert result.status == "completed"
    assert result.source_changed is False
    assert result.error_summary is None
    assert (result.records_inserted, result.records_replayed) == (50, 0)
    assert result.rejected_by_reason == {"malformed_line": 1, "oversized_line": 1}
    # Clean completion requires the digest to cover every consumed byte,
    # including newlines and the rejected/oversized lines.
    assert result.consumed_sha256 == result.file_fingerprint == sha256_file(root / "mixed.log")


def test_interrupted_consumption_leaves_no_consumed_digest(tmp_path):
    from app.ingestion.stream import ImportReport, iter_records

    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes((FIXTURES / "combined" / "nginx_combined.txt").read_bytes())
    report = ImportReport(source_id="s", format_id="nginx_combined")
    stream = iter_records(
        root / "access.log",
        source_id="s",
        format_id="nginx_combined",
        hmac_key=HMAC_KEY,
        report=report,
    )
    first = next(stream)
    assert first is not None
    stream.close()
    assert report.consumed_sha256 is None
    full_report = ImportReport(source_id="s", format_id="nginx_combined")
    items = list(
        iter_records(
            root / "access.log",
            source_id="s",
            format_id="nginx_combined",
            hmac_key=HMAC_KEY,
            report=full_report,
        )
    )
    assert len(items) == 10
    from app.db.importer import sha256_file

    assert full_report.consumed_sha256 == sha256_file(root / "access.log")


def test_source_appended_during_import_is_flagged(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    write_synthetic_log(root / "grow.log", 20, seed=11, base=datetime(2026, 10, 1, tzinfo=UTC))
    db = tmp_path / "import.sqlite3"

    def append_after_first_batch(index: int) -> None:
        if index == 1:
            with open(root / "grow.log", "ab") as stream:
                stream.write(
                    b'203.0.113.90 - - [01/Oct/2026:00:00:25 +0100] "GET /late HTTP/1.1" 200 9 "-" "t/1.0"\n'
                )

    result = _run(db, root, "grow.log", batch_size=10, after_batch=append_after_first_batch)
    assert result.status == "completed"
    assert result.source_changed is True
    assert result.error_summary is not None and "source_changed" in result.error_summary
    assert _row_count(db) >= 20


def test_concurrent_writer_fails_bounded(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes((FIXTURES / "combined" / "nginx_combined.txt").read_bytes())
    db = tmp_path / "import.sqlite3"
    migrate(db)
    ready = threading.Event()

    def hold_lock() -> None:
        with writer_transaction(db, lock_timeout_s=30):
            ready.set()
            time.sleep(3)

    thread = threading.Thread(target=hold_lock)
    thread.start()
    assert ready.wait(timeout=10)
    try:
        with pytest.raises(WriterBusy):
            _run(db, root, "access.log", lock_timeout_s=0.5)
    finally:
        thread.join()


def test_retention_then_replay_reinserts_only_deleted(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    old_tallies = write_synthetic_log(
        root / "old.log", 10, seed=21, base=datetime(2026, 1, 5, tzinfo=UTC)
    )
    new_tallies = write_synthetic_log(
        root / "new.log", 10, seed=22, base=datetime(2026, 10, 20, tzinfo=UTC)
    )
    db = tmp_path / "import.sqlite3"
    _run(db, root, "old.log", source=_source(root, "old.log", source_id="old-source"))
    _run(db, root, "new.log", source=_source(root, "new.log", source_id="new-source"))
    conn = connect(db)
    with conn:
        deleted = apply_retention(conn, days=30, now=NOW)
    conn.close()
    assert deleted == old_tallies["accepted"]
    assert _row_count(db) == new_tallies["accepted"]
    replayed = _run(db, root, "old.log", source=_source(root, "old.log", source_id="old-source"))
    assert (replayed.records_inserted, replayed.records_replayed) == (old_tallies["accepted"], 0)
    assert _row_count(db) == old_tallies["accepted"] + new_tallies["accepted"]


def test_backup_restore_then_retention_reapplied(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes((FIXTURES / "combined" / "nginx_combined.txt").read_bytes())
    db = tmp_path / "import.sqlite3"
    _run(db, root, "access.log")
    backup = backup_database(db, tmp_path / "backups" / "snap.sqlite3")
    restored = restore_database(backup, tmp_path / "isolated" / "restored.sqlite3")
    assert _row_count(restored) == 10
    conn = connect(restored)
    with conn:
        deleted = apply_retention(conn, days=30, now=datetime(2027, 6, 1, tzinfo=UTC))
    conn.close()
    assert deleted == 10
    assert _row_count(restored) == 0
    conn = connect(restored, read_only=True)
    try:
        assert conn.execute("SELECT COUNT(*) FROM imports").fetchone()[0] == 1
    finally:
        conn.close()


def test_cli_import_reports_counts(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes((FIXTURES / "combined" / "nginx_combined.txt").read_bytes())
    db = tmp_path / "import.sqlite3"
    env = dict(os.environ)
    env["HMAC_KEY"] = "synthetic-test-hmac-key"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "app.db.cli",
            "--db",
            str(db),
            "import",
            "--source-id",
            "example-combined",
            "--format",
            "nginx_combined",
            "--root",
            str(root),
            "--path",
            "access.log",
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
    assert (summary["records_inserted"], summary["records_replayed"]) == (10, 0)
    assert summary["status"] == "completed"
    assert _row_count(db) == 10


def test_benchmark_100k_generated_records(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    source_file = root / "bench.log"
    tallies = write_synthetic_log(
        source_file, 100_000, seed=20261029, base=datetime(2026, 10, 1, tzinfo=UTC)
    )
    file_bytes = source_file.stat().st_size
    db = tmp_path / "bench.sqlite3"
    peak_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    started = time.perf_counter()
    result = _run(db, root, "bench.log", batch_size=1000)
    elapsed = time.perf_counter() - started
    peak_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    assert result.status == "completed"
    assert result.lines_total == 100_000
    assert result.lines_accepted == tallies["accepted"]
    assert result.lines_rejected == tallies["rejected"]
    assert result.records_inserted == tallies["accepted"]
    assert result.records_replayed == 0
    assert _row_count(db) == tallies["accepted"]
    db_bytes = sum(
        p.stat().st_size for p in (db, Path(str(db) + "-wal"), Path(str(db) + "-shm")) if p.exists()
    )
    divisor = 1024 * 1024 if sys.platform == "darwin" else 1024
    peak_mib = (peak_after - peak_before) / divisor
    assert peak_mib < 512, f"import exceeded bounded-memory budget: {peak_mib:.1f} MiB"
    print(
        f"\n[T3 benchmark] rows={tallies['accepted']} file={file_bytes}B db(+wal+shm)={db_bytes}B"
        f" elapsed={elapsed:.1f}s throughput={tallies['accepted'] / elapsed:.0f} rows/s"
        f" peak_rss_delta={peak_mib:.1f}MiB platform={sys.platform}"
    )
