"""T5b2 follow corrections (unit): partial cursor, replay idempotency, stale CAS, live accounting.

Compact regression cases for the concrete final-check defects A-D.
Synthetic fixtures only. No sleeps, no network or model calls.
"""

import hashlib
import sqlite3
from pathlib import Path

from app.db.follow import (
    STALE_GENERATION_CODE,
    replay_archive,
    run_follow,
)
from app.ingestion.combined import NGINX_COMBINED, Limits
from app.ingestion.sources import SourceConfig

HMAC_KEY = b"t5b2-corrections-hmac"


def _line(ip: str = "203.0.113.10", path: str = "/a") -> str:
    return f'{ip} - - [27/Oct/2026:09:15:32 +0000] "GET {path} HTTP/1.1" 200 512 "-" "T/1.0"\n'


def _source(root: Path, relative: str) -> SourceConfig:
    return SourceConfig(
        source_id="t5b2c", format_id=NGINX_COMBINED, allowed_root=root, relative_path=relative
    )


def _follow(db: Path, root: Path, relative: str, **kwargs):
    kwargs.setdefault("max_polls", 3)
    kwargs.setdefault("poll_interval_s", 0)
    return run_follow(
        db,
        source=_source(root, relative),
        site_id="default",
        site_name="T5b2c",
        site_hostname="example.org",
        server_type="nginx",
        path_alias=relative,
        hmac_key=HMAC_KEY,
        **kwargs,
    )


def _gen(db: Path, seq: int = 1):
    conn = sqlite3.connect(db)
    try:
        return conn.execute(
            "SELECT next_offset, consumed_sha256, status FROM follow_generations"
            " WHERE source_id = 't5b2c' AND generation_seq = ?",
            (seq,),
        ).fetchone()
    finally:
        conn.close()


def test_partial_line_within_one_run_exact_offset_and_digest(tmp_path):
    """A: a line split across polls commits once with the exact raw span digest."""
    root = tmp_path / "logs"
    root.mkdir()
    target = root / "a.log"
    line = _line()
    target.write_bytes(line[:40].encode())
    state = {"n": 0}

    def after_poll(poll, _result):
        state["n"] += 1
        if state["n"] == 1:
            with open(target, "ab") as stream:
                stream.write(line[40:].encode())

    result = _follow(tmp_path / "t.db", root, "a.log", after_poll=after_poll)
    assert result.status == "completed"
    assert (result.lines_accepted, result.lines_rejected) == (1, 0)
    assert result.records_inserted == 1
    offset, digest, status = _gen(tmp_path / "t.db")
    assert status == "active"
    assert offset == len(line.encode())
    assert digest == hashlib.sha256(line.encode()).hexdigest()
    conn = sqlite3.connect(tmp_path / "t.db")
    try:
        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 1
        assert conn.execute("SELECT byte_offset FROM requests").fetchone()[0] == 0
    finally:
        conn.close()


def test_oversized_line_across_bounded_reads_single_rejection_exact_digest(tmp_path):
    """A: a >limit line spanning several 1024-byte polls rejects exactly once hashed whole."""
    root = tmp_path / "logs"
    root.mkdir()
    first = _line(path="/ok")
    big = _line(path="/" + "x" * 3000)
    assert len(big) > 1024
    (root / "o.log").write_text(first + big, encoding="utf-8")
    db = tmp_path / "t.db"
    result = _follow(
        db, root, "o.log", max_polls=5, max_bytes_per_poll=1024, limits=Limits(max_line_bytes=128)
    )
    assert result.status == "completed"
    assert (result.lines_accepted, result.lines_rejected) == (1, 1)
    assert result.rejected_by_reason.get("oversized_line") == 1
    assert result.records_inserted == 1
    offset, digest, _status = _gen(db)
    raw = (first + big).encode()
    assert offset == len(raw)
    assert digest == hashlib.sha256(raw).hexdigest()


def test_repeated_archive_replay_stays_completed_plain(tmp_path):
    """B: replaying the same archive twice completes idempotently, never prefix-mismatch."""
    root = tmp_path / "logs"
    root.mkdir()
    live = root / "live.log"
    live.write_text(_line(path="/one"), encoding="utf-8")
    db = tmp_path / "t.db"
    assert _follow(db, root, "live.log", max_polls=1).status == "completed"
    live.rename(root / "arch.log")
    live.write_text(_line(path="/two"), encoding="utf-8")
    second = _follow(db, root, "live.log", max_polls=2)
    assert second.sealed_generations == [1]

    def _replay():
        return replay_archive(
            db,
            archive=_source(root, "arch.log"),
            site_id="default",
            site_name="T5b2c",
            site_hostname="example.org",
            server_type="nginx",
            path_alias="arch.log",
            hmac_key=HMAC_KEY,
        )

    first = _replay()
    assert (first.status, first.error_summary) == ("completed", None)
    assert (first.records_inserted, first.records_replayed) == (0, 1)
    again = _replay()
    assert (again.status, again.error_summary) == ("completed", None)
    assert (again.records_inserted, again.records_replayed) == (0, 1)
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 2
    finally:
        conn.close()


def test_stale_concurrent_follower_refuses_without_rewind(tmp_path):
    """C: a nested full consume wins; the stale outer refuses, no rewind or dupes."""
    root = tmp_path / "logs"
    root.mkdir()
    live = root / "live.log"
    live.write_text(_line(path="/zero"), encoding="utf-8")
    db = tmp_path / "t.db"
    inner = {}

    def after_poll(poll, _result):
        if poll == 1:
            with open(live, "a", encoding="utf-8") as stream:
                stream.writelines(_line(path=f"/p{index}") for index in range(100))
            nested = _follow(db, root, "live.log", max_polls=1)
            inner["status"] = nested.status
            inner["accepted"] = nested.lines_accepted

    outer = _follow(
        db, root, "live.log", max_polls=2, max_bytes_per_poll=1024, after_poll=after_poll
    )
    assert outer.status == "failed"
    assert outer.error_summary == STALE_GENERATION_CODE
    assert outer.generations_started == 1
    assert inner == {"status": "completed", "accepted": 100}
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 101
        rows = conn.execute(
            "SELECT next_offset, status FROM follow_generations WHERE source_id = 't5b2c'"
        ).fetchall()
        assert len(rows) == 1 and rows[0][1] == "active"
        total = sum(len(_line(path=f"/p{index}").encode()) for index in range(100))
        total += len(_line(path="/zero").encode())
        assert rows[0][0] == total
    finally:
        conn.close()


def test_active_generation_reports_running_attempt_counts(tmp_path):
    """D: a long active generation carries durable attempt totals before any seal."""
    root = tmp_path / "logs"
    root.mkdir()
    (root / "live.log").write_text(
        "".join(_line(path=f"/q{i}") for i in range(5)), encoding="utf-8"
    )
    db = tmp_path / "t.db"
    result = _follow(db, root, "live.log", max_polls=1)
    assert result.status == "completed"
    assert result.lines_accepted == 5
    conn = sqlite3.connect(db)
    try:
        row = conn.execute(
            "SELECT status, lines_total, lines_accepted, lines_rejected,"
            " records_inserted, records_replayed FROM imports"
        ).fetchone()
        assert row == ("running", 5, 5, 0, 5, 0)
    finally:
        conn.close()
