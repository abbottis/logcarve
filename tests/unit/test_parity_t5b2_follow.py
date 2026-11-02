"""T5b2 follow (unit): splitter, identity honesty, guards, coverage bound.

Synthetic fixtures only. No sleeps, no live files beyond tmp_path, no
network or model calls.
"""

import gzip
import hashlib
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.analytics import queries as queries_mod
from app.analytics.contracts import AnalyticsFilter, TimeWindow
from app.db import follow as follow_mod
from app.db.follow import (
    AMBIGUOUS_PREFIX_ADOPTION,
    FOLLOW_GZIP_UNSUPPORTED,
    PREFIX_TAINTED,
    _LineFollower,
    generation_fingerprint,
    run_follow,
)
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.combined import NGINX_COMBINED
from app.ingestion.sources import SourceConfig

HMAC_KEY = b"t5b2-unit-hmac-key"


def _line(ip: str, path: str = "/a", ts: str = "27/Oct/2026:09:15:32 +0000") -> str:
    return f'{ip} - - [{ts}] "GET {path} HTTP/1.1" 200 512 "-" "T/1.0"\n'


def _source(root: Path, relative: str) -> SourceConfig:
    return SourceConfig(
        source_id="t5b2", format_id=NGINX_COMBINED, allowed_root=root, relative_path=relative
    )


def _follow(db: Path, root: Path, relative: str, **kwargs):
    kwargs.setdefault("max_polls", 2)
    kwargs.setdefault("poll_interval_s", 0)
    return run_follow(
        db,
        source=_source(root, relative),
        site_id="default",
        site_name="T5b2",
        site_hostname="example.org",
        server_type="nginx",
        path_alias=relative,
        hmac_key=HMAC_KEY,
        **kwargs,
    )


def test_splitter_partial_across_feeds():
    splitter = _LineFollower(64)
    first = splitter.feed(b"abc", 0)
    assert first == []
    second = splitter.feed(b"def\nGH\n", 3)
    assert second == [(0, b"abcdef", 7), (7, b"GH", 10)]


def test_splitter_oversized_exactly_once_across_feeds():
    splitter = _LineFollower(4)
    assert splitter.feed(b"ab", 0) == []
    assert splitter.feed(b"cdef", 2) == []
    # Line "abcdef" (6 > 4) completes here: exactly one marker.
    assert splitter.feed(b"ghi\nOK\n", 6) == [(0, None, 10), (10, b"OK", 13)]
    assert splitter.pending == bytearray()
    assert not splitter.skipping


def test_splitter_strips_carriage_return_and_seals_final():
    splitter = _LineFollower(64)
    assert splitter.feed(b"A\r\npart", 0) == [(0, b"A", 3)]
    sealed = splitter.seal()
    assert sealed == [(3, b"part", 7)]


def test_splitter_seal_empty_is_quiet():
    splitter = _LineFollower(64)
    assert splitter.seal() == []
    splitter.feed(b"X\n", 0)
    assert splitter.seal() == []


def test_generation_fingerprint_is_honest_label():
    first = generation_fingerprint("s", 1)
    assert first.startswith("follow:v1:s:1")
    assert first != hashlib.sha256(b"x").hexdigest()
    assert generation_fingerprint("s", 2) != first


def test_live_gzip_refused(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "a.log.gz").write_bytes(gzip.compress(_line("203.0.113.10").encode()))
    db = tmp_path / "t.db"
    with pytest.raises(follow_mod.FollowRefused) as excinfo:
        _follow(db, root, "a.log.gz", max_polls=1)
    assert excinfo.value.code == FOLLOW_GZIP_UNSUPPORTED
    # Refusal writes no events and no import attempts.
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM imports").fetchone()[0] == 0
    finally:
        conn.close()


def test_ambiguous_prefix_adoption_refused(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    target = root / "a.log"
    target.write_text(_line("203.0.113.10"), encoding="utf-8")
    db = tmp_path / "t.db"
    first = run_import(
        db,
        source=_source(root, "a.log"),
        site_id="default",
        site_name="T5b2",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="a.log",
        hmac_key=HMAC_KEY,
    )
    assert first.status == "completed" and first.records_inserted == 1
    # Replace the content with unrelated bytes: the stored prefix no
    # longer matches any clean batch import.
    target.write_text(_line("198.51.100.7", path="/other") * 2, encoding="utf-8")
    refused = _follow(db, root, "a.log", max_polls=1)
    assert refused.status == "refused"
    assert refused.error_summary == AMBIGUOUS_PREFIX_ADOPTION
    assert refused.guidance
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM follow_generations").fetchone()[0] == 0
    finally:
        conn.close()


def test_fresh_start_overrides_ambiguity(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    target = root / "a.log"
    target.write_text(_line("203.0.113.10"), encoding="utf-8")
    db = tmp_path / "t.db"
    run_import(
        db,
        source=_source(root, "a.log"),
        site_id="default",
        site_name="T5b2",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="a.log",
        hmac_key=HMAC_KEY,
    )
    target.write_text(_line("198.51.100.7", path="/other") * 2, encoding="utf-8")
    done = _follow(db, root, "a.log", max_polls=1, fresh_start=True)
    assert done.status == "completed", done.error_summary
    assert done.records_inserted == 2
    conn = sqlite3.connect(db)
    try:
        row = conn.execute(
            "SELECT fresh_start FROM follow_generations WHERE generation_seq = 1"
        ).fetchone()
        assert row[0] == 1
    finally:
        conn.close()


def test_restart_taints_mutated_span(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    target = root / "a.log"
    target.write_text(_line("203.0.113.10"), encoding="utf-8")
    db = tmp_path / "t.db"
    first = _follow(db, root, "a.log", max_polls=1)
    assert first.status == "completed" and first.records_inserted == 1
    # Same-size rewrite of the consumed span: restart must taint, never adopt.
    target.write_bytes(_line("203.0.113.10").replace("GET /a ", "GET /b ").encode())
    second = _follow(db, root, "a.log", max_polls=1)
    assert second.status == "refused"
    assert second.error_summary == PREFIX_TAINTED
    conn = sqlite3.connect(db)
    try:
        status = conn.execute(
            "SELECT status, detail FROM follow_generations WHERE generation_seq = 1"
        ).fetchone()
        assert status == ("tainted", "follow:prefix_mismatch")
        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 1
    finally:
        conn.close()


def _filt():
    return AnalyticsFilter(
        site_id="default",
        window=TimeWindow(
            time_from=datetime(2026, 10, 27, tzinfo=UTC),
            time_to=datetime(2026, 10, 28, tzinfo=UTC),
        ),
    )


def test_coverage_sample_bounded_with_exact_aggregates(tmp_path):
    db = tmp_path / "t.db"
    migrate(db)
    conn = sqlite3.connect(db)
    try:
        conn.execute(
            "INSERT INTO sites (id, name, hostname, created_at)"
            " VALUES ('s', 'S', 'example.org', '2026-10-27T00:00:00+00:00')"
        )
        conn.execute(
            "INSERT INTO log_sources (id, site_id, server_type, format_id, path_alias)"
            " VALUES ('src', 's', 'nginx', 'nginx_combined', 'a.log')"
        )
        for i in range(5):
            conn.execute(
                "INSERT INTO imports (source_id, file_fingerprint, file_size,"
                " started_at, finished_at, lines_total, lines_accepted,"
                " lines_rejected, records_inserted, records_replayed, status)"
                " VALUES ('src', ?, 10, 't', 't', 3, 2, 1, 2, 1, 'completed')",
                (f"fp{i}",),
            )
        conn.commit()
    finally:
        conn.close()
    conn = sqlite3.connect(db)
    try:
        old_limit = queries_mod.IMPORT_HISTORY_SAMPLE_LIMIT
        queries_mod.IMPORT_HISTORY_SAMPLE_LIMIT = 2
        try:
            filt = AnalyticsFilter(
                site_id="s",
                window=TimeWindow(
                    time_from=datetime(2026, 10, 27, tzinfo=UTC),
                    time_to=datetime(2026, 10, 28, tzinfo=UTC),
                ),
                source_id="src",
            )
            cov = queries_mod.coverage(conn, filt, None)
        finally:
            queries_mod.IMPORT_HISTORY_SAMPLE_LIMIT = old_limit
    finally:
        conn.close()
    assert cov["imports_truncated"] is True
    assert len(cov["imports"]) == 2
    assert cov["import_attempts"] == {
        "lines_total": 15,
        "lines_accepted": 10,
        "lines_rejected": 5,
        "records_replayed": 5,
    }
