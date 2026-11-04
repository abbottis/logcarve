"""T5b2 follow (integration): rotation, restart, replay, privacy boundaries.

Synthetic fixtures only. Controlled polling (interval 0, bounded polls);
no sleeps, no system services, no network or model calls. Rotations are
performed through ``after_poll`` hooks inside a single bounded run, so
an old descriptor is genuinely held open while the path is replaced.
"""

import gzip
from pathlib import Path

import pytest

from app.db.database import WriterBusy, connect
from app.db.follow import (
    ARCHIVE_NO_SEALED_GENERATION,
    ARCHIVE_PREFIX_MISMATCH,
    replay_archive,
    run_follow,
)
from app.db.importer import run_import
from app.ingestion.combined import NGINX_COMBINED
from app.ingestion.sources import SourceConfig

HMAC_KEY = b"t5b2-integration-hmac-key"
SITE = "default"


def _line(ip: str, path: str = "/a") -> str:
    return f'{ip} - - [27/Oct/2026:09:15:32 +0000] "GET {path} HTTP/1.1" 200 512 "-" "T/1.0"\n'


def _source(root: Path, relative: str, source_id: str = "t5b2") -> SourceConfig:
    return SourceConfig(
        source_id=source_id, format_id=NGINX_COMBINED, allowed_root=root, relative_path=relative
    )


def _follow(db: Path, root: Path, relative: str, **kwargs):
    kwargs.setdefault("max_polls", 4)
    kwargs.setdefault("poll_interval_s", 0)
    return run_follow(
        db,
        source=_source(root, relative),
        site_id=SITE,
        site_name="T5b2",
        site_hostname="example.org",
        server_type="nginx",
        path_alias=relative,
        hmac_key=HMAC_KEY,
        **kwargs,
    )


def _counts(db: Path):
    conn = connect(db)
    try:
        events = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
        imports = conn.execute("SELECT COUNT(*) FROM imports").fetchone()[0]
        batches = conn.execute("SELECT COUNT(*) FROM follow_batches").fetchone()[0]
        gens = conn.execute(
            "SELECT generation_seq, status, next_offset FROM follow_generations"
            " ORDER BY generation_seq"
        ).fetchall()
        return events, imports, batches, [tuple(g) for g in gens]
    finally:
        conn.close()


def test_append_across_polls_then_restart_without_duplicates(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    target = root / "a.log"
    target.write_text(_line("203.0.113.10") * 2, encoding="utf-8")
    db = tmp_path / "t.db"

    def _append(poll: int, _result) -> None:
        if poll == 1:
            with open(target, "a", encoding="utf-8") as stream:
                stream.write(_line("203.0.113.11"))

    first = _follow(db, root, "a.log", max_polls=2, after_poll=_append)
    assert first.status == "completed", first.error_summary
    assert first.records_inserted == 3
    assert first.records_replayed == 0

    second = _follow(db, root, "a.log", max_polls=3)
    assert second.status == "completed", second.error_summary
    assert second.polls == 3 and second.empty_polls == 3
    assert second.records_inserted == 0 and second.records_replayed == 0

    events, imports, batches, gens = _counts(db)
    assert events == 3
    # One generation attempt row; empty polls add no history rows.
    assert imports == 1
    assert gens == [
        (1, "active", len((_line("203.0.113.10") * 2 + _line("203.0.113.11")).encode()))
    ]
    assert batches >= 1


def test_crash_after_commit_replays_nothing(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    target = root / "a.log"
    target.write_text(_line("203.0.113.10"), encoding="utf-8")
    db = tmp_path / "t.db"

    class _Crash(RuntimeError):
        pass

    def _crash(_poll: int, _result) -> None:
        raise _Crash("simulated crash after commit")

    with pytest.raises(_Crash):
        _follow(db, root, "a.log", max_polls=1, after_poll=_crash)
    # The committed progress survives: a restart replays nothing.
    second = _follow(db, root, "a.log", max_polls=2)
    assert second.status == "completed", second.error_summary
    assert second.records_inserted == 0 and second.records_replayed == 0
    assert second.empty_polls == 2
    events, imports, _batches, _gens = _counts(db)
    assert events == 1 and imports == 1


def test_partial_final_line_reread_on_restart(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    target = root / "a.log"
    full = _line("203.0.113.10")
    target.write_bytes((full + full[: len(full) // 2]).encode())
    db = tmp_path / "t.db"
    first = _follow(db, root, "a.log", max_polls=1)
    assert first.status == "completed", first.error_summary
    assert first.records_inserted == 1
    # The partial tail is not imported, rejected, or checkpointed past.
    assert first.lines_rejected == 0
    with open(target, "ab") as stream:
        stream.write(full[len(full) // 2 :].encode())
    second = _follow(db, root, "a.log", max_polls=1)
    assert second.status == "completed", second.error_summary
    assert second.records_inserted == 1
    events, _imports, _batches, _gens = _counts(db)
    assert events == 2


def test_rename_and_create_with_old_fd_tail_drain(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    target = root / "a.log"
    target.write_text(_line("203.0.113.10"), encoding="utf-8")
    db = tmp_path / "t.db"

    def _rotate(poll: int, _result) -> None:
        if poll == 1:
            # Late write to the old descriptor, then rename + new file.
            with open(target, "a", encoding="utf-8") as stream:
                stream.write(_line("203.0.113.11"))
            (root / "a.log").rename(root / "a.log.1")
            (root / "a.log").write_text(_line("198.51.100.7", path="/new"), encoding="utf-8")

    done = _follow(db, root, "a.log", max_polls=4, after_poll=_rotate)
    assert done.status == "completed", done.error_summary
    assert done.sealed_generations == [1]
    assert done.generations_started == 2
    assert done.records_inserted == 3
    events, imports, _batches, gens = _counts(db)
    assert events == 3
    assert [g[1] for g in gens] == ["rotated", "active"]
    # Two generations own one attempt row each; no duplicates.
    assert imports == 2
    conn = connect(db)
    try:
        fps = conn.execute(
            "SELECT DISTINCT file_fingerprint FROM requests ORDER BY file_fingerprint"
        ).fetchall()
        assert [row[0] for row in fps] == ["follow:v1:t5b2:1", "follow:v1:t5b2:2"]
    finally:
        conn.close()


def test_copytruncate_fast_regrowth(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    target = root / "a.log"
    target.write_text(_line("203.0.113.10") * 2, encoding="utf-8")
    db = tmp_path / "t.db"

    def _truncate(poll: int, _result) -> None:
        if poll == 1:
            with open(target, "w", encoding="utf-8") as stream:
                stream.write(_line("198.51.100.7", path="/fresh") * 3)

    done = _follow(db, root, "a.log", max_polls=3, after_poll=_truncate)
    assert done.status == "completed", done.error_summary
    assert done.sealed_generations == [1]
    assert done.records_inserted == 5
    events, _imports, _batches, gens = _counts(db)
    assert events == 5
    assert [g[1] for g in gens] == ["rotated", "active"]


def test_file_replacement_starts_new_generation(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    target = root / "a.log"
    target.write_text(_line("203.0.113.10"), encoding="utf-8")
    db = tmp_path / "t.db"
    first = _follow(db, root, "a.log", max_polls=1)
    assert first.records_inserted == 1
    other = root / "staged.log"
    other.write_text(_line("198.51.100.7", path="/v2") * 2, encoding="utf-8")
    other.replace(target)
    second = _follow(db, root, "a.log", max_polls=1)
    assert second.status == "completed", second.error_summary
    assert second.generations_started == 1  # this run started gen 2
    assert second.records_inserted == 2
    _events, _imports, _batches, gens = _counts(db)
    assert [g[1] for g in gens] == ["rotated", "active"]


def _replay(db: Path, root: Path, archive_relative: str, **kwargs):
    return replay_archive(
        db,
        archive=_source(root, archive_relative),
        site_id=SITE,
        site_name="T5b2",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="a.log",
        hmac_key=HMAC_KEY,
        **kwargs,
    )


def test_archive_plain_replay_inserts_nothing_and_replays_all(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    target = root / "a.log"
    body = _line("203.0.113.10") * 2
    target.write_text(body, encoding="utf-8")
    db = tmp_path / "t.db"
    first = _follow(db, root, "a.log", max_polls=1)
    assert first.records_inserted == 2
    (root / "a.log").rename(root / "a.log.1")
    (root / "a.log").write_text("", encoding="utf-8")
    drain = _follow(db, root, "a.log", max_polls=1)
    assert drain.sealed_generations == [1]
    replayed = _replay(db, root, "a.log.1")
    assert replayed.status == "completed", replayed.error_summary
    assert replayed.generation_seq == 1
    assert replayed.records_inserted == 0
    assert replayed.records_replayed == 2
    events, _imports, _batches, _gens = _counts(db)
    assert events == 2


def test_archive_gzip_replay_matches_plain_prefix(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    target = root / "a.log"
    body = _line("203.0.113.10") + _line("203.0.113.11", path="/b")
    target.write_text(body, encoding="utf-8")
    db = tmp_path / "t.db"
    first = _follow(db, root, "a.log", max_polls=1)
    assert first.records_inserted == 2
    (root / "a.log").rename(root / "a.log.1")
    (root / "a.log.1.gz").write_bytes(gzip.compress((root / "a.log.1").read_bytes()))
    (root / "a.log").write_text("", encoding="utf-8")
    drain = _follow(db, root, "a.log", max_polls=1)
    assert drain.sealed_generations == [1]
    replayed = _replay(db, root, "a.log.1.gz")
    assert replayed.status == "completed", replayed.error_summary
    assert replayed.records_inserted == 0
    assert replayed.records_replayed == 2


def test_archive_tail_appends_only_new_lines(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    target = root / "a.log"
    target.write_text(_line("203.0.113.10"), encoding="utf-8")
    db = tmp_path / "t.db"
    _follow(db, root, "a.log", max_polls=1)
    archived = root / "a.log.1"
    (root / "a.log").rename(archived)
    with open(archived, "a", encoding="utf-8") as stream:
        stream.write(_line("203.0.113.11", path="/tail"))
    (root / "a.log").write_text("", encoding="utf-8")
    drain = _follow(db, root, "a.log", max_polls=1)
    assert drain.sealed_generations == [1]
    replayed = _replay(db, root, "a.log.1")
    assert replayed.status == "completed", replayed.error_summary
    assert replayed.records_inserted == 1
    assert replayed.records_replayed == 1
    events, _imports, _batches, _gens = _counts(db)
    assert events == 2


def test_archive_prefix_mismatch_refused_without_writes(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    target = root / "a.log"
    target.write_text(_line("203.0.113.10"), encoding="utf-8")
    db = tmp_path / "t.db"
    _follow(db, root, "a.log", max_polls=1)
    (root / "a.log").rename(root / "a.log.1")
    (root / "a.log").write_text("", encoding="utf-8")
    drain = _follow(db, root, "a.log", max_polls=1)
    assert drain.sealed_generations == [1]
    (root / "a.log.1").write_text(_line("198.51.100.99", path="/evil"), encoding="utf-8")
    before = _counts(db)
    refused = _replay(db, root, "a.log.1")
    assert refused.status == "refused"
    assert refused.error_summary == ARCHIVE_PREFIX_MISMATCH
    assert refused.guidance
    assert _counts(db) == before


def test_archive_without_sealed_generation_refused(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    db = tmp_path / "t.db"
    (root / "stray.log").write_text(_line("203.0.113.10"), encoding="utf-8")
    refused = _replay(db, root, "stray.log")
    assert refused.status == "refused"
    assert refused.error_summary == ARCHIVE_NO_SEALED_GENERATION


def test_batch_prefix_adopted_without_duplicates(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    target = root / "a.log"
    target.write_text(_line("203.0.113.10") * 2, encoding="utf-8")
    db = tmp_path / "t.db"
    batch = run_import(
        db,
        source=_source(root, "a.log"),
        site_id=SITE,
        site_name="T5b2",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="a.log",
        hmac_key=HMAC_KEY,
    )
    assert batch.status == "completed" and batch.records_inserted == 2
    with open(target, "a", encoding="utf-8") as stream:
        stream.write(_line("203.0.113.11", path="/tail"))
    done = _follow(db, root, "a.log", max_polls=1)
    assert done.status == "completed", done.error_summary
    assert done.records_inserted == 1
    assert done.records_replayed == 0
    conn = connect(db)
    try:
        adopted = conn.execute(
            "SELECT adopted_import_id, adopted_prefix_sha, gen_start_offset"
            " FROM follow_generations WHERE generation_seq = 1"
        ).fetchone()
        assert adopted[0] == batch.import_id
        assert adopted[1] == batch.file_fingerprint
        assert adopted[2] == len((_line("203.0.113.10") * 2).encode())
        events = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
        assert events == 3
    finally:
        conn.close()


def test_follow_capture_and_checkpoint_privacy(tmp_path, monkeypatch):
    import hashlib as _hashlib

    root = tmp_path / "logs"
    root.mkdir()
    target = root / "a.log"
    target.write_text(_line("203.0.113.10"), encoding="utf-8")
    db = tmp_path / "t.db"
    key = _hashlib.sha256(b"t5b2-follow-ip-key").digest()
    done = _follow(db, root, "a.log", max_polls=1, capture_originals=True, ip_key=key)
    assert done.status == "completed", done.error_summary
    assert done.originals_captured == 1
    assert done.originals_skipped_mismatch == 0
    from app.db import private as private_mod

    conn = connect(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM request_original_ips").fetchone()[0] == 1
        rid = conn.execute("SELECT id FROM requests").fetchone()[0]
        assert private_mod.read_original_ip(conn, request_id=rid, key=key) == "203.0.113.10"
        # Checkpoint/progress tables persist digests and counts only.
        texts = []
        for table in ("follow_generations", "follow_batches"):
            for row in conn.execute(f"SELECT * FROM {table}").fetchall():
                texts.append(" ".join("" if v is None else str(v) for v in row))
        blob = "\n".join(texts)
        assert "203.0.113.10" not in blob
    finally:
        conn.close()


def test_writer_busy_retried_then_succeeds(tmp_path, monkeypatch):
    import app.db.follow as follow_module

    root = tmp_path / "logs"
    root.mkdir()
    (root / "a.log").write_text(_line("203.0.113.10"), encoding="utf-8")
    db = tmp_path / "t.db"
    real_writer = follow_module.writer_transaction
    calls = {"n": 0}

    def _flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise WriterBusy("busy")
        return real_writer(*args, **kwargs)

    monkeypatch.setattr(follow_module, "writer_transaction", _flaky)
    done = _follow(db, root, "a.log", max_polls=1, max_writer_retries=3)
    assert done.status == "completed", done.error_summary
    assert done.records_inserted == 1
    assert calls["n"] > 1


def test_source_escape_and_symlink_refused(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    outside = tmp_path / "outside.log"
    outside.write_text(_line("203.0.113.10"), encoding="utf-8")
    (root / "evil-link.log").symlink_to(outside)
    db = tmp_path / "t.db"
    from app.ingestion.sources import SourceError

    with pytest.raises(SourceError):
        _follow(db, root, "evil-link.log", max_polls=1)
    conn = connect(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 0
    finally:
        conn.close()
