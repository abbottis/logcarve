"""T5b1c replay private association (integration): mismatched-original refusal.

Synthetic fixtures only. A source mutation between initial fingerprinting
and the actual reader can attach a mismatched encrypted original IP to an
EXISTING replayed event. The import must verify the stored core/HMAC
against the consumed record under the same writer transaction and refuse
the inconsistent association with safe diagnostics.

Valid control: replay with capture and unchanged content attaches the
original and the decrypted address matches the stored request HMAC.
"""

import hashlib
import hmac
from pathlib import Path

from app.db import importer as importer_mod
from app.db import private as private_mod
from app.db.database import connect
from app.db.importer import run_import
from app.ingestion.combined import NGINX_COMBINED
from app.ingestion.sources import SourceConfig

HMAC_KEY = b"t5b1c-replay-hmac-key"
SITE = "default"

LINE_A = (
    '203.0.113.10 - - [27/Oct/2026:09:15:32 +0000] "GET /safe HTTP/1.1" 200 512 "-" "Test/1.0"\n'
)
# Same byte length, different documentation address: offsets stay stable
# so the replay identity still hits while the HMAC changes.
LINE_B = LINE_A.replace("203.0.113.10", "203.0.113.99")
assert len(LINE_A.encode()) == len(LINE_B.encode())


def _key_bytes(seed: int = 7) -> bytes:
    return hashlib.sha256(f"t5b1c-ip-key-{seed}".encode()).digest()


def _source(root: Path, relative: str) -> SourceConfig:
    return SourceConfig(
        source_id="t5b1c", format_id=NGINX_COMBINED, allowed_root=root, relative_path=relative
    )


def _run(db: Path, root: Path, relative: str, **kwargs):
    return run_import(
        db,
        source=_source(root, relative),
        site_id=SITE,
        site_name="T5b1c",
        site_hostname="example.org",
        server_type="nginx",
        path_alias=relative,
        hmac_key=HMAC_KEY,
        **kwargs,
    )


def _expected_pseudonym(ip: str) -> str:
    return hmac.new(HMAC_KEY, ip.encode(), hashlib.sha256).hexdigest()


def _stored_row(db: Path):
    conn = connect(db)
    try:
        row = conn.execute("SELECT id, client_pseudonym, file_fingerprint FROM requests").fetchone()
        count = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
        privates = conn.execute("SELECT COUNT(*) FROM request_original_ips").fetchone()[0]
        return row, count, privates
    finally:
        conn.close()


def test_matching_replay_capture_attaches_original(tmp_path):
    """Valid control: unchanged replay with capture stores one original."""
    root = tmp_path / "logs"
    root.mkdir()
    (root / "a.log").write_text(LINE_A, encoding="utf-8")
    db = tmp_path / "t.db"
    key = _key_bytes()

    first = _run(db, root, "a.log")
    assert first.status == "completed", first.error_summary
    assert first.records_inserted == 1
    assert first.originals_captured == 0

    second = _run(db, root, "a.log", capture_originals=True, ip_key=key)
    assert second.status == "completed", second.error_summary
    assert second.records_inserted == 0
    assert second.records_replayed == 1
    assert second.originals_captured == 1
    assert second.originals_skipped_mismatch == 0

    (row, count, privates) = _stored_row(db)
    assert count == 1 and privates == 1
    assert row[1] == _expected_pseudonym("203.0.113.10")
    conn = connect(db)
    try:
        assert private_mod.read_original_ip(conn, request_id=row[0], key=key) == "203.0.113.10"
    finally:
        conn.close()


def test_mutated_replay_capture_refuses_mismatched_original(tmp_path, monkeypatch):
    """Transient same-size mutation: replayed row keeps stored HMAC, no private row."""
    root = tmp_path / "logs"
    root.mkdir()
    target = root / "b.log"
    target.write_text(LINE_A, encoding="utf-8")
    db = tmp_path / "t.db"
    key = _key_bytes()
    original_bytes = target.read_bytes()

    first = _run(db, root, "b.log")
    assert first.status == "completed", first.error_summary
    assert first.records_inserted == 1
    (stored_before, _, _) = _stored_row(db)
    event_id_before, hmac_before, fp_before = stored_before

    real_iter = importer_mod.iter_records

    def _mutating_iter(path, **kwargs):
        assert kwargs.get("capture_original") is True
        target.write_bytes(LINE_B.encode())
        try:
            yield from real_iter(path, **kwargs)
        finally:
            target.write_bytes(original_bytes)

    monkeypatch.setattr(importer_mod, "iter_records", _mutating_iter)

    second = _run(db, root, "b.log", capture_originals=True, ip_key=key)
    assert second.records_inserted == 0
    assert second.records_replayed == 1
    assert second.source_changed is True
    assert "source_content_mismatch" in (second.error_summary or "")
    # The mismatched original is refused: nothing stored, counted safely.
    assert second.originals_captured == 0
    assert second.originals_skipped_mismatch == 1

    (stored_after, count, privates) = _stored_row(db)
    assert count == 1 and privates == 0
    assert stored_after[0] == event_id_before
    assert stored_after[1] == hmac_before == _expected_pseudonym("203.0.113.10")
    assert stored_after[2] == fp_before
    # The source file itself is restored byte-identical by the wrapper.
    assert target.read_bytes() == original_bytes
