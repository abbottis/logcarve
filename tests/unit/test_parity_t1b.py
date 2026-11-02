"""T1b unit tests: residual T1a gates plus storage-foundation crypto/schema units.

Residuals (frozen T1a code rechecked here): Combined-family autodetect
gates, the global custom-timeout budget, withheld diagnostics, and
multi-parameter MIME. Storage units: key parsing/separation, AESGCM
round-trips and fail-closed errors, atomic migration splitting, and the
admin IP-display preference helper. Synthetic data only.
"""

import base64
import sqlite3
import subprocess
import sys
import time
from datetime import UTC
from pathlib import Path

import pytest

from app.db import migrations_runner, private
from app.db.database import connect
from app.db.migrations_runner import migrate
from app.db.private import PrivateUnavailable
from app.ingestion.autodetect import MIN_CONFIDENCE, MIN_MARGIN, detect_lines
from app.ingestion.combined import NGINX_COMBINED, NGINX_EXTENDED, LineRejection, parse_line
from app.ingestion.custom import CUSTOM_MATCH_TIMEOUT_S, load_spec
from app.ingestion.stream import (
    CUSTOM_TIMEOUT_ABORT_STREAK,
    CUSTOM_TIMEOUT_ABORT_TOTAL,
    HostSkipped,
    iter_records,
)

ROOT = Path(__file__).resolve().parent.parent.parent
HMAC_KEY = b"parity-t1b-unit-key"
GOOD = b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1" 200 10 "-" "-"'
COMMON = b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /y HTTP/1.1" 200 5'


def _key_bytes(seed: int = 7) -> bytes:
    return bytes((seed * 31 + i) % 256 for i in range(32))


# --- Autodetect: the Combined family clears the same gates ---


def test_autodetect_low_confidence_combined_is_ambiguous():
    result = detect_lines([GOOD] + [b"invalid"] * 9)
    assert result.confidence == pytest.approx(0.1)
    assert result.ambiguous is True
    assert result.format_id is None


def test_autodetect_mixed_combined_common_is_ambiguous():
    result = detect_lines([GOOD] * 6 + [COMMON] * 4)
    assert result.confidence == pytest.approx(0.6)
    assert result.ambiguous is True
    assert result.format_id is None


def test_autodetect_threshold_equality_resolves():
    result = detect_lines([GOOD] * 8 + [b"invalid"] * 2)
    assert result.confidence == pytest.approx(MIN_CONFIDENCE)
    assert result.ambiguous is False
    assert result.format_id == NGINX_COMBINED


def test_autodetect_just_below_threshold_is_ambiguous():
    result = detect_lines([GOOD] * 7 + [b"invalid"] * 3)
    assert result.confidence < MIN_CONFIDENCE
    assert result.ambiguous is True


def test_autodetect_noisy_sample_is_ambiguous():
    result = detect_lines([GOOD] * 5 + [b"invalid"] * 5)
    assert result.ambiguous is True


def test_autodetect_clean_combined_still_resolves():
    result = detect_lines([GOOD] * 10)
    assert result.ambiguous is False
    assert result.format_id == NGINX_COMBINED
    assert result.confidence == pytest.approx(1.0)


def test_autodetect_mixed_family_margin_applies():
    assert MIN_MARGIN == pytest.approx(0.2)
    # Strong family lead still resolves when a third grammar scores.
    vhost = (
        b'example.org 203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /v HTTP/1.1"'
        b' 200 10 "-" "-"'
    )
    result = detect_lines([GOOD] * 8 + [vhost])
    assert result.ambiguous is False


# --- Global custom-timeout budget ---


EVIL_TRAILING_PATTERN = (
    r"^(?P<host>\S+) \[(?P<time>[^\]]+)\] \"(?P<request>[^\"]*)\""
    r" (?P<status>\d{3}) (?P<size>\d+|-) (?:a|aa)+$"
)
EVIL_TRAILING_LINE = (
    b'203.0.113.20 [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1" 200 10 ' + b"a" * 45 + b"!"
)


def _evil_spec():
    return load_spec({"format_id": "custom-adv", "pattern": EVIL_TRAILING_PATTERN})


def test_global_timeout_budget_catches_interleaved_adversarial_lines(tmp_path, monkeypatch):
    """Alternating valid/adversarial lines reset the streak but not the total."""
    import app.ingestion.stream as stream_mod

    spec = _evil_spec()
    valid_line = b'203.0.113.20 [27/Oct/2026:10:15:32 +0100] "GET /ok HTTP/1.1" 200 10\n'
    evil_line = EVIL_TRAILING_LINE + b"\n"
    target = tmp_path / "mixed.log"
    target.write_bytes((evil_line + valid_line) * (CUSTOM_TIMEOUT_ABORT_TOTAL + 4))
    original_parse_item = stream_mod._parse_item

    def _flaky(raw, **kwargs):
        if raw is not None and raw.startswith(b"203.0.113.20 [") and raw.rstrip().endswith(b"!"):
            return (
                LineRejection(0, 0, "custom_timeout", "<withheld>:custom_timeout"),
                None,
            )
        return original_parse_item(raw, **kwargs)

    monkeypatch.setattr(stream_mod, "_parse_item", _flaky)
    import app.ingestion.custom as custom_mod

    with pytest.raises(custom_mod.CustomFormatError) as excinfo:
        list(
            iter_records(
                target, source_id="s", format_id="custom", hmac_key=HMAC_KEY, custom_format=spec
            )
        )
    assert excinfo.value.code == "interrupted:custom_timeout"
    assert CUSTOM_TIMEOUT_ABORT_TOTAL <= CUSTOM_TIMEOUT_ABORT_STREAK * 4


def test_genuine_engine_deadline_probe_in_subprocess(tmp_path):
    """One real engine-timeout probe with a hard subprocess kill budget."""
    script = tmp_path / "evil_match.py"
    script.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(ROOT)!r})\n"
        "from app.ingestion.custom import load_spec, parse_custom_line\n"
        f"spec = load_spec({{'format_id': 'custom-adv', 'pattern': {EVIL_TRAILING_PATTERN!r}}})\n"
        f"line = {EVIL_TRAILING_LINE!r}\n"
        "item = parse_custom_line(line, spec=spec, source_id='s', hmac_key=b'k')\n"
        "print(type(item).__name__ + ':' + item.reason)\n"
    )
    started = time.time()
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    elapsed = time.time() - started
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "LineRejection:custom_timeout"
    assert CUSTOM_MATCH_TIMEOUT_S - 0.1 <= elapsed < 60


# --- Withheld diagnostics ---


def test_rejection_excerpt_never_carries_attacker_bytes():
    # Malformed shape with an IPv4 client and secret query values.
    bad = b"192.0.2.44 " + b"A" * 10 + b"\xff\xfe?token=hunter2&pw=secret"
    item = parse_line(bad, source_id="s", format_id=NGINX_COMBINED, hmac_key=HMAC_KEY)
    assert isinstance(item, LineRejection)
    assert item.excerpt == f"<withheld>:{item.reason}"
    for sentinel in ("192.0.2.44", "hunter2", "secret"):
        assert sentinel not in item.excerpt
        assert sentinel not in repr(item)


def test_ipv6_malformed_line_withheld():
    bad = b"2001:db8::25 this is not a log line ?token=hunter2"
    item = parse_line(bad, source_id="s", format_id=NGINX_COMBINED, hmac_key=HMAC_KEY)
    assert isinstance(item, LineRejection)
    assert item.excerpt == "<withheld>:malformed_line"
    assert "2001:db8::25" not in item.excerpt
    assert "hunter2" not in item.excerpt


def test_invalid_utf8_and_short_lines_withheld():
    short = b"\xff\xfe"
    item = parse_line(short, source_id="s", format_id=NGINX_COMBINED, hmac_key=HMAC_KEY)
    assert isinstance(item, LineRejection)
    assert item.reason == "invalid_encoding"
    assert item.excerpt == "<withheld>:invalid_encoding"


def test_address_like_foreign_host_withheld(tmp_path):
    target = tmp_path / "vhost.log"
    target.write_bytes(
        b'192.0.2.99 203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1" 200 1 "-" "-"\n'
    )
    from app.ingestion.sources import HostFilter

    items = list(
        iter_records(
            target,
            source_id="s",
            format_id="apache_vhost_combined",
            hmac_key=HMAC_KEY,
            host_filter=HostFilter(["example.org"]),
        )
    )
    assert len(items) == 1 and isinstance(items[0], HostSkipped)
    assert items[0].host == "<withheld>"
    assert "192.0.2.99" not in repr(items[0])


# --- Multi-parameter MIME ---


def test_mime_with_several_parameters_keeps_tls_upstream():
    raw = (
        b'192.0.2.1 - - [27/Oct/2026:10:15:00 +0000] "GET / HTTP/1.1" 200 10 '
        b'"-" "Example/1.0" example.org HIT 0.123 text/html; charset=utf-8; version=1.0 '
        b'TLSv1.3 "0.100"'
    )
    item = parse_line(raw, source_id="s", format_id=NGINX_EXTENDED, hmac_key=HMAC_KEY)
    assert not isinstance(item, LineRejection)
    assert item.extra.mime_type == "text/html"
    assert item.extra.tls_protocol == "TLSv1.3"
    assert item.extra.upstream_time_ms == pytest.approx(100.0)
    assert item.extra.cache_status == "HIT"


# --- Key parsing and separation ---


def test_key_parsing_accepts_all_forms_and_rejects_empty():
    raw = _key_bytes()
    assert private.parse_ip_key(raw) == raw
    assert private.parse_ip_key(raw.hex()) == raw
    assert private.parse_ip_key(base64.b64encode(raw).decode()) == raw
    assert private.parse_ip_key(base64.urlsafe_b64encode(raw).decode().rstrip("=")) == raw
    with pytest.raises(PrivateUnavailable) as excinfo:
        private.parse_ip_key("")
    assert excinfo.value.code == "private_unavailable:no_key"
    with pytest.raises(PrivateUnavailable) as excinfo:
        private.parse_ip_key(None)
    assert excinfo.value.code == "private_unavailable:no_key"


def test_key_validation_never_echoes_input():
    evil = "SECRET-ABC-123-not-a-key"
    with pytest.raises(PrivateUnavailable) as excinfo:
        private.parse_ip_key(evil)
    assert excinfo.value.code == "private_unavailable:invalid_key"
    assert "SECRET-ABC-123" not in str(excinfo.value)
    with pytest.raises(PrivateUnavailable) as excinfo:
        private.parse_ip_key("00" * 31)
    assert "00" * 8 not in str(excinfo.value)


def test_missing_key_fails_closed(monkeypatch):
    monkeypatch.delenv("ORIGINAL_IP_KEY", raising=False)
    assert private.load_ip_key() is None
    with pytest.raises(PrivateUnavailable) as excinfo:
        private.require_ip_key()
    assert excinfo.value.code == "private_unavailable:no_key"
    with pytest.raises(PrivateUnavailable) as excinfo:
        private.require_ip_key(explicit="")
    assert excinfo.value.code == "private_unavailable:no_key"


def test_forbidden_keys_rejected(monkeypatch):
    raw = _key_bytes()
    monkeypatch.setenv("HMAC_KEY", base64.b64encode(raw).decode())
    with pytest.raises(PrivateUnavailable) as excinfo:
        private.require_ip_key(explicit=raw)
    assert excinfo.value.code == "private_unavailable:invalid_key"


# --- AESGCM behavior ---


def _aad(**overrides):
    base = {
        "site_id": "site",
        "source_id": "src",
        "file_fingerprint": "fp",
        "byte_offset": 0,
    }
    base.update(overrides)
    return private.build_aad(**base)


def test_encrypt_same_ip_twice_uses_fresh_nonce():
    key = _key_bytes()
    aad = _aad()
    nonce1, ct1 = private.encrypt_ip("203.0.113.20", key=key, aad=aad)
    nonce2, ct2 = private.encrypt_ip("203.0.113.20", key=key, aad=aad)
    assert len(nonce1) == 12 and len(nonce2) == 12
    assert nonce1 != nonce2
    assert ct1 != ct2
    assert private.decrypt_ip(nonce1, ct1, key=key, aad=aad) == "203.0.113.20"
    assert private.decrypt_ip(nonce2, ct2, key=key, aad=aad) == "203.0.113.20"


def test_ipv6_round_trip_preserves_spelling():
    key = _key_bytes(9)
    aad = _aad()
    for text in ("2001:db8::25", "2001:0DB8:0000:0000:0000:0000:0000:0025"):
        nonce, ciphertext = private.encrypt_ip(text, key=key, aad=aad)
        assert private.decrypt_ip(nonce, ciphertext, key=key, aad=aad) == text


def test_wrong_key_tamper_and_swapped_aad_fail_closed():
    key = _key_bytes()
    aad = _aad()
    nonce, ciphertext = private.encrypt_ip("198.51.100.7", key=key, aad=aad)
    with pytest.raises(PrivateUnavailable) as excinfo:
        private.decrypt_ip(nonce, ciphertext, key=_key_bytes(11), aad=aad)
    assert excinfo.value.code == "private_unavailable:decrypt_failed"
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 0x01
    with pytest.raises(PrivateUnavailable) as excinfo:
        private.decrypt_ip(nonce, bytes(tampered), key=key, aad=aad)
    assert excinfo.value.code == "private_unavailable:decrypt_failed"
    for other in (
        _aad(byte_offset=1),
        _aad(site_id="other"),
        _aad(source_id="other"),
        _aad(file_fingerprint="other"),
    ):
        with pytest.raises(PrivateUnavailable) as excinfo:
            private.decrypt_ip(nonce, ciphertext, key=key, aad=other)
        assert excinfo.value.code == "private_unavailable:decrypt_failed"


def test_store_is_keep_first_and_reader_needs_row(tmp_path):
    from app.db import repositories

    db = tmp_path / "priv.sqlite3"
    assert migrate(db).applied == (1, 2, 3, 4, 5, 6, 7)
    conn = connect(db)
    try:
        with conn:
            repositories.ensure_site(
                conn, site_id="s", name="n", hostname="h", created_at="2026-11-01T00:00:00+00:00"
            )
            repositories.ensure_source(
                conn,
                source_id="src",
                site_id="s",
                server_type="nginx",
                format_id="nginx_combined",
                path_alias="a.log",
            )
            import_id = repositories.create_import(
                conn, source_id="src", file_fingerprint="fp", file_size=1, started_at="x"
            )
            conn.execute(
                "INSERT INTO requests (import_id, site_id, source_id, file_fingerprint,"
                " byte_offset, line_number, ts_utc, method, path, status, bytes,"
                " referer_host, user_agent, client_pseudonym, duration_ms)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    import_id,
                    "s",
                    "src",
                    "fp",
                    0,
                    1,
                    "2026-10-27T00:00:00+00:00",
                    "GET",
                    "/",
                    200,
                    1,
                    None,
                    None,
                    "pseudo",
                    None,
                ),
            )
            request_id = conn.execute("SELECT id FROM requests").fetchone()[0]
        key = _key_bytes()
        aad = private.build_aad(site_id="s", source_id="src", file_fingerprint="fp", byte_offset=0)
        nonce, ciphertext = private.encrypt_ip("203.0.113.20", key=key, aad=aad)
        with conn:
            assert (
                private.store_private_ip(
                    conn, request_id=request_id, nonce=nonce, ciphertext=ciphertext
                )
                is True
            )
            assert (
                private.store_private_ip(
                    conn, request_id=request_id, nonce=nonce, ciphertext=ciphertext
                )
                is False
            )
        assert private.read_original_ip(conn, request_id=request_id, key=key) == "203.0.113.20"
        with pytest.raises(PrivateUnavailable) as excinfo:
            private.read_original_ip(conn, request_id=request_id + 999, key=key)
        assert excinfo.value.code == "private_unavailable:not_stored"
    finally:
        conn.close()


# --- Migration atomicity ---


def test_failing_migration_leaves_no_partial_ddl_or_version(tmp_path, monkeypatch):
    staged = tmp_path / "migrations"
    staged.mkdir()
    (staged / "0001_initial.sql").write_text(
        "CREATE TABLE t (id INTEGER PRIMARY KEY, note TEXT NOT NULL);", encoding="utf-8"
    )
    monkeypatch.setattr(migrations_runner, "MIGRATIONS_DIR", staged)
    db = tmp_path / "atomic.sqlite3"
    assert migrate(db).applied == (1,)
    (staged / "0002_extra.sql").write_text(
        "ALTER TABLE t ADD COLUMN extra TEXT;\nTHIS IS NOT SQL;\n", encoding="utf-8"
    )
    with pytest.raises(sqlite3.OperationalError):
        migrate(db)
    probe = sqlite3.connect(str(db))
    try:
        cols = [row[1] for row in probe.execute("PRAGMA table_info(t)")]
        assert cols == ["id", "note"]
        assert probe.execute("SELECT version FROM schema_migrations").fetchall() == [(1,)]
    finally:
        probe.close()
    (staged / "0002_extra.sql").write_text("ALTER TABLE t ADD COLUMN extra TEXT;", encoding="utf-8")
    assert migrate(db).applied == (2,)
    probe = sqlite3.connect(str(db))
    try:
        assert [row[1] for row in probe.execute("PRAGMA table_info(t)")] == ["id", "note", "extra"]
    finally:
        probe.close()


def test_splitter_respects_quotes_and_trigger_bodies():
    statements = migrations_runner._split_statements(
        "CREATE TABLE t (id INTEGER PRIMARY KEY, note TEXT DEFAULT 'a;b');\n"
        "-- a comment; with a semicolon\n"
        "CREATE TRIGGER trg AFTER INSERT ON t BEGIN\n"
        "  UPDATE t SET note = note || ';x' WHERE id = NEW.id;\n"
        "  UPDATE t SET note = note || ';y' WHERE id = NEW.id;\n"
        "END;\n"
        "/* block; comment */\n"
        "CREATE INDEX idx ON t (note);"
    )
    assert len(statements) == 3
    assert "a;b" in statements[0]
    assert statements[1].lstrip().startswith("-- a comment;")
    assert "CREATE TRIGGER trg" in statements[1]
    assert statements[1].rstrip().endswith("END")
    assert statements[2].rstrip().endswith("CREATE INDEX idx ON t (note)")


def test_transaction_control_scripts_rejected(tmp_path, monkeypatch):
    staged = tmp_path / "migrations"
    staged.mkdir()
    (staged / "0001_initial.sql").write_text(
        "CREATE TABLE t (id INTEGER PRIMARY KEY);", encoding="utf-8"
    )
    monkeypatch.setattr(migrations_runner, "MIGRATIONS_DIR", staged)
    db = tmp_path / "tx.sqlite3"
    assert migrate(db).applied == (1,)
    (staged / "0002_bad.sql").write_text(
        "ALTER TABLE t ADD COLUMN extra TEXT; COMMIT;", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="transaction control"):
        migrate(db)
    probe = sqlite3.connect(str(db))
    try:
        assert [row[1] for row in probe.execute("PRAGMA table_info(t)")] == ["id"]
        assert probe.execute("SELECT version FROM schema_migrations").fetchall() == [(1,)]
    finally:
        probe.close()


# --- Admin IP-display preference helper ---


def test_ip_display_mode_defaults_full_and_validates(tmp_path):
    db = tmp_path / "mode.sqlite3"
    assert migrate(db).applied == (1, 2, 3, 4, 5, 6, 7)
    conn = connect(db)
    try:
        assert private.get_ip_display_mode(conn) == "full"
        with conn:
            assert private.set_ip_display_mode(conn, "suffix_mask") == "suffix_mask"
        assert private.get_ip_display_mode(conn) == "suffix_mask"
        with conn:
            assert private.set_ip_display_mode(conn, "pseudonym_only") == "pseudonym_only"
        assert private.get_ip_display_mode(conn) == "pseudonym_only"
        with pytest.raises(ValueError):
            private.set_ip_display_mode(conn, "everyone")
    finally:
        conn.close()


def test_ip_display_modes_mask_before_dom():
    assert private.format_original_for_display("203.0.113.20", "pseudo", "full") == "203.0.113.20"
    masked4 = private.format_original_for_display("203.0.113.20", "pseudo", "suffix_mask")
    assert "203.0.113.20" not in masked4
    assert masked4.startswith("203.0.113.")
    assert masked4.endswith(".*")
    masked6 = private.format_original_for_display("2001:db8::25", "pseudo", "suffix_mask")
    assert "25" not in masked6.split(":")[-1]
    assert "2001" in masked6 and "db8" in masked6
    assert masked6.endswith(":*")
    assert (
        private.format_original_for_display("2001:db8::25", "pseudo", "pseudonym_only") == "pseudo"
    )
    with pytest.raises(ValueError):
        private.format_original_for_display("2001:db8::25", "pseudo", "everyone")


# --- Migration atomicity: confirmed-probe regressions ---


def test_comment_prefixed_commit_leaves_no_tables(tmp_path, monkeypatch):
    """The exact confirmed escape: comment-then-COMMIT must not commit DDL."""
    staged = tmp_path / "migrations"
    staged.mkdir()
    (staged / "0001_base.sql").write_text("CREATE TABLE keep_me (v);", encoding="utf-8")
    monkeypatch.setattr(migrations_runner, "MIGRATIONS_DIR", staged)
    db = tmp_path / "evil.sqlite3"
    assert migrate(db).applied == (1,)
    (staged / "0002_evil.sql").write_text(
        "CREATE TABLE first (v); -- harmless comment\n COMMIT; CREATE TABLE second (v);",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="transaction control"):
        migrate(db)
    probe = sqlite3.connect(str(db))
    try:
        tables = {
            row[0]
            for row in probe.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        assert "first" not in tables and "second" not in tables
        assert probe.execute("SELECT version FROM schema_migrations").fetchall() == [(1,)]
    finally:
        probe.close()


def test_trigger_case_body_applies_as_one_statement(tmp_path, monkeypatch):
    """CREATE TRIGGER with CASE ... END must not be split by the runner."""
    staged = tmp_path / "migrations"
    staged.mkdir()
    (staged / "0001_trg.sql").write_text(
        "CREATE TABLE t (id INTEGER PRIMARY KEY, note TEXT DEFAULT '');\n"
        "CREATE TRIGGER trg AFTER INSERT ON t BEGIN\n"
        "  UPDATE t SET note = CASE WHEN NEW.id > 0 THEN 'pos' ELSE 'other' END\n"
        "    WHERE id = NEW.id;\n"
        "END;\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(migrations_runner, "MIGRATIONS_DIR", staged)
    db = tmp_path / "trg.sqlite3"
    assert migrate(db).applied == (1,)
    conn = sqlite3.connect(str(db))
    try:
        with conn:
            conn.execute("INSERT INTO t (id) VALUES (1)")
        assert conn.execute("SELECT note FROM t WHERE id = 1").fetchone()[0] == "pos"
    finally:
        conn.close()


def test_bracketed_identifiers_and_quoted_semicolons_apply(tmp_path, monkeypatch):
    staged = tmp_path / "migrations"
    staged.mkdir()
    (staged / "0001_b.sql").write_text(
        "CREATE TABLE [we;ird]([a;b] TEXT DEFAULT 'x;y');\n"
        "INSERT INTO [we;ird] ([a;b]) VALUES ('v;v');",
        encoding="utf-8",
    )
    monkeypatch.setattr(migrations_runner, "MIGRATIONS_DIR", staged)
    db = tmp_path / "br.sqlite3"
    assert migrate(db).applied == (1,)
    probe = sqlite3.connect(str(db))
    try:
        assert probe.execute("SELECT [a;b] FROM [we;ird]").fetchone()[0] == "v;v"
    finally:
        probe.close()


def test_migration_writer_coordination_is_bounded(tmp_path, monkeypatch):
    """A held writer lock fails fast with WriterBusy instead of hanging."""
    from app.db.database import WriterBusy
    from app.db.database import connect as app_connect

    staged = tmp_path / "migrations"
    staged.mkdir()
    (staged / "0001_base.sql").write_text("CREATE TABLE t (v);", encoding="utf-8")
    monkeypatch.setattr(migrations_runner, "MIGRATIONS_DIR", staged)
    db = tmp_path / "busy.sqlite3"
    assert migrate(db).applied == (1,)
    extra = staged / "0099_extra.sql"
    extra.write_text("CREATE TABLE u (v);", encoding="utf-8")
    holder = app_connect(db)
    try:
        holder.execute("BEGIN IMMEDIATE")
        with pytest.raises(WriterBusy):
            migrations_runner._apply_migration(db, 99, extra, lock_timeout_s=0.2)
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    probe = sqlite3.connect(str(db))
    try:
        assert probe.execute("SELECT version FROM schema_migrations").fetchall() == [(1,)]
    finally:
        probe.close()
    assert migrate(db).applied == (99,)


# --- Strict key parsing ---


def test_key_parsing_rejects_appended_junk_and_whitespace():
    raw = _key_bytes()
    std = base64.b64encode(raw).decode()
    for bad in (
        std + "!!!",
        " " + std + " ",
        "\t" + std,
        "00" * 32 + " ",
        raw.hex() + "\n ",
        "A" * 45,
        "A" * 42,
        "!" * 44,
    ):
        with pytest.raises(PrivateUnavailable) as excinfo:
            private.parse_ip_key(bad)
        assert excinfo.value.code == "private_unavailable:invalid_key"
        assert std[:8] not in str(excinfo.value)


def test_key_parsing_accepts_newline_and_unpadded_urlsafe():
    raw = _key_bytes()
    std = base64.b64encode(raw).decode()
    assert private.parse_ip_key(std + "\n") == raw
    assert private.parse_ip_key(std.rstrip("=")) == raw
    url = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    assert private.parse_ip_key(url) == raw
    assert private.parse_ip_key(url + "\r\n") == raw


def test_forbidden_key_unpadded_urlsafe_form_rejected(monkeypatch):
    raw = _key_bytes()
    url_unpadded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    monkeypatch.setenv("HMAC_KEY", url_unpadded)
    with pytest.raises(PrivateUnavailable) as excinfo:
        private.require_ip_key(explicit=raw)
    assert excinfo.value.code == "private_unavailable:invalid_key"


# --- AAD framing and blob validation ---


def test_aad_has_no_delimiter_collisions():
    aaa = private.build_aad(site_id="a\x00b", source_id="c", file_fingerprint="f", byte_offset=0)
    bbb = private.build_aad(site_id="a", source_id="b\x00c", file_fingerprint="f", byte_offset=0)
    assert aaa != bbb
    assert private.build_aad(
        site_id="s", source_id="src", file_fingerprint="fp", byte_offset=0
    ) == private.build_aad(site_id="s", source_id="src", file_fingerprint="fp", byte_offset=0)


def test_malformed_blobs_fail_closed_without_leak(tmp_path):
    from app.db import repositories

    db = tmp_path / "blob.sqlite3"
    assert migrate(db).applied == (1, 2, 3, 4, 5, 6, 7)
    conn = connect(db)
    try:
        with conn:
            repositories.ensure_site(
                conn, site_id="s", name="n", hostname="h", created_at="2026-11-01T00:00:00+00:00"
            )
            repositories.ensure_source(
                conn,
                source_id="src",
                site_id="s",
                server_type="nginx",
                format_id="nginx_combined",
                path_alias="a.log",
            )
            import_id = repositories.create_import(
                conn, source_id="src", file_fingerprint="fp", file_size=1, started_at="x"
            )
            conn.execute(
                "INSERT INTO requests (import_id, site_id, source_id, file_fingerprint,"
                " byte_offset, line_number, ts_utc, method, path, status, bytes,"
                " referer_host, user_agent, client_pseudonym, duration_ms)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    import_id,
                    "s",
                    "src",
                    "fp",
                    0,
                    1,
                    "2026-10-27T00:00:00+00:00",
                    "GET",
                    "/",
                    200,
                    1,
                    None,
                    None,
                    "pseudo",
                    None,
                ),
            )
            request_id = conn.execute("SELECT id FROM requests").fetchone()[0]
            conn.execute(
                "INSERT INTO request_original_ips (request_id, nonce, ciphertext, created_at)"
                " VALUES (?, 'TEXT-NOT-A-BLOB', 'ALSO-TEXT', 'x')",
                (request_id,),
            )
        with pytest.raises(PrivateUnavailable) as excinfo:
            private.fetch_private_row(conn, request_id=request_id)
        assert excinfo.value.code == "private_unavailable:decrypt_failed"
        with pytest.raises(PrivateUnavailable) as excinfo:
            private.read_original_ip(conn, request_id=request_id, key=_key_bytes())
        assert excinfo.value.code == "private_unavailable:decrypt_failed"
        assert "TEXT-NOT-A-BLOB" not in str(excinfo.value)
        with pytest.raises(PrivateUnavailable) as excinfo:
            private.decrypt_ip("nope", b"\x00", key=_key_bytes(), aad=b"aad")
        assert excinfo.value.code == "private_unavailable:decrypt_failed"
    finally:
        conn.close()


# --- Transient capture protection ---


def test_captured_original_repr_withholds_plaintext():
    from app.ingestion.combined import CapturedOriginal

    item = parse_line(
        GOOD, source_id="s", format_id=NGINX_COMBINED, hmac_key=HMAC_KEY, capture_original=True
    )
    record, captured = item
    assert isinstance(captured, CapturedOriginal)
    assert captured.reveal() == "203.0.113.20"
    # Legacy HMAC input stays byte-exact through the capture path.
    assert (
        record.client_pseudonym
        == parse_line(
            GOOD, source_id="s", format_id=NGINX_COMBINED, hmac_key=HMAC_KEY
        ).client_pseudonym
    )
    for rendered in (repr(item), repr(captured), str(captured), repr([captured])):
        assert "203.0.113.20" not in rendered
    import json as _json

    with pytest.raises(TypeError):
        _json.dumps({"original": captured})
    rejected = parse_line(
        b"bogus line",
        source_id="s",
        format_id=NGINX_COMBINED,
        hmac_key=HMAC_KEY,
        capture_original=True,
    )
    assert rejected[1] is None
    with pytest.raises(TypeError):
        private.encrypt_captured("203.0.113.20", key=_key_bytes(), aad=b"aad")


def test_no_original_leaves_with_skips_or_rejections(tmp_path):
    from app.ingestion.sources import HostFilter
    from app.ingestion.stream import ImportReport

    target = tmp_path / "vhost.log"
    target.write_bytes(
        b'foreign.example 203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1"'
        b' 200 10 "-" "-"\n'
        b"this is not a log line\n"
    )
    report = ImportReport(source_id="s", format_id="apache_vhost_combined")
    yielded = list(
        iter_records(
            target,
            source_id="s",
            format_id="apache_vhost_combined",
            hmac_key=HMAC_KEY,
            host_filter=HostFilter(["example.org"]),
            report=report,
            capture_original=True,
        )
    )
    assert len(yielded) == 2
    for produced, original in yielded:
        assert original is None
        assert "203.0.113.20" not in repr(produced)


# --- Exact abort accounting: plain and gzip ---


@pytest.mark.parametrize("as_gzip", [False, True])
def test_terminal_timeout_line_counted_exactly(tmp_path, monkeypatch, as_gzip):
    import gzip as _gzip

    import app.ingestion.stream as stream_mod
    from app.ingestion.stream import ImportReport

    spec = _evil_spec()
    # A single trailing "a" satisfies the evil grammar immediately (fast
    # accept); the 45-a-plus-"!" evil line burns the engine budget.
    valid_line = b'203.0.113.20 [27/Oct/2026:10:15:32 +0100] "GET /ok HTTP/1.1" 200 10 a\n'
    evil_line = EVIL_TRAILING_LINE + b"\n"
    body = (evil_line + valid_line) * (CUSTOM_TIMEOUT_ABORT_TOTAL + 4)
    target = tmp_path / ("mixed.log.gz" if as_gzip else "mixed.log")
    target.write_bytes(_gzip.compress(body) if as_gzip else body)
    original_parse_item = stream_mod._parse_item

    def _flaky(raw, **kwargs):
        if raw is not None and raw.startswith(b"203.0.113.20 [") and raw.rstrip().endswith(b"!"):
            return (
                LineRejection(0, 0, "custom_timeout", "<withheld>:custom_timeout"),
                None,
            )
        return original_parse_item(raw, **kwargs)

    monkeypatch.setattr(stream_mod, "_parse_item", _flaky)
    import app.ingestion.custom as custom_mod

    report = ImportReport(source_id="s", format_id="custom")
    with pytest.raises(custom_mod.CustomFormatError) as excinfo:
        list(
            iter_records(
                target,
                source_id="s",
                format_id="custom",
                hmac_key=HMAC_KEY,
                custom_format=spec,
                report=report,
            )
        )
    assert excinfo.value.code == "interrupted:custom_timeout"
    # Alternating evil/valid: the 32nd timeout lands on physical line 63
    # and is counted exactly once; the digest stays unset on interruption.
    assert report.lines_read == 2 * CUSTOM_TIMEOUT_ABORT_TOTAL - 1
    assert report.rejected == CUSTOM_TIMEOUT_ABORT_TOTAL
    assert report.accepted == CUSTOM_TIMEOUT_ABORT_TOTAL - 1
    assert report.consumed_sha256 is None


# --- Retention connection requirement ---


def test_retention_fails_closed_without_enforced_fks(tmp_path):
    from app.db import repositories
    from app.db.retention import apply_retention

    db = tmp_path / "ret.sqlite3"
    assert migrate(db).applied == (1, 2, 3, 4, 5, 6, 7)
    conn = connect(db)
    try:
        with conn:
            repositories.ensure_site(
                conn, site_id="s", name="n", hostname="h", created_at="2026-11-01T00:00:00+00:00"
            )
            repositories.ensure_source(
                conn,
                source_id="src",
                site_id="s",
                server_type="nginx",
                format_id="nginx_combined",
                path_alias="a.log",
            )
            import_id = repositories.create_import(
                conn, source_id="src", file_fingerprint="fp", file_size=1, started_at="x"
            )
            conn.execute(
                "INSERT INTO requests (import_id, site_id, source_id, file_fingerprint,"
                " byte_offset, line_number, ts_utc, method, path, status, bytes,"
                " referer_host, user_agent, client_pseudonym, duration_ms)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    import_id,
                    "s",
                    "src",
                    "fp",
                    0,
                    1,
                    "2020-01-01T00:00:00+00:00",
                    "GET",
                    "/",
                    200,
                    1,
                    None,
                    None,
                    "pseudo",
                    None,
                ),
            )
            request_id = conn.execute("SELECT id FROM requests").fetchone()[0]
            key = _key_bytes()
            aad = private.build_aad(
                site_id="s", source_id="src", file_fingerprint="fp", byte_offset=0
            )
            nonce, ciphertext = private.encrypt_ip("203.0.113.20", key=key, aad=aad)
            assert private.store_private_ip(
                conn, request_id=request_id, nonce=nonce, ciphertext=ciphertext
            )
    finally:
        conn.close()
    # Caller connection with FKs OFF inside an active transaction: fail
    # closed before deleting, leaving no private orphans behind.
    raw = sqlite3.connect(str(db))
    try:
        assert raw.execute("PRAGMA foreign_keys").fetchone()[0] == 0
        raw.execute("BEGIN")
        from datetime import datetime as _dt

        with pytest.raises(sqlite3.IntegrityError):
            apply_retention(raw, days=30, now=_dt(2026, 11, 1, tzinfo=UTC))
        raw.execute("ROLLBACK")
        assert raw.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 1
        assert raw.execute("SELECT COUNT(*) FROM request_original_ips").fetchone()[0] == 1
    finally:
        raw.close()
    # Normal app connection cascades the private row and counts requests.
    app_conn = connect(db)
    try:
        from datetime import datetime as _dt

        with app_conn:
            deleted = apply_retention(app_conn, days=30, now=_dt(2026, 11, 1, tzinfo=UTC))
        assert deleted == 1
        assert app_conn.execute("SELECT COUNT(*) FROM request_original_ips").fetchone()[0] == 0
    finally:
        app_conn.close()


def test_enrichment_policy_tags_and_custom_fingerprint():
    from app.ingestion.combined import PARSER_POLICY_VERSION, enrichment_policy

    assert enrichment_policy(NGINX_COMBINED) == PARSER_POLICY_VERSION
    assert enrichment_policy(NGINX_COMBINED) == "t1b.1"

    from typing import ClassVar

    class _Spec:
        format_id: ClassVar[str] = "custom-demo"
        pattern: ClassVar[object] = None
        timing: ClassVar[object] = {"request_time": {"unit": "s"}}

    import re as _re

    _Spec.pattern = _re.compile("(?P<host>\\S+) (?P<time>[^ ]+)")
    first = enrichment_policy("custom", _Spec())
    _Spec.timing = {"request_time": {"unit": "ms"}}
    second = enrichment_policy("custom", _Spec())
    assert first.startswith("t1b.1+custom:") and second.startswith("t1b.1+custom:")
    assert first != second
