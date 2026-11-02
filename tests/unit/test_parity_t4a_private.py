"""T4a unit tests: fail-closed display preferences, robust masking, private binding.

Covers PAR-02 display units on temporary synthetic databases: unset
mode defaults full while a present-but-invalid mode fails closed to
pseudonym-only; hidden octet/hextet counts validate with max-hide
fallback; masking handles compressed/expanded/mapped IPv6 and rejects
scoped forms and invalid input without plaintext fallback; the
transient private binder resolves each row by internal id with fixed
unavailable codes; referrer links allow http/https only; CSRF field
comparison never raises. Synthetic data only.
"""

from datetime import UTC, datetime

import pytest

from app.db import private
from app.db.database import connect
from app.db.migrations_runner import migrate
from app.db.private import PrivateUnavailable
from app.web import private_ip
from app.web.routes import _valid_csrf_field


def _db(tmp_path):
    db = tmp_path / "t4a.sqlite3"
    assert migrate(db).applied == (1, 2, 3, 4, 5, 6, 7, 8)
    return db


def test_mode_unset_defaults_full_not_corrupt(tmp_path):
    conn = connect(_db(tmp_path))
    try:
        assert private.get_ip_display_mode(conn) == "full"
        assert private.is_ip_display_corrupt(conn) is False
        state = private.resolve_display_state(conn)
        assert state["mode"] == "full"
        assert state["corrupt"] is False
        assert state["defaulted"] is True
    finally:
        conn.close()


def test_mode_present_invalid_fails_closed_pseudonym(tmp_path):
    db = _db(tmp_path)
    conn = connect(db)
    try:
        conn.execute(
            "INSERT INTO admin_settings (key, value, updated_at) VALUES (?, ?, ?)",
            ("ip_display_mode", "everyone", datetime.now(UTC).isoformat()),
        )
        conn.commit()
        # A present-but-invalid preference must NOT silently unmask:
        # effective mode is pseudonym-only with a corrupt signal.
        assert private.get_ip_display_mode(conn) == "pseudonym_only"
        assert private.is_ip_display_corrupt(conn) is True
        state = private.resolve_display_state(conn)
        assert state["mode"] == "pseudonym_only"
        assert state["corrupt"] is True
        assert state["defaulted"] is False
    finally:
        conn.close()


def test_hidden_counts_defaults_and_validation(tmp_path):
    db = _db(tmp_path)
    conn = connect(db)
    try:
        assert private.get_ip_hidden_counts(conn) == (1, 4)
        assert private.are_ip_hidden_counts_corrupt(conn) is False
        with conn:
            assert private.set_ip_hidden_counts(conn, 2, 6) == (2, 6)
        assert private.get_ip_hidden_counts(conn) == (2, 6)
        assert private.are_ip_hidden_counts_corrupt(conn) is False
        for bad_v4, bad_v6 in [(0, 4), (5, 4), (1, 0), (1, 9)]:
            with pytest.raises(ValueError):
                private.set_ip_hidden_counts(conn, bad_v4, bad_v6)
        for bad_v4, bad_v6 in [("x", 4), (1, "y"), (True, 4), (1, False), (None, 4)]:
            with pytest.raises(TypeError):
                private.set_ip_hidden_counts(conn, bad_v4, bad_v6)
        # Corrupt stored counts fail closed to maximum hiding.
        conn.execute(
            "INSERT INTO admin_settings (key, value, updated_at) VALUES (?, ?, ?)"
            " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            ("ip_hidden_octets", "99", datetime.now(UTC).isoformat()),
        )
        conn.execute(
            "INSERT INTO admin_settings (key, value, updated_at) VALUES (?, ?, ?)"
            " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            ("ip_hidden_hextets", "junk", datetime.now(UTC).isoformat()),
        )
        conn.commit()
        assert private.get_ip_hidden_counts(conn) == (4, 8)
        assert private.are_ip_hidden_counts_corrupt(conn) is True
        state = private.resolve_display_state(conn)
        assert state["mode"] == "pseudonym_only"
        assert state["corrupt"] is True
    finally:
        conn.close()


def test_mask_ipv4_defaults_and_maxhide():
    assert private.mask_ip_suffix("203.0.113.20") == "203.0.113.*"
    assert private.mask_ip_suffix("203.0.113.20", v4_hidden=2) == "203.0.*.*"
    assert private.mask_ip_suffix("203.0.113.20", v4_hidden=4) == "*.*.*.*"
    rendered = private.mask_ip_suffix("203.0.113.20")
    assert "203.0.113.20" not in rendered


def test_mask_ipv6_spellings_and_mapped():
    default = private.mask_ip_suffix("2001:db8::25")
    assert default.endswith(":*")
    assert "2001" in default and "db8" in default
    assert "2001:db8::25" not in default
    expanded = private.mask_ip_suffix("2001:0db8:0000:0000:0000:0000:0000:0025")
    assert expanded == default
    maxhide = private.mask_ip_suffix("2001:db8::25", v6_hidden=8)
    assert maxhide == "*"
    mapped = private.mask_ip_suffix("::ffff:192.0.2.1")
    assert mapped.endswith(":*")
    assert "192.0.2.1" not in mapped
    # Legacy byte identity is preserved by full mode, not by masking.
    assert private.format_original_for_display("2001:db8::25", "pseudo", "full") == "2001:db8::25"


def test_mask_scoped_and_invalid_fail_closed():
    for bad in ("fe80::1%eth0", "FE80::1%en0", "not-an-ip", "999.1.1.1", "", "203.0.113.20/24"):
        with pytest.raises(ValueError):
            private.mask_ip_suffix(bad)
    for kwargs in ({"v4_hidden": 0}, {"v4_hidden": 5}, {"v6_hidden": 0}, {"v6_hidden": 9}):
        with pytest.raises(ValueError):
            private.mask_ip_suffix("203.0.113.20", **kwargs)
            private.mask_ip_suffix("::1", **kwargs)
    for kwargs in ({"v4_hidden": "1"}, {"v6_hidden": "4"}, {"v4_hidden": True}):
        with pytest.raises(TypeError):
            private.mask_ip_suffix("::1", **kwargs)
    with pytest.raises(ValueError):
        private.format_original_for_display("fe80::1%eth0", "pseudo", "full")


def test_format_modes_and_pseudonym():
    assert private.format_original_for_display("203.0.113.20", "abc", "full") == "203.0.113.20"
    masked = private.format_original_for_display("203.0.113.20", "abc", "suffix_mask")
    assert masked == "203.0.113.*"
    assert private.format_original_for_display("203.0.113.20", "abc", "pseudonym_only") == "abc"
    with pytest.raises(ValueError):
        private.format_original_for_display("203.0.113.20", "abc", "everyone")


def _private_conn(tmp_path, key):
    """Minimal store with two requests: one enriched, one legacy unenriched."""
    db = _db(tmp_path)
    conn = connect(db)
    conn.execute(
        "INSERT INTO sites (id, name, hostname, timezone, created_at)"
        " VALUES ('s', 'S', 'example.org', 'UTC', '2026-10-27T10:00:00+00:00')"
    )
    conn.execute(
        "INSERT INTO log_sources (id, site_id, server_type, format_id, path_alias, enabled)"
        " VALUES ('src', 's', 'nginx', 'nginx_extended', 'a.log', 1)"
    )
    cursor = conn.execute(
        "INSERT INTO imports (source_id, file_fingerprint, file_size, lines_total,"
        " lines_accepted, lines_rejected, records_inserted, records_replayed,"
        " status, started_at) VALUES ('src', 'fp', 10, 2, 2, 0, 2, 0, 'done',"
        " '2026-10-27T10:00:00+00:00')"
    )
    import_id = cursor.lastrowid
    conn.execute(
        "INSERT INTO requests (site_id, source_id, file_fingerprint, byte_offset,"
        " line_number, ts_utc, method, path, status, bytes, client_pseudonym, import_id)"
        " VALUES ('s', 'src', 'fp', 100, 1, '2026-10-27T10:00:00+00:00',"
        f" 'GET', '/a', 200, 10, 'pseudo-same', {import_id})"
    )
    first = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        "INSERT INTO requests (site_id, source_id, file_fingerprint, byte_offset,"
        " line_number, ts_utc, method, path, status, bytes, client_pseudonym, import_id)"
        " VALUES ('s', 'src', 'fp', 200, 2, '2026-10-27T10:00:00+00:00',"
        f" 'GET', '/a', 200, 10, 'pseudo-same', {import_id})"
    )
    second = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    aad1 = private.build_aad(site_id="s", source_id="src", file_fingerprint="fp", byte_offset=100)
    nonce, ciphertext = private.encrypt_ip("203.0.113.20", key=key, aad=aad1)
    private.store_private_ip(conn, request_id=first, nonce=nonce, ciphertext=ciphertext)
    conn.commit()
    return conn, first, second


def test_attach_binds_duplicates_by_id_and_marks_legacy(tmp_path):
    key = bytes(range(32))
    conn, first, second = _private_conn(tmp_path, key)
    try:
        state = {"mode": "full", "v4_hidden": 1, "v6_hidden": 4, "corrupt": False}
        rows = private_ip.attach_private(
            conn,
            [
                (first, {"client_pseudonym": "pseudo-same"}),
                (second, {"client_pseudonym": "pseudo-same"}),
            ],
            key=key,
            key_code=None,
            state=state,
        )
        # Identical adjacent rows resolve to their OWN events: the
        # enriched row shows its original, the legacy row is unavailable.
        assert rows[0]["ip_display"] == "203.0.113.20"
        assert rows[0]["ip_state"] == "shown"
        assert rows[1]["ip_display"] == "pseudo-same"
        assert rows[1]["ip_state"] == "unavailable"
        assert rows[1]["ip_notice"] == "privacy.ip_unavailable_not_stored"
        # Shared identity is untouched by the private layer.
        assert rows[0]["client_pseudonym"] == rows[1]["client_pseudonym"] == "pseudo-same"
    finally:
        conn.close()


def test_attach_masks_suffix_absent_and_pseudonym_passthrough(tmp_path):
    key = bytes(range(32))
    conn, first, _ = _private_conn(tmp_path, key)
    try:
        masked = private_ip.attach_private(
            conn,
            [(first, {"client_pseudonym": "pseudo-same"})],
            key=key,
            key_code=None,
            state={"mode": "suffix_mask", "v4_hidden": 1, "v6_hidden": 4, "corrupt": False},
        )
        assert masked[0]["ip_display"] == "203.0.113.*"
        assert masked[0]["ip_state"] == "masked"
        assert "203.0.113.20" not in masked[0]["ip_display"]
        pseudo = private_ip.attach_private(
            conn,
            [(first, {"client_pseudonym": "pseudo-same"})],
            key=key,
            key_code=None,
            state={"mode": "pseudonym_only", "v4_hidden": 1, "v6_hidden": 4, "corrupt": False},
        )
        assert pseudo[0]["ip_display"] == "pseudo-same"
        assert pseudo[0]["ip_state"] == "pseudonym"
    finally:
        conn.close()


def test_attach_unavailable_codes_fail_closed(tmp_path):
    key = bytes(range(32))
    wrong = bytes(32)
    conn, first, _ = _private_conn(tmp_path, key)
    try:
        state = {"mode": "full", "v4_hidden": 1, "v6_hidden": 4, "corrupt": False}
        no_key = private_ip.attach_private(
            conn,
            [(first, {"client_pseudonym": "p"})],
            key=None,
            key_code=private.UNAVAILABLE_NO_KEY,
            state=state,
        )
        assert no_key[0]["ip_state"] == "unavailable"
        assert no_key[0]["ip_notice"] == "privacy.ip_unavailable_no_key"
        bad_key = private_ip.attach_private(
            conn,
            [(first, {"client_pseudonym": "p"})],
            key=wrong,
            key_code=private.UNAVAILABLE_INVALID_KEY,
            state=state,
        )
        assert bad_key[0]["ip_state"] == "unavailable"
        assert bad_key[0]["ip_display"] == "p"
        # Tampered ciphertext fails closed, never plaintext.
        conn.execute(
            "UPDATE request_original_ips SET ciphertext = ? WHERE request_id = ?",
            (b"tampered-bytes", first),
        )
        conn.commit()
        tampered = private_ip.attach_private(
            conn,
            [(first, {"client_pseudonym": "p"})],
            key=key,
            key_code=None,
            state=state,
        )
        assert tampered[0]["ip_state"] == "unavailable"
        assert tampered[0]["ip_notice"] == "privacy.ip_unavailable_decrypt_failed"
        # Corrupt preferences force pseudonym-only even in full mode.
        corrupt = private_ip.attach_private(
            conn,
            [(first, {"client_pseudonym": "p"})],
            key=key,
            key_code=None,
            state={"mode": "pseudonym_only", "v4_hidden": 4, "v6_hidden": 8, "corrupt": True},
        )
        assert corrupt[0]["ip_state"] == "pseudonym"
    finally:
        conn.close()


def test_safe_referrer_url_allows_only_http_https():
    assert (
        private_ip.safe_referrer_url("https", "example.org", "/old?a=1")
        == "https://example.org/old?a=1"
    )
    assert private_ip.safe_referrer_url("http", "example.org", "") == "http://example.org"
    assert private_ip.safe_referrer_url("HTTP", "example.org", "/x") == "http://example.org/x"
    for scheme, host, path in [
        ("javascript", "x", "alert(1)"),
        ("data", "text/plain", "base64,AA=="),
        ("ftp", "example.org", "/f"),
        ("", "example.org", "/x"),
        (None, "example.org", "/x"),
        ("https", None, "/x"),
        ("https", "", "/x"),
        ("https", "exam\\ple.org", "/x"),
        ("https", "example.org", "noslash"),
        ("https", "example.org", "/bad\\path"),
        ("https", "ex ample.org", "/x"),
        ("https", "münchen.de", "/x"),
    ]:
        assert private_ip.safe_referrer_url(scheme, host, path) is None


def test_csrf_field_check_never_raises():
    assert _valid_csrf_field("tok", "tok") is True
    assert _valid_csrf_field("tok", "other") is False
    assert _valid_csrf_field("", "tok") is False
    assert _valid_csrf_field(None, "tok") is False
    assert _valid_csrf_field("tok", None) is False
    # Non-ASCII/malformed values fail closed instead of raising
    # (compare_digest rejects non-ASCII str): even equal Unicode
    # tokens yield the safe False, never a TypeError/500.
    assert _valid_csrf_field("tökén-☃", "tökén-☃") is False
    assert _valid_csrf_field("tökén", "other") is False
    assert _valid_csrf_field(123, "tok") is False


def test_key_status_codes_without_echo(tmp_path):
    conn = connect(_db(tmp_path))
    try:
        key, code = private_ip.key_status(conn)
        assert key is None
        assert code in (private.UNAVAILABLE_NO_KEY, private.UNAVAILABLE_INVALID_KEY)
    finally:
        conn.close()
    with pytest.raises(PrivateUnavailable):
        private.require_ip_key(explicit="not-a-key!!!")


def test_malformed_blob_types_fail_closed():
    with pytest.raises(PrivateUnavailable):
        private.decrypt_ip("nonce", b"cipher", key=bytes(32), aad=b"aad")
