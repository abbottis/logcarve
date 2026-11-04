"""T5 auth unit tests: Argon2 passwords, sessions, scoped tokens, rate limits."""

from datetime import UTC, datetime, timedelta

import pytest

from app.api.deps import LoginRateLimiter
from app.auth import tokens
from app.auth.passwords import hash_password, verify_password
from app.db.database import connect
from app.db.migrations_runner import migrate

NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "auth.sqlite3"
    migrate(path)
    return path


def _conn(db):
    return connect(db)


def test_password_roundtrip_and_failures():
    encoded = hash_password("correct horse battery staple")
    assert encoded.startswith("$argon2")
    assert verify_password(encoded, "correct horse battery staple") is True
    assert verify_password(encoded, "wrong password") is False
    assert verify_password("not-a-hash", "whatever") is False
    with pytest.raises(ValueError):
        hash_password("")


def test_admin_user_and_session_lifecycle(db):
    conn = _conn(db)
    with conn:
        user_id = tokens.create_admin_user(
            conn, username="admin", password_hash=hash_password("pw")
        )
        session = tokens.create_session(conn, user_id=user_id, username="admin", now=NOW)
    assert session.csrf_token and session.id != session.csrf_token
    assert tokens.get_session(conn, session_id=session.id, now=NOW) == session
    assert tokens.get_session(conn, session_id="nope", now=NOW) is None
    assert tokens.get_session(conn, session_id=session.id, now=NOW + timedelta(hours=13)) is None
    conn.close()


def test_credentials_do_not_enumerate(db):
    conn = _conn(db)
    with conn:
        tokens.create_admin_user(conn, username="admin", password_hash=hash_password("pw"))
    assert tokens.verify_admin_credentials(conn, username="admin", password="pw") == 1
    assert tokens.verify_admin_credentials(conn, username="admin", password="wrong") is None
    assert tokens.verify_admin_credentials(conn, username="ghost", password="pw") is None
    conn.close()


def test_token_issue_verify_expiry_revoke(db):
    conn = _conn(db)
    with conn:
        from app.db import repositories

        repositories.ensure_site(
            conn, site_id="default", name="s", hostname="example.org", created_at=NOW.isoformat()
        )
        token_id, plaintext = tokens.issue_token(conn, name="t", site_id="default")
    assert plaintext.startswith("lc_")
    token = tokens.verify_token(conn, plaintext=plaintext)
    assert token is not None and token.site_id == "default" and token.scopes == ("analytics:read",)
    assert tokens.verify_token(conn, plaintext="lc_bogus") is None
    assert tokens.verify_token(conn, plaintext="Basic abc") is None
    with conn:
        tokens.revoke_token(conn, token_id=token_id)
    assert tokens.verify_token(conn, plaintext=plaintext) is None
    with conn:
        _, expired = tokens.issue_token(
            conn, name="e", site_id="default", expires_at="2020-01-01T00:00:00+00:00"
        )
    assert tokens.verify_token(conn, plaintext=expired, now=NOW) is None
    conn.close()


def test_token_hash_never_stores_plaintext(db):
    conn = _conn(db)
    with conn:
        from app.db import repositories

        repositories.ensure_site(
            conn, site_id="default", name="s", hostname="example.org", created_at=NOW.isoformat()
        )
        _, plaintext = tokens.issue_token(conn, name="t", site_id="default")
        stored = conn.execute("SELECT token_hash FROM api_tokens").fetchone()[0]
    assert stored != plaintext
    assert stored == tokens.hash_token(plaintext)
    metas = tokens.list_tokens(conn)
    assert all("token" not in meta and "token_hash" not in meta for meta in metas)
    conn.close()


def test_rate_limiter_sliding_window():
    limiter = LoginRateLimiter(max_attempts=2, window_s=300.0)
    assert limiter.allowed("a") and limiter.allowed("a")
    limiter.register("a")
    assert limiter.allowed("a")
    limiter.register("a")
    assert not limiter.allowed("a")
    assert limiter.allowed("b")
    tight = LoginRateLimiter(max_attempts=1, window_s=0.0)
    tight.register("c")
    assert tight.allowed("c")


def _site(conn):
    from app.db import repositories

    repositories.ensure_site(
        conn, site_id="default", name="s", hostname="example.org", created_at=NOW.isoformat()
    )


def test_token_expiry_offsets_compare_as_instants(db):
    conn = _conn(db)
    with conn:
        _site(conn)
        _, positive = tokens.issue_token(
            conn, name="pos", site_id="default", expires_at="2026-10-30T12:00:00+05:00"
        )
        _, negative = tokens.issue_token(
            conn, name="neg", site_id="default", expires_at="2026-10-30T08:00:00-05:00"
        )
    # Both expiries are after NOW (07:00Z / 13:00Z on 2026-10-30).
    assert tokens.verify_token(conn, plaintext=positive, now=NOW) is not None
    assert tokens.verify_token(conn, plaintext=negative, now=NOW) is not None
    # 2026-10-30T12:00:00+05:00 is 07:00Z: expired half an hour later,
    # though the raw string still sorts after the UTC reference.
    later = datetime(2026, 10, 30, 7, 30, 0, tzinfo=UTC)
    assert tokens.verify_token(conn, plaintext=positive, now=later) is None
    assert tokens.verify_token(conn, plaintext=negative, now=later) is not None
    conn.close()


def test_token_expiry_exact_instant_rejected(db):
    conn = _conn(db)
    with conn:
        _site(conn)
        _, plaintext = tokens.issue_token(
            conn, name="e", site_id="default", expires_at=NOW.isoformat()
        )
    assert tokens.verify_token(conn, plaintext=plaintext, now=NOW) is None
    conn.close()


def test_token_issue_rejects_naive_and_malformed_expiry(db):
    conn = _conn(db)
    with conn:
        _site(conn)
        with pytest.raises(ValueError):
            tokens.issue_token(conn, name="n", site_id="default", expires_at="2026-10-30T12:00:00")
        with pytest.raises(ValueError):
            tokens.issue_token(conn, name="m", site_id="default", expires_at="not-a-time")
        _, plaintext = tokens.issue_token(
            conn, name="ok", site_id="default", expires_at="2026-10-30T07:00:00+00:00"
        )
        stored = conn.execute(
            "SELECT expires_at FROM api_tokens WHERE token_hash = ?",
            (tokens.hash_token(plaintext),),
        ).fetchone()[0]
    # Canonical UTC storage regardless of the supplied offset.
    assert stored == "2026-10-30T07:00:00+00:00"
    conn.close()


def test_legacy_offset_expiry_evaluates_correctly_and_malformed_fails_closed(db):
    conn = _conn(db)
    with conn:
        _site(conn)
        _, plaintext = tokens.issue_token(conn, name="t", site_id="default")
        digest = tokens.hash_token(plaintext)
        # Legacy rows may carry non-UTC offsets; rewrite them directly.
        conn.execute(
            "UPDATE api_tokens SET expires_at = ? WHERE token_hash = ?",
            ("2026-10-29T14:00:00+05:00", digest),  # 09:00Z, before NOW noon
        )
    assert tokens.verify_token(conn, plaintext=plaintext, now=NOW) is None
    with conn:
        conn.execute(
            "UPDATE api_tokens SET expires_at = ? WHERE token_hash = ?",
            ("not-a-timestamp", digest),
        )
    assert tokens.verify_token(conn, plaintext=plaintext, now=NOW) is None
    with conn:
        conn.execute(
            "UPDATE api_tokens SET expires_at = ? WHERE token_hash = ?",
            ("2026-10-30T12:00:00", digest),  # naive legacy value fails closed
        )
    assert tokens.verify_token(conn, plaintext=plaintext, now=NOW) is None
    conn.close()


def test_unknown_username_runs_dummy_verify_without_authenticating(db, monkeypatch):
    calls = []
    from app.auth import passwords

    original = passwords.verify_password

    def recording(encoded_hash, password):
        calls.append((encoded_hash, password))
        return original(encoded_hash, password)

    monkeypatch.setattr(passwords, "verify_password", recording)
    conn = _conn(db)
    with conn:
        tokens.create_admin_user(conn, username="admin", password_hash=hash_password("pw"))
    assert tokens.verify_admin_credentials(conn, username="ghost", password="pw") is None
    # The normal verification path ran once against the dummy hash.
    assert len(calls) == 1
    assert calls[0][1] == "pw"
    assert calls[0][0] == tokens._unknown_user_hash()
    # Even a password matching the dummy input never authenticates.
    assert tokens.verify_admin_credentials(conn, username="ghost", password="x") is None
    assert len(calls) == 2
    conn.close()
