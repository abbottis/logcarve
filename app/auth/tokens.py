"""Server-side admin sessions and scoped Bearer [REDACTED] (T5).

Sessions are opaque random IDs validated against the database; the
cookie itself carries no authority beyond the lookup. Every session
carries a CSRF token that browser mutations must echo in the
``X-CSRF-Token`` header. API tokens are random values stored as
SHA-256 hashes, bound to one site and one scope set, with expiry and
revocation. Plaintext tokens exist only at issuance.
"""

import hashlib
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

SESSION_TTL = timedelta(hours=12)
TOKEN_BYTES = 32


def parse_expiry(value: str | None) -> datetime | None:
    """Parse a stored expiry to a UTC instant.

    Returns None for absent values. Malformed or timezone-naive values
    also yield None so callers fail closed; they must never be compared
    as raw strings (lexicographic order is wrong across UTC offsets).
    """
    if value is None:
        return None
    try:
        moment = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None
    if moment.tzinfo is None:
        return None
    return moment.astimezone(UTC)


def normalize_expiry(value: str) -> str:
    """Validate an issuance-time expiry and return canonical UTC storage form.

    Timezone-aware ISO timestamps (any offset) are accepted and stored
    normalized to UTC. Naive or malformed values raise ValueError.
    """
    parsed = parse_expiry(value)
    if parsed is None:
        raise ValueError("expires_at must be a timezone-aware ISO timestamp")
    return parsed.isoformat()


@dataclass(frozen=True)
class AdminSession:
    id: str
    user_id: int
    username: str
    csrf_token: str
    expires_at: str


@dataclass(frozen=True)
class ApiToken:
    id: int
    name: str
    site_id: str
    scopes: tuple[str, ...]
    expires_at: str | None


def _utcnow() -> datetime:
    return datetime.now(UTC)


def hash_token(plaintext: str) -> str:
    """SHA-256 of a high-entropy random token (Argon2 is for passwords)."""
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def create_admin_user(
    conn: sqlite3.Connection, *, username: str, password_hash: str, now: datetime | None = None
) -> int:
    """Insert an admin user; usernames are unique."""
    if not username or not password_hash:
        raise ValueError("username and password_hash must be non-empty")
    cursor = conn.execute(
        "INSERT INTO admin_users (username, password_hash, created_at) VALUES (?, ?, ?)",
        (username, password_hash, (now or _utcnow()).isoformat()),
    )
    row_id = cursor.lastrowid
    assert row_id is not None
    return row_id


_dummy_password_hash: str | None = None


def _unknown_user_hash() -> str:
    """Lazily built Argon2 hash used only to balance unknown-user login cost."""
    global _dummy_password_hash
    if _dummy_password_hash is None:
        from app.auth.passwords import hash_password

        _dummy_password_hash = hash_password("logcarve-unknown-user-dummy-password")
    return _dummy_password_hash


def verify_admin_credentials(
    conn: sqlite3.Connection, *, username: str, password: str
) -> int | None:
    """Return the user id on match, else None (no enumeration signal).

    Unknown usernames still run the normal password-verification path
    against a fixed dummy hash, so valid and invalid usernames cost the
    same Argon2 work and neither message content nor timing distinguishes
    them. A dummy match never authenticates: the result is always None.
    """
    from app.auth.passwords import verify_password

    row = conn.execute(
        "SELECT id, password_hash FROM admin_users WHERE username = ?", (username,)
    ).fetchone()
    if row is None:
        verify_password(_unknown_user_hash(), password)
        return None
    user_id, encoded = row
    return user_id if verify_password(encoded, password) else None


def create_session(
    conn: sqlite3.Connection, *, user_id: int, username: str, now: datetime | None = None
) -> AdminSession:
    """Open a server-side session with a fresh CSRF token."""
    moment = now or _utcnow()
    session_id = secrets.token_hex(32)
    csrf_token = secrets.token_urlsafe(32)
    expires_at = (moment + SESSION_TTL).isoformat()
    conn.execute(
        "INSERT INTO admin_sessions (id, user_id, csrf_token, created_at, expires_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (session_id, user_id, csrf_token, moment.isoformat(), expires_at),
    )
    return AdminSession(
        id=session_id,
        user_id=user_id,
        username=username,
        csrf_token=csrf_token,
        expires_at=expires_at,
    )


def get_session(
    conn: sqlite3.Connection, *, session_id: str, now: datetime | None = None
) -> AdminSession | None:
    """Validate a session cookie value; expired or unknown sessions return None."""
    if not session_id:
        return None
    reference = now or _utcnow()
    row = conn.execute(
        "SELECT s.id, s.user_id, u.username, s.csrf_token, s.expires_at"
        " FROM admin_sessions s JOIN admin_users u ON u.id = s.user_id"
        " WHERE s.id = ?",
        (session_id,),
    ).fetchone()
    if row is None:
        return None
    # Sessions are written in UTC by create_session, but the expiry is
    # still compared as a parsed instant so legacy or unexpected stored
    # values fail closed instead of comparing as raw strings.
    expires = parse_expiry(row[4])
    if expires is None or expires <= reference:
        return None
    return AdminSession(
        id=row[0], user_id=row[1], username=row[2], csrf_token=row[3], expires_at=row[4]
    )


def destroy_session(conn: sqlite3.Connection, *, session_id: str) -> None:
    conn.execute("DELETE FROM admin_sessions WHERE id = ?", (session_id,))


def issue_token(
    conn: sqlite3.Connection,
    *,
    name: str,
    site_id: str,
    scopes: tuple[str, ...] = ("analytics:read",),
    expires_at: str | None = None,
    now: datetime | None = None,
) -> tuple[int, str]:
    """Create a scoped token; return (id, plaintext shown once only)."""
    if not name or not site_id or not scopes:
        raise ValueError("name, site_id and scopes must be non-empty")
    if any(not scope or " " in scope for scope in scopes):
        raise ValueError("scopes must be single tokens")
    if expires_at is not None:
        expires_at = normalize_expiry(expires_at)
    plaintext = "lc_" + secrets.token_urlsafe(TOKEN_BYTES)
    cursor = conn.execute(
        "INSERT INTO api_tokens (name, token_hash, site_id, scopes, created_at, expires_at, revoked_at)"
        " VALUES (?, ?, ?, ?, ?, ?, NULL)",
        (
            name,
            hash_token(plaintext),
            site_id,
            " ".join(sorted(scopes)),
            (now or _utcnow()).isoformat(),
            expires_at,
        ),
    )
    row_id = cursor.lastrowid
    assert row_id is not None
    return row_id, plaintext


def verify_token(
    conn: sqlite3.Connection, *, plaintext: str, now: datetime | None = None
) -> ApiToken | None:
    """Validate a Bearer [REDACTED] honoring expiry and revocation; else None.

    Expiry is compared as parsed UTC instants. Stored values with a
    non-UTC offset evaluate correctly; malformed or naive stored values
    fail closed (the token is rejected).
    """
    if not plaintext or not plaintext.startswith("lc_"):
        return None
    reference = now or _utcnow()
    row = conn.execute(
        "SELECT id, name, site_id, scopes, expires_at FROM api_tokens"
        " WHERE token_hash = ? AND revoked_at IS NULL",
        (hash_token(plaintext),),
    ).fetchone()
    if row is None:
        return None
    if row[4] is not None:
        expires = parse_expiry(row[4])
        if expires is None or expires <= reference:
            return None
    return ApiToken(
        id=row[0], name=row[1], site_id=row[2], scopes=tuple(row[3].split()), expires_at=row[4]
    )


def revoke_token(conn: sqlite3.Connection, *, token_id: int, now: datetime | None = None) -> None:
    conn.execute(
        "UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
        ((now or _utcnow()).isoformat(), token_id),
    )


def list_tokens(conn: sqlite3.Connection) -> list[dict[str, object]]:
    """Token metadata for administration; hashes and plaintext never leave the store."""
    return [
        {
            "id": row[0],
            "name": row[1],
            "site_id": row[2],
            "scopes": row[3],
            "created_at": row[4],
            "expires_at": row[5],
            "revoked_at": row[6],
        }
        for row in conn.execute(
            "SELECT id, name, site_id, scopes, created_at, expires_at, revoked_at"
            " FROM api_tokens ORDER BY id"
        ).fetchall()
    ]
