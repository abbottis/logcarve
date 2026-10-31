"""Request authentication, authorization and login rate limiting (T5).

Bearer [REDACTED] authorize analytics reads only: the token's site and
scope are derived server-side from the stored hash, never from client
claims. Admin routes require a server-side session cookie plus a
per-session CSRF header. Login attempts are bounded per client address.
"""

import hmac
import secrets
import sqlite3
import time
from collections import deque
from contextlib import contextmanager
from pathlib import Path

from fastapi import Request

from app.api.errors import error_response
from app.auth.tokens import ApiToken, get_session, verify_admin_credentials, verify_token
from app.db.database import connect

SESSION_COOKIE = "lc_admin_session"
CSRF_HEADER = "X-CSRF-Token"


class StoreUnavailable(RuntimeError):
    """The credential store cannot be read (missing, corrupt or uninitialized)."""


class LoginRateLimiter:
    """In-memory sliding-window login bound (single process, documented)."""

    def __init__(self, *, max_attempts: int = 10, window_s: float = 300.0) -> None:
        self.max_attempts = max_attempts
        self.window_s = window_s
        self._attempts: dict[str, deque[float]] = {}

    def allowed(self, key: str) -> bool:
        now = time.monotonic()
        recent = self._attempts.setdefault(key, deque())
        while recent and now - recent[0] > self.window_s:
            recent.popleft()
        return len(recent) < self.max_attempts

    def register(self, key: str) -> None:
        self._attempts.setdefault(key, deque()).append(time.monotonic())


def _client_key(request: Request) -> str:
    if request.client is not None and request.client.host:
        return request.client.host
    return "unknown"


def _db_path(request: Request) -> Path:
    return request.app.state.db_path


def open_read_db(request: Request) -> sqlite3.Connection:
    return connect(_db_path(request), read_only=True)


@contextmanager
def read_store(request: Request):
    """Yield a read-only store connection for one request.

    Missing, corrupt or uninitialized stores surface only as the narrow
    ``StoreUnavailable`` signal (mapped to a safe 503 elsewhere); only
    storage-access failures (``sqlite3.Error``/``OSError``) are mapped,
    never arbitrary programming exceptions. Nothing is created: the
    handle is read-only.
    """
    try:
        conn = open_read_db(request)
    except (sqlite3.Error, OSError) as exc:
        raise StoreUnavailable("data store unavailable") from exc
    try:
        yield conn
    except (sqlite3.Error, OSError) as exc:
        raise StoreUnavailable("data store unavailable") from exc
    finally:
        conn.close()


def bearer_credentials(request: Request) -> str | None:
    header = request.headers.get("Authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


def _unauthorized(request_id: str, code: str, message: str, status: int = 401):
    return error_response(status, code, message, request_id)


def require_analytics_token(request: Request) -> ApiToken | object:
    """Validate the Bearer [REDACTED] return the stored token or an error response."""
    request_id = request.state.request_id
    if not request.headers.get("Authorization", "").strip():
        return _unauthorized(request_id, "missing_token", "A Bearer [REDACTED] is required.")
    plaintext = bearer_credentials(request)
    if plaintext is None:
        return _unauthorized(
            request_id, "invalid_token", "The Authorization header must be a Bearer token."
        )
    with read_store(request) as conn:
        token = verify_token(conn, plaintext=plaintext)
    if token is None:
        return _unauthorized(
            request_id, "invalid_token", "The Bearer [REDACTED] is invalid, expired or revoked."
        )
    if "analytics:read" not in token.scopes:
        return _unauthorized(
            request_id,
            "insufficient_scope",
            "This token lacks the analytics:read scope.",
            status=403,
        )
    return token


def require_token_site(token: ApiToken, site_id: str, request_id: str):
    """Tokens only authorize their own bound site."""
    if token.site_id != site_id:
        return _unauthorized(
            request_id,
            "forbidden_site",
            "This token is not authorized for the requested site.",
            status=403,
        )
    return None


def require_token_source(
    conn: sqlite3.Connection, *, token: ApiToken, source_id: str, request_id: str
):
    """Source filters must belong to the token's bound site (no cross-site reads)."""
    row = conn.execute("SELECT site_id FROM log_sources WHERE id = ?", (source_id,)).fetchone()
    if row is None or row[0] != token.site_id:
        return _unauthorized(
            request_id,
            "forbidden_source",
            "The requested source is not authorized for this token.",
            status=403,
        )
    return None


def require_admin_session(request: Request):
    """Validate the session cookie; CSRF is checked separately per mutation."""
    request_id = request.state.request_id
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id:
        return _unauthorized(
            request_id, "expired_session", "A valid admin session is required.", status=401
        )
    with read_store(request) as conn:
        session = get_session(conn, session_id=session_id)
    if session is None:
        return _unauthorized(
            request_id, "expired_session", "The admin session is invalid or expired.", status=401
        )
    return session


def require_csrf(request: Request, session, request_id: str):
    """Browser mutations must echo the per-session CSRF token."""
    presented = request.headers.get(CSRF_HEADER, "")
    if not presented or not hmac.compare_digest(presented, session.csrf_token):
        return _unauthorized(
            request_id, "csrf_required", "A valid CSRF token is required.", status=403
        )
    return None


def check_password(username: str, password: str, db_path: Path) -> int | None:
    """Verify credentials without ever writing: read-only handle, no file creation."""
    try:
        conn = connect(db_path, read_only=True)
    except (sqlite3.Error, OSError) as exc:
        raise StoreUnavailable(f"credential store unavailable: {db_path}") from exc
    try:
        return verify_admin_credentials(conn, username=username, password=password)
    except (sqlite3.Error, OSError) as exc:
        raise StoreUnavailable(f"credential store unavailable: {db_path}") from exc
    finally:
        conn.close()


def random_token_hex(nbytes: int = 32) -> str:
    return secrets.token_hex(nbytes)
