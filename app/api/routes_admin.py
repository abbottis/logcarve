"""Admin session and token-administration endpoints (T5).

Browser login/logout plus scoped machine-token issuance, listing and
revocation. Mutations require a valid server-side session cookie and
the per-session CSRF header. Login attempts are bounded per client
address with generic errors that do not enumerate users.
"""

from datetime import datetime

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.api import schemas
from app.api.deps import (
    SESSION_COOKIE,
    _client_key,
    _db_path,
    check_password,
    read_store,
    require_admin_session,
    require_csrf,
)
from app.api.errors import error_response
from app.auth.tokens import (
    create_session,
    destroy_session,
    issue_token,
    list_tokens,
    normalize_expiry,
    revoke_token,
)
from app.db.database import writer_transaction

router = APIRouter(prefix="/api/v1/admin")


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class TokenIssueBody(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    scopes: str = "analytics:read"
    expires_at: str | None = None


def _limited(request: Request) -> bool:
    limiter = request.app.state.login_limiter
    return limiter.allowed(_client_key(request))


@router.post("/login", response_model=schemas.LoginResponse, status_code=200)
def login(request: Request, body: LoginBody):
    request_id = request.state.request_id
    limiter = request.app.state.login_limiter
    key = _client_key(request)
    if not limiter.allowed(key):
        return error_response(
            429, "rate_limited", "Too many login attempts. Try again later.", request_id
        )
    limiter.register(key)
    # A missing/corrupt/uninitialized store raises StoreUnavailable,
    # mapped to a safe structured 503 by the application handler.
    user_id = check_password(body.username, body.password, _db_path(request))
    if user_id is None:
        return error_response(
            401, "invalid_credentials", "Invalid username or password.", request_id
        )
    with writer_transaction(_db_path(request)) as conn:
        session = create_session(conn, user_id=user_id, username=body.username)
    response = JSONResponse(
        status_code=200,
        content={
            "username": body.username,
            "csrf_token": session.csrf_token,
            "expires_at": session.expires_at,
        },
    )
    secure = request.app.state.secure_cookies
    response.set_cookie(
        SESSION_COOKIE,
        session.id,
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
        max_age=12 * 3600,
    )
    return response


@router.post("/logout")
def logout(request: Request):
    request_id = request.state.request_id
    session = require_admin_session(request)
    if isinstance(session, JSONResponse):
        return session
    denied = require_csrf(request, session, request_id)
    if denied is not None:
        return denied
    with writer_transaction(_db_path(request)) as conn:
        destroy_session(conn, session_id=session.id)
    response = JSONResponse(status_code=200, content={"logged_out": True})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@router.post("/tokens", response_model=schemas.TokenIssueResponse, status_code=201)
def create_token(request: Request, body: TokenIssueBody):
    request_id = request.state.request_id
    session = require_admin_session(request)
    if isinstance(session, JSONResponse):
        return session
    denied = require_csrf(request, session, request_id)
    if denied is not None:
        return denied
    scopes = tuple(sorted({scope for scope in body.scopes.split() if scope}))
    if not scopes:
        return error_response(400, "invalid_request", "At least one scope is required.", request_id)
    expires_at = body.expires_at
    if expires_at is not None:
        try:
            moment = datetime.fromisoformat(expires_at)
        except ValueError:
            return error_response(
                400, "invalid_request", "expires_at must be an ISO timestamp.", request_id
            )
        if moment.tzinfo is None:
            return error_response(
                400,
                "invalid_request",
                "expires_at must carry a timezone.",
                request_id,
            )
        expires_at = normalize_expiry(expires_at)
    with writer_transaction(_db_path(request)) as conn:
        site = conn.execute("SELECT id FROM sites WHERE id = ?", (body.site_id,)).fetchone()
        if site is None:
            return error_response(
                404, "unknown_site", "The requested site does not exist.", request_id
            )
        token_id, plaintext = issue_token(
            conn, name=body.name, site_id=body.site_id, scopes=scopes, expires_at=expires_at
        )
    return {
        "token_id": token_id,
        "token": plaintext,
        "name": body.name,
        "site_id": body.site_id,
        "scopes": " ".join(scopes),
        "expires_at": expires_at,
    }


@router.get("/tokens", response_model=list[schemas.TokenMetaOut])
def get_tokens(request: Request):
    session = require_admin_session(request)
    if isinstance(session, JSONResponse):
        return session
    with read_store(request) as conn:
        return list_tokens(conn)


@router.delete("/tokens/{token_id}")
def delete_token(request: Request, token_id: int):
    request_id = request.state.request_id
    session = require_admin_session(request)
    if isinstance(session, JSONResponse):
        return session
    denied = require_csrf(request, session, request_id)
    if denied is not None:
        return denied
    with writer_transaction(_db_path(request)) as conn:
        row = conn.execute("SELECT id FROM api_tokens WHERE id = ?", (token_id,)).fetchone()
        if row is None:
            return error_response(
                404, "unknown_token", "The requested token does not exist.", request_id
            )
        revoke_token(conn, token_id=token_id)
    return {"revoked": token_id}


@router.get("/csrf")
def get_csrf(request: Request):
    """Return the session CSRF token for browser clients (session required)."""
    session = require_admin_session(request)
    if isinstance(session, JSONResponse):
        return session
    return {"csrf_token": session.csrf_token}
