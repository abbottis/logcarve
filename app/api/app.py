"""FastAPI composition for the external API and admin endpoints (T5).

Interactive documentation is disabled; the versioned OpenAPI contract
is served as data behind a valid analytics token. Readiness is
restricted to admin sessions; liveness stays public and minimal.
"""

import uuid
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.analytics.rules import load_rules
from app.api import routes_admin, routes_analytics, routes_chat
from app.api.deps import LoginRateLimiter, StoreUnavailable, require_admin_session
from app.api.errors import error_response, store_unavailable_handler, validation_error_handler
from app.db.database import connect
from app.web import routes as web_routes
from app.web.headers import security_headers_middleware

DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent.parent / "config"


def build_api(
    *,
    db_path: Path,
    rules_dir: Path | None = None,
    secure_cookies: bool = False,
    login_max_attempts: int = 10,
    login_window_s: float = 300.0,
) -> FastAPI:
    rules_path = Path(rules_dir) if rules_dir is not None else DEFAULT_RULES_DIR
    rules = (
        load_rules(rules_path / "bot_rules.yaml").rules
        + load_rules(rules_path / "security_rules.yaml").rules
    )

    app = FastAPI(
        title="LogCarve", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None
    )
    app.state.db_path = Path(db_path)
    app.state.rules = rules
    app.state.secure_cookies = secure_cookies
    app.state.login_limiter = LoginRateLimiter(
        max_attempts=login_max_attempts, window_s=login_window_s
    )

    @app.middleware("http")
    async def add_request_id(request: Request, call_next):
        request.state.request_id = uuid.uuid4().hex
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    app.middleware("http")(security_headers_middleware)

    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(StoreUnavailable, store_unavailable_handler)

    @app.get("/healthz")
    def healthz() -> dict:
        from app.config import load_settings

        return {"status": "ok", "service": "logcarve", "ai_enabled": load_settings().ai_enabled}

    @app.get("/readyz")
    def readyz(request: Request):
        session = require_admin_session(request)
        if isinstance(session, JSONResponse):
            return session
        try:
            conn = connect(app.state.db_path, read_only=True)
            try:
                row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
                conn.execute("SELECT 1 FROM sites LIMIT 1").fetchall()
            finally:
                conn.close()
        except Exception:  # noqa: BLE001 - readiness maps any DB failure to 503
            return error_response(
                503, "not_ready", "The database is not ready.", request.state.request_id
            )
        return {"ready": True, "database": "ok", "schema_version": row[0]}

    app.include_router(routes_analytics.router)
    app.include_router(routes_admin.router)
    app.include_router(routes_chat.router)
    web_static = Path(__file__).resolve().parent.parent / "web" / "static"
    app.mount("/static", StaticFiles(directory=str(web_static)), name="web_static")
    app.include_router(web_routes.router)
    return app
