"""Authenticated assistant chat transport (T7).

Admin sessions only: the caller needs a valid server-side session
cookie plus the per-session CSRF header. Analytics Bearer [REDACTED]
grant no model access and are rejected here. Chat is additionally
bounded by a per-session rate limit and a small global concurrency
semaphore; both bounds are documented constants until later slices
promote them to configuration.

AI service/adapter modules are imported lazily inside the
authenticated enabled-chat path, never at router import: unavailable
AI code must not break deterministic application startup or reads.
With AI disabled the endpoint returns a local English error and the
deterministic API is untouched. T7 ships no real provider transport,
so an enabled configuration without an injected backend reports
unavailable instead of answering from a fake.
"""

import json
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.api.deps import _db_path, require_admin_session, require_csrf
from app.api.errors import error_response

router = APIRouter(prefix="/api/v1/chat")

CHAT_RATE_MAX = 30
CHAT_RATE_WINDOW_S = 600.0
CHAT_MAX_CONCURRENT = 2

_chat_attempts: dict[str, deque[float]] = {}
_chat_slots = threading.Semaphore(CHAT_MAX_CONCURRENT)

_ERROR_STATUS = {
    "ai_disabled": 409,
    "budget_reached": 429,
    "invalid_request": 400,
    "unknown_site": 404,
    "forbidden_actor": 403,
    "forbidden_source": 403,
    "tool_rejected": 400,
    "invalid_response": 422,
    "tool_limit_reached": 422,
    "output_limit_reached": 422,
    "egress_blocked": 422,
    "step_limit_reached": 422,
    "cancelled": 499,
    "provider_unavailable": 503,
    "store_unavailable": 503,
}


class ChatBody(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    site_id: str = Field(min_length=1, max_length=128)
    source_id: str | None = Field(default=None, min_length=1, max_length=128)
    time_from: datetime
    time_to: datetime


def _chat_allowed(session_id: str) -> bool:
    now = time.monotonic()
    recent = _chat_attempts.setdefault(session_id, deque())
    while recent and now - recent[0] > CHAT_RATE_WINDOW_S:
        recent.popleft()
    if len(recent) >= CHAT_RATE_MAX:
        return False
    recent.append(now)
    return True


def _locale_message(key: str, fallback: str) -> str:
    try:
        catalog = Path(__file__).resolve().parent.parent.parent / "config" / "locales" / "en.json"
        return json.loads(catalog.read_text(encoding="utf-8")).get(key, fallback)
    except (OSError, ValueError):
        return fallback


@router.post("/ask")
def post_chat(request: Request, body: ChatBody):
    request_id = request.state.request_id
    session = require_admin_session(request)
    if isinstance(session, JSONResponse):
        return session
    denied = require_csrf(request, session, request_id)
    if denied is not None:
        return denied
    if not _chat_allowed(session.id):
        return error_response(
            429, "rate_limited", "Too many chat requests. Try again later.", request_id
        )
    if not _chat_slots.acquire(blocking=False):
        return error_response(
            429, "chat_busy", "The assistant is busy. Try again later.", request_id
        )
    try:
        from app.config import load_settings

        settings = load_settings()
        if not settings.ai_enabled:
            return error_response(
                409,
                "ai_disabled",
                _locale_message(
                    "ai.disabled",
                    "The AI assistant is disabled. Analytics remain available.",
                ),
                request_id,
            )
        try:
            from app.ai.providers.base import BackendUnavailable
            from app.ai.service import Actor, InvestigationError, run_investigation, select_provider
        except ImportError:
            return error_response(
                503,
                "ai_unavailable",
                _locale_message(
                    "ai.unavailable",
                    "The AI assistant is unavailable. Please try again later.",
                ),
                request_id,
            )
        try:
            provider = select_provider(settings)
        except BackendUnavailable:
            return error_response(
                503,
                "ai_unavailable",
                _locale_message(
                    "ai.unavailable",
                    "The AI assistant is unavailable. Please try again later.",
                ),
                request_id,
            )
        try:
            result = run_investigation(
                db_path=_db_path(request),
                rules=request.app.state.rules,
                settings=settings,
                provider=provider,
                actor=Actor(kind="admin", username=session.username, session_id=session.id),
                question=body.question,
                site_id=body.site_id,
                source_id=body.source_id,
                time_from=body.time_from,
                time_to=body.time_to,
            )
        except InvestigationError as exc:
            return error_response(_ERROR_STATUS.get(exc.code, 500), exc.code, str(exc), request_id)
        except ImportError:
            return error_response(
                503,
                "ai_unavailable",
                _locale_message(
                    "ai.unavailable",
                    "The AI assistant is unavailable. Please try again later.",
                ),
                request_id,
            )
        from app.web.evidence import envelope_href

        evidence = []
        for envelope in result.evidence:
            item = dict(envelope) if isinstance(envelope, dict) else {}
            # Server-generated per-result link from the single trusted
            # formatter: the browser renders this href directly and never
            # reconstructs URLs from tool names or model text.
            item["href"] = envelope_href(item.get("tool"), item.get("filters", {}), "UTC")
            evidence.append(item)
        return {
            "investigation_id": result.investigation_id,
            "answer": result.answer_text,
            "evidence": evidence,
            "tool_calls": result.tool_calls,
            "provider": result.provider,
            "model": result.model,
            "usage": result.usage,
            "warnings": result.warnings,
            "observation_time": result.observation_time,
            "response_ids": result.response_ids,
            "provider_calls": result.provider_calls,
        }
    finally:
        _chat_slots.release()
