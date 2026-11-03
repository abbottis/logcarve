"""Authenticated assistant chat transport (T7).

Admin sessions only: the caller needs a valid server-side session
cookie plus the per-session CSRF header. Analytics Bearer tokens
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

from app.api.deps import (
    StoreUnavailable,
    _db_path,
    read_store,
    require_admin_session,
    require_csrf,
)
from app.api.errors import error_response

router = APIRouter(prefix="/api/v1/chat")

CHAT_RATE_MAX = 30
CHAT_RATE_WINDOW_S = 600.0
CHAT_MAX_CONCURRENT = 2

_chat_attempts: dict[str, deque[float]] = {}
_chat_slots = threading.Semaphore(CHAT_MAX_CONCURRENT)

_ERROR_STATUS = {
    "ai_disabled": 409,
    "usage_not_authorized": 403,
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


def attach_evidence_receipts(evidence: list, *, secret_value: str) -> list:
    """Attach stateless signed replay scopes to local evidence envelopes.

    Bounded safe metadata plus digests only, never raw results. Receipts
    stay local (browser only) and never enter the provider wire. Envelopes
    that lack the expected fields keep no receipt and are later reported
    as unverifiable, never current.
    """
    from app.ai import receipts

    for item in evidence:
        if not isinstance(item, dict):
            continue
        try:
            if (
                secret_value
                and isinstance(item.get("tool"), str)
                and isinstance(item.get("filters"), dict)
                and isinstance(item.get("result_digest"), str)
                and isinstance(item.get("provenance"), dict)
                and isinstance(item.get("observation_time"), str)
            ):
                item["receipt"] = receipts.sign_receipt(
                    receipts.receipt_payload(
                        tool=item["tool"],
                        filters=item["filters"],
                        digest=item["result_digest"],
                        provenance=item["provenance"],
                        observation_time=item["observation_time"],
                    ),
                    secret=secret_value,
                )
        except (TypeError, ValueError):
            continue
    return evidence


class RecheckBody(BaseModel):
    """Evidence recheck request: a signed receipt, or legacy scope.

    The receipt's embedded tool plus filters are the ONLY trusted scope:
    client-supplied filters are never executed. Legacy evidence without
    a receipt returns ``unverified`` and never a current claim. Unknown
    fields are rejected outright instead of silently changing behavior.
    """

    model_config = {"extra": "forbid"}

    receipt: str | None = Field(default=None, min_length=1, max_length=65536)
    tool: str | None = Field(default=None, min_length=1, max_length=64)
    filters: dict | None = None


class ChatBody(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    site_id: str = Field(min_length=1, max_length=128)
    source_id: str | None = Field(default=None, min_length=1, max_length=128)
    time_from: datetime
    time_to: datetime
    method: str | None = Field(default=None, min_length=1, max_length=32)
    status: int | None = Field(default=None, ge=100, le=599)
    path_prefix: str | None = Field(default=None, min_length=1, max_length=1024)
    path_exact: str | None = Field(default=None, min_length=1, max_length=1024)
    referer_host: str | None = Field(default=None, min_length=1, max_length=253)
    traffic: str = Field(default="all", max_length=32)
    bot: str | None = Field(default=None, min_length=1, max_length=64)
    category: str | None = Field(default=None, min_length=1, max_length=64)
    provider: str | None = Field(default=None, min_length=1, max_length=120)
    purpose: str | None = Field(default=None, min_length=1, max_length=120)
    status_class: str | None = Field(default=None, min_length=1, max_length=8)
    search: str | None = Field(default=None, min_length=1, max_length=128)
    client: str | None = Field(
        default=None, min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"
    )
    server_host: str | None = Field(default=None, min_length=1, max_length=253)
    http_version: str | None = Field(default=None, min_length=1, max_length=16)
    mime_type: str | None = Field(default=None, min_length=1, max_length=128)
    cache_status: str | None = Field(default=None, min_length=1, max_length=32)
    tls_protocol: str | None = Field(default=None, min_length=1, max_length=32)
    timing_available: bool | None = Field(default=None)
    upstream_available: bool | None = Field(default=None)
    timing_min_ms: float | None = Field(default=None, ge=0)
    timing_max_ms: float | None = Field(default=None, ge=0)
    country: str | None = Field(default=None, min_length=1, max_length=16)


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
        from app.ai.effective import resolve
        from app.config import load_settings

        db_path = _db_path(request)
        settings = resolve(db_path, load_settings())
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

        def _reload_settings():
            from app.ai.effective import resolve as _resolve
            from app.config import load_settings as _load

            return _resolve(_db_path(request), _load())

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
                settings_loader=_reload_settings,
                rules=request.app.state.rules,
                settings=settings,
                provider=provider,
                actor=Actor(kind="admin", username=session.username, session_id=session.id),
                question=body.question,
                site_id=body.site_id,
                source_id=body.source_id,
                time_from=body.time_from,
                time_to=body.time_to,
                method=body.method,
                status=body.status,
                path_prefix=body.path_prefix,
                path_exact=body.path_exact,
                referer_host=body.referer_host,
                traffic=body.traffic,
                bot=body.bot,
                category=body.category,
                provider_claim=body.provider,
                purpose=body.purpose,
                status_class=body.status_class,
                search=body.search,
                client=body.client,
                server_host=body.server_host,
                http_version=body.http_version,
                mime_type=body.mime_type,
                cache_status=body.cache_status,
                tls_protocol=body.tls_protocol,
                timing_available=body.timing_available,
                upstream_available=body.upstream_available,
                timing_min_ms=body.timing_min_ms,
                timing_max_ms=body.timing_max_ms,
                country=body.country,
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
        from app.config import load_settings as _load_secret_settings
        from app.web.evidence import envelope_href

        # The receipt key is the raw server session secret, which the
        # effective AI settings intentionally do not carry.
        secret = _load_secret_settings().session_secret
        secret_value = secret.get_secret_value() if hasattr(secret, "get_secret_value") else secret
        if not isinstance(secret_value, str):
            secret_value = ""
        evidence = []
        for envelope in result.evidence:
            item = dict(envelope) if isinstance(envelope, dict) else {}
            # Server-generated per-result link from the single trusted
            # formatter: the browser renders this href directly and never
            # reconstructs URLs from tool names or model text.
            item["href"] = envelope_href(item.get("tool"), item.get("filters", {}), "UTC")
            evidence.append(item)
        # Stateless signed replay scopes for the recheck endpoint.
        attach_evidence_receipts(evidence, secret_value=secret_value)
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


@router.post("/evidence/recheck")
def post_evidence_recheck(request: Request, body: RecheckBody):
    """Re-run one signed evidence scope locally and classify its freshness.

    Admin session plus CSRF, exactly like chat. No AI gate, no provider,
    no key, no network and no usage reservation: the receipt's embedded
    tool plus filters are re-executed through the SAME deterministic
    tool path with a fresh observation time, then digests and generation
    heads decide ``current`` / ``changed`` / ``unavailable``. A missing
    receipt (legacy evidence) is ``unverified``, never current; a
    mis-signed receipt or an unknown tool/scope fails closed with no
    execution. Analytics Bearer tokens carry no session and are rejected.
    """
    from datetime import UTC, datetime

    from app.ai import receipts
    from app.ai.tools.definitions import TOOL_NAMES, ToolError, execute_tool
    from app.config import load_settings
    from app.web.evidence import envelope_href

    request_id = request.state.request_id
    session = require_admin_session(request)
    if isinstance(session, JSONResponse):
        return session
    denied = require_csrf(request, session, request_id)
    if denied is not None:
        return denied
    settings = load_settings()
    secret = settings.session_secret
    secret_value = secret.get_secret_value() if hasattr(secret, "get_secret_value") else secret
    if not isinstance(secret_value, str):
        secret_value = ""
    if not body.receipt:
        # Legacy evidence without a receipt cannot prove its scope:
        # report it honestly instead of replaying client filters. The
        # client filters object is NOT echoed back: it is untrusted,
        # unbounded input and must never read as trusted metadata.
        if body.tool is None or not isinstance(body.filters, dict):
            return error_response(
                400, "invalid_request", "An evidence receipt is required.", request_id
            )
        return {
            "status": "unverified",
            "reason": "legacy_no_receipt",
            "tool": body.tool,
            "filters": None,
            "observation_time": None,
            "original_observation_time": None,
        }
    payload = receipts.verify_receipt(body.receipt, secret=secret_value) if secret_value else None
    if payload is None:
        return error_response(
            400, "invalid_receipt", "The evidence receipt is invalid.", request_id
        )
    tool = payload["tool"]
    filters = payload["filters"]
    if tool not in TOOL_NAMES:
        return error_response(
            400, "invalid_tool", "The evidence tool is not available.", request_id
        )
    if not isinstance(filters, dict):
        return error_response(
            400, "invalid_receipt", "The evidence receipt is invalid.", request_id
        )
    # The signed receipt scope is the ONLY executed scope: any client
    # ``filters`` riding alongside a receipt are ignored, never merged.
    # The whole replay — handle open, tool read and provenance read —
    # runs inside the shared read snapshot: storage-access failures
    # surface as the narrow ``StoreUnavailable`` signal (safe structured
    # 503 with request-id parity, no paths/SQL), never a bare 500. A
    # plain ``ValueError`` unrelated to storage keeps its own 400 below.
    try:
        with read_store(request) as conn:
            fresh = execute_tool(
                conn,
                request.app.state.rules,
                name=tool,
                arguments=filters,
                tool_call_id="recheck",
                observation_time=datetime.now(UTC),
            )
    except StoreUnavailable:
        return error_response(
            503, "store_unavailable", "The data store is unavailable.", request_id
        )
    except ToolError as exc:
        status = {
            "forbidden_site": 403,
            "forbidden_source": 403,
            "store_unavailable": 503,
        }.get(exc.code, 400)
        return error_response(status, exc.code, str(exc), request_id)
    except (ValueError, TypeError):
        return error_response(
            400, "invalid_arguments", "Tool arguments failed validation.", request_id
        )
    fresh_provenance = fresh.get("provenance") if isinstance(fresh.get("provenance"), dict) else {}
    old_provenance = (
        payload.get("provenance") if isinstance(payload.get("provenance"), dict) else {}
    )
    # A capped or otherwise incomplete provenance cannot support a
    # completeness claim: report honestly instead of risking ``current``.
    # Pre-cap receipts carry no ``complete`` marker and keep the legacy
    # assumption; an explicit ``False`` (old or fresh) withholds it.
    if not fresh_provenance.get("complete", True) or not old_provenance.get("complete", True):
        return {
            "status": "unverified",
            "reason": "provenance_incomplete",
            "tool": tool,
            "filters": filters,
            "observation_time": fresh.get("observation_time"),
            "original_observation_time": payload.get("observation_time"),
        }
    fresh_digest = fresh.get("result_digest")
    result_match = fresh_digest == payload.get("result_digest")
    fresh_coverage = fresh.get("coverage") if isinstance(fresh.get("coverage"), dict) else {}
    unique_events = fresh_coverage.get("unique_events")
    try:
        surviving = int(unique_events) if unique_events is not None else -1
    except (TypeError, ValueError):
        surviving = -1
    old_sources = (
        payload["provenance"].get("sources")
        if isinstance(payload.get("provenance"), dict)
        else None
    )
    new_sources = (
        fresh["provenance"].get("sources") if isinstance(fresh.get("provenance"), dict) else None
    )
    generation_changed = old_sources != new_sources
    if surviving == 0:
        status = "unavailable"
    elif result_match:
        status = "current"
    else:
        status = "changed"
    return {
        "status": status,
        "tool": tool,
        "filters": filters,
        "original_observation_time": payload.get("observation_time"),
        "observation_time": fresh.get("observation_time"),
        "result_match": bool(result_match),
        "generation_changed": bool(generation_changed),
        "coverage": fresh_coverage,
        "provenance": fresh.get("provenance"),
        "href": envelope_href(tool, filters, "UTC"),
    }
