"""Bounded investigation orchestration (T7).

One investigation: validate the trusted actor/scope contract, gate the
settings, then run a bounded tool-calling loop against the injected
provider, return traceable evidence or a safe English error. Scope,
question and gate checks all complete before any budget reservation
or provider dispatch, so invalid work costs nothing and sends nothing.

Every provider-bound string — the question, the system instructions,
tool results, retries and replayed history — crosses the egress
boundary before transmission. Tool execution stays server-side
against a read-only store handle; the provider only ever names
allowlisted tools, and site/source/time always come from the trusted
investigation scope, never from model arguments.

Each dispatch revalidates the live gate, reserves a conservative
per-step hold from the actual bounded prompt plus the output bound,
and waits on a daemon worker with a polling deadline: control returns
at the timeout even when the adapter ignores cancellation, and
abandoned workers are bounded by a fixed worker capacity that fails
closed instead of queuing forever. Measured usage is reconciled per
step; dispatched work of unknown size keeps its full hold instead of
being released as if it were free.

Provider selection is an explicit seam: tests inject the fake
provider; production without an implemented real transport reports
unavailable instead of answering from a fake.
"""

import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from app.ai import budget, egress, gate, smoke
from app.ai.egress import MAX_WIRE_BYTES
from app.ai.providers.base import (
    BackendUnavailable,
    ProviderAdapter,
    ProviderCancelled,
    ProviderError,
    ProviderRequest,
    ProviderResponse,
    ProviderTimeout,
)
from app.ai.providers.meta_responses import (
    WIRE_FRAMING_TOKENS,
    MetaResponsesAdapter,
    build_dispatch_body,
    cost_micro_usd,
    parse_endpoint,
    serialize_body,
)
from app.ai.tools.definitions import TOOL_NAMES, execute_tool, response_tool_definitions
from app.analytics.classification import build_classifier, resolve_selector_indexes
from app.analytics.contracts import TimeWindow
from app.analytics.service import (
    LIMITATIONS_BOT,
    LIMITATIONS_LOGS,
    LIMITATIONS_PERFORMANCE,
    LIMITATIONS_SECURITY,
    LIMITATIONS_SEO,
)
from app.db.database import connect

SYSTEM_PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "assistant_system.md"

MAX_QUESTION_CHARS = 2000
MAX_STEPS = 6
MAX_OUTPUT_TOKENS = 2048
MAX_TOOLS_PER_RESPONSE = 8
MAX_TOTAL_TOOLS = 32
MAX_ANSWER_CHARS = 4000
HISTORY_MAX_CHARS = 4000
PROVIDER_TIMEOUT_S = 30.0
PROVIDER_TIMEOUT_MIN_S = 0.001
PROVIDER_TIMEOUT_MAX_S = 120.0
WORKER_CAPACITY = 8
WORKER_POLL_S = 0.02
# Application-side planning estimate for legacy/fake reservation
# accounting ONLY: 100 micro-USD per 1k tokens (input and output
# alike). Fake-provider paths keep this estimate; real Meta
# dispatches use the verified pricing in
# app.ai.providers.meta_responses instead.
ESTIMATE_MICRO_USD_PER_1K_TOKENS = 100
# Real Standard Spark pricing is verified in code
# (meta_responses.PRICING_VERSION, primary docs 31 Oct 2026).
PRICING_VERIFIED = True
# Serialized protocol overhead added to legacy fake input estimates.
# Real dispatches reserve for the exact immutable serialized body
# plus WIRE_FRAMING_TOKENS instead of this planning overhead.
PROTOCOL_OVERHEAD_TOKENS = 512


class InvestigationError(RuntimeError):
    """A safe, localizable investigation failure with a stable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Actor:
    kind: str
    username: str
    session_id: str


@dataclass
class InvestigationResult:
    """One investigation outcome with safe correlation metadata.

    ``response_ids`` holds one bounded server response ID per dispatch;
    ``provider_calls`` links each local ``tool_call_id`` to the provider
    ``call_id`` and tool name. Opaque IDs only: no response content,
    reasoning, or prompts are retained here.
    """

    investigation_id: str
    answer_text: str
    evidence: list = field(default_factory=list)
    tool_calls: int = 0
    provider: str = ""
    model: str = ""
    usage: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)
    observation_time: str = ""
    response_ids: list = field(default_factory=list)
    provider_calls: list = field(default_factory=list)


@dataclass(frozen=True)
class ValidatedScope:
    """Trusted investigation scope; model arguments can never widen it.

    Traffic/bot/category/provider/purpose/status_class/search narrow the
    same shared stored analytics the dashboard and API read. Search covers
    sanitized indexed fields only (path, UA, referrer host, pseudonym);
    the raw-row explorer itself stays a UI/API read, never a model tool.
    Enrichment matchers (host, HTTP version, MIME, cache, TLS, timing
    availability and finite ranges) and the exact-path selector travel
    the same trusted path; a selected ``False``/``0`` is a real
    selection, never an omitted dimension.
    """

    site_id: str
    source_id: str | None
    time_from: datetime
    time_to: datetime
    method: str | None = None
    status: int | None = None
    status_class: str | None = None
    path_prefix: str | None = None
    path_exact: str | None = None
    referer_host: str | None = None
    traffic: str = "all"
    bot: str | None = None
    category: str | None = None
    provider_claim: str | None = None
    purpose: str | None = None
    search: str | None = None
    client: str | None = None
    server_host: str | None = None
    http_version: str | None = None
    mime_type: str | None = None
    cache_status: str | None = None
    tls_protocol: str | None = None
    timing_available: bool | None = None
    upstream_available: bool | None = None
    timing_min_ms: float | None = None
    timing_max_ms: float | None = None


_TRAFFIC_VALUES = ("all", "browser_like", "claimed_bot", "other_automation", "unknown")
_STATUS_CLASS_VALUES = ("2xx", "3xx", "4xx", "5xx")


def load_system_prompt() -> str:
    return SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")


def estimate_micro_usd(input_tokens: int, output_tokens: int) -> int:
    total_1k = (max(0, input_tokens) + max(0, output_tokens)) / 1000.0
    return max(1, round(total_1k * ESTIMATE_MICRO_USD_PER_1K_TOKENS))


def estimate_input_tokens_upper(prompt: str) -> int:
    """Defensible input-token upper bound for a bounded prompt.

    A BPE token always spans at least one byte, so the UTF-8 byte length
    bounds the token count from above even for adversarial Unicode
    (unlike a chars/4 average). Serialized protocol overhead for future
    real transport is added on top. Planning-only, like the estimate.
    """
    return len(prompt.encode("utf-8")) + PROTOCOL_OVERHEAD_TOKENS


def select_provider(settings) -> ProviderAdapter:
    """Resolve the real Meta transport for settings, else unavailable.

    Every binding is revalidated here: allowlisted provider/model/
    tier plus verified data policy (gate), the configured endpoint
    against the strict HTTPS allowlist, and a non-empty product key.
    Tests inject FakeProvider directly and never go through this
    seam; fake paths never require an endpoint or key.
    """
    try:
        decision = gate.validate_for_real_data(settings)
    except gate.GateBlocked as exc:
        raise BackendUnavailable(
            "Real-data transmission is not enabled under these settings."
        ) from exc
    if not PRICING_VERIFIED:
        raise BackendUnavailable("No verified pricing is implemented in this version.")
    endpoint = str(getattr(settings, "model_endpoint", "") or "")
    try:
        parse_endpoint(endpoint)
    except ProviderError as exc:
        raise BackendUnavailable("No usable provider endpoint is configured.") from exc
    key = getattr(settings, "model_api_key", None)
    secret = key.get_secret_value() if hasattr(key, "get_secret_value") else key
    if not isinstance(secret, str) or not secret:
        raise BackendUnavailable("No product key is configured.")
    return MetaResponsesAdapter(endpoint=endpoint, model=decision.model, api_key=key)


_worker_slots = threading.Semaphore(WORKER_CAPACITY)


class _WorkerBusy(ProviderError):
    """No bounded provider-worker capacity is currently available."""


def _wait_provider(
    provider: ProviderAdapter,
    request: ProviderRequest,
    *,
    timeout_s: float,
    cancel: threading.Event,
) -> ProviderResponse:
    """Wait for one provider completion with a hard control deadline.

    The adapter runs on a daemon worker so a hung implementation can
    never hold the request: control returns at the deadline (or
    promptly on cancellation) while the abandoned worker keeps its
    bounded capacity slot until it finishes. Python cannot forcibly
    kill a running thread, so saturation fails closed immediately
    instead of queuing unbounded work.
    """
    if not _worker_slots.acquire(blocking=False):
        raise _WorkerBusy("The assistant has no provider capacity right now.")
    box: queue.Queue = queue.Queue(maxsize=1)

    def _run() -> None:
        try:
            box.put((True, provider.complete(request, cancel=cancel)))
        except Exception as exc:  # noqa: BLE001 - adapter failures cross to the waiter, which maps them
            box.put((False, exc))
        finally:
            _worker_slots.release()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    deadline = time.monotonic() + timeout_s
    while True:
        if cancel.is_set():
            raise ProviderCancelled("The investigation was cancelled.")
        try:
            ok, payload = box.get(timeout=min(WORKER_POLL_S, max(0.0, deadline - time.monotonic())))
        except queue.Empty:
            if time.monotonic() >= deadline:
                cancel.set()
                raise ProviderTimeout("The provider did not answer in time.")
            continue
        if ok:
            return payload
        if isinstance(payload, ProviderError):
            raise payload
        raise ProviderError(f"The provider failed: {type(payload).__name__}.")


def validate_scope(
    db_path: Path,
    *,
    actor: Actor,
    site_id: str,
    source_id: str | None,
    time_from: datetime,
    time_to: datetime,
    method: str | None = None,
    status: int | None = None,
    status_class: str | None = None,
    path_prefix: str | None = None,
    path_exact: str | None = None,
    referer_host: str | None = None,
    traffic: str = "all",
    bot: str | None = None,
    category: str | None = None,
    provider_claim: str | None = None,
    purpose: str | None = None,
    search: str | None = None,
    client: str | None = None,
    server_host: str | None = None,
    http_version: str | None = None,
    mime_type: str | None = None,
    cache_status: str | None = None,
    tls_protocol: str | None = None,
    timing_available: bool | None = None,
    upstream_available: bool | None = None,
    timing_min_ms: float | None = None,
    timing_max_ms: float | None = None,
) -> ValidatedScope:
    """Validate the trusted actor/site/source/window/selector contract first.

    Runs before any budget reservation or provider dispatch using the
    shared TimeWindow bound and a read-only store handle. Only the
    "admin" actor kind may run investigations; model-supplied arguments
    are overridden with this scope later and can never widen it.
    Selector membership against the versioned rules is checked by the
    caller, which holds the rules.
    """
    if not isinstance(actor, Actor) or actor.kind != "admin":
        raise InvestigationError("forbidden_actor", "This actor may not run investigations.")
    if traffic not in _TRAFFIC_VALUES:
        raise InvestigationError("invalid_request", "The requested traffic selector is invalid.")
    if status_class is not None and status_class not in _STATUS_CLASS_VALUES:
        raise InvestigationError("invalid_request", "The requested status class is invalid.")
    for name, value, bound in (
        ("method", method, 32),
        ("bot", bot, 64),
        ("category", category, 64),
        ("provider", provider_claim, 120),
        ("purpose", purpose, 120),
        ("path_prefix", path_prefix, 1024),
        ("path_exact", path_exact, 1024),
        ("referer_host", referer_host, 253),
        ("search", search, 128),
        ("server_host", server_host, 253),
        ("http_version", http_version, 16),
        ("mime_type", mime_type, 128),
        ("cache_status", cache_status, 32),
        ("tls_protocol", tls_protocol, 32),
    ):
        if value is not None and (not isinstance(value, str) or not 1 <= len(value) <= bound):
            raise InvestigationError(
                "invalid_request", f"The requested {name} selector is invalid."
            )
    if client is not None and (
        not isinstance(client, str)
        or len(client) != 64
        or any(char not in "0123456789abcdef" for char in client)
    ):
        raise InvestigationError("invalid_request", "The requested client selector is invalid.")
    if status is not None and (
        not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599
    ):
        raise InvestigationError("invalid_request", "The requested status selector is invalid.")
    if status is not None and status_class is not None and f"{status // 100}xx" != status_class:
        raise InvestigationError(
            "invalid_request", "The requested status selectors contradict each other."
        )
    if (
        path_exact is not None
        and path_prefix is not None
        and not path_exact.startswith(path_prefix)
    ):
        raise InvestigationError(
            "invalid_request", "The requested path selectors contradict each other."
        )
    for name, value in (
        ("timing_available", timing_available),
        ("upstream_available", upstream_available),
    ):
        if value is not None and not isinstance(value, bool):
            raise InvestigationError(
                "invalid_request", f"The requested {name} selector is invalid."
            )
    import math as _math

    for name, value in (("timing_min_ms", timing_min_ms), ("timing_max_ms", timing_max_ms)):
        if value is not None and (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not _math.isfinite(value)
            or value < 0
        ):
            raise InvestigationError(
                "invalid_request", f"The requested {name} selector is invalid."
            )
    if timing_min_ms is not None and timing_max_ms is not None and timing_min_ms > timing_max_ms:
        raise InvestigationError(
            "invalid_request", "The requested timing range contradicts itself."
        )
    try:
        window = TimeWindow(time_from=time_from, time_to=time_to)
    except ValidationError as exc:
        raise InvestigationError(
            "invalid_request", "The requested time window is invalid."
        ) from exc
    try:
        conn = connect(Path(db_path), read_only=True)
        try:
            site = conn.execute("SELECT id FROM sites WHERE id = ?", (site_id,)).fetchone()
            if site is None:
                raise InvestigationError("unknown_site", "The requested site is unknown.")
            if source_id is not None:
                row = conn.execute(
                    "SELECT site_id FROM log_sources WHERE id = ?", (source_id,)
                ).fetchone()
                if row is None or row[0] != site_id:
                    raise InvestigationError(
                        "forbidden_source", "The requested source is not in this site."
                    )
        finally:
            conn.close()
    except InvestigationError:
        raise
    except Exception as exc:
        raise InvestigationError("store_unavailable", "The data store is unavailable.") from exc
    return ValidatedScope(
        site_id=site_id,
        source_id=source_id,
        time_from=window.time_from,
        time_to=window.time_to,
        method=method,
        status=status,
        status_class=status_class,
        path_prefix=path_prefix,
        path_exact=path_exact,
        referer_host=referer_host,
        traffic=traffic,
        bot=bot,
        category=category,
        provider_claim=provider_claim,
        purpose=purpose,
        search=search,
        client=client,
        server_host=server_host,
        http_version=http_version,
        mime_type=mime_type,
        cache_status=cache_status,
        tls_protocol=tls_protocol,
        timing_available=timing_available,
        upstream_available=upstream_available,
        timing_min_ms=timing_min_ms,
        timing_max_ms=timing_max_ms,
    )


def _smoke_error(exc: smoke.SmokeRefused) -> "InvestigationError":
    """Map a smoke refusal to a safe investigation failure."""
    if exc.code in (
        "investigation_cap_reached",
        "request_cap_reached",
        "cost_cap_reached",
    ):
        return InvestigationError(
            "budget_reached",
            "The AI usage limit has been reached. Analytics remain available.",
        )
    return InvestigationError("invalid_request", str(exc))


def _settle_step(
    db_path: Path, *, reservation_id: int, smoke_hold: int | None, actual_micro_usd: int
) -> None:
    """Convert budget and smoke holds into measured charges."""
    budget.charge(db_path, reservation_id=reservation_id, actual_micro_usd=actual_micro_usd)
    if smoke_hold is not None:
        smoke.settle_hold(db_path, hold_id=smoke_hold, actual_micro_usd=actual_micro_usd)


def _abandon_step(
    db_path: Path, *, reservation_id: int, smoke_hold: int | None, cap_micro_usd: int
) -> None:
    """Keep full holds for dispatched work of unknown size."""
    budget.charge(db_path, reservation_id=reservation_id, actual_micro_usd=cap_micro_usd)
    if smoke_hold is not None:
        smoke.abandon_hold(db_path, hold_id=smoke_hold)


def _release_step(db_path: Path, *, reservation_id: int, smoke_hold: int | None) -> None:
    """Release holds for work that never dispatched (no worker capacity)."""
    budget.release(db_path, reservation_id=reservation_id)
    if smoke_hold is not None:
        smoke.release_hold(db_path, hold_id=smoke_hold)


def _validate_response_shape(
    response: ProviderResponse, *, tool_total: int, input_upper: int, require_call_ids: bool = False
) -> list:
    """Validate one provider response before executing any of its work.

    Declared usage must fit the requested bounds: output within the
    configured maximum and input within the dispatched prompt's upper
    bound, whether or not tool calls are present. Anything larger fails
    closed instead of entering the ledger or the tool layer. Real
    stateless dispatches additionally require unique, well-formed
    call IDs so results correlate to the right calls.
    """
    if not isinstance(response.text, str):
        raise InvestigationError("invalid_response", "The provider answer is malformed.")
    for field_name in ("input_tokens", "output_tokens"):
        tokens = getattr(response, field_name, None)
        if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 0:
            raise InvestigationError("invalid_response", "The provider usage is malformed.")
    if response.output_tokens > MAX_OUTPUT_TOKENS or response.input_tokens > input_upper:
        raise InvestigationError(
            "invalid_response", "The provider usage exceeds its requested bounds."
        )
    calls = response.tool_calls
    if calls is None:
        return []
    if not isinstance(calls, (tuple, list)):
        raise InvestigationError("invalid_response", "The provider tool calls are malformed.")
    if len(calls) > MAX_TOOLS_PER_RESPONSE:
        raise InvestigationError(
            "tool_limit_reached", "The provider requested too many tools at once."
        )
    if tool_total + len(calls) > MAX_TOTAL_TOOLS:
        raise InvestigationError(
            "tool_limit_reached", "The investigation requested too many tools."
        )
    parsed = []
    seen_call_ids: set[str] = set()
    for call in calls:
        name = call.name if hasattr(call, "name") else None
        if name is None and isinstance(call, dict):
            name = call.get("name")
        if hasattr(call, "arguments"):
            raw_args = call.arguments
        elif isinstance(call, dict):
            raw_args = call.get("arguments")
        else:
            raw_args = None
        if hasattr(call, "call_id"):
            raw_call_id = call.call_id
        elif isinstance(call, dict):
            raw_call_id = call.get("call_id", "")
        else:
            raw_call_id = ""
        if not isinstance(name, str) or not name or not isinstance(raw_args, dict):
            raise InvestigationError("invalid_response", "A provider tool call is malformed.")
        call_id = raw_call_id if isinstance(raw_call_id, str) else ""
        if require_call_ids:
            if not 1 <= len(call_id) <= 64 or call_id in seen_call_ids:
                raise InvestigationError("invalid_response", "A provider tool call is malformed.")
            seen_call_ids.add(call_id)
        parsed.append((name, raw_args, call_id))
    return parsed


def _utc_today(clock) -> str:
    """Trusted current UTC budget day for one dispatch/reservation.

    Naive clock readings are treated as UTC rather than guessed; the
    investigation observation timestamp stays stable separately.
    """
    moment = clock()
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).date().isoformat()


def _budget_limits(settings) -> dict:
    return {
        "daily_limit_micro_usd": budget.usd_to_micro(
            float(getattr(settings, "llm_daily_limit_usd", 0.0))
        ),
        "stop_micro_usd": budget.usd_to_micro(float(getattr(settings, "llm_stop_at_usd", 0.0))),
        "total_micro_usd": budget.usd_to_micro(float(getattr(settings, "llm_budget_usd", 0.0))),
        "warn_micro_usd": budget.usd_to_micro(float(getattr(settings, "llm_warn_at_usd", 0.0))),
    }


def run_investigation(
    *,
    db_path: Path,
    rules,
    settings,
    provider: ProviderAdapter,
    actor: Actor,
    question: str,
    site_id: str,
    source_id: str | None = None,
    time_from: datetime,
    time_to: datetime,
    method: str | None = None,
    status: int | None = None,
    status_class: str | None = None,
    path_prefix: str | None = None,
    path_exact: str | None = None,
    referer_host: str | None = None,
    traffic: str = "all",
    bot: str | None = None,
    category: str | None = None,
    provider_claim: str | None = None,
    purpose: str | None = None,
    search: str | None = None,
    client: str | None = None,
    server_host: str | None = None,
    http_version: str | None = None,
    mime_type: str | None = None,
    cache_status: str | None = None,
    tls_protocol: str | None = None,
    timing_available: bool | None = None,
    upstream_available: bool | None = None,
    timing_min_ms: float | None = None,
    timing_max_ms: float | None = None,
    max_steps: int = MAX_STEPS,
    timeout_s: float = PROVIDER_TIMEOUT_S,
    cancel: threading.Event | None = None,
    now: datetime | None = None,
    clock=None,
    smoke_enforced: bool | None = None,
) -> InvestigationResult:
    """Run one bounded investigation with fake-provider-safe egress.

    `now` fixes the stable observation timestamp; `clock` (a zero-arg
    callable returning the current UTC time) fixes the budget day.
    Production passes neither, so every dispatch reads the live clock
    while observation metadata stays stable. Tests may inject a frozen
    `now` (which also freezes the clock unless `clock` is given) or a
    scripted advancing `clock` for midnight rollover. `smoke_enforced`
    admits every investigation and request against the lifetime smoke
    allowance from settings. The default (None) enforces it for every
    REAL dispatch — including authenticated UI/API chat — and leaves
    fake-only paths alone; pass False explicitly only to opt a
    fake-provider test out.
    """
    if not bool(getattr(settings, "ai_enabled", False)):
        raise InvestigationError(
            "ai_disabled", "The AI assistant is disabled. Analytics remain available."
        )
    if not isinstance(question, str) or not question.strip():
        raise InvestigationError("invalid_request", "A question is required.")
    if len(question) > MAX_QUESTION_CHARS:
        raise InvestigationError("invalid_request", "The question exceeds the length bound.")
    if not 1 <= max_steps <= MAX_STEPS:
        raise InvestigationError("invalid_request", "The step bound is out of range.")
    if not PROVIDER_TIMEOUT_MIN_S <= timeout_s <= PROVIDER_TIMEOUT_MAX_S:
        raise InvestigationError("invalid_request", "The timeout bound is out of range.")
    try:
        selector_clf = build_classifier(list(rules))
        resolve_selector_indexes(
            selector_clf,
            bot=bot,
            category=category,
            provider=provider_claim,
            purpose=purpose,
        )
    except ValueError as exc:
        raise InvestigationError("invalid_request", "Unknown or contradictory selector.") from exc
    scope = validate_scope(
        Path(db_path),
        actor=actor,
        site_id=site_id,
        source_id=source_id,
        time_from=time_from,
        time_to=time_to,
        method=method,
        status=status,
        status_class=status_class,
        path_prefix=path_prefix,
        path_exact=path_exact,
        referer_host=referer_host,
        traffic=traffic,
        bot=bot,
        category=category,
        provider_claim=provider_claim,
        purpose=purpose,
        search=search,
        client=client,
        server_host=server_host,
        http_version=http_version,
        mime_type=mime_type,
        cache_status=cache_status,
        tls_protocol=tls_protocol,
        timing_available=timing_available,
        upstream_available=upstream_available,
        timing_min_ms=timing_min_ms,
        timing_max_ms=timing_max_ms,
    )
    try:
        gate.validate_for_real_data(settings)
    except gate.GateBlocked as exc:
        raise InvestigationError(
            "egress_blocked", "The assistant cannot run under these settings."
        ) from exc
    if search is not None:
        # Operator search text replays into typed tool arguments, so it
        # crosses the egress boundary like the question: sensitive shapes
        # reject the investigation instead of silently broadening the read.
        try:
            egress.check_outgoing(search, context="search selector")
        except egress.EgressViolation as exc:
            raise InvestigationError(
                "egress_blocked", "The search selector cannot be sent safely."
            ) from exc
    observed = datetime.now(UTC) if now is None else now
    if clock is None:
        clock_fn = (lambda: now) if now is not None else (lambda: datetime.now(UTC))
    else:
        clock_fn = clock
    investigation_id = uuid.uuid4().hex
    cancel_event = threading.Event() if cancel is None else cancel
    limits = _budget_limits(settings)

    try:
        egress.check_outgoing(question, context="question")
        system_prompt = egress.check_outgoing(load_system_prompt(), context="system prompt")
    except egress.EgressViolation as exc:
        raise InvestigationError("egress_blocked", "The request cannot be sent safely.") from exc

    is_real = getattr(provider, "name", "") == MetaResponsesAdapter.name
    response_ids: list[str] = []
    provider_calls: list[dict] = []
    if smoke_enforced is None:
        smoke_enforced = is_real
    if smoke_enforced:
        try:
            smoke.init_or_check(
                Path(db_path),
                max_investigations=int(getattr(settings, "smoke_max_investigations", 3)),
                max_requests=int(getattr(settings, "smoke_max_requests", 12)),
                max_micro_usd=budget.usd_to_micro(
                    float(getattr(settings, "smoke_budget_usd", 1.0))
                ),
            )
            smoke.admit_investigation(Path(db_path), investigation_id=investigation_id)
        except smoke.SmokeRefused as exc:
            raise _smoke_error(exc) from exc

    history: list[str] = []
    evidence: list[dict] = []
    exchanges: list[dict] = []
    warnings: list[str] = []
    tool_total = 0
    spent_input = 0
    spent_output = 0
    spent_cached = 0
    spent_reasoning = 0
    spent_micro_usd = 0
    charged_input = 0
    charged_output = 0
    model = str(getattr(settings, "model_id", ""))
    started = time.monotonic()
    for _ in range(max_steps):
        if cancel_event.is_set():
            raise InvestigationError("cancelled", "The investigation was cancelled.")
        if sum(len(entry) for entry in history) > HISTORY_MAX_CHARS:
            raise InvestigationError(
                "output_limit_reached", "The investigation outgrew its history bound."
            )
        try:
            decision = gate.validate_for_real_data(settings)
        except gate.GateBlocked as exc:
            raise InvestigationError(
                "egress_blocked", "The assistant cannot run under these settings."
            ) from exc
        model = decision.model
        prompt = _compose_prompt(
            system_prompt,
            question,
            scope.site_id,
            scope.source_id,
            scope.time_from,
            scope.time_to,
            history,
            method=scope.method,
            status=scope.status,
            status_class=scope.status_class,
            path_prefix=scope.path_prefix,
            path_exact=scope.path_exact,
            referer_host=scope.referer_host,
            traffic=scope.traffic,
            bot=scope.bot,
            category=scope.category,
            provider_claim=scope.provider_claim,
            purpose=scope.purpose,
            search=scope.search,
            client=scope.client,
            server_host=scope.server_host,
            http_version=scope.http_version,
            mime_type=scope.mime_type,
            cache_status=scope.cache_status,
            tls_protocol=scope.tls_protocol,
            timing_available=scope.timing_available,
            upstream_available=scope.upstream_available,
            timing_min_ms=scope.timing_min_ms,
            timing_max_ms=scope.timing_max_ms,
        )
        if is_real:
            # Real dispatch: decoded body from already-gated values,
            # recursive decoded validation, exact immutable bytes, and
            # a reservation for those exact bytes plus framing. The
            # user text stays minimal (question + trusted scope): each
            # tool result replays exactly once through the typed
            # exchanges below, never duplicated as history text.
            # Fake-provider prompts keep the legacy history behavior.
            user_text = _compose_user_text(
                question,
                scope.site_id,
                scope.source_id,
                scope.time_from,
                scope.time_to,
                [],
                method=scope.method,
                status=scope.status,
                status_class=scope.status_class,
                path_prefix=scope.path_prefix,
                path_exact=scope.path_exact,
                referer_host=scope.referer_host,
                traffic=scope.traffic,
                bot=scope.bot,
                category=scope.category,
                provider_claim=scope.provider_claim,
                purpose=scope.purpose,
                search=scope.search,
                client=scope.client,
                server_host=scope.server_host,
                http_version=scope.http_version,
                mime_type=scope.mime_type,
                cache_status=scope.cache_status,
                tls_protocol=scope.tls_protocol,
                timing_available=scope.timing_available,
                upstream_available=scope.upstream_available,
                timing_min_ms=scope.timing_min_ms,
                timing_max_ms=scope.timing_max_ms,
            )
            try:
                body_dict = build_dispatch_body(
                    model=model,
                    max_output_tokens=MAX_OUTPUT_TOKENS,
                    instructions=system_prompt,
                    user_text=user_text,
                    exchanges=exchanges,
                    tools=response_tool_definitions(),
                )
            except egress.EgressViolation as exc:
                raise InvestigationError(
                    "egress_blocked", "The request cannot be sent safely."
                ) from exc
            wire = serialize_body(body_dict)
            try:
                checker = getattr(provider, "check_dispatch", None)
                if callable(checker):
                    checker(wire)
            except ProviderError as exc:
                raise InvestigationError(
                    "invalid_response", "The provider dispatch is malformed."
                ) from exc
            if len(wire) > MAX_WIRE_BYTES:
                raise InvestigationError(
                    "output_limit_reached", "The investigation outgrew its prompt bound."
                )
            input_upper = len(wire) + WIRE_FRAMING_TOKENS
            step_cap = cost_micro_usd(
                input_tokens=input_upper, cached_tokens=0, output_tokens=MAX_OUTPUT_TOKENS
            )
            dispatch_request = ProviderRequest(
                prompt_text=prompt, max_output_tokens=MAX_OUTPUT_TOKENS, body=wire
            )
        else:
            input_upper = estimate_input_tokens_upper(prompt)
            step_cap = estimate_micro_usd(input_upper, MAX_OUTPUT_TOKENS)
            dispatch_request = ProviderRequest(
                prompt_text=prompt, max_output_tokens=MAX_OUTPUT_TOKENS
            )
        dispatch_day = _utc_today(clock_fn)
        try:
            step_reservation, warned = budget.reserve(
                Path(db_path),
                day=dispatch_day,
                amount_micro_usd=step_cap,
                investigation_id=investigation_id,
                **limits,
            )
        except budget.BudgetExhausted as exc:
            raise InvestigationError(
                "budget_reached",
                "The AI usage limit has been reached. Analytics remain available.",
            ) from exc
        if warned and "usage warning threshold reached" not in warnings:
            warnings.append("usage warning threshold reached")
        smoke_hold: int | None = None
        if smoke_enforced:
            try:
                smoke_hold = smoke.admit_request(
                    Path(db_path),
                    amount_micro_usd=step_cap,
                    investigation_id=investigation_id,
                )
            except smoke.SmokeRefused as exc:
                budget.release(Path(db_path), reservation_id=step_reservation)
                raise _smoke_error(exc) from exc
        try:
            response = _wait_provider(
                provider,
                dispatch_request,
                timeout_s=timeout_s,
                cancel=cancel_event,
            )
        except _WorkerBusy as exc:
            _release_step(Path(db_path), reservation_id=step_reservation, smoke_hold=smoke_hold)
            raise InvestigationError(
                "provider_unavailable", "The AI assistant is unavailable. Please try again later."
            ) from exc
        except ProviderCancelled as exc:
            # Cancelled after dispatch: dispatched work of unknown size
            # keeps its full hold rather than leaking an open reservation.
            _abandon_step(
                Path(db_path),
                reservation_id=step_reservation,
                smoke_hold=smoke_hold,
                cap_micro_usd=step_cap,
            )
            raise InvestigationError("cancelled", "The investigation was cancelled.") from exc
        except (ProviderTimeout, ProviderError) as exc:
            # Dispatched work of unknown size keeps its full hold.
            _abandon_step(
                Path(db_path),
                reservation_id=step_reservation,
                smoke_hold=smoke_hold,
                cap_micro_usd=step_cap,
            )
            raise InvestigationError(
                "provider_unavailable", "The AI assistant is unavailable. Please try again later."
            ) from exc
        try:
            calls = _validate_response_shape(
                response,
                tool_total=tool_total,
                input_upper=input_upper,
                require_call_ids=is_real,
            )
        except InvestigationError:
            _abandon_step(
                Path(db_path),
                reservation_id=step_reservation,
                smoke_hold=smoke_hold,
                cap_micro_usd=step_cap,
            )
            raise
        spent_input += response.input_tokens
        spent_output += response.output_tokens
        if is_real and response.response_id:
            response_ids.append(response.response_id)
        real_usage = dict(response.usage) if response.usage else {}
        if is_real:
            if not real_usage:
                _abandon_step(
                    Path(db_path),
                    reservation_id=step_reservation,
                    smoke_hold=smoke_hold,
                    cap_micro_usd=step_cap,
                )
                raise InvestigationError("invalid_response", "The provider usage is malformed.")
            try:
                step_actual = cost_micro_usd(
                    input_tokens=real_usage["input_tokens"],
                    cached_tokens=real_usage.get("cached_tokens", 0),
                    output_tokens=real_usage["output_tokens"],
                )
            except (KeyError, ProviderError):
                _abandon_step(
                    Path(db_path),
                    reservation_id=step_reservation,
                    smoke_hold=smoke_hold,
                    cap_micro_usd=step_cap,
                )
                raise InvestigationError("invalid_response", "The provider usage is malformed.")
            spent_cached += real_usage.get("cached_tokens", 0)
            spent_reasoning += real_usage.get("reasoning_tokens", 0)
            spent_micro_usd += step_actual
        else:
            step_actual = estimate_micro_usd(
                spent_input - charged_input, spent_output - charged_output
            )
        if calls:
            exchange_calls: list[dict] = []
            exchange_outputs: list[dict] = []
            try:
                for name, raw_args, call_id in calls:
                    tool_total += 1
                    result = _execute_bounded_tool(
                        db_path,
                        rules,
                        name,
                        raw_args,
                        site_id=scope.site_id,
                        source_id=scope.source_id,
                        time_from=scope.time_from,
                        time_to=scope.time_to,
                        method=scope.method,
                        status=scope.status,
                        status_class=scope.status_class,
                        path_prefix=scope.path_prefix,
                        path_exact=scope.path_exact,
                        referer_host=scope.referer_host,
                        traffic=scope.traffic,
                        bot=scope.bot,
                        category=scope.category,
                        provider_claim=scope.provider_claim,
                        purpose=scope.purpose,
                        search=scope.search,
                        client=scope.client,
                        server_host=scope.server_host,
                        http_version=scope.http_version,
                        mime_type=scope.mime_type,
                        cache_status=scope.cache_status,
                        tls_protocol=scope.tls_protocol,
                        timing_available=scope.timing_available,
                        upstream_available=scope.upstream_available,
                        timing_min_ms=scope.timing_min_ms,
                        timing_max_ms=scope.timing_max_ms,
                        tool_index=tool_total,
                        investigation_id=investigation_id,
                        observation_time=observed,
                    )
                    evidence.append(result["envelope"])
                    history.append(result["history_line"])
                    if is_real:
                        provider_calls.append(
                            {
                                "tool_call_id": result["envelope"]["tool_call_id"],
                                "call_id": call_id,
                                "tool": name,
                            }
                        )
                        exchange_calls.append(
                            {
                                "call_id": call_id,
                                "name": name,
                                "arguments": result["arguments"],
                            }
                        )
                        exchange_outputs.append(
                            {"call_id": call_id, "evidence": result["evidence_output"]}
                        )
            except InvestigationError:
                # Dispatched work of unknown reconciled size keeps its
                # full step hold.
                _abandon_step(
                    Path(db_path),
                    reservation_id=step_reservation,
                    smoke_hold=smoke_hold,
                    cap_micro_usd=step_cap,
                )
                raise
            if is_real:
                exchanges.append({"calls": exchange_calls, "outputs": exchange_outputs})
            _settle_step(
                Path(db_path),
                reservation_id=step_reservation,
                smoke_hold=smoke_hold,
                actual_micro_usd=step_actual,
            )
            charged_input, charged_output = spent_input, spent_output
            if not is_real:
                # Fake/legacy path has no per-response usage ledger, so
                # accumulate each settled incremental estimate: the final
                # display is exactly the ledger sum including rounding.
                spent_micro_usd += step_actual
            continue
        if len(response.text) > MAX_ANSWER_CHARS:
            _abandon_step(
                Path(db_path),
                reservation_id=step_reservation,
                smoke_hold=smoke_hold,
                cap_micro_usd=step_cap,
            )
            raise InvestigationError(
                "output_limit_reached", "The provider answer exceeds its bound."
            )
        try:
            egress.check_outgoing(response.text, context="provider answer")
        except egress.EgressViolation as exc:
            _abandon_step(
                Path(db_path),
                reservation_id=step_reservation,
                smoke_hold=smoke_hold,
                cap_micro_usd=step_cap,
            )
            raise InvestigationError(
                "egress_blocked", "The provider answer cannot be shown safely."
            ) from exc
        if is_real:
            # `spent_micro_usd` already includes this step's settled
            # micro-USD (added above), so the display is exactly the
            # ledger sum — never the last step twice.
            actual_micro = spent_micro_usd
            usage_record = {
                "input_tokens": spent_input,
                "output_tokens": spent_output,
                "cached_tokens": spent_cached,
                "reasoning_tokens": spent_reasoning,
                "estimated_cost_usd": budget.micro_to_usd(actual_micro),
                "pricing_version": "2026-10-31-dev.meta.ai",
                "response_ids": list(response_ids),
                "duration_s": round(time.monotonic() - started, 3),
                "tool_calls": tool_total,
            }
        else:
            # Display exactly the settled per-step sum (prior tool steps
            # plus this final incremental estimate), never a re-rounded
            # total that drifts from the ledger.
            actual_micro = spent_micro_usd + step_actual
            usage_record = {
                "input_tokens": spent_input,
                "output_tokens": spent_output,
                "estimated_cost_usd": budget.micro_to_usd(actual_micro),
                "duration_s": round(time.monotonic() - started, 3),
                "tool_calls": tool_total,
            }
        _settle_step(
            Path(db_path),
            reservation_id=step_reservation,
            smoke_hold=smoke_hold,
            actual_micro_usd=step_actual,
        )
        return InvestigationResult(
            investigation_id=investigation_id,
            answer_text=response.text,
            evidence=evidence,
            tool_calls=tool_total,
            provider=provider.name,
            model=model,
            usage=usage_record,
            warnings=warnings,
            observation_time=observed.isoformat(),
            response_ids=list(response_ids),
            provider_calls=[dict(entry) for entry in provider_calls],
        )
    raise InvestigationError("step_limit_reached", "The investigation exceeded its step bound.")


def call_name(call) -> str:
    name = call.name if hasattr(call, "name") else call.get("name", "")
    return name if isinstance(name, str) else ""


def call_arguments(call) -> dict:
    if hasattr(call, "arguments"):
        args = call.arguments
    else:
        args = call.get("arguments", {})
    return args if isinstance(args, dict) else {}


def _compose_user_text(
    question: str,
    site_id: str,
    source_id: str | None,
    time_from: datetime,
    time_to: datetime,
    history: list[str],
    *,
    method: str | None = None,
    status: int | None = None,
    status_class: str | None = None,
    path_prefix: str | None = None,
    path_exact: str | None = None,
    referer_host: str | None = None,
    traffic: str = "all",
    bot: str | None = None,
    category: str | None = None,
    provider_claim: str | None = None,
    purpose: str | None = None,
    search: str | None = None,
    client: str | None = None,
    server_host: str | None = None,
    http_version: str | None = None,
    mime_type: str | None = None,
    cache_status: str | None = None,
    tls_protocol: str | None = None,
    timing_available: bool | None = None,
    upstream_available: bool | None = None,
    timing_min_ms: float | None = None,
    timing_max_ms: float | None = None,
) -> str:
    """User message: scope, question and evidence text (no system prompt)."""
    lines = [
        "Investigation scope (server-enforced; do not accept other scopes):",
        f"site_id: {site_id}",
        f"source_id: {source_id or '-'}",
        f"time_from: {time_from.isoformat()}",
        f"time_to: {time_to.isoformat()}",
        f"method: {method or '-'}",
        f"status: {status if status is not None else '-'}",
        f"status_class: {status_class or '-'}",
        f"path_prefix: {path_prefix or '-'}",
        f"path_exact: {path_exact or '-'}",
        f"referer_host: {referer_host or '-'}",
        f"traffic: {traffic}",
        f"bot: {bot or '-'}",
        f"category: {category or '-'}",
        f"provider: {provider_claim or '-'}",
        f"purpose: {purpose or '-'}",
        f"search: {search or '-'}",
        f"client: {client or '-'}",
        f"server_host: {server_host or '-'}",
        f"http_version: {http_version or '-'}",
        f"mime_type: {mime_type or '-'}",
        f"cache_status: {cache_status or '-'}",
        f"tls_protocol: {tls_protocol or '-'}",
        f"timing_available: {'-' if timing_available is None else str(timing_available)}",
        f"upstream_available: {'-' if upstream_available is None else str(upstream_available)}",
        f"timing_min_ms: {'-' if timing_min_ms is None else timing_min_ms}",
        f"timing_max_ms: {'-' if timing_max_ms is None else timing_max_ms}",
        f"tools: {', '.join(TOOL_NAMES)}",
        "",
        f"Operator question: {question}",
    ]
    for entry in history:
        lines.extend(["", entry])
    text = "\n".join(lines)
    try:
        return egress.check_outgoing(text, context="prompt")
    except egress.EgressViolation as exc:
        raise InvestigationError(
            "output_limit_reached", "The investigation outgrew its prompt bound."
        ) from exc


def _compose_prompt(
    system_prompt: str,
    question: str,
    site_id: str,
    source_id: str | None,
    time_from: datetime,
    time_to: datetime,
    history: list[str],
    *,
    method: str | None = None,
    status: int | None = None,
    status_class: str | None = None,
    path_prefix: str | None = None,
    path_exact: str | None = None,
    referer_host: str | None = None,
    traffic: str = "all",
    bot: str | None = None,
    category: str | None = None,
    provider_claim: str | None = None,
    purpose: str | None = None,
    search: str | None = None,
    client: str | None = None,
    server_host: str | None = None,
    http_version: str | None = None,
    mime_type: str | None = None,
    cache_status: str | None = None,
    tls_protocol: str | None = None,
    timing_available: bool | None = None,
    upstream_available: bool | None = None,
    timing_min_ms: float | None = None,
    timing_max_ms: float | None = None,
) -> str:
    prompt = (
        system_prompt
        + "\n\n"
        + _compose_user_text(
            question,
            site_id,
            source_id,
            time_from,
            time_to,
            history,
            method=method,
            status=status,
            status_class=status_class,
            path_prefix=path_prefix,
            path_exact=path_exact,
            referer_host=referer_host,
            traffic=traffic,
            bot=bot,
            category=category,
            provider_claim=provider_claim,
            purpose=purpose,
            search=search,
            client=client,
            server_host=server_host,
            http_version=http_version,
            mime_type=mime_type,
            cache_status=cache_status,
            tls_protocol=tls_protocol,
            timing_available=timing_available,
            upstream_available=upstream_available,
            timing_min_ms=timing_min_ms,
            timing_max_ms=timing_max_ms,
        )
    )
    try:
        return egress.check_outgoing(prompt, context="prompt")
    except egress.EgressViolation as exc:
        raise InvestigationError(
            "output_limit_reached", "The investigation outgrew its prompt bound."
        ) from exc


def _inherit_narrowing(scope_value, model_value, default):
    """Scope wins when selected; otherwise a bounded model value may narrow.

    A selected parent constraint (anything but the unset default) is
    enforced exactly, so hostile omissions or overrides cannot widen the
    read. An omitted model selector (None) always falls back to the
    scope, and an unset parent leaves the dimension to the model, whose
    value is still validated by the typed tool contract before execution.
    """
    if model_value is None:
        return scope_value
    return model_value if scope_value == default else scope_value


def _projection_quality(tool_name: str, envelope: dict) -> dict:
    """Compact quality state the model needs to interpret one result.

    Timing, warning notes, import state and the tool's limitation text
    travel explicitly; a bare count is never a substitute. Only
    server-generated notes and integer import metadata travel — stored
    `error_summary` free text (including legacy pre-allowlist
    diagnostics and any poisoned metadata) is never included. Completed
    imports carrying the allowlisted source-change/content-mismatch
    segments (and the legacy withheld marker) surface as fixed notes on
    every tool, not only on summary warnings.
    """
    coverage = envelope.get("coverage")
    coverage = coverage if isinstance(coverage, dict) else {}
    result = envelope.get("result")
    result = result if isinstance(result, dict) else {}
    quality: dict[str, object] = {}
    duration = result.get("duration")
    if isinstance(duration, dict):
        quality["timing"] = "available" if duration.get("available") else "unavailable"
    elif isinstance(result.get("latency_available"), bool):
        # Performance reports carry measured latency directly:
        # available exactly when enriched request_time_ms exists.
        quality["timing"] = "available" if result["latency_available"] else "unavailable"
        if isinstance(result.get("latency_ms"), dict):
            quality["measured"] = result["latency_ms"].get("measured")
    warnings: list[str] = []
    raw_warnings = result.get("warnings")
    if isinstance(raw_warnings, list):
        warnings.extend(item for item in raw_warnings if isinstance(item, str))
    by_status: dict[str, int] = {}
    imports = coverage.get("imports")
    if isinstance(imports, list):
        for imp in imports:
            if not isinstance(imp, dict):
                continue
            status = imp.get("status")
            if isinstance(status, str) and status:
                by_status[status] = by_status.get(status, 0) + 1
            imp_id = imp.get("import_id")
            if not isinstance(imp_id, int) or isinstance(imp_id, bool):
                continue
            if status == "failed":
                note = f"import {imp_id} failed: committed batches kept, resume to complete"
                if note not in warnings:
                    warnings.append(note)
            elif status == "running":
                note = f"import {imp_id} still running: data may be partial"
                if note not in warnings:
                    warnings.append(note)
            # Allowlisted source-change/mismatch segments (already
            # sanitized at the shared query boundary) surface as fixed
            # notes on every tool; raw `error_summary` text never travels.
            summary = imp.get("error_summary")
            segments = set(summary.split("; ")) if isinstance(summary, str) and summary else set()
            if "source_changed_during_import" in segments:
                note = f"import {imp_id} source changed during import: data may be incomplete"
                if note not in warnings:
                    warnings.append(note)
            if "source_content_mismatch" in segments:
                note = f"import {imp_id} source content mismatch: data may be incomplete"
                if note not in warnings:
                    warnings.append(note)
            if "diagnostic_withheld:legacy_format" in segments:
                note = f"import {imp_id} diagnostic withheld: legacy format"
                if note not in warnings:
                    warnings.append(note)
    attempts = coverage.get("import_attempts")
    if isinstance(attempts, dict):
        quality["imports"] = {
            str(key): value for key, value in attempts.items() if isinstance(value, int)
        }
    if by_status:
        quality["imports_by_status"] = dict(sorted(by_status.items()))
    if warnings:
        quality["warnings_total"] = len(warnings)
        quality["warnings"] = warnings[:3]
        if len(warnings) > 3:
            quality["warnings_more"] = len(warnings) - 3
    if tool_name == "get_security_findings":
        quality["limitations"] = [*LIMITATIONS_SECURITY, *LIMITATIONS_LOGS]
    elif tool_name == "get_crawler_claims":
        quality["limitations"] = [*LIMITATIONS_BOT, *LIMITATIONS_LOGS]
    elif tool_name == "get_report":
        report = ""
        filters = envelope.get("filters")
        if isinstance(filters, dict) and isinstance(filters.get("report"), str):
            report = filters["report"]
        if report in ("performance", "slow_endpoints"):
            quality["limitations"] = [*LIMITATIONS_PERFORMANCE, *LIMITATIONS_LOGS]
        elif report in (
            "seo_redirects",
            "seo_client_errors",
            "seo_server_errors",
            "seo_ai_only",
            "referrer_404s",
        ):
            quality["limitations"] = [*LIMITATIONS_SEO, *LIMITATIONS_LOGS]
        elif report in ("journeys", "journey_entries"):
            # Compact model-facing limitation notes: the full service
            # and API envelopes keep the exact long-form sentences, but
            # the 1600-char bounded evidence line carries these shorter
            # equivalents so a 1-client/1-journey read still fits with
            # its exact scope, counts, coverage and observation intact.
            quality["limitations"] = [
                (
                    "journeys group stored requests by HMAC client plus sanitized UA "
                    "with a 30-minute split: never visitors, people, sessions or clicks"
                ),
                "a gap over 1800 seconds starts a new journey: exactly 1800 continues",
                "filters hide rows but never move journey boundaries: unfiltered stream",
                "edge partial journeys stay flagged: never read outside the window",
                "coverage describes observed events only: not proven completeness",
                "missing timing stays unavailable, never zero",
            ]
        elif report == "comparison":
            quality["limitations"] = [*LIMITATIONS_BOT, *LIMITATIONS_LOGS]
        else:
            quality["limitations"] = list(LIMITATIONS_LOGS)
    else:
        quality["limitations"] = list(LIMITATIONS_LOGS)
    return quality


def _execute_bounded_tool(
    db_path: Path,
    rules,
    name: str,
    arguments: dict,
    *,
    site_id: str,
    source_id: str | None,
    time_from: datetime,
    time_to: datetime,
    method: str | None = None,
    status: int | None = None,
    status_class: str | None = None,
    path_prefix: str | None = None,
    path_exact: str | None = None,
    referer_host: str | None = None,
    traffic: str = "all",
    bot: str | None = None,
    category: str | None = None,
    provider_claim: str | None = None,
    purpose: str | None = None,
    search: str | None = None,
    client: str | None = None,
    server_host: str | None = None,
    http_version: str | None = None,
    mime_type: str | None = None,
    cache_status: str | None = None,
    tls_protocol: str | None = None,
    timing_available: bool | None = None,
    upstream_available: bool | None = None,
    timing_min_ms: float | None = None,
    timing_max_ms: float | None = None,
    tool_index: int,
    investigation_id: str,
    observation_time: datetime,
) -> dict:
    # Site, source and time always come from the trusted investigation
    # scope. Every other selector is enforced when the parent selected it
    # and left to bounded model narrowing otherwise; the merged arguments
    # still cross the typed tool contract, so invalid or contradictory
    # combinations fail closed instead of widening. Selected ``False``
    # and ``0``/``0.0`` travel as real selections via ``is None``
    # narrowing only — they are never treated as omitted dimensions.
    model = dict(arguments) if isinstance(arguments, dict) else {}
    scoped = dict(model)
    scoped["site_id"] = site_id
    scoped["source_id"] = source_id
    scoped["time_from"] = time_from.isoformat()
    scoped["time_to"] = time_to.isoformat()
    scoped["method"] = _inherit_narrowing(method, model.get("method"), None)
    scoped["status"] = _inherit_narrowing(status, model.get("status"), None)
    scoped["status_class"] = _inherit_narrowing(status_class, model.get("status_class"), None)
    scoped["path_prefix"] = _inherit_narrowing(path_prefix, model.get("path_prefix"), None)
    scoped["path_exact"] = _inherit_narrowing(path_exact, model.get("path_exact"), None)
    scoped["referer_host"] = _inherit_narrowing(referer_host, model.get("referer_host"), None)
    scoped["traffic"] = _inherit_narrowing(traffic, model.get("traffic"), "all")
    scoped["bot"] = _inherit_narrowing(bot, model.get("bot"), None)
    scoped["category"] = _inherit_narrowing(category, model.get("category"), None)
    scoped["provider"] = _inherit_narrowing(provider_claim, model.get("provider"), None)
    scoped["purpose"] = _inherit_narrowing(purpose, model.get("purpose"), None)
    scoped["search"] = _inherit_narrowing(search, model.get("search"), None)
    # Trusted exact client: a selected pseudonym can never be changed by
    # the model (scope wins); an unset scope leaves bounded model
    # narrowing to the typed tool contract. Either way no original
    # address is involved and HMAC identities are never rekeyed here.
    scoped["client"] = _inherit_narrowing(client, model.get("client"), None)
    scoped["server_host"] = _inherit_narrowing(server_host, model.get("server_host"), None)
    scoped["http_version"] = _inherit_narrowing(http_version, model.get("http_version"), None)
    scoped["mime_type"] = _inherit_narrowing(mime_type, model.get("mime_type"), None)
    scoped["cache_status"] = _inherit_narrowing(cache_status, model.get("cache_status"), None)
    scoped["tls_protocol"] = _inherit_narrowing(tls_protocol, model.get("tls_protocol"), None)
    scoped["timing_available"] = _inherit_narrowing(
        timing_available, model.get("timing_available"), None
    )
    scoped["upstream_available"] = _inherit_narrowing(
        upstream_available, model.get("upstream_available"), None
    )
    scoped["timing_min_ms"] = _inherit_narrowing(timing_min_ms, model.get("timing_min_ms"), None)
    scoped["timing_max_ms"] = _inherit_narrowing(timing_max_ms, model.get("timing_max_ms"), None)
    tool_call_id = f"{investigation_id[:8]}-tc{tool_index}"
    conn = connect(Path(db_path), read_only=True)
    try:
        envelope = execute_tool(
            conn,
            rules,
            name=name,
            arguments=scoped,
            tool_call_id=tool_call_id,
            observation_time=observation_time,
        )
    except Exception as exc:
        code = getattr(exc, "code", "tool_failed")
        raise InvestigationError(
            "tool_rejected", f"A tool request was rejected ({code}). No action was taken."
        ) from exc
    finally:
        conn.close()
    if envelope["filters"].get("site_id") != site_id:
        raise InvestigationError("tool_rejected", "A tool result left the investigation scope.")
    try:
        minimized = egress.serialize_evidence(name, envelope["result"])
        history_line = egress.project_evidence_summary(
            tool_name=name,
            tool_call_id=tool_call_id,
            minimized=minimized,
            filters=envelope["filters"],
            observation_time=envelope["observation_time"],
            coverage=envelope["coverage"],
            full_result=envelope["result"] if isinstance(envelope.get("result"), dict) else None,
            quality=_projection_quality(name, envelope),
        )
    except egress.EgressViolation as exc:
        if exc.code == "payload_too_large":
            raise InvestigationError(
                "output_limit_reached", "The investigation outgrew its evidence bound."
            ) from exc
        raise InvestigationError(
            "egress_blocked", "A tool result cannot be forwarded safely."
        ) from exc
    # Typed replay metadata both model paths share: the exact local
    # evidence ID and actual observation time travel explicitly, so the
    # model never has to guess them from a minimized result. The full
    # local envelope (with complete filters, coverage and result) stays
    # server-side for the UI and reproducible evidence links.
    evidence_output = {
        "tool_call_id": tool_call_id,
        "tool": name,
        "observation_time": envelope["observation_time"],
        "summary": history_line,
    }
    return {
        "envelope": envelope,
        "history_line": history_line,
        # Executed (scope-overridden) arguments and projection metadata
        # for typed stateless replay on real dispatches.
        "arguments": dict(scoped),
        "evidence_output": evidence_output,
    }
