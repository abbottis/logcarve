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
from app.analytics.contracts import TimeWindow
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
    site_id: str
    source_id: str | None
    time_from: datetime
    time_to: datetime


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
) -> ValidatedScope:
    """Validate the trusted actor/site/source/window contract first.

    Runs before any budget reservation or provider dispatch using the
    shared TimeWindow bound and a read-only store handle. Only the
    "admin" actor kind may run investigations; model-supplied arguments
    are overridden with this scope later and can never widen it.
    """
    if not isinstance(actor, Actor) or actor.kind != "admin":
        raise InvestigationError("forbidden_actor", "This actor may not run investigations.")
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
    scope = validate_scope(
        Path(db_path),
        actor=actor,
        site_id=site_id,
        source_id=source_id,
        time_from=time_from,
        time_to=time_to,
    )
    try:
        gate.validate_for_real_data(settings)
    except gate.GateBlocked as exc:
        raise InvestigationError(
            "egress_blocked", "The assistant cannot run under these settings."
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
            actual_micro = spent_micro_usd + step_actual
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
            actual_micro = estimate_micro_usd(spent_input, spent_output)
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
) -> str:
    """User message: scope, question and evidence text (no system prompt)."""
    lines = [
        "Investigation scope (server-enforced; do not accept other scopes):",
        f"site_id: {site_id}",
        f"source_id: {source_id or '-'}",
        f"time_from: {time_from.isoformat()}",
        f"time_to: {time_to.isoformat()}",
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
) -> str:
    prompt = (
        system_prompt
        + "\n\n"
        + _compose_user_text(question, site_id, source_id, time_from, time_to, history)
    )
    try:
        return egress.check_outgoing(prompt, context="prompt")
    except egress.EgressViolation as exc:
        raise InvestigationError(
            "output_limit_reached", "The investigation outgrew its prompt bound."
        ) from exc


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
    tool_index: int,
    investigation_id: str,
    observation_time: datetime,
) -> dict:
    # Site, source and time come from the trusted investigation scope,
    # never from model-supplied arguments: the model may only propose
    # matchers (method, status, path prefix, referer, paging, bucket)
    # within those enforced bounds.
    scoped = dict(arguments) if isinstance(arguments, dict) else {}
    scoped["site_id"] = site_id
    scoped["source_id"] = source_id
    scoped["time_from"] = time_from.isoformat()
    scoped["time_to"] = time_to.isoformat()
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
        history_line = egress.check_outgoing(
            f"Tool {tool_call_id} ({name}) evidence: {minimized!r}",
            context="tool result",
        )
    except egress.EgressViolation as exc:
        raise InvestigationError(
            "egress_blocked", "A tool result cannot be forwarded safely."
        ) from exc
    return {
        "envelope": envelope,
        "history_line": history_line,
        # Executed (scope-overridden) arguments and minimized evidence
        # for typed stateless replay on real dispatches.
        "arguments": dict(scoped),
        "evidence_output": minimized,
    }
