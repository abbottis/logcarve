"""T7 correction regressions (independent review of 21cc6da).

Each test exercises the real service/HTTP path with finite synthetic
adapters: no test-only helper shortcuts for the corrected behavior.
"""

import ipaddress
import re
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from app.ai import budget, egress
from app.ai.providers.base import ProviderAdapter, ProviderError, ProviderResponse, ToolCall
from app.ai.providers.fake import FakeProvider
from app.ai.service import Actor, InvestigationError, run_investigation
from app.analytics.rules import load_rules
from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user, issue_token
from app.config import Settings
from app.db.database import writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.sources import SourceConfig

NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)
FROM = datetime(2026, 10, 27, tzinfo=UTC)
TO = datetime(2026, 10, 28, tzinfo=UTC)
ROOT = Path(__file__).resolve().parent.parent.parent
HMAC_KEY = b"synthetic-test-hmac-key"
ACTOR = Actor(kind="admin", username="admin", session_id="s1")


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes(
        (ROOT / "tests" / "fixtures" / "combined" / "nginx_combined.txt").read_bytes()
    )
    db = tmp_path / "corr.sqlite3"
    migrate(db)
    run_import(
        db,
        source=SourceConfig(
            source_id="example-combined",
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="access.log",
        ),
        site_id="default",
        site_name="s",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="access.log",
        hmac_key=HMAC_KEY,
    )
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
        _, token = issue_token(conn, name="api", site_id="default")
    rules = (
        load_rules(ROOT / "config" / "bot_rules.yaml").rules
        + load_rules(ROOT / "config" / "security_rules.yaml").rules
    )
    settings = Settings(
        ai_enabled=True,
        model_data_policy_verified=True,
        model_allow_real_data=True,
        llm_daily_limit_usd=50.0,
        llm_budget_usd=150.0,
        llm_warn_at_usd=120.0,
        llm_stop_at_usd=140.0,
    )
    return {"db": db, "rules": rules, "settings": settings, "token": token}


def _investigate(env, fake, **overrides):
    params = {
        "db_path": env["db"],
        "rules": env["rules"],
        "settings": env["settings"],
        "provider": fake,
        "actor": ACTOR,
        "question": "What claimed crawler activity is visible?",
        "site_id": "default",
        "source_id": None,
        "time_from": FROM,
        "time_to": TO,
        "now": NOW,
    }
    params.update(overrides)
    return run_investigation(**params)


def _direct_answer(text="Done."):
    return [ProviderResponse(text=text, input_tokens=10, output_tokens=5)]


class ModeSwitchFake(FakeProvider):
    """Flip the live settings tier after the first response (R1 probe)."""

    def __init__(self, settings, **kwargs):
        super().__init__(**kwargs)
        self._settings = settings
        self._calls = 0

    def complete(self, request, *, cancel):
        self._calls += 1
        response = super().complete(request, cancel=cancel)
        if self._calls == 1:
            self._settings.model_service_tier = "contributor"
        return response


def test_gate_revalidated_before_each_dispatch(env):
    script = [
        ProviderResponse(
            text="",
            input_tokens=10,
            output_tokens=5,
            tool_calls=(ToolCall(name="get_summary", arguments={"limit": 5}),),
        ),
        ProviderResponse(text="Second answer.", input_tokens=10, output_tokens=5),
    ]
    fake = ModeSwitchFake(env["settings"], script=script)
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(env, fake)
    assert excinfo.value.code == "egress_blocked"
    assert len(fake.outgoing) == 1


def _independent_addresses(text):
    """Address scan independent of the implementation's regexes."""
    found = []
    for token in re.split(r"\s+", text):
        cleaned = token.strip("[],()\"'<>").rstrip(".,;:")
        if not cleaned or ":" not in cleaned:
            continue
        candidate = cleaned[1:-1] if cleaned.startswith("[") and cleaned.endswith("]") else cleaned
        try:
            address = ipaddress.ip_address(candidate.split("%")[0])
        except ValueError:
            continue
        if isinstance(address, ipaddress.IPv6Address):
            found.append(candidate)
    return found


def test_captured_prompts_contain_no_raw_address(env):
    script = [
        ProviderResponse(
            text="",
            input_tokens=10,
            output_tokens=5,
            tool_calls=(ToolCall(name="get_crawler_claims", arguments={"limit": 5}),),
        ),
        ProviderResponse(text="No raw addresses here.", input_tokens=10, output_tokens=5),
    ]
    fake = FakeProvider(script=script)
    _investigate(env, fake)
    assert fake.outgoing
    for prompt in fake.captured_prompts():
        egress.check_outgoing(prompt, context="replay")
        assert _independent_addresses(prompt) == []


class IgnoringAdapter(ProviderAdapter):
    """Finite adapter that ignores cancellation (R3 probe)."""

    name = "ignoring"

    def __init__(self, delay_s):
        self.delay_s = delay_s

    def complete(self, request, *, cancel):
        time.sleep(self.delay_s)
        return ProviderResponse(text="Slow answer.", input_tokens=5, output_tokens=5)


def test_timeout_returns_at_deadline_with_ignoring_adapter(env):
    fake = IgnoringAdapter(delay_s=0.5)
    started = time.monotonic()
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(env, fake, timeout_s=0.02)
    assert excinfo.value.code == "provider_unavailable"
    assert time.monotonic() - started < 0.3


def test_external_cancel_during_wait_is_prompt(env):
    cancel = threading.Event()
    fake = IgnoringAdapter(delay_s=5.0)
    outcomes = []

    def _run():
        try:
            _investigate(env, fake, cancel=cancel, timeout_s=30)
        except InvestigationError as exc:
            outcomes.append(exc.code)

    thread = threading.Thread(target=_run)
    started = time.monotonic()
    thread.start()
    time.sleep(0.2)
    cancel.set()
    thread.join(timeout=30)
    assert outcomes == ["cancelled"]
    assert time.monotonic() - started < 5.0


def test_repeated_timeouts_recover_worker_capacity(env):
    for _ in range(3):
        with pytest.raises(InvestigationError):
            _investigate(env, IgnoringAdapter(delay_s=0.25), timeout_s=0.02)
    result = _investigate(env, FakeProvider(script=_direct_answer()))
    assert result.answer_text == "Done."


def test_oversized_tool_list_rejected_before_execution(env):
    calls = tuple(ToolCall(name="get_summary", arguments={"limit": 1}) for _ in range(20))
    fake = FakeProvider(
        script=[ProviderResponse(text="", input_tokens=10, output_tokens=5, tool_calls=calls)]
    )
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(env, fake)
    assert excinfo.value.code == "tool_limit_reached"
    assert budget.lifetime_micro_usd(env["db"]) > 0


def test_aggregate_history_bound_is_safe_error(env):
    calls = tuple(ToolCall(name="get_summary", arguments={"limit": 100}) for _ in range(8))
    script = [
        ProviderResponse(text="", input_tokens=10, output_tokens=5, tool_calls=calls)
        for _ in range(6)
    ]
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(env, FakeProvider(script=script))
    assert excinfo.value.code == "output_limit_reached"


def test_malformed_response_shape_rejected(env):
    class BadShape(ProviderAdapter):
        name = "bad"

        def complete(self, request, *, cancel):
            return ProviderResponse(text=123, input_tokens=-5, output_tokens=0)

    with pytest.raises(InvestigationError) as excinfo:
        _investigate(env, BadShape())
    assert excinfo.value.code == "invalid_response"


def test_inflated_usage_declarations_rejected(env):
    from app.ai.service import MAX_OUTPUT_TOKENS

    oversized = FakeProvider(
        script=[ProviderResponse(text="rich", input_tokens=10, output_tokens=MAX_OUTPUT_TOKENS + 1)]
    )
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(env, oversized)
    assert excinfo.value.code == "invalid_response"
    inflated = FakeProvider(
        script=[ProviderResponse(text="rich", input_tokens=10**9, output_tokens=5)]
    )
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(env, inflated)
    assert excinfo.value.code == "invalid_response"


def test_per_step_budget_stops_growth_near_cap(env):
    cap_usd = 0.0015
    env["settings"].llm_daily_limit_usd = cap_usd
    env["settings"].llm_stop_at_usd = cap_usd
    env["settings"].llm_budget_usd = cap_usd
    env["settings"].llm_warn_at_usd = 0.001
    calls = (ToolCall(name="get_summary", arguments={"limit": 5}),)
    script = [
        ProviderResponse(text="", input_tokens=1500, output_tokens=2048, tool_calls=calls)
        for _ in range(6)
    ]
    fake = FakeProvider(script=script)
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(env, fake)
    assert excinfo.value.code == "budget_reached"
    # Growth stopped before dispatching the full script, and measured
    # spend never exceeded the cap.
    assert len(fake.outgoing) < 6
    assert 0 < budget.lifetime_micro_usd(env["db"]) <= budget.usd_to_micro(cap_usd)


def test_unknown_usage_preserves_full_step_hold(env):
    step_prompts = []

    class FailSecond(FakeProvider):
        def complete(self, request, *, cancel):
            step_prompts.append(request.prompt_text)
            if len(step_prompts) == 2:
                raise ProviderError("billable work of unknown size")
            return super().complete(request, cancel=cancel)

    script = [
        ProviderResponse(
            text="",
            input_tokens=1500,
            output_tokens=2048,
            tool_calls=(ToolCall(name="get_summary", arguments={"limit": 5}),),
        )
    ]
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(env, FailSecond(script=script))
    assert excinfo.value.code == "provider_unavailable"
    from app.ai.service import (
        MAX_OUTPUT_TOKENS,
        estimate_input_tokens_upper,
        estimate_micro_usd,
    )

    first_step_actual = estimate_micro_usd(1500, 2048)
    second_step_hold = estimate_micro_usd(
        estimate_input_tokens_upper(step_prompts[1]), MAX_OUTPUT_TOKENS
    )
    assert budget.lifetime_micro_usd(env["db"]) == first_step_actual + second_step_hold


def test_unknown_site_has_no_dispatch_or_reservation(env):
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(env, FakeProvider(script=_direct_answer()), site_id="no-such-site")
    assert excinfo.value.code in ("unknown_site", "invalid_request", "forbidden_site")
    assert budget.lifetime_micro_usd(env["db"]) == 0


def test_reversed_window_has_no_dispatch_or_reservation(env):
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(env, FakeProvider(script=_direct_answer()), time_from=TO, time_to=FROM)
    assert excinfo.value.code == "invalid_request"
    assert budget.lifetime_micro_usd(env["db"]) == 0


DAY1 = datetime(2026, 10, 31, 23, 59, 59, tzinfo=UTC)
DAY2 = datetime(2026, 11, 1, 0, 0, 1, tzinfo=UTC)


def _clock(*moments):
    ticks = list(moments)

    def _tick():
        return ticks.pop(0) if len(ticks) > 1 else ticks[0]

    return _tick


def _seed_charge(db, *, day, amount_micro):
    big = 10**12
    reservation, _ = budget.reserve(
        db,
        day=day,
        amount_micro_usd=amount_micro,
        daily_limit_micro_usd=big,
        stop_micro_usd=big,
        total_micro_usd=big,
        warn_micro_usd=big,
        investigation_id="seed",
    )
    budget.charge(db, reservation_id=reservation, actual_micro_usd=amount_micro)


def test_rollover_into_exhausted_next_day_blocks_second_dispatch(env):
    _seed_charge(env["db"], day="2026-11-01", amount_micro=1000)
    env["settings"].llm_daily_limit_usd = 0.001
    calls = (ToolCall(name="get_summary", arguments={"limit": 5}),)
    script = [
        ProviderResponse(text="", input_tokens=10, output_tokens=5, tool_calls=calls),
        ProviderResponse(text="", input_tokens=10, output_tokens=5, tool_calls=calls),
    ]
    fake = FakeProvider(script=script)
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(env, fake, now=DAY1, clock=_clock(DAY1, DAY2))
    assert excinfo.value.code == "budget_reached"
    assert len(fake.outgoing) == 1
    assert budget.outstanding_micro_usd(env["db"], day="2026-11-01") == 1000
    assert budget.outstanding_micro_usd(env["db"], day="2026-10-31") > 0


def test_rollover_into_available_next_day_charges_each_day(env):
    calls = (ToolCall(name="get_summary", arguments={"limit": 5}),)
    script = [
        ProviderResponse(text="", input_tokens=10, output_tokens=5, tool_calls=calls),
        ProviderResponse(text="Across midnight.", input_tokens=10, output_tokens=5),
    ]
    result = _investigate(env, FakeProvider(script=script), now=DAY1, clock=_clock(DAY1, DAY2))
    assert result.answer_text == "Across midnight."
    assert result.observation_time == DAY1.isoformat()
    assert budget.outstanding_micro_usd(env["db"], day="2026-10-31") > 0
    assert budget.outstanding_micro_usd(env["db"], day="2026-11-01") > 0


def test_lifetime_stop_survives_rollover(env):
    _seed_charge(env["db"], day="2026-10-30", amount_micro=1000)
    env["settings"].llm_stop_at_usd = 0.002
    env["settings"].llm_warn_at_usd = 0.001
    calls = (ToolCall(name="get_summary", arguments={"limit": 5}),)
    script = [
        ProviderResponse(text="", input_tokens=1500, output_tokens=2048, tool_calls=calls)
        for _ in range(3)
    ]
    fake = FakeProvider(script=script)
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(env, fake, now=DAY1, clock=_clock(DAY1, DAY2, DAY2))
    assert excinfo.value.code == "budget_reached"
    assert len(fake.outgoing) == 2
    assert budget.outstanding_micro_usd(env["db"], day="2026-10-31") > 0
    assert budget.outstanding_micro_usd(env["db"], day="2026-11-01") > 0
    assert budget.lifetime_micro_usd(env["db"]) == 1000 + 2 * 355


def test_non_admin_actor_rejected_without_dispatch(env):
    intruder = Actor(kind="token", username="bearer", session_id="-")
    fake = FakeProvider(script=_direct_answer())
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(env, fake, actor=intruder)
    assert excinfo.value.code == "forbidden_actor"
    assert fake.outgoing == []
    assert budget.lifetime_micro_usd(env["db"]) == 0


def _login(client):
    response = client.post(
        "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
    )
    assert response.status_code == 200
    return response.json()["csrf_token"]


def _chat_body(**overrides):
    body = {
        "question": "What claimed crawler activity is visible?",
        "site_id": "default",
        "time_from": FROM.isoformat(),
        "time_to": TO.isoformat(),
    }
    body.update(overrides)
    return body


def test_chat_ask_route_aligned(env, monkeypatch):
    from app.main import create_app

    fake = FakeProvider(script=_direct_answer("Aligned answer."))
    monkeypatch.setenv("AI_ENABLED", "true")
    monkeypatch.setenv("MODEL_DATA_POLICY_VERIFIED", "true")
    monkeypatch.setenv("MODEL_ALLOW_REAL_DATA", "true")
    monkeypatch.setenv("LLM_DAILY_LIMIT_USD", "50")
    monkeypatch.setattr("app.ai.service.select_provider", lambda settings: fake)
    client = TestClient(create_app(db_path=env["db"], secure_cookies=False))
    csrf = _login(client)
    response = client.post("/api/v1/chat/ask", json=_chat_body(), headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    assert response.json()["answer"] == "Aligned answer."
    assert client.post("/api/v1/admin/chat", json=_chat_body()).status_code == 404


def test_chat_scope_validated_before_work(env, monkeypatch):
    from app.main import create_app

    fake = FakeProvider(script=_direct_answer())
    monkeypatch.setenv("AI_ENABLED", "true")
    monkeypatch.setenv("MODEL_DATA_POLICY_VERIFIED", "true")
    monkeypatch.setenv("MODEL_ALLOW_REAL_DATA", "true")
    monkeypatch.setenv("LLM_DAILY_LIMIT_USD", "50")
    monkeypatch.setattr("app.ai.service.select_provider", lambda settings: fake)
    client = TestClient(create_app(db_path=env["db"], secure_cookies=False))
    csrf = _login(client)
    headers = {"X-CSRF-Token": csrf}
    bad_window = client.post(
        "/api/v1/chat/ask",
        json=_chat_body(time_from=TO.isoformat(), time_to=FROM.isoformat()),
        headers=headers,
    )
    assert bad_window.status_code == 400
    unknown_site = client.post(
        "/api/v1/chat/ask", json=_chat_body(site_id="no-such-site"), headers=headers
    )
    assert unknown_site.status_code in (400, 403, 404)
    assert fake.outgoing == []
    assert budget.lifetime_micro_usd(env["db"]) == 0


def test_unavailable_ai_import_keeps_deterministic_api(env, monkeypatch):
    monkeypatch.setitem(sys.modules, "app.ai.service", None)
    monkeypatch.setitem(sys.modules, "app.ai.tools.definitions", None)
    monkeypatch.setenv("AI_ENABLED", "true")
    from app.main import create_app

    client = TestClient(create_app(db_path=env["db"], secure_cookies=False))
    assert client.get("/healthz").status_code == 200
    response = client.get(
        "/api/v1/summary",
        params={"site_id": "default", "from": FROM.isoformat(), "to": TO.isoformat()},
        headers={"Authorization": f"Bearer {env['token']}"},
    )
    assert response.status_code == 200
    assert response.json()["totals"]["requests"] == 10
    response = client.post(
        "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
    )
    csrf = response.json()["csrf_token"]
    chat = client.post("/api/v1/chat/ask", json=_chat_body(), headers={"X-CSRF-Token": csrf})
    assert chat.status_code == 503
    assert chat.json()["code"] == "ai_unavailable"
