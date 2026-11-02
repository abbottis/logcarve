"""Runtime vs historical-T8 mode separation (independent review F6).

Offline ONLY (stubbed Meta transport, blocked sockets, synthetic T8
fixture, temporary stores): the explicit historical T8 entrypoint
keeps ONLY its once-only ledger limits, while normal runtime chat
requires the explicit bounded runtime grant plus the global budget.
Neither mode touches the other's counters: refused runtime calls
never mutate historical smoke counters, an exhausted historical row
never blocks a separately authorized runtime path, and no lifetime
approval is inferred from enable/save/provider switch.

This NEVER authorizes real calls: no production transport, key,
account or paid call exists here.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.ai import allowance as allowance_mod
from app.ai import budget as budget_mod
from app.ai import registry
from app.ai import smoke as smoke_mod
from app.ai.providers.meta_responses import MetaResponsesAdapter
from app.ai.service import Actor, InvestigationError, run_investigation
from app.analytics.rules import load_rules
from app.config import Settings
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.sources import SourceConfig

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "combined" / "t8_smoke.txt"

NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)
WIN_C = (datetime(2026, 10, 28, 9, 0, tzinfo=UTC), datetime(2026, 10, 28, 10, 0, tzinfo=UTC))
ACTOR = Actor(kind="admin", username="admin", session_id="modes")
MODEL = "muse-spark-1.3"
ENDPOINT = registry.endpoint_for("meta", MODEL)


@pytest.fixture
def no_network(monkeypatch):
    def _blocked(self, *args, **kwargs):
        raise AssertionError("network is blocked in this offline test")

    monkeypatch.setattr("socket.socket.connect", _blocked)


@pytest.fixture
def menv(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    monkeypatch.delenv("DEFAULT_TIMEZONE", raising=False)
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes(FIXTURE.read_bytes())
    db = tmp_path / "modes.sqlite3"
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
        hmac_key=b"synthetic-test-hmac-key",
    )
    rules = (
        load_rules(ROOT / "config" / "bot_rules.yaml").rules
        + load_rules(ROOT / "config" / "security_rules.yaml").rules
    )
    return {"db": db, "rules": rules}


def _settings():
    return Settings(
        ai_enabled=True,
        model_provider="meta",
        model_id=MODEL,
        model_service_tier="standard",
        model_data_policy_verified=True,
        model_allow_real_data=True,
        model_api_key="synthetic-test-key-never-sent",
        llm_daily_limit_usd=50.0,
        llm_budget_usd=150.0,
        llm_warn_at_usd=120.0,
        llm_stop_at_usd=140.0,
    )


def _payload(turn):
    if turn == 1:
        return {
            "id": "resp_tool",
            "model": MODEL,
            "status": "completed",
            "output": [
                {
                    "type": "function_call",
                    "name": "get_summary",
                    "arguments": '{"limit": 5}',
                    "call_id": "call_1_0",
                    "status": "completed",
                }
            ],
            "usage": {
                "input_tokens": 400,
                "output_tokens": 20,
                "total_tokens": 420,
                "input_tokens_details": {"cached_tokens": 0},
            },
        }
    return {
        "id": "resp_final",
        "model": MODEL,
        "status": "completed",
        "output": [
            {
                "type": "message",
                "content": [{"type": "output_text", "text": "Evidence-backed answer."}],
            }
        ],
        "usage": {
            "input_tokens": 600,
            "output_tokens": 20,
            "total_tokens": 620,
            "input_tokens_details": {"cached_tokens": 50},
        },
    }


def _adapter():
    seen = {"turn": 0}

    def transport(*, url, headers, body, timeout_s, max_response_bytes, max_wire_bytes=None):
        assert url == ENDPOINT
        assert headers["Authorization"].startswith("Bearer ")
        seen["turn"] += 1
        return _payload(seen["turn"])

    return MetaResponsesAdapter(
        endpoint=ENDPOINT, model=MODEL, api_key="synthetic-test-key", transport=transport
    )


def _investigate(menv, **overrides):
    params = {
        "db_path": menv["db"],
        "rules": menv["rules"],
        "settings": _settings(),
        "provider": _adapter(),
        "actor": ACTOR,
        "question": "Which suspicious request patterns are visible in this window?",
        "site_id": "default",
        "source_id": "example-combined",
        "time_from": WIN_C[0],
        "time_to": WIN_C[1],
        "now": NOW,
    }
    params.update(overrides)
    return run_investigation(**params)


def _smoke_state(db):
    return smoke_mod.init_or_check(
        db,
        max_investigations=3,
        max_requests=12,
        max_micro_usd=budget_mod.usd_to_micro(1.0),
    )


def test_refused_runtime_call_leaves_smoke_untouched(menv, no_network):
    before = _smoke_state(menv["db"])
    assert allowance_mod.status(menv["db"]) is None
    with pytest.raises(InvestigationError) as exc:
        _investigate(menv)
    assert exc.value.code == "usage_not_authorized"
    after = _smoke_state(menv["db"])
    assert after["used_investigations"] == before["used_investigations"] == 0
    assert after["used_requests"] == before["used_requests"] == 0


def test_exhausted_smoke_does_not_block_granted_runtime(menv, no_network):
    allowance_mod.grant(
        menv["db"],
        max_investigations=50,
        max_requests=500,
        max_micro_usd=budget_mod.usd_to_micro(50.0),
    )
    # Exhaust the historical once-only ledger directly.
    _smoke_state(menv["db"])
    for index in range(3):
        smoke_mod.admit_investigation(menv["db"], investigation_id=f"old-{index}")
    exhausted = _smoke_state(menv["db"])
    assert exhausted["used_investigations"] == 3
    # The separately authorized runtime path still runs: the default
    # mode touches only the runtime grant plus the global budget.
    result = _investigate(menv)
    assert result.answer_text == "Evidence-backed answer."
    after = _smoke_state(menv["db"])
    assert after["used_investigations"] == 3
    assert after["used_requests"] == 0
    grants = allowance_mod.status(menv["db"])
    assert grants["used_investigations"] == 1
    assert grants["used_requests"] == 2


def test_t8_mode_uses_only_historical_limits(menv, no_network):
    # Explicit T8 entrypoint with NO runtime grant: historical limits
    # admit the run and no grant row is created or required.
    assert allowance_mod.status(menv["db"]) is None
    result = _investigate(menv, smoke_enforced=True)
    assert result.answer_text == "Evidence-backed answer."
    assert allowance_mod.status(menv["db"]) is None
    state = _smoke_state(menv["db"])
    assert state["used_investigations"] == 1
    assert state["used_requests"] == 2


def test_t8_refusal_leaves_runtime_grant_untouched(menv, no_network):
    allowance_mod.grant(
        menv["db"],
        max_investigations=50,
        max_requests=500,
        max_micro_usd=budget_mod.usd_to_micro(50.0),
    )
    _smoke_state(menv["db"])
    for index in range(3):
        smoke_mod.admit_investigation(menv["db"], investigation_id=f"old-{index}")
    with pytest.raises(InvestigationError) as exc:
        _investigate(menv, smoke_enforced=True)
    assert exc.value.code == "budget_reached"
    grants = allowance_mod.status(menv["db"])
    assert grants["used_investigations"] == 0
    assert grants["used_requests"] == 0
    assert _smoke_state(menv["db"])["used_investigations"] == 3
