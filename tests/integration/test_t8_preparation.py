"""T8 preparation integration: hand-derived fixture cases, exact replay.

One site, one configured source, one combined synthetic fixture with
three explicit UTC windows. All expectations were counted by hand
from tests/fixtures/combined/t8_smoke.txt. Mocked transport only:
no key file, no network.
"""

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from app.ai import budget
from app.ai import egress as egress_mod
from app.ai import smoke as smoke_mod
from app.ai.providers.meta_responses import MetaResponsesAdapter
from app.ai.service import Actor, run_investigation
from app.ai.tools.definitions import execute_tool
from app.analytics.rules import load_rules
from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user
from app.config import Settings
from app.db.database import connect, writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.sources import SourceConfig
from app.web import routes as web_routes
from app.web.evidence import evidence_url

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "combined" / "t8_smoke.txt"
HMAC_KEY = b"synthetic-test-hmac-key"
ACTOR = Actor(kind="admin", username="admin", session_id="t8")

WIN_A = (datetime(2026, 10, 26, 10, 0, tzinfo=UTC), datetime(2026, 10, 26, 11, 0, tzinfo=UTC))
WIN_B = (datetime(2026, 10, 27, 14, 0, tzinfo=UTC), datetime(2026, 10, 27, 15, 0, tzinfo=UTC))
WIN_C = (datetime(2026, 10, 28, 9, 0, tzinfo=UTC), datetime(2026, 10, 28, 10, 0, tzinfo=UTC))

ENDPOINT = "https://api.meta.ai/v1/responses"


def _seed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes(FIXTURE.read_bytes())
    db = tmp_path / "t8.sqlite3"
    migrate(db)
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
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
    return db


def _bot_rules():
    return load_rules(ROOT / "config" / "bot_rules.yaml").rules


def _all_rules():
    return _bot_rules() + load_rules(ROOT / "config" / "security_rules.yaml").rules


def _args(window, **matchers):
    time_from, time_to = window
    return {
        "site_id": "default",
        "time_from": time_from.isoformat(),
        "time_to": time_to.isoformat(),
        **matchers,
    }


def test_case_a_ai_crawler_families(tmp_path, monkeypatch):
    db = _seed(tmp_path, monkeypatch)
    conn = connect(db, read_only=True)
    try:
        envelope = execute_tool(
            conn,
            _bot_rules(),
            name="get_crawler_claims",
            arguments=_args(WIN_A),
            tool_call_id="tc-a",
        )
    finally:
        conn.close()
    items = envelope["result"]["items"]
    assert envelope["result"]["total"] == 2
    by_rule = {item["rule_id"]: item for item in items}
    assert by_rule["bot-ai-gpt"]["counts"] == {"requests": 7, "distinct_agents": 1}
    assert by_rule["bot-ai-claude"]["counts"] == {"requests": 2, "distinct_agents": 1}
    assert "claims" in by_rule["bot-ai-gpt"]["meaning"].lower()


def test_case_b_missing_pages_and_referrers(tmp_path, monkeypatch):
    db = _seed(tmp_path, monkeypatch)
    conn = connect(db, read_only=True)
    try:
        errors = execute_tool(
            conn,
            _all_rules(),
            name="get_error_groups",
            arguments=_args(WIN_B),
            tool_call_id="tc-b1",
        )
        referrers = execute_tool(
            conn,
            _all_rules(),
            name="get_top_referrers",
            arguments=_args(WIN_B),
            tool_call_id="tc-b2",
        )
    finally:
        conn.close()
    assert errors["result"]["total_groups"] == 1
    group = errors["result"]["items"][0]
    assert group == {
        "path": "/docs/missing-page",
        "status": 404,
        "requests": 5,
        "referrers": 2,
    }
    by_host = {row["referer_host"]: row for row in referrers["result"]["items"]}
    assert by_host["blog.example.org"]["requests"] == 3
    assert by_host["docs.example.org"]["requests"] == 2


def test_case_c_exactly_two_findings(tmp_path, monkeypatch):
    db = _seed(tmp_path, monkeypatch)
    conn = connect(db, read_only=True)
    try:
        envelope = execute_tool(
            conn,
            _all_rules(),
            name="get_security_findings",
            arguments=_args(WIN_C),
            tool_call_id="tc-c",
        )
        options = execute_tool(
            conn,
            _all_rules(),
            name="get_summary",
            arguments=_args(WIN_C, method="OPTIONS"),
            tool_call_id="tc-c2",
        )
        lower = execute_tool(
            conn,
            _all_rules(),
            name="get_summary",
            arguments=_args(WIN_C, method="options"),
            tool_call_id="tc-c3",
        )
        star = execute_tool(
            conn,
            _all_rules(),
            name="get_summary",
            arguments=_args(WIN_C, path_prefix="*"),
            tool_call_id="tc-c4",
        )
        mixed = execute_tool(
            conn,
            _all_rules(),
            name="get_summary",
            arguments=_args(WIN_C, referer_host="Example.ORG"),
            tool_call_id="tc-c5",
        )
    finally:
        conn.close()
    items = envelope["result"]["items"]
    assert envelope["result"]["total"] == 2
    by_rule = {item["rule_id"]: item for item in items}
    assert by_rule["sec-sensitive-path"]["counts"] == {"requests": 2, "distinct_paths": 2}
    assert by_rule["sec-repeated-client-errors"]["counts"]["errors"] == 5
    assert options["result"]["totals"]["requests"] == 1
    assert lower["result"]["totals"]["requests"] == 0
    assert star["result"]["totals"]["requests"] == 1
    assert mixed["result"]["totals"]["requests"] == 0


def test_exact_replay_preserves_valid_values():
    """Tool filters replay verbatim through evidence URLs into web parsing."""
    matchers, error = web_routes._parse_matchers(
        {"method": "get", "path_prefix": "*", "referer_host": "Example.ORG", "status": "404"}
    )
    assert error is None
    assert matchers == {
        "method": "get",
        "status": 404,
        "path_prefix": "*",
        "referer_host": "Example.ORG",
    }
    matchers, error = web_routes._parse_matchers({"method": "OPTIONS"})
    assert error is None and matchers["method"] == "OPTIONS"
    _, error = web_routes._parse_matchers({"path_prefix": "noslash"})
    assert error == "error.bad_params"
    link = evidence_url(
        "/errors",
        {
            "site_id": "default",
            "time_from": WIN_C[0].isoformat(),
            "time_to": WIN_C[1].isoformat(),
            "method": "get",
            "path_prefix": "*",
            "referer_host": "Example.ORG",
            "limit": 20,
            "offset": 0,
        },
    )
    assert "method=get" in link and "path_prefix=%2A" in link
    assert "referer_host=Example.ORG" in link


def test_web_replays_exact_filters_without_folding(tmp_path, monkeypatch):
    db = _seed(tmp_path, monkeypatch)
    from app.main import create_app

    client = TestClient(create_app(db_path=db, secure_cookies=False), raise_server_exceptions=False)
    login = client.post("/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"})
    assert login.status_code == 200
    window_qs = (
        "range=custom&from=2026-10-28T09%3A00%3A00%2B00%3A00&to=2026-10-28T10%3A00%3A00%2B00%3A00"
    )
    base = f"/errors?site=default&{window_qs}&tz=UTC"
    lower = client.get(base + "&method=get")
    assert lower.status_code == 200
    assert "method=get" in lower.text
    upper = client.get(base + "&method=GET")
    assert upper.status_code == 200
    star = client.get(base + "&path_prefix=%2A")
    assert star.status_code == 200
    mixed = client.get(base + "&referer_host=Example.ORG")
    assert mixed.status_code == 200
    assert "referer_host=Example.ORG" in mixed.text
    bad = client.get(base + "&path_prefix=noslash")
    assert bad.status_code == 400


class MockTransport:
    """Mocked Responses server: bounded simulated usage, recorded bodies."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def __call__(self, *, url, headers, body, timeout_s, max_response_bytes):
        assert url == "https://api.meta.ai:443/v1/responses"
        assert headers["Content-Type"] == "application/json"
        assert headers["Authorization"].startswith("Bearer ")
        payload = json.loads(body.decode("utf-8"))
        assert payload["model"] == "muse-spark-1.3"
        assert payload["store"] is False
        assert "previous_response_id" not in payload
        self.calls.append(body)
        step = self.script.pop(0) if self.script else {"text": "done"}
        output = []
        for index, call in enumerate(step.get("calls", [])):
            output.append(
                {
                    "type": "function_call",
                    "name": call,
                    "arguments": '{"limit": 10}',
                    "call_id": f"call_{len(self.calls)}_{index}",
                    "status": "completed",
                }
            )
        if step.get("text") is not None:
            output.append(
                {"type": "message", "content": [{"type": "output_text", "text": step["text"]}]}
            )
        return {
            "id": f"resp_{len(self.calls)}",
            "model": "muse-spark-1.3",
            "status": "completed",
            "output": output,
            "usage": {
                "input_tokens": min(len(body), 60000),
                "output_tokens": 25,
                "total_tokens": min(len(body), 60000) + 25,
                "input_tokens_details": {"cached_tokens": 0},
                "output_tokens_details": {"reasoning_tokens": 5},
            },
        }


def _settings():
    return Settings(
        ai_enabled=True,
        model_data_policy_verified=True,
        model_allow_real_data=True,
        model_endpoint=ENDPOINT,
        llm_daily_limit_usd=50.0,
        llm_budget_usd=150.0,
        llm_warn_at_usd=120.0,
        llm_stop_at_usd=140.0,
    )


def test_mocked_real_investigation_correlates_and_settles(tmp_path, monkeypatch):
    db = _seed(tmp_path, monkeypatch)
    transport = MockTransport(
        [
            {"calls": ["get_security_findings"]},
            {"text": "Two candidate findings are visible with rule references."},
        ]
    )
    provider = MetaResponsesAdapter(
        endpoint=ENDPOINT,
        model="muse-spark-1.3",
        api_key="synthetic-test-key",
        transport=transport,
    )
    result = run_investigation(
        db_path=db,
        rules=_all_rules(),
        settings=_settings(),
        provider=provider,
        actor=ACTOR,
        question="Which suspicious request patterns are visible?",
        site_id="default",
        source_id=None,
        time_from=WIN_C[0],
        time_to=WIN_C[1],
        smoke_enforced=True,
    )
    assert result.provider == "meta-responses"
    assert result.tool_calls == 1
    assert len(result.evidence) == 1
    assert result.evidence[0]["tool"] == "get_security_findings"
    assert result.usage["pricing_version"] == "2026-10-31-dev.meta.ai"
    assert result.usage["cached_tokens"] == 0
    assert result.usage["reasoning_tokens"] == 10
    # Reservation covers reasoning inside MAX_OUTPUT at the output rate;
    # per-step integer ceiling keeps the charge conservative (>= combined).
    from app.ai import budget as budget_mod
    from app.ai.providers.meta_responses import cost_micro_usd

    combined = cost_micro_usd(
        input_tokens=result.usage["input_tokens"],
        cached_tokens=0,
        output_tokens=result.usage["output_tokens"],
    )
    assert result.usage["estimated_cost_usd"] >= budget_mod.micro_to_usd(combined)
    assert result.usage["estimated_cost_usd"] > 0
    assert result.response_ids == ["resp_1", "resp_2"]
    assert result.usage["response_ids"] == ["resp_1", "resp_2"]
    assert result.provider_calls == [
        {
            "tool_call_id": result.evidence[0]["tool_call_id"],
            "call_id": "call_1_0",
            "tool": "get_security_findings",
        }
    ]
    # Stateless correlation: the second dispatch replays the first
    # turn's call_id in a paired function_call_output item.
    assert len(transport.calls) == 2
    replay = json.loads(transport.calls[1].decode("utf-8"))
    kinds = [item["type"] for item in replay["input"]]
    assert "function_call" in kinds and "function_call_output" in kinds
    call_ids = [i["call_id"] for i in replay["input"] if i["type"] == "function_call"]
    out_ids = [i["call_id"] for i in replay["input"] if i["type"] == "function_call_output"]
    assert call_ids == ["call_1_0"] == out_ids
    # Minimized wire: user text is question + scope only (no history
    # duplication), so the tool result replays exactly once overall.
    user_text = replay["input"][0]["content"][0]["text"]
    assert "Which suspicious request patterns are visible?" in user_text
    assert "Tool " not in user_text and "sec-sensitive-path" not in user_text
    assert transport.calls[1].decode("utf-8").count("sec-sensitive-path") == 1
    state = smoke_mod.init_or_check(
        db, max_investigations=3, max_requests=12, max_micro_usd=budget.usd_to_micro(1.0)
    )
    assert state["used_investigations"] == 1
    assert state["used_requests"] == 2
    assert state["used_micro_usd"] > 0


def test_wire_values_reject_escaped_bypass_and_bounds():
    line = '198.51.100.9 - - [27/Oct/2026:12:05:00 +0100] "GET / HTTP/1.1" 200 12 "-" "evil/1.0"'
    # Decoded validation sees through JSON escaping: the escaped form
    # would scan differently, the decoded value still fails closed.
    with pytest.raises(egress_mod.EgressViolation):
        egress_mod.check_wire_values({"output": line}, context="t")
    with pytest.raises(egress_mod.EgressViolation):
        egress_mod.check_wire_values({"a": ["ok", {"b": line}]}, context="t")
    egress_mod.check_wire_values(
        {"model": "muse-spark-1.3", "n": 3, "ok": True, "nothing": None}, context="t"
    )
    with pytest.raises(egress_mod.EgressViolation):
        egress_mod.check_wire_values(b"bytes-are-not-text", context="t")
    with pytest.raises(egress_mod.EgressViolation):
        egress_mod.check_wire_values(["ok"] * (egress_mod.MAX_WIRE_VALUES + 1), context="t")


def test_plain_answer_guard_is_static_and_safe():
    html = (ROOT / "app" / "web" / "templates" / "pages" / "ask.html").read_text()
    assert 'data-ask-answer class="ask-answer' in html
    css = (ROOT / "app" / "web" / "static" / "app.css").read_text()
    assert ".ask-answer" in css and "pre-wrap" in css and "overflow-wrap" in css
    js = (ROOT / "app" / "web" / "static" / "js" / "ask.js").read_text()
    assert "textContent" in js and "innerHTML" not in js


def _load_runner():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "smoke_meta", str(ROOT / "scripts" / "smoke_meta.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_dry_run_proves_zero_key_access_and_network():
    assert _load_runner().main([]) == 0


class EntryStub:
    """Alternating summary-call/final-answer stub for the entry test."""

    def __init__(self):
        self.calls = []

    def __call__(self, *, url, headers, body, timeout_s, max_response_bytes):
        assert url == "https://api.meta.ai:443/v1/responses"
        assert headers["Authorization"].startswith("Bearer ")
        payload = json.loads(body.decode("utf-8"))
        assert payload["model"] == "muse-spark-1.3"
        assert payload["store"] is False
        turn = len(self.calls)
        self.calls.append(body)
        if turn % 2 == 0:
            output = [
                {
                    "type": "function_call",
                    "name": "get_summary",
                    "arguments": '{"limit": 5}',
                    "call_id": f"entry_{turn}",
                    "status": "completed",
                }
            ]
        else:
            output = [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": "Synthetic case answer."}],
                }
            ]
        return {
            "id": f"resp_entry_{turn}",
            "model": "muse-spark-1.3",
            "status": "completed",
            "output": output,
            "usage": {
                "input_tokens": min(len(body), 60000),
                "output_tokens": 20,
                "total_tokens": min(len(body), 60000) + 20,
                "input_tokens_details": {"cached_tokens": 0},
                "output_tokens_details": {"reasoning_tokens": 3},
            },
        }


def _entry_env(monkeypatch, **overrides):
    monkeypatch.setenv("AI_ENABLED", "true")
    monkeypatch.setenv("MODEL_DATA_POLICY_VERIFIED", "true")
    monkeypatch.setenv("MODEL_ALLOW_REAL_DATA", "true")
    monkeypatch.setenv("MODEL_ENDPOINT", ENDPOINT)
    monkeypatch.setenv("LLM_DAILY_LIMIT_USD", "50.0")
    monkeypatch.setenv("LLM_BUDGET_USD", "150.0")
    monkeypatch.setenv("LLM_WARN_AT_USD", "120.0")
    monkeypatch.setenv("LLM_STOP_AT_USD", "140.0")
    for key, value in overrides.items():
        monkeypatch.setenv(key, value)


def test_real_run_entry_offline_with_temporary_fake_key(tmp_path, monkeypatch):
    """R6/R7: the real-run ENTRY works offline on a stub; owner key untouched."""
    import argparse

    module = _load_runner()
    _entry_env(monkeypatch)
    key_file = tmp_path / "fake.key"
    key_file.write_text("temporary-fake-key-never-real\n")
    args = argparse.Namespace(
        db=str(tmp_path / "entry.sqlite3"),
        ledger=str(tmp_path / "ledger.jsonl"),
        results=str(tmp_path / "results.jsonl"),
        staging=str(tmp_path / "staging-logs"),
        key_file=str(key_file),
        endpoint=ENDPOINT,
    )
    stub = EntryStub()
    assert module.real_run(args, transport=stub) == 0
    assert len(stub.calls) == 6
    ledger = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    results = [json.loads(line) for line in (tmp_path / "results.jsonl").read_text().splitlines()]
    assert [entry["status"] for entry in ledger] == ["completed"] * 3
    assert all(entry["tool_calls"] == 1 for entry in ledger)
    allowed_ledger_keys = {
        "case",
        "status",
        "model",
        "input_tokens",
        "output_tokens",
        "cached_tokens",
        "reasoning_tokens",
        "tool_calls",
        "response_ids",
        "estimated_cost_usd",
        "duration_s",
        "observation_time",
    }
    assert all(set(entry) <= allowed_ledger_keys for entry in ledger)
    for item in results:
        assert item["status"] == "completed"
        assert item["answer"] == "Synthetic case answer."
        assert item["tool_calls"] == 1 and len(item["evidence"]) == 1
        assert item["evidence"][0]["tool"] == "get_summary"
        assert "input_text" not in json.dumps(item)
        assert "function_call_output" not in json.dumps(item)
    blob = (tmp_path / "ledger.jsonl").read_text() + (tmp_path / "results.jsonl").read_text()
    assert "temporary-fake-key-never-real" not in blob
    state = smoke_mod.init_or_check(
        tmp_path / "entry.sqlite3",
        max_investigations=3,
        max_requests=12,
        max_micro_usd=budget.usd_to_micro(1.0),
    )
    assert state["used_investigations"] == 3 and state["used_requests"] == 6


def test_real_run_refuses_foreign_dataset(tmp_path, monkeypatch):
    import argparse

    from app.db.importer import run_import as run_import_db
    from app.db.migrations_runner import migrate as migrate_db
    from app.ingestion.sources import SourceConfig as SourceConfigDb

    module = _load_runner()
    _entry_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "access.log").write_bytes(
        (ROOT / "tests" / "fixtures" / "combined" / "nginx_combined.txt").read_bytes()
    )
    db = tmp_path / "foreign.sqlite3"
    migrate_db(db)
    run_import_db(
        db,
        source=SourceConfigDb(
            source_id="example-combined",
            format_id="nginx_combined",
            allowed_root=logs,
            relative_path="access.log",
        ),
        site_id="default",
        site_name="s",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="access.log",
        hmac_key=HMAC_KEY,
    )
    key_file = tmp_path / "fake.key"
    key_file.write_text("temporary-fake-key-never-real\n")
    args = argparse.Namespace(
        db=str(db),
        ledger=str(tmp_path / "ledger.jsonl"),
        results=str(tmp_path / "results.jsonl"),
        staging=str(tmp_path / "staging-logs"),
        key_file=str(key_file),
        endpoint=ENDPOINT,
    )
    stub = EntryStub()
    assert module.real_run(args, transport=stub) == 2
    assert stub.calls == []
    assert not (tmp_path / "ledger.jsonl").exists()


def test_real_run_honors_blocking_operator_config(tmp_path, monkeypatch):
    import argparse

    module = _load_runner()
    _entry_env(monkeypatch, MODEL_ALLOW_REAL_DATA="false")
    args = argparse.Namespace(
        db=str(tmp_path / "entry.sqlite3"),
        ledger=str(tmp_path / "ledger.jsonl"),
        results=str(tmp_path / "results.jsonl"),
        staging=str(tmp_path / "staging-logs"),
        key_file=str(tmp_path / "missing.key"),
        endpoint=ENDPOINT,
    )
    assert module.real_run(args, transport=EntryStub()) == 2


def _preflight_rules():
    from app.analytics.rules import load_rules

    return (
        load_rules(ROOT / "config" / "bot_rules.yaml").rules
        + load_rules(ROOT / "config" / "security_rules.yaml").rules
    )


def test_preflight_refuses_existing_staging_sentinel(tmp_path):
    """Probe 1: an existing staging file is never truncated; refused."""
    import hashlib

    module = _load_runner()
    staging = tmp_path / "staging"
    staging.mkdir()
    sentinel = staging / "access.log"
    sentinel.write_bytes(b"SYNTHETIC SOURCE SENTINEL DO NOT OVERWRITE\n")
    before = hashlib.sha256(sentinel.read_bytes()).hexdigest()
    with pytest.raises(module.PreflightError):
        module.preflight(tmp_path / "new.sqlite3", staging, _preflight_rules(), b"synthetic-hmac")
    assert hashlib.sha256(sentinel.read_bytes()).hexdigest() == before
    assert not (tmp_path / "new.sqlite3").exists()


def test_preflight_staging_symlink_target_unchanged(tmp_path):
    """A symlinked staging source and its target are refused untouched."""
    module = _load_runner()
    staging = tmp_path / "staging"
    staging.mkdir()
    target = tmp_path / "target.log"
    target.write_bytes(b"SYNTHETIC SYMLINK TARGET DO NOT TOUCH\n")
    link = staging / "access.log"
    link.symlink_to(target)
    with pytest.raises(module.PreflightError):
        module.preflight(tmp_path / "new.sqlite3", staging, _preflight_rules(), b"synthetic-hmac")
    assert link.is_symlink() and os.readlink(link) == str(target)
    assert target.read_bytes() == b"SYNTHETIC SYMLINK TARGET DO NOT TOUCH\n"
    assert not (tmp_path / "new.sqlite3").exists()


def test_preflight_reuses_byte_exact_fixture(tmp_path):
    """Known fixture bytes seed once and reuse safely across restarts."""
    module = _load_runner()
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "access.log").write_bytes(FIXTURE.read_bytes())
    db = tmp_path / "reuse.sqlite3"
    info = module.preflight(db, staging, _preflight_rules(), b"synthetic-hmac")
    assert info == {"rows": 30, "windows": [12, 10, 8]}
    assert (staging / "access.log").read_bytes() == FIXTURE.read_bytes()
    again = module.preflight(db, staging, _preflight_rules(), b"synthetic-hmac")
    assert again == info
    assert (staging / "access.log").read_bytes() == FIXTURE.read_bytes()


def test_preflight_rejects_aggregate_equivalent_foreign_db(tmp_path, monkeypatch):
    """Probe 2: same counts/aggregates from a foreign file are refused."""
    import hashlib

    from app.db.importer import run_import
    from app.db.migrations_runner import migrate
    from app.ingestion.sources import SourceConfig

    module = _load_runner()
    monkeypatch.chdir(tmp_path)
    raw = FIXTURE.read_bytes()
    altered = raw.replace(
        b"GET /blog/ HTTP/1.1", b"GET /foreign-private-synthetic-sentinel HTTP/1.1", 1
    )
    assert altered != raw and hashlib.sha256(altered).hexdigest() != hashlib.sha256(raw).hexdigest()
    (tmp_path / "foreign.log").write_bytes(altered)
    db = tmp_path / "foreign.sqlite3"
    migrate(db)
    run_import(
        db,
        source=SourceConfig(
            source_id="example-combined",
            format_id="nginx_combined",
            allowed_root=tmp_path,
            relative_path="foreign.log",
        ),
        site_id="default",
        site_name="s",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="foreign.log",
        hmac_key=b"synthetic-hmac",
    )
    rows_before = _request_count(db)
    with pytest.raises(module.PreflightError):
        module.preflight(db, tmp_path / "other-staging", _preflight_rules(), b"synthetic-hmac")
    assert not (tmp_path / "other-staging").exists()
    assert _request_count(db) == rows_before == 30


def _request_count(db):
    conn = connect(db, read_only=True)
    try:
        return conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
    finally:
        conn.close()


def test_outputs_refuse_symlink_collision_and_preexisting(tmp_path):
    """R7 outputs: 0600 owned creation; symlinks/collisions/pre-existing refused."""
    import os
    import stat as stat_mod

    module = _load_runner()
    owned: set = set()
    protected = {os.path.abspath(tmp_path / "key")}
    fresh = tmp_path / "fresh.jsonl"
    module._append_owned(fresh, {"a": 1}, owned=owned, protected=protected)
    assert stat_mod.S_IMODE(os.stat(fresh).st_mode) == 0o600
    module._append_owned(fresh, {"a": 2}, owned=owned, protected=protected)
    assert len(fresh.read_text().splitlines()) == 2
    with pytest.raises(module.OutputRefused):
        module._claim_output(fresh, owned=set(), protected=protected)
    link = tmp_path / "link.jsonl"
    link.symlink_to(fresh)
    with pytest.raises(module.OutputRefused):
        module._claim_output(link, owned=set(), protected=protected)
    with pytest.raises(module.OutputRefused):
        module._claim_output(tmp_path / "key", owned=set(), protected=protected)


def test_real_run_refuses_preexisting_ledger_before_dispatch(tmp_path, monkeypatch):
    import argparse

    module = _load_runner()
    _entry_env(monkeypatch)
    key_file = tmp_path / "fake.key"
    key_file.write_text("temporary-fake-key-never-real\n")
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("ACTUAL LEDGER SENTINEL\n")
    args = argparse.Namespace(
        db=str(tmp_path / "entry.sqlite3"),
        ledger=str(ledger),
        results=str(tmp_path / "results.jsonl"),
        staging=str(tmp_path / "staging-logs"),
        key_file=str(key_file),
        endpoint=ENDPOINT,
    )
    stub = EntryStub()
    assert module.real_run(args, transport=stub) == 2
    assert stub.calls == []
    assert ledger.read_text() == "ACTUAL LEDGER SENTINEL\n"
    assert not (tmp_path / "results.jsonl").exists()
