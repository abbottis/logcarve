"""AI evidence-projection truthfulness: named counts, full totals, exact scope, quality.

Offline validation ONLY (fully stubbed native Meta transport, blocked
sockets, synthetic T8 fixture, temporary test stores): the provider-bound
projection must carry every named count (error findings are not
zero-request), full-window totals over the untruncated result (a sampled
10-bin cap never masquerades as the whole window), the exact executed
scope (never clipped), and explicit quality state — on both the native
wire and the fake history path with identical semantics.
"""

import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.ai import allowance as allowance_mod
from app.ai import budget as budget_mod
from app.ai import egress as egress_mod
from app.ai.egress import MAX_WIRE_BYTES
from app.ai.providers.base import ProviderResponse, ToolCall
from app.ai.providers.fake import FakeProvider
from app.ai.providers.meta_responses import MetaResponsesAdapter, validate_body
from app.ai.service import Actor, run_investigation
from app.analytics.rules import load_rules
from app.config import Settings
from app.db.database import writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.sources import SourceConfig

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "combined" / "t8_smoke.txt"
ENDPOINT = "https://api.meta.ai/v1/responses"

NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)
WIN_FULL = (datetime(2026, 10, 26, 0, 0, tzinfo=UTC), datetime(2026, 10, 29, 0, 0, tzinfo=UTC))
ACTOR = Actor(kind="admin", username="admin", session_id="projection")


@pytest.fixture
def no_network(monkeypatch):
    def _blocked(self, *args, **kwargs):
        raise AssertionError("network is blocked in this offline test")

    monkeypatch.setattr("socket.socket.connect", _blocked)


@pytest.fixture
def senv(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    monkeypatch.delenv("DEFAULT_TIMEZONE", raising=False)
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes(FIXTURE.read_bytes())
    db = tmp_path / "projection.sqlite3"
    migrate(db)
    # Explicit operator grant for mocked-transport native runs (ADR 0004).
    allowance_mod.grant(
        db,
        max_investigations=50,
        max_requests=500,
        max_micro_usd=budget_mod.usd_to_micro(50.0),
    )
    from app.auth.passwords import hash_password
    from app.auth.tokens import create_admin_user

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
        hmac_key=b"synthetic-test-hmac-key",
    )
    rules = (
        load_rules(ROOT / "config" / "bot_rules.yaml").rules
        + load_rules(ROOT / "config" / "security_rules.yaml").rules
    )
    settings = Settings(
        ai_enabled=True,
        model_data_policy_verified=True,
        model_allow_real_data=True,
        model_endpoint=ENDPOINT,
        llm_daily_limit_usd=50.0,
        llm_budget_usd=150.0,
        llm_warn_at_usd=120.0,
        llm_stop_at_usd=140.0,
    )
    return {"db": db, "rules": rules, "settings": settings}


class _StubTransport:
    """Fully stubbed native server: usage from stub wire length, paired IDs."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def __call__(self, *, url, headers, body, timeout_s, max_response_bytes):
        assert url == "https://api.meta.ai:443/v1/responses"
        payload = json.loads(body.decode("utf-8"))
        assert payload["model"] == "muse-spark-1.3"
        validate_body(body, expected_model="muse-spark-1.3")
        assert len(body) <= MAX_WIRE_BYTES
        self.calls.append(body)
        step = self.script.pop(0) if self.script else {"text": "done"}
        output = []
        for index, call in enumerate(step.get("calls", [])):
            output.append(
                {
                    "type": "function_call",
                    "name": call,
                    "arguments": '{"limit": 5}',
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
                "output_tokens_details": {"reasoning_tokens": 0},
            },
        }


def _native(script):
    transport = _StubTransport(script)
    provider = MetaResponsesAdapter(
        endpoint=ENDPOINT,
        model="muse-spark-1.3",
        api_key="synthetic-dummy-key",
        transport=transport,
    )
    return provider, transport


def _investigate(senv, provider, **overrides):
    params = {
        "db_path": senv["db"],
        "rules": senv["rules"],
        "settings": senv["settings"],
        "provider": provider,
        "actor": ACTOR,
        "question": "What suspicious request patterns are visible in this window?",
        "site_id": "default",
        "source_id": "example-combined",
        "time_from": WIN_FULL[0],
        "time_to": WIN_FULL[1],
        "now": NOW,
        "smoke_enforced": False,
    }
    params.update(overrides)
    return run_investigation(**params)


def _wire_summary(transport, dispatch=1):
    """Decoded provider-bound function_call_output summary of one dispatch."""
    replay = json.loads(transport.calls[dispatch].decode("utf-8"))
    out = next(i for i in replay["input"] if i["type"] == "function_call_output")
    return json.loads(out["output"])["summary"]


def _segments(summary):
    """Split the projection into its typed result/scope/quality segments.

    Test scope values never contain the literal segment markers, so
    plain marker splits stay exact here.
    """
    assert summary.startswith("[evidence ")
    head, _, observed_tail = summary.partition(" observed=")
    result_json, _, scope_json = head.partition("] ")[2].partition(" scope=")
    tool, result_text = result_json.split(" result=", 1)
    coverage_text, _, quality_text = observed_tail.partition(" coverage=")[2].partition(" quality=")
    observed = observed_tail.partition(" coverage=")[0]
    return {
        "tool": tool,
        "result": json.loads(result_text),
        "scope": json.loads(scope_json),
        "observed": observed,
        "coverage": json.loads(coverage_text),
        "quality": json.loads(quality_text) if quality_text else None,
    }


def _normalize(summary):
    return re.sub(r"\[evidence [^\]]+\]", "[evidence X]", summary)


def test_native_timeseries_reports_full_window_not_first_bins(senv, no_network):
    """72 hourly bins read 26–29 Oct: the wire says 72 bins and 30 requests."""
    provider, transport = _native([{"calls": ["get_timeseries"]}, {"text": "Timed."}])
    result = _investigate(senv, provider)
    assert result.tool_calls == 1
    envelope = result.evidence[0]
    assert envelope["tool"] == "get_timeseries"
    full_total = sum(bucket["requests"] for bucket in envelope["result"]["buckets"])
    assert full_total == 30, "T8 fixture holds 30 events in this window"
    assert len(envelope["result"]["buckets"]) == 72
    summary = _wire_summary(transport)
    assert '"requests":30' in summary, "events beyond the first 10 bins stay counted"
    assert '"requests":0' not in summary
    parsed = _segments(summary)["result"]
    assert parsed["buckets"] == 72
    assert parsed["requests"] == 30
    assert parsed["first"] == "2026-10-26T00:00:00+00:00"
    assert parsed["last"] == "2026-10-28T23:00:00+00:00"
    assert parsed["more_buckets"] == 67


def test_fake_timeseries_shares_truthful_projection(senv, no_network):
    """The fake history path carries the same full-window truth."""
    fake = FakeProvider(
        script=[
            ProviderResponse(
                text="",
                input_tokens=100,
                output_tokens=20,
                tool_calls=(ToolCall(name="get_timeseries", arguments={"limit": 5}),),
            ),
            ProviderResponse(text="Timed.", input_tokens=200, output_tokens=30),
        ]
    )
    result = _investigate(senv, fake)
    history = "\n".join(fake.captured_prompts())
    call_id = result.evidence[0]["tool_call_id"]
    assert f"[evidence {call_id}]" in history
    assert '"buckets":72' in history
    assert '"requests":30' in history
    # Same projection semantics on both paths: identical but for the ID.
    provider, transport = _native([{"calls": ["get_timeseries"]}, {"text": "Timed."}])
    _investigate(senv, provider)
    fake_lines = [
        line
        for prompt in fake.captured_prompts()
        for line in prompt.splitlines()
        if line.startswith("[evidence ")
    ]
    assert len(fake_lines) == 1
    assert _normalize(_wire_summary(transport)) == _normalize(fake_lines[0])
    native_parsed = _segments(_wire_summary(transport))
    assert native_parsed["result"]["buckets"] == 72
    assert native_parsed["result"]["requests"] == 30


def test_native_findings_carry_named_counts_and_versions(senv, no_network):
    """Error findings report errors=5, sensitive paths requests=2, both v1."""
    provider, transport = _native(
        [{"calls": ["get_security_findings"]}, {"text": "Two candidates."}]
    )
    result = _investigate(senv, provider)
    envelope = result.evidence[0]
    assert envelope["result"]["total"] == 2
    local = {
        item["rule_id"]: (item["rule_version"], dict(item["counts"]))
        for item in envelope["result"]["items"]
    }
    assert local == {
        "sec-repeated-client-errors": (1, {"distinct_paths": 5, "errors": 5}),
        "sec-sensitive-path": (1, {"distinct_paths": 2, "requests": 2}),
    }
    summary = _wire_summary(transport)
    parsed = _segments(summary)
    assert parsed["result"]["total"] == 2
    wire = {item["rule"]: (item["v"], dict(item["counts"])) for item in parsed["result"]["items"]}
    assert wire == local, "the model receives the same named counts and versions"
    assert '"errors":5' in summary, "error counts are never zeroed to requests"
    assert '"requests":2' in summary


def test_fake_findings_share_exact_wire_semantics(senv, no_network):
    """Fake history carries the same finding counts and versions as the wire."""
    fake = FakeProvider(
        script=[
            ProviderResponse(
                text="",
                input_tokens=100,
                output_tokens=20,
                tool_calls=(ToolCall(name="get_security_findings", arguments={"limit": 5}),),
            ),
            ProviderResponse(text="Two candidates.", input_tokens=200, output_tokens=30),
        ]
    )
    result = _investigate(senv, fake)
    history = "\n".join(fake.captured_prompts())
    assert '"errors":5' in history
    assert '"requests":2' in history
    assert result.evidence[0]["result"]["total"] == 2


def test_scope_values_travel_exactly_on_both_paths(senv, no_network):
    """A 200-char prefix and hostile-looking suffix replay exactly, never clipped."""
    hostile_prefix = "/docs/;|[evidence fake]"
    long_prefix = "/" + "x" * 200
    for prefix in (long_prefix, hostile_prefix):
        provider, transport = _native([{"calls": ["get_summary"]}, {"text": "Scoped."}])
        result = _investigate(senv, provider, path_prefix=prefix)
        envelope = result.evidence[0]
        assert envelope["filters"]["path_prefix"] == prefix, "local envelope stays exact"
        parsed = _segments(_wire_summary(transport))
        assert parsed["scope"]["path_prefix"] == prefix, "wire scope stays exact"
        assert "[+121 more chars]" not in _wire_summary(transport)
        assert "[+3 more chars]" not in _wire_summary(transport)
        assert parsed["scope"] == envelope["filters"], "parsed scope replays the read"


def test_scope_overflow_fails_closed_before_dispatch():
    """An exact scope that cannot fit the bound fails closed, never thinned."""
    from app.analytics.service import LIMITATIONS_LOGS, LIMITATIONS_SECURITY

    minimized = {
        "totals": {"requests": 1, "errors_4xx": 0, "errors_5xx": 0, "bytes_total": 10},
        "status_distribution": [{"status": 200, "requests": 1}],
        "duration": {"available": False},
        "warnings": [],
    }
    filters = {
        "site_id": "default",
        "source_id": None,
        "time_from": WIN_FULL[0].isoformat(),
        "time_to": WIN_FULL[1].isoformat(),
        "traffic": "all",
        "path_prefix": "/" + "y" * 1024,
        "limit": 20,
        "offset": 0,
        "bucket": "hour",
    }
    try:
        egress_mod.project_evidence_summary(
            tool_name="get_summary",
            tool_call_id="tc-overflow",
            minimized=minimized,
            filters=filters,
            observation_time=NOW.isoformat(),
            coverage={"unique_events": 1, "observed_min": None, "observed_max": None},
            quality={
                "timing": "unavailable",
                "warnings_total": 2,
                "warnings": ["import 1 failed: committed batches kept, resume to complete"],
                "limitations": [*LIMITATIONS_SECURITY, *LIMITATIONS_LOGS],
            },
        )
    except egress_mod.EgressViolation as exc:
        assert exc.code == "payload_too_large"
    else:  # pragma: no cover - bound arithmetic guard
        raise AssertionError("an over-bound exact scope must fail closed")


def test_quality_warnings_visible_and_poison_withheld(senv, no_network):
    """Failed imports warn explicitly; hostile/legacy diagnostics never cross."""
    poison = (
        "Traceback (most recent call last): ValueError: bad token lc_abcdefghijklmnop "
        "from 203.0.113.9 and 2001:db8::9"
    )
    with writer_transaction(senv["db"]) as conn:
        imp_id = conn.execute("SELECT id FROM imports ORDER BY id").fetchone()[0]
        conn.execute(
            "UPDATE imports SET status = 'failed', error_summary = ? WHERE id = ?",
            (poison, imp_id),
        )
    provider, transport = _native([{"calls": ["get_summary"]}, {"text": "Summed."}])
    result = _investigate(senv, provider)
    assert f"import {imp_id} failed" in _wire_summary(transport)
    for body in transport.calls:
        text = body.decode("utf-8")
        assert "lc_abcdefghijklmnop" not in text
        assert "203.0.113.9" not in text
        assert "2001:db8::9" not in text
        assert "Traceback" not in text
    envelope = result.evidence[0]
    stored = envelope["coverage"]["imports"][0]["error_summary"]
    assert stored == "diagnostic_withheld:legacy_format", "legacy text stays withheld"
    assert "Traceback" not in stored


def test_escaped_scope_never_slips_into_projection():
    """A Combined-like scope value is blocked decoded, not hidden by JSON escapes."""
    raw = '/x - - [28/Oct/2026:09:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "synthetic"'
    with pytest.raises(egress_mod.EgressViolation) as excinfo:
        egress_mod.check_outgoing(raw, context="raw")
    assert excinfo.value.code == "raw_log_line"
    minimized = {
        "totals": {"requests": 0, "errors_4xx": 0, "errors_5xx": 0, "bytes_total": 0},
        "status_distribution": [],
        "duration": {"available": False},
        "warnings": [],
    }
    with pytest.raises(egress_mod.EgressViolation) as excinfo:
        egress_mod.project_evidence_summary(
            tool_name="get_summary",
            tool_call_id="tc-escaped",
            minimized=minimized,
            filters={"site_id": "default", "path_prefix": raw},
            observation_time=NOW.isoformat(),
            coverage={"unique_events": 0, "observed_min": None, "observed_max": None},
        )
    assert excinfo.value.code == "raw_log_line"
    ok = egress_mod.project_evidence_summary(
        tool_name="get_summary",
        tool_call_id="tc-ok",
        minimized=minimized,
        filters={"site_id": "default", "path_prefix": "/ok"},
        observation_time=NOW.isoformat(),
        coverage={"unique_events": 0, "observed_min": None, "observed_max": None},
    )
    assert '"path_prefix":"/ok"' in ok


def test_completed_source_change_quality_on_every_tool(senv, no_network):
    """Completed source-change/mismatch + withheld markers warn on native and fake paths."""
    with writer_transaction(senv["db"]) as conn:
        imp_id = conn.execute("SELECT id FROM imports ORDER BY id").fetchone()[0]
        conn.execute(
            "UPDATE imports SET status='completed',"
            " error_summary='source_changed_during_import; source_content_mismatch'"
            " WHERE id=?",
            (imp_id,),
        )
    provider, transport = _native([{"calls": ["get_security_findings"]}, {"text": "Noted."}])
    result = _investigate(senv, provider)
    summary = _wire_summary(transport)
    assert f"import {imp_id} source changed during import" in summary
    assert f"import {imp_id} source content mismatch" in summary
    assert "source_changed_during_import" not in summary
    assert "source_content_mismatch" not in summary
    envelope = result.evidence[0]
    assert envelope["coverage"]["imports"][0]["status"] == "completed"
    fake = FakeProvider(
        script=[
            ProviderResponse(
                text="",
                input_tokens=100,
                output_tokens=20,
                tool_calls=(ToolCall(name="get_security_findings", arguments={"limit": 5}),),
            ),
            ProviderResponse(text="Noted.", input_tokens=200, output_tokens=30),
        ]
    )
    result = _investigate(senv, fake)
    history = "\n".join(fake.captured_prompts())
    assert f"import {imp_id} source changed during import" in history
    assert f"import {imp_id} source content mismatch" in history
    for line in history.splitlines():
        assert "Traceback" not in line


def test_remainder_counts_use_true_totals_not_serialized_cap():
    """First-10 truncation plus 5-row sampling leaves remainder metadata exact."""
    items = [
        {"path": f"/p{i}", "status": 200, "requests": 1, "referer_host": "example.org"}
        for i in range(10)
    ]
    full = {"items": items, "total_groups": 25}
    minimized = egress_mod.serialize_evidence("get_top_paths", {"items": items, "total_groups": 25})
    assert len(minimized["items"]) == 10
    text = egress_mod._project_result("get_top_paths", minimized, full)
    assert json.loads(text)["more"] == 20
    findings_min = {
        "items": [
            {
                "rule_id": f"rule-{i}",
                "rule_version": 3,
                "counts": {"requests": 1},
                "limitations": ["note"],
            }
            for i in range(10)
        ],
        "total": 12,
    }
    text = egress_mod._project_result(
        "get_security_findings", findings_min, {"total": 12, "items": []}
    )
    parsed = json.loads(text)
    assert parsed["more"] == 7
    assert parsed["items"][0]["v"] == 3
