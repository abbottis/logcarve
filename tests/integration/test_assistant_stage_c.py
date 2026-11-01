"""Stage C assistant/tooling regressions: reports, selectors, snapshots.

Offline validation ONLY (fake and stubbed native-wire providers,
blocked sockets, synthetic enriched fixture, temporary test stores):
the bounded ``get_report`` aggregate surface, full selector
propagation with trusted-scope enforcement, one-snapshot tool reads
released before any provider dispatch, measured-vs-missing timing
honesty, malicious-metadata fail-closeds, evidence links, client
report/download operations and provider-failure behavior.

This NEVER labels real-AI acceptance passed: no production
transport, key, account or paid call exists here. Temporary stores
only; the real smoke allowance is never opened.
"""

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.ai import egress as egress_mod
from app.ai.egress import MAX_WIRE_BYTES
from app.ai.providers.base import ProviderError, ProviderResponse
from app.ai.providers.fake import FakeProvider
from app.ai.providers.meta_responses import MetaResponsesAdapter, validate_body
from app.ai.service import Actor, InvestigationError, run_investigation
from app.ai.tools import definitions
from app.ai.tools.definitions import REPORT_NAMES, execute_tool
from app.analytics.rules import load_rules
from app.config import Settings
from app.db.database import connect, writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.sources import SourceConfig
from app.web.evidence import envelope_href

ROOT = Path(__file__).resolve().parent.parent.parent
ENDPOINT = "https://api.meta.ai/v1/responses"

NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)
FROM = datetime(2026, 10, 27, 10, 0, tzinfo=UTC)
TO = datetime(2026, 10, 27, 11, 0, tzinfo=UTC)
PREV_FROM = datetime(2026, 10, 27, 9, 0, tzinfo=UTC)
ACTOR = Actor(kind="admin", username="admin", session_id="stage-c")
HMAC_KEY = b"stage-c-hmac-key"


def _line(ip, stamp, method, path, status, referer, ua, host, cache, rt, mime, tls, upstream):
    return (
        f"{ip} - - [{stamp} +0000] "
        f'"{method} {path} HTTP/1.1" {status} 10 "{referer}" "{ua}" '
        f'{host} {cache} {rt} {mime} {tls} "{upstream}"\n'
    ).encode()


@pytest.fixture
def cenv(tmp_path, monkeypatch):
    """Isolated enriched store: measured, zero, missing timing; bots; 404s."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    monkeypatch.delenv("DEFAULT_TIMEZONE", raising=False)
    root = tmp_path / "logs"
    root.mkdir()
    host = "example.org"
    rows = [
        # (stamp, method, path, status, referer, ua, cache, rt, mime, tls, upstream)
        (
            "27/Oct/2026:10:00:00",
            "GET",
            "/measured-fast",
            200,
            "-",
            "Browser/1.0",
            "HIT",
            "0.010",
            "text/html",
            "TLSv1.3",
            "0.005",
        ),
        (
            "27/Oct/2026:10:01:00",
            "GET",
            "/measured-zero",
            200,
            "-",
            "Browser/1.0",
            "MISS",
            "0.000",
            "text/html",
            "TLSv1.3",
            "-",
        ),
        (
            "27/Oct/2026:10:02:00",
            "GET",
            "/measured-slow",
            500,
            "-",
            "Browser/1.0",
            "-",
            "0.900",
            "application/json",
            "-",
            "-",
        ),
        (
            "27/Oct/2026:10:03:00",
            "GET",
            "/unmeasured-a",
            200,
            "-",
            "Browser/1.0",
            "HIT",
            "-",
            "text/html",
            "TLSv1.3",
            "-",
        ),
        (
            "27/Oct/2026:10:04:00",
            "GET",
            "/unmeasured-b",
            404,
            "http://example.org/start",
            "GPTBot/1.0",
            "-",
            "-",
            "-",
            "-",
            "-",
        ),
        (
            "27/Oct/2026:10:05:00",
            "GET",
            "/ai-only",
            200,
            "-",
            "GPTBot/1.0",
            "-",
            "0.050",
            "text/html",
            "-",
            "-",
        ),
        (
            "27/Oct/2026:10:06:00",
            "GET",
            "/shared",
            200,
            "-",
            "GPTBot/1.0",
            "-",
            "0.060",
            "text/html",
            "-",
            "-",
        ),
        (
            "27/Oct/2026:10:07:00",
            "GET",
            "/shared",
            200,
            "-",
            "Browser/1.0",
            "-",
            "0.070",
            "text/html",
            "-",
            "-",
        ),
        (
            "27/Oct/2026:10:08:00",
            "GET",
            "/gone",
            404,
            "https://external.example/page",
            "Browser/1.0",
            "-",
            "-",
            "-",
            "-",
            "-",
        ),
        (
            "27/Oct/2026:10:09:00",
            "GET",
            "/find?q=hunter2&token=topsecret",
            200,
            "-",
            "Browser/1.0",
            "-",
            "0.020",
            "text/html",
            "-",
            "-",
        ),
        # Rows outside the selected window: the model comparison must
        # never read them (inside-split baseline stays in-window).
        (
            "27/Oct/2026:09:30:00",
            "GET",
            "/measured-fast",
            200,
            "-",
            "Browser/1.0",
            "HIT",
            "0.020",
            "text/html",
            "TLSv1.3",
            "-",
        ),
        (
            "27/Oct/2026:09:31:00",
            "GET",
            "/measured-fast",
            200,
            "-",
            "Browser/1.0",
            "HIT",
            "0.030",
            "text/html",
            "TLSv1.3",
            "-",
        ),
    ]
    (root / "access.log").write_bytes(
        b"".join(
            _line(
                "198.51.100.7",
                stamp,
                method,
                path,
                status,
                referer,
                ua,
                host,
                cache,
                rt,
                mime,
                tls,
                upstream,
            )
            for stamp, method, path, status, referer, ua, cache, rt, mime, tls, upstream in rows
        )
    )
    db = tmp_path / "stage-c.sqlite3"
    migrate(db)
    from app.auth.passwords import hash_password
    from app.auth.tokens import create_admin_user

    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
    run_import(
        db,
        source=SourceConfig(
            source_id="enriched",
            format_id="nginx_extended",
            allowed_root=root,
            relative_path="access.log",
        ),
        site_id="default",
        site_name="s",
        site_hostname=host,
        server_type="nginx",
        path_alias="access.log",
        hmac_key=HMAC_KEY,
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


@pytest.fixture
def no_network(monkeypatch):
    def _blocked(self, *args, **kwargs):
        raise AssertionError("network is blocked in this offline test")

    monkeypatch.setattr("socket.socket.connect", _blocked)


def _args(**overrides):
    base = {"site_id": "default", "time_from": FROM.isoformat(), "time_to": TO.isoformat()}
    base.update(overrides)
    return base


def _run(cenv, name, args, **overrides):
    db, rules = cenv["db"], cenv["rules"]
    conn = connect(db, read_only=True)
    try:
        params = {"observation_time": NOW}
        params.update(overrides)
        return execute_tool(conn, rules, name=name, arguments=args, tool_call_id="tc1", **params)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Selector propagation: trusted scope wins, False/0 are real, invalid fails
# ---------------------------------------------------------------------------


def test_new_selectors_travel_to_evidence_and_links(cenv):
    envelope = _run(
        cenv,
        "get_summary",
        _args(
            path_prefix="/measured",
            path_exact="/measured-fast",
            server_host="example.org",
            http_version="HTTP/1.1",
            mime_type="text/html",
            cache_status="HIT",
            tls_protocol="TLSv1.3",
            timing_available=True,
            upstream_available=True,
            timing_min_ms=0,
            timing_max_ms=1.5,
        ),
    )
    filters = envelope["filters"]
    assert filters["path_exact"] == "/measured-fast"
    assert filters["server_host"] == "example.org"
    assert filters["http_version"] == "HTTP/1.1"
    assert filters["mime_type"] == "text/html"
    assert filters["cache_status"] == "HIT"
    assert filters["tls_protocol"] == "TLSv1.3"
    # Selected False/0 travel as real selections, never as omissions.
    assert filters["timing_available"] is True
    assert filters["upstream_available"] is True
    assert filters["timing_min_ms"] == 0
    assert filters["timing_max_ms"] == 1.5
    assert filters["timing_min_ms"] is not None
    href = envelope_href("get_summary", filters, "UTC")
    assert href is not None and href.startswith("/?")
    for fragment in (
        "path_exact=%2Fmeasured-fast",
        "server_host=example.org",
        "timing_available=True",
        "timing_min_ms=0",
    ):
        assert fragment in href, fragment


def test_selected_false_and_zero_are_real_selections(cenv):
    envelope = _run(cenv, "get_summary", _args(timing_available=False, timing_min_ms=0))
    assert envelope["filters"]["timing_available"] is False
    assert envelope["filters"]["timing_min_ms"] == 0
    # timing_available=False keeps only the unmeasured rows.
    assert envelope["result"]["duration"] == {
        "available": False,
        "measured": 0,
        "reason": "no_measured_request_timing",
    }
    envelope = _run(cenv, "get_summary", _args(timing_available=True))
    assert envelope["result"]["duration"]["available"] is True
    assert envelope["result"]["duration"]["measured"] == 7


def test_contradictory_and_invalid_selectors_fail_safely(cenv):
    from app.ai.tools.definitions import ToolError

    with pytest.raises(ToolError) as excinfo:
        _run(cenv, "get_summary", _args(path_prefix="/other", path_exact="/measured-fast"))
    assert excinfo.value.code == "invalid_arguments"
    with pytest.raises(ToolError) as excinfo:
        _run(cenv, "get_summary", _args(timing_min_ms=2.0, timing_max_ms=1.0))
    assert excinfo.value.code == "invalid_arguments"
    with pytest.raises(ToolError) as excinfo:
        _run(cenv, "get_summary", _args(report="performance"))
    assert excinfo.value.code == "invalid_arguments"  # unknown field, never ignored
    with pytest.raises(ToolError) as excinfo:
        _run(cenv, "get_report", _args())
    assert excinfo.value.code == "invalid_arguments"  # report is required
    with pytest.raises(ToolError) as excinfo:
        _run(cenv, "get_report", _args(report="timelines"))
    assert excinfo.value.code == "invalid_arguments"
    with pytest.raises(ToolError) as excinfo:
        _run(cenv, "get_report", _args(report="performance", timing_available="maybe"))
    assert excinfo.value.code == "invalid_arguments"


# ---------------------------------------------------------------------------
# One snapshot per tool read, released before any provider dispatch
# ---------------------------------------------------------------------------


def test_tool_read_holds_one_snapshot_across_queries(cenv, monkeypatch):
    """A writer committing mid-read cannot split aggregates from coverage."""
    from app.analytics import queries as queries_mod

    before = _run(cenv, "get_summary", _args())["result"]["totals"]["requests"]
    assert before == 10
    committed = {"done": False}

    def commit_late_write():
        with writer_transaction(cenv["db"]) as wconn:
            scope = wconn.execute(
                "SELECT import_id, site_id, source_id, file_fingerprint FROM requests LIMIT 1"
            ).fetchone()
            base = wconn.execute("SELECT COALESCE(MAX(byte_offset), 0) FROM requests").fetchone()[0]
            wconn.execute(
                "INSERT INTO requests (import_id, site_id, source_id, file_fingerprint,"
                " byte_offset, line_number, ts_utc, method, path, status, bytes,"
                " referer_host, user_agent, client_pseudonym)"
                " VALUES (?, ?, ?, ?, ?, ?, '2026-10-27T10:30:00+00:00', 'GET',"
                " '/late-write', 200, 10, NULL, 'Browser/1.0', 'late-pseudo')",
                (scope[0], scope[1], scope[2], scope[3], base + 1, base + 1),
            )

    real_coverage = queries_mod.coverage

    def hooked(conn, filt, clf):
        # The aggregate reads above already established the snapshot;
        # this writer commit lands strictly between aggregates and
        # coverage, exactly the split-generation hazard.
        if not committed["done"]:
            committed["done"] = True
            commit_late_write()
        return real_coverage(conn, filt, clf)

    monkeypatch.setattr(queries_mod, "coverage", hooked)
    envelope = _run(cenv, "get_summary", _args())
    assert committed["done"]
    # Same snapshot: the committed row stays invisible to every query.
    assert envelope["result"]["totals"]["requests"] == before
    assert envelope["coverage"]["unique_events"] == before


def test_no_read_transaction_open_during_provider_dispatch(cenv, monkeypatch, no_network):
    """Tool connections are closed before the provider is ever awaited."""
    import app.ai.service as service_mod

    opened = []
    real_connect = service_mod.connect

    def tracking_connect(*args, **kwargs):
        conn = real_connect(*args, **kwargs)
        opened.append(conn)
        return conn

    monkeypatch.setattr(service_mod, "connect", tracking_connect)

    class AssertingFake(FakeProvider):
        def complete(self, request, *, cancel):
            assert opened, "expected at least the tool connection to have been opened"
            for conn in opened:
                with pytest.raises(sqlite3.ProgrammingError):
                    conn.execute("SELECT 1")
            return super().complete(request, cancel=cancel)

    script = [
        ProviderResponse(
            text="",
            input_tokens=10,
            output_tokens=5,
            tool_calls=(
                {
                    "name": "get_report",
                    "arguments": {"limit": 5, "report": "performance"},
                    "call_id": "call_1",
                },
            ),
        ),
        ProviderResponse(text="Performance is available.", input_tokens=10, output_tokens=5),
    ]
    result = run_investigation(
        db_path=cenv["db"],
        rules=cenv["rules"],
        settings=cenv["settings"],
        provider=AssertingFake(script=script),
        actor=ACTOR,
        question="Is request timing measured in this window?",
        site_id="default",
        source_id="enriched",
        time_from=FROM,
        time_to=TO,
        now=NOW,
        smoke_enforced=False,
    )
    assert result.tool_calls == 1
    assert result.evidence[0]["tool"] == "get_report"
    assert result.evidence[0]["filters"]["report"] == "performance"


# ---------------------------------------------------------------------------
# Reports: shared layer, bounded projection, honest timing
# ---------------------------------------------------------------------------


def test_report_names_are_allowlisted_and_bounded():
    assert set(REPORT_NAMES) == {
        "performance",
        "slow_endpoints",
        "seo_redirects",
        "seo_client_errors",
        "seo_server_errors",
        "seo_ai_only",
        "referrer_404s",
        "journeys",
        "journey_entries",
        "comparison",
    }
    assert "get_report" in definitions.TOOL_NAMES
    assert len(definitions.TOOL_NAMES) == 8
    for raw in ("timelines", "requests", "export", "sql", "shell", ""):
        with pytest.raises(ValidationError):
            definitions.ReportArguments(
                site_id="default",
                time_from=FROM,
                time_to=TO,
                report=raw,
            )


def test_performance_report_carries_measured_timing(cenv):
    envelope = _run(cenv, "get_report", _args(report="performance"))
    result = envelope["result"]
    assert result["latency_available"] is True
    assert result["latency_ms"]["measured"] == 7
    assert result["latency_ms"]["missing"] == 3
    assert result["latency_ms"]["min_ms"] == 0.0  # zero is measured, never missing
    assert result["latency_ms"]["p50_ms"] is not None
    assert result["units"] == "milliseconds"
    assert envelope["filters"]["report"] == "performance"
    minimized = egress_mod.serialize_evidence("get_report", result)
    assert minimized["latency_available"] is True
    assert minimized["latency_ms"]["measured"] == 7
    summary = egress_mod.project_evidence_summary(
        tool_name="get_report",
        tool_call_id="tc1",
        minimized=minimized,
        filters=envelope["filters"],
        observation_time=envelope["observation_time"],
        coverage=envelope["coverage"],
        full_result=result,
    )
    assert '"latency_available":true' in summary
    assert '"measured":7' in summary
    assert "unavailable" not in summary.split('"latency_available"')[0]


def test_combined_scope_reports_unavailable_timing_without_zero(cenv):
    envelope = _run(cenv, "get_report", _args(report="performance", timing_available=False))
    result = envelope["result"]
    assert result["latency_available"] is False
    assert result["latency_ms"]["measured"] == 0
    assert result["latency_ms"]["p50_ms"] is None
    assert result["latency_ms"]["average_ms"] is None
    minimized = egress_mod.serialize_evidence("get_report", result)
    summary = egress_mod.project_evidence_summary(
        tool_name="get_report",
        tool_call_id="tc1",
        minimized=minimized,
        filters=envelope["filters"],
        observation_time=envelope["observation_time"],
        coverage=envelope["coverage"],
        full_result=result,
    )
    assert '"latency_available":false' in summary
    assert '"p50_ms":null' in summary
    assert '"average_ms":null' in summary


def test_slow_endpoints_report_exact_totals_and_bounded_sample(cenv):
    envelope = _run(cenv, "get_report", _args(report="slow_endpoints"))
    result = envelope["result"]
    assert result["total_paths"] == 6  # six distinct measured paths
    assert result["meta"]["candidate_paths"] == 6
    assert result["meta"]["ranking"] == "avg_desc"
    assert result["limit"] == 20 and result["offset"] == 0
    minimized = egress_mod.serialize_evidence("get_report", result)
    summary = egress_mod.project_evidence_summary(
        tool_name="get_report",
        tool_call_id="tc1",
        minimized=minimized,
        filters=envelope["filters"],
        observation_time=envelope["observation_time"],
        coverage=envelope["coverage"],
        full_result=result,
    )
    data = json.loads(summary.split("result=", 1)[1].split(" scope=", 1)[0])
    assert data["paths"] == 6
    assert data["more"] == max(0, 6 - len(data["top"]))
    assert data["top"][0]["p95_ms"] is None or isinstance(data["top"][0]["p95_ms"], float)


def test_seo_reports_share_deterministic_layer(cenv):
    from app.analytics import service as service_mod
    from app.db.database import connect as _connect

    conn = _connect(cenv["db"], read_only=True)
    try:
        from app.analytics.contracts import AnalyticsFilter, TimeWindow

        filt = AnalyticsFilter(
            site_id="default",
            window=TimeWindow(time_from=FROM, time_to=TO),
            limit=20,
            offset=0,
        )
        for report, status_class in (
            ("seo_redirects", "3xx"),
            ("seo_client_errors", "4xx"),
            ("seo_server_errors", "5xx"),
        ):
            envelope = _run(cenv, "get_report", _args(report=report))
            expected = service_mod.seo_status_groups(
                conn, filt, cenv["rules"], status_class=status_class
            )
            assert envelope["result"]["items"] == expected["items"]
            assert envelope["result"]["total_groups"] == expected["total_groups"]
    finally:
        conn.close()
    envelope = _run(cenv, "get_report", _args(report="seo_client_errors"))
    assert envelope["result"]["status_class"] == "4xx"
    assert envelope["result"]["total_groups"] >= 1
    minimized = egress_mod.serialize_evidence("get_report", envelope["result"])
    item = minimized["items"][0]
    assert set(item) <= {
        "path",
        "status_class",
        "rule_id",
        "category",
        "provider",
        "purpose",
        "requests",
        "bytes_total",
        "drilldown",
    }


def test_seo_ai_only_stays_in_scope(cenv):
    envelope = _run(cenv, "get_report", _args(report="seo_ai_only"))
    result = envelope["result"]
    assert result["comparison"]["selectors_removed"] == []
    assert result["vacuous"] is False
    assert result["total_paths"] >= 1
    paths = [item["path"] for item in result["items"]]
    assert "/ai-only" in paths
    assert "/shared" not in paths  # shared with browser traffic: never AI-only
    assert envelope["filters"]["site_id"] == "default"


def test_referrer_404s_labels_relations(cenv):
    envelope = _run(cenv, "get_report", _args(report="referrer_404s"))
    result = envelope["result"]
    assert result["total_groups"] == 2
    assert result["relation"] == "all"
    by_host = {item["referer_host"]: item for item in result["items"]}
    assert by_host["example.org"]["internal"] is True
    assert by_host["external.example"]["internal"] is False
    assert by_host["external.example"]["target_path"] == "/gone"


def test_journey_reports_are_aggregates_only(cenv):
    envelope = _run(cenv, "get_report", _args(report="journeys"))
    result = envelope["result"]
    assert result["total_groups"] >= 1
    assert result["gap_definition"].startswith("new journey when the gap")
    first = result["items"][0]
    assert set(first) >= {"entry_path", "requests_total", "requests_shown", "completeness"}
    assert "user_agent" not in first
    entries = _run(cenv, "get_report", _args(report="journey_entries"))["result"]
    assert entries["total_groups"] >= 1
    assert set(entries["items"][0]) == {
        "entry_path",
        "journeys",
        "complete_journeys",
        "partial_journeys",
    }
    assert entries["partial_caveat"].startswith("partial journeys may start")
    # Timelines have no tool: raw per-request dumps cannot cross.
    assert "journey_timeline" not in REPORT_NAMES
    assert "get_requests" not in definitions.TOOL_NAMES
    assert "export" not in " ".join(REPORT_NAMES)


def test_comparison_reads_inside_split_windows(cenv):
    envelope = _run(cenv, "get_report", _args(report="comparison"))
    result = envelope["result"]
    mid = FROM + (TO - FROM) / 2
    assert result["previous_window"] == {
        "time_from": FROM.isoformat(),
        "time_to": mid.isoformat(),
    }
    assert result["current_window"] == {
        "time_from": mid.isoformat(),
        "time_to": TO.isoformat(),
    }
    assert result["parent_window"] == {
        "time_from": FROM.isoformat(),
        "time_to": TO.isoformat(),
    }
    assert "inside" in result["definition"] and "never outside" in result["definition"]
    assert result["selectors"]["traffic"] == "all"
    assert result["filters"]["current"]["site_id"] == "default"
    names = [metric["name"] for metric in result["metrics"]]
    assert "requests" in names
    minimized = egress_mod.serialize_evidence("get_report", result)
    summary = egress_mod.project_evidence_summary(
        tool_name="get_report",
        tool_call_id="tc1",
        minimized=minimized,
        filters=envelope["filters"],
        observation_time=envelope["observation_time"],
        coverage={},
        full_result=result,
    )
    assert FROM.isoformat() in summary  # baseline start is explicit, never invented
    assert mid.isoformat() in summary  # current start is explicit, never invented
    assert "definition" in summary


# ---------------------------------------------------------------------------
# Investigations: scope enforcement, widening attempts, replay, failure
# ---------------------------------------------------------------------------


def _answer_script(*calls):
    return [
        ProviderResponse(text="", input_tokens=10, output_tokens=5, tool_calls=tuple(calls)),
        ProviderResponse(text="Scoped answer.", input_tokens=10, output_tokens=5),
    ]


def _investigate(cenv, provider, **overrides):
    params = {
        "db_path": cenv["db"],
        "rules": cenv["rules"],
        "settings": cenv["settings"],
        "provider": provider,
        "actor": ACTOR,
        "question": "What performance and crawler patterns are visible?",
        "site_id": "default",
        "source_id": "enriched",
        "time_from": FROM,
        "time_to": TO,
        "now": NOW,
        "smoke_enforced": False,
    }
    params.update(overrides)
    return run_investigation(**params)


def test_investigation_scope_overrides_hostile_model_args(cenv, no_network):
    from app.ai.providers.base import ToolCall

    fake = FakeProvider(
        script=_answer_script(
            ToolCall(
                name="get_report",
                arguments={
                    "limit": 5,
                    "report": "comparison",
                    "site_id": "other",
                    "time_from": "2020-01-01T00:00:00+00:00",
                    "time_to": "2020-01-02T00:00:00+00:00",
                    "path_exact": "/elsewhere",
                    "timing_available": False,
                    "timing_min_ms": 99.0,
                },
            )
        )
    )
    result = _investigate(
        cenv,
        fake,
        path_prefix="/measured",
        path_exact="/measured-fast",
        timing_available=True,
        timing_min_ms=0,
    )
    filters = result.evidence[0]["filters"]
    assert filters["site_id"] == "default"
    assert filters["source_id"] == "enriched"
    assert filters["time_from"] == FROM.isoformat()
    assert filters["time_to"] == TO.isoformat()
    assert filters["path_prefix"] == "/measured"
    assert filters["path_exact"] == "/measured-fast"
    assert filters["timing_available"] is True
    assert filters["timing_min_ms"] == 0
    # The comparison baseline stays server-derived inside the trusted
    # window: never model history, never outside the selected scope.
    mid = FROM + (TO - FROM) / 2
    assert result.evidence[0]["result"]["previous_window"]["time_from"] == FROM.isoformat()
    assert result.evidence[0]["result"]["previous_window"]["time_to"] == mid.isoformat()
    assert result.evidence[0]["result"]["current_window"]["time_from"] == mid.isoformat()
    assert result.evidence[0]["result"]["current_window"]["time_to"] == TO.isoformat()


def test_investigation_rejects_contradictory_scope_before_dispatch(cenv, no_network):
    fake = FakeProvider(script=[])
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(cenv, fake, path_prefix="/other", path_exact="/measured-fast")
    assert excinfo.value.code == "invalid_request"
    assert fake.outgoing == []
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(cenv, fake, timing_min_ms=5.0, timing_max_ms=1.0)
    assert excinfo.value.code == "invalid_request"
    assert fake.outgoing == []


def test_evidence_replay_crosses_egress_with_ids_and_bounds(cenv, no_network):
    from app.ai.providers.base import ToolCall

    fake = FakeProvider(
        script=_answer_script(
            ToolCall(name="get_report", arguments={"limit": 5, "report": "seo_client_errors"})
        )
    )
    result = _investigate(cenv, fake)
    assert len(fake.outgoing) == 2
    assert "[evidence" in fake.outgoing[1].prompt_text
    assert result.evidence[0]["tool_call_id"] in fake.outgoing[1].prompt_text
    assert result.evidence[0]["observation_time"] == NOW.isoformat()
    assert len(fake.outgoing[1].prompt_text) <= egress_mod.MAX_OUTGOING_CHARS
    href = envelope_href("get_report", result.evidence[0]["filters"], "UTC")
    assert href is not None and href.startswith("/errors?")
    assert "report=seo_client_errors" in href
    assert envelope_href("get_report", {"report": "timelines"}, "UTC").startswith("/?")
    assert envelope_href("get_unknown_tool", {}, "UTC") is None
    perf_href = envelope_href(
        "get_report", {**result.evidence[0]["filters"], "report": "performance"}, "UTC"
    )
    assert perf_href is not None and perf_href.startswith("/?")


def test_provider_failure_preserves_deterministic_api(cenv, no_network):
    from app.analytics import service as service_mod
    from app.analytics.contracts import AnalyticsFilter, TimeWindow

    fake = FakeProvider(script=[], fail_with=ProviderError("boom"))
    with pytest.raises(InvestigationError) as excinfo:
        _investigate(cenv, fake)
    assert excinfo.value.code == "provider_unavailable"
    conn = connect(cenv["db"], read_only=True)
    try:
        filt = AnalyticsFilter(site_id="default", window=TimeWindow(time_from=FROM, time_to=TO))
        assert service_mod.summarize(conn, filt, cenv["rules"])["totals"]["requests"] == 10
    finally:
        conn.close()


def test_corrupt_store_fails_tool_safely(tmp_path):
    db = tmp_path / "empty.sqlite3"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE unrelated (id INTEGER)")
    conn.commit()
    conn.close()
    conn = connect(db, read_only=True)
    try:
        with pytest.raises(Exception) as excinfo:
            execute_tool(
                conn,
                [],
                name="get_report",
                arguments=_args(report="performance"),
                tool_call_id="tc1",
            )
        assert getattr(excinfo.value, "code", "") == "store_unavailable"
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Native-wire scripted provider: same evidence, byte-capped, socket-free
# ---------------------------------------------------------------------------


class StubTransport:
    """Fully stubbed native server: paired IDs, validated byte-capped bodies."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def __call__(self, *, url, headers, body, timeout_s, max_response_bytes):
        assert url == "https://api.meta.ai:443/v1/responses"
        assert headers["Authorization"].startswith("Bearer ")
        validate_body(body, expected_model="muse-spark-1.3")
        assert len(body) <= MAX_WIRE_BYTES
        self.calls.append(body)
        step = self.script.pop(0) if self.script else {"text": "done"}
        output = []
        for index, call in enumerate(step.get("calls", [])):
            output.append(
                {
                    "type": "function_call",
                    "name": call[0],
                    "arguments": call[1],
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


def _native(script):
    transport = StubTransport(script)
    provider = MetaResponsesAdapter(
        endpoint=ENDPOINT,
        model="muse-spark-1.3",
        api_key="synthetic-dummy-key",
        transport=transport,
    )
    return provider, transport


def test_native_wire_report_replay_and_pairing(cenv, no_network):
    provider, transport = _native(
        [
            {"calls": [("get_report", '{"limit": 5, "report": "slow_endpoints"}')]},
            {"text": "Slow endpoints listed with rule references."},
        ]
    )
    result = _investigate(cenv, provider)
    assert result.tool_calls == 1
    assert result.provider == "meta-responses"
    assert result.response_ids == ["resp_1", "resp_2"]
    assert result.provider_calls == [
        {
            "tool_call_id": result.evidence[0]["tool_call_id"],
            "call_id": "call_1_0",
            "tool": "get_report",
        }
    ]
    assert len(transport.calls) == 2
    replay = json.loads(transport.calls[1].decode("utf-8"))
    kinds = [item["type"] for item in replay["input"]]
    assert kinds.count("function_call") == 1
    assert kinds.count("function_call_output") == 1
    out = next(i for i in replay["input"] if i["type"] == "function_call_output")
    wire_output = json.loads(out["output"])
    assert wire_output["tool_call_id"] == result.evidence[0]["tool_call_id"]
    assert "slow_endpoints" in wire_output["summary"]
    assert "198.51.100" not in wire_output["summary"]  # original IPs never cross
    assert "hunter2" not in wire_output["summary"]  # query values never cross


def test_native_wire_timing_evidence_is_measured_not_hardcoded(cenv, no_network):
    provider, transport = _native(
        [
            {"calls": [("get_report", '{"limit": 5, "report": "performance"}')]},
            {"text": "Timing is measured."},
        ]
    )
    result = _investigate(cenv, provider)
    summary = result.evidence[0]  # local envelope stays server-side
    assert summary["result"]["latency_available"] is True
    assert summary["result"]["latency_ms"]["measured"] == 7
    replay = json.loads(transport.calls[1].decode("utf-8"))
    out = next(i for i in replay["input"] if i["type"] == "function_call_output")
    wire_output = json.loads(out["output"])
    assert '"latency_available":true' in wire_output["summary"]
    assert '"measured":7' in wire_output["summary"]
    assert "Combined" not in wire_output["summary"]


# ---------------------------------------------------------------------------
# Sentinels: original IPs, keys, query secrets never cross; poison fails safe
# ---------------------------------------------------------------------------


def test_report_evidence_carries_no_original_ips_or_query_secrets(cenv):
    for report in REPORT_NAMES:
        envelope = _run(cenv, "get_report", _args(report=report))
        minimized = egress_mod.serialize_evidence("get_report", envelope["result"])
        blob = json.dumps(minimized)
        assert "198.51.100" not in blob
        assert "hunter2" not in blob
        assert "topsecret" not in blob
        assert "lc_" not in blob
        summary = egress_mod.project_evidence_summary(
            tool_name="get_report",
            tool_call_id="tc1",
            minimized=minimized,
            filters=envelope["filters"],
            observation_time=envelope["observation_time"],
            coverage=envelope["coverage"],
            full_result=envelope["result"],
        )
        assert "198.51.100" not in summary
        assert "hunter2" not in summary


def test_credential_shaped_log_metadata_fails_tool_closed(tmp_path, monkeypatch):
    """A stored product-token shape cannot leak: the tool fails safely."""
    from app.ai.egress import EgressViolation, serialize_evidence

    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes(
        b'198.51.100.9 - - [27/Oct/2026:10:00:00 +0000] "GET /x-lc_abcdef12345 HTTP/1.1"'
        b' 200 10 "-" "Browser/1.0" example.org - - - - "-"\n'
    )
    db = tmp_path / "poison.sqlite3"
    migrate(db)
    run_import(
        db,
        source=SourceConfig(
            source_id="poison",
            format_id="nginx_extended",
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
    rules = (
        load_rules(ROOT / "config" / "bot_rules.yaml").rules
        + load_rules(ROOT / "config" / "security_rules.yaml").rules
    )
    conn = connect(db, read_only=True)
    try:
        # The server-side envelope may hold the stored path, but the
        # egress allowlist refuses to minimize it: nothing crosses.
        envelope = execute_tool(
            conn,
            rules,
            name="get_top_paths",
            arguments=_args(),
            tool_call_id="tc1",
            observation_time=NOW,
        )
        assert "lc_abcdef12345" in json.dumps(envelope["result"])
        with pytest.raises(EgressViolation) as excinfo:
            serialize_evidence("get_top_paths", envelope["result"])
        assert excinfo.value.code == "credential_material"
    finally:
        conn.close()
    with pytest.raises(InvestigationError) as excinfo:
        run_investigation(
            db_path=db,
            rules=rules,
            settings=Settings(
                ai_enabled=True,
                model_data_policy_verified=True,
                model_allow_real_data=True,
                model_endpoint=ENDPOINT,
                llm_daily_limit_usd=50.0,
                llm_budget_usd=150.0,
                llm_warn_at_usd=120.0,
                llm_stop_at_usd=140.0,
            ),
            provider=FakeProvider(
                script=[
                    ProviderResponse(
                        text="",
                        input_tokens=10,
                        output_tokens=5,
                        tool_calls=({"name": "get_top_paths", "arguments": {"limit": 5}},),
                    ),
                    ProviderResponse(text="done", input_tokens=10, output_tokens=5),
                ]
            ),
            actor=ACTOR,
            question="What paths are visible?",
            site_id="default",
            time_from=FROM,
            time_to=TO,
            now=NOW,
            smoke_enforced=False,
        )
    assert excinfo.value.code == "egress_blocked"


def test_chat_route_forwards_new_selectors_over_hostile_args(cenv, monkeypatch):
    """ChatBody carries the full selector set into the trusted scope."""
    from starlette.testclient import TestClient

    import app.ai.service as ai_service
    from app.ai.providers.base import ToolCall
    from app.main import create_app

    monkeypatch.setenv("AI_ENABLED", "true")
    monkeypatch.setenv("MODEL_DATA_POLICY_VERIFIED", "true")
    monkeypatch.setenv("MODEL_ALLOW_REAL_DATA", "true")
    monkeypatch.setenv("LLM_DAILY_LIMIT_USD", "50")
    hostile = FakeProvider(
        script=_answer_script(
            ToolCall(
                name="get_report",
                arguments={
                    "limit": 5,
                    "report": "journeys",
                    "path_exact": "/elsewhere",
                    "timing_available": True,
                },
            )
        )
    )
    monkeypatch.setattr(ai_service, "select_provider", lambda settings: hostile)
    client = TestClient(
        create_app(db_path=cenv["db"], secure_cookies=False), raise_server_exceptions=False
    )
    login = client.post("/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"})
    assert login.status_code == 200
    headers = {"X-CSRF-Token": login.json()["csrf_token"]}
    response = client.post(
        "/api/v1/chat/ask",
        json={
            "question": "Which request journeys are visible?",
            "site_id": "default",
            "time_from": FROM.isoformat(),
            "time_to": TO.isoformat(),
            "path_prefix": "/measured",
            "path_exact": "/measured-fast",
            "server_host": "example.org",
            "timing_available": False,
            "timing_min_ms": 0,
        },
        headers=headers,
    )
    assert response.status_code == 200, response.text[:500]
    evidence = response.json()["evidence"]
    assert evidence[0]["tool"] == "get_report"
    assert evidence[0]["filters"]["path_exact"] == "/measured-fast"
    assert evidence[0]["filters"]["server_host"] == "example.org"
    assert evidence[0]["filters"]["timing_available"] is False
    assert evidence[0]["filters"]["timing_min_ms"] == 0
    assert evidence[0]["href"].startswith("/?")
    assert "path_exact=%2Fmeasured-fast" in evidence[0]["href"]


def test_chat_body_rejects_invalid_timing_range():
    from app.api.routes_chat import ChatBody

    body = ChatBody(
        question="q",
        site_id="default",
        time_from=FROM,
        time_to=TO,
        timing_available=False,
        timing_min_ms=0,
    )
    assert body.timing_available is False
    assert body.timing_min_ms == 0
    with pytest.raises(ValidationError):
        ChatBody(question="q", site_id="default", time_from=FROM, time_to=TO, timing_min_ms=-1)


# ---------------------------------------------------------------------------
# Client: typed report operations and bounded streaming export download
# ---------------------------------------------------------------------------


def test_client_route_map_covers_reports_and_exports():
    import clients.logcarve_api_client as client_mod

    assert client_mod._route_for("findings") == "security/findings"
    assert client_mod._route_for("slow-endpoints") == "performance/slow-endpoints"
    assert client_mod._route_for("seo-ai-only-paths") == "seo/ai-only-paths"
    assert client_mod._route_for("referrer-404-targets") == "referrers/404-targets"
    assert client_mod._route_for("comparison") == "comparison"
    assert client_mod._route_for("summary") == "summary"
    parser = client_mod.build_parser()
    choices = next(a.choices for a in parser._actions if "--endpoint" in a.option_strings)
    for name in (
        "performance",
        "slow-endpoints",
        "journeys",
        "comparison",
        "export-csv",
        "export-json",
    ):
        assert name in choices


def test_client_verify_export_file_accepts_complete_bodies(tmp_path):
    import clients.logcarve_api_client as client_mod

    complete_json = tmp_path / "ok.json"
    complete_json.write_bytes(
        json.dumps(
            {
                "metadata": {"row_count": 2},
                "rows": [{"path": "/a"}, {"path": "/b"}],
                "complete": True,
            }
        ).encode()
    )
    summary = client_mod._verify_export_file(str(complete_json), "json", 2)
    assert summary == {"path": str(complete_json), "format": "json", "rows": 2, "complete": True}
    complete_csv = tmp_path / "ok.csv"
    complete_csv.write_text("path,status\n/a,200\n/b,200\n", encoding="utf-8")
    summary = client_mod._verify_export_file(str(complete_csv), "csv", 2)
    assert summary["rows"] == 2 and summary["complete"] is True


def test_client_verify_export_file_rejects_truncated_bodies(tmp_path):
    import clients.logcarve_api_client as client_mod

    truncated = tmp_path / "cut.json"
    truncated.write_bytes(b'{"metadata": {"row_count": 2}, "rows": [{"path": "/a"}')
    with pytest.raises(SystemExit):
        client_mod._verify_export_file(str(truncated), "json", 2)
    assert not truncated.exists()
    short = tmp_path / "short.csv"
    short.write_text("path,status\n/a,200\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        client_mod._verify_export_file(str(short), "csv", 2)
    assert not short.exists()
    wrong_count = tmp_path / "wrong.json"
    wrong_count.write_bytes(
        json.dumps(
            {"metadata": {"row_count": 1}, "rows": [{"path": "/a"}], "complete": True}
        ).encode()
    )
    with pytest.raises(SystemExit):
        client_mod._verify_export_file(str(wrong_count), "json", 2)
    assert not wrong_count.exists()
