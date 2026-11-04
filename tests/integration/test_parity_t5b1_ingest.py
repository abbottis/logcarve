"""T5b1 parity integration: custom timestamp ingest, microsecond journeys, exact sums.

Synthetic fixtures only. Expected instants were derived by hand and
cross-checked with an independent ``datetime`` construction; byte
totals use exact int64 edge values (2**62, 2**63 - 1) with hand-checked
integer expectations — including a pair whose true total exceeds
int64 and stays exact through split-half aggregation (never float,
never a database overflow error).
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from starlette.testclient import TestClient

from app.ai import egress as egress_mod
from app.analytics import service as analytics_service
from app.analytics.contracts import AnalyticsFilter, JourneyQuery, TimeWindow, TopPathsQuery
from app.analytics.rules import load_rules
from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user, issue_token
from app.db.database import writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.db.reprocess import run_reprocess
from app.ingestion.custom import load_spec
from app.ingestion.sources import SourceConfig

HMAC_KEY = b"t5b1-integration-hmac-key"
ROOT = Path(__file__).resolve().parent.parent.parent

BOT_RULES = load_rules(ROOT / "config" / "bot_rules.yaml").rules
SEC_RULES = load_rules(ROOT / "config" / "security_rules.yaml").rules
RULES = BOT_RULES + SEC_RULES

PATTERN = (
    r"^(?P<host>\S+) \[(?P<time>[^\]]+)\] \"(?P<request>[^\"]*)\""
    r" (?P<status>\d{3}) (?P<size>\d+|-)$"
)

MAX_BYTES = 2**63 - 1

ISO_LINES = [
    # Journey pair A: exactly 1800 s apart -> one journey.
    '203.0.113.31 [2026-10-27T12:00:00Z] "GET /a HTTP/1.1" 200 10',
    '203.0.113.31 [2026-10-27T12:30:00+00:00] "GET /b HTTP/1.1" 200 10',
    # Journey pair B: 1800.000001 s apart -> two journeys.
    '203.0.113.32 [2026-10-27T13:00:00Z] "GET /a HTTP/1.1" 200 10',
    '203.0.113.32 [2026-10-27T13:30:00.000001Z] "GET /b HTTP/1.1" 200 10',
    # Offset spelling of the pair-A start (same instant, +01:00,
    # same client as pair A).
    '203.0.113.31 [2026-10-27T13:00:00+01:00] "GET /c HTTP/1.1" 200 10',
]


ISO_LOG = "\n".join(ISO_LINES)


def _filt(db_window=None, **overrides):
    base = {
        "site_id": "default",
        "window": TimeWindow(
            time_from=datetime(2026, 10, 27, tzinfo=UTC),
            time_to=datetime(2026, 10, 28, tzinfo=UTC),
        ),
    }
    base.update(overrides)
    return AnalyticsFilter(**base)


def _source(root, relative, fmt):
    return SourceConfig(source_id="t5b1", format_id=fmt, allowed_root=root, relative_path=relative)


def _import(db, root, relative, fmt, **kwargs):
    return run_import(
        db,
        source=_source(root, relative, fmt),
        site_id="default",
        site_name="T5b1",
        site_hostname="example.org",
        server_type="nginx",
        path_alias=relative,
        hmac_key=HMAC_KEY,
        **kwargs,
    )


def _client(db):
    from app.main import create_app

    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
        _, token = issue_token(conn, name="t5b1", site_id="default")
    client = TestClient(create_app(db_path=db, secure_cookies=False), raise_server_exceptions=False)
    assert (
        client.post(
            "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
        ).status_code
        == 200
    )
    return client, token


def _stored_ts(db):
    with writer_transaction(db) as conn:
        return [
            row[0]
            for row in conn.execute("SELECT ts_utc FROM requests ORDER BY ts_utc, id").fetchall()
        ]


def test_custom_iso8601_import_canonical_replay_and_identity(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "t5b1-session-secret")
    monkeypatch.setenv("HMAC_KEY", "t5b1-integration-hmac-key")
    root = tmp_path / "logs"
    root.mkdir()
    (root / "iso.log").write_text(ISO_LOG + "\n", encoding="utf-8")
    db = tmp_path / "t5b1.sqlite3"
    migrate(db)
    spec = load_spec({"format_id": "custom-t5b1", "pattern": PATTERN, "time_format": "iso8601"})
    first = _import(db, root, "iso.log", spec.format_id, custom_format=spec)
    assert first.status == "completed", first.error_summary
    assert (first.records_inserted, first.records_replayed) == (5, 0)
    assert first.lines_rejected == 0
    # Canonical UTC storage: Z, +00:00 and +01:00 spellings collapse.
    assert _stored_ts(db) == [
        "2026-10-27T12:00:00+00:00",
        "2026-10-27T12:00:00+00:00",
        "2026-10-27T12:30:00+00:00",
        "2026-10-27T13:00:00+00:00",
        "2026-10-27T13:30:00.000001+00:00",
    ]
    with writer_transaction(db) as conn:
        pseudonyms = [
            row[0]
            for row in conn.execute(
                "SELECT client_pseudonym FROM requests ORDER BY ts_utc, id"
            ).fetchall()
        ]
    # Same client text -> same pseudonym across offset spellings.
    assert pseudonyms[0] == pseudonyms[1] == pseudonyms[2]
    assert pseudonyms[2] != pseudonyms[3]
    assert pseudonyms[3] == pseudonyms[4]
    repro = run_reprocess(
        db,
        source=_source(root, "iso.log", spec.format_id),
        site_id="default",
        site_hostname="example.org",
        server_type="nginx",
        hmac_key=HMAC_KEY,
        custom_format=spec,
    )
    assert repro.status == "completed", repro.error_summary
    assert repro.rows_mismatched == 0 and repro.rows_unparseable == 0
    assert _stored_ts(db) == [
        "2026-10-27T12:00:00+00:00",
        "2026-10-27T12:00:00+00:00",
        "2026-10-27T12:30:00+00:00",
        "2026-10-27T13:00:00+00:00",
        "2026-10-27T13:30:00.000001+00:00",
    ]


def test_epoch_modes_match_iso8601_instants(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "t5b1-session-secret")
    monkeypatch.setenv("HMAC_KEY", "t5b1-integration-hmac-key")
    moment = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
    stamp = int(moment.timestamp())
    root = tmp_path / "logs"
    root.mkdir()
    (root / "epoch.log").write_text(
        "\n".join(
            [
                f'203.0.113.31 [{stamp}] "GET /e HTTP/1.1" 200 10',
                f'203.0.113.31 [{stamp * 1000 + 750}] "GET /f HTTP/1.1" 200 10',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    db = tmp_path / "t5b1e.sqlite3"
    migrate(db)
    spec_s = load_spec({"format_id": "custom-t5b1s", "pattern": PATTERN, "time_format": "epoch_s"})
    result = _import(db, root, "epoch.log", spec_s.format_id, custom_format=spec_s)
    assert result.status == "completed", result.error_summary
    assert _stored_ts(db) == ["2026-10-27T12:00:00+00:00"]
    assert result.lines_rejected == 1  # the millisecond value under a seconds mode
    assert result.rejected_by_reason == {"invalid_time": 1}
    spec_ms = load_spec(
        {"format_id": "custom-t5b1m", "pattern": PATTERN, "time_format": "epoch_ms"}
    )
    db2 = tmp_path / "t5b1m.sqlite3"
    migrate(db2)
    result_ms = _import(db2, root, "epoch.log", spec_ms.format_id, custom_format=spec_ms)
    assert result_ms.status == "completed", result_ms.error_summary
    # Under a millisecond mode the seconds-scale value is an ordinary
    # small 1970 instant, not an error: both lines import.
    small = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(milliseconds=stamp)
    assert result_ms.lines_accepted == 2 and result_ms.lines_rejected == 0
    assert _stored_ts(db2) == [
        small.isoformat(),
        "2026-10-27T12:00:00.750000+00:00",
    ]


def test_journey_gap_exact_microsecond_boundary(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "t5b1-session-secret")
    monkeypatch.setenv("HMAC_KEY", "t5b1-integration-hmac-key")
    root = tmp_path / "logs"
    root.mkdir()
    (root / "iso.log").write_text(ISO_LOG + "\n", encoding="utf-8")
    db = tmp_path / "t5b1j.sqlite3"
    migrate(db)
    spec = load_spec({"format_id": "custom-t5b1", "pattern": PATTERN, "time_format": "iso8601"})
    assert _import(db, root, "iso.log", spec.format_id, custom_format=spec).status == "completed"
    with writer_transaction(db) as conn:
        journeys = analytics_service.journeys(conn, JourneyQuery(filt=_filt()), None)
    by_client = {}
    for item in journeys["items"]:
        by_client.setdefault(item["client_pseudonym"], []).append(item)
    assert len(by_client) == 2
    pair_a = next(
        rows for rows in by_client.values() if len(rows) == 1 and rows[0]["requests_total"] == 3
    )
    pair_b = [rows for rows in by_client.values() if len(rows) == 2]
    assert len(pair_b) == 1
    # Exactly 1800 s continues; 1800.000001 s splits. Elapsed stays exact.
    assert pair_a[0]["duration_us"] == 1_800_000_000
    assert pair_a[0]["ended_at"] == "2026-10-27T12:30:00+00:00"
    assert [row["started_at"] for row in pair_b[0]] == [
        "2026-10-27T13:00:00+00:00",
        "2026-10-27T13:30:00.000001+00:00",
    ]


def test_large_sums_exact_beyond_int64(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "t5b1-session-secret")
    monkeypatch.setenv("HMAC_KEY", "t5b1-integration-hmac-key")
    root = tmp_path / "logs"
    root.mkdir()
    (root / "bytes.log").write_text(
        "\n".join(
            [
                f'203.0.113.41 [2026-10-27T14:00:00Z] "GET /big HTTP/1.1" 200 {MAX_BYTES}',
                f'203.0.113.42 [2026-10-27T14:01:00Z] "GET /big HTTP/1.1" 200 {MAX_BYTES}',
                f'203.0.113.43 [2026-10-27T14:02:00Z] "GET /large HTTP/1.1" 200 {2**62}',
                f'203.0.113.44 [2026-10-27T14:03:00Z] "GET /large HTTP/1.1" 200 {2**62 - 1}',
                f'203.0.113.45 [2026-10-27T14:04:00Z] "GET /big HTTP/1.1" 200 {2**63}',
                '203.0.113.46 [not-a-time] "GET /big HTTP/1.1" 200 10',
                '203.0.113.47 [2026-10-27T14:05:00Z] "GET /ok HTTP/1.1" 200 7',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    db = tmp_path / "t5b1b.sqlite3"
    migrate(db)
    spec = load_spec({"format_id": "custom-t5b1", "pattern": PATTERN, "time_format": "iso8601"})
    result = _import(db, root, "bytes.log", spec.format_id, custom_format=spec)
    assert result.status == "completed", result.error_summary
    assert result.lines_accepted == 5 and result.lines_rejected == 2
    assert result.rejected_by_reason == {"invalid_bytes": 1, "invalid_time": 1}
    everything_expected = 2 * MAX_BYTES + 2**62 + (2**62 - 1) + 7
    assert everything_expected == 2**64 + 2**63 + 4
    filt = _filt()
    with writer_transaction(db) as conn:
        everything = analytics_service.summarize(conn, filt, None)
        # Beyond int64 yet exact: split-half sums never touch float.
        assert everything["totals"]["bytes_total"] == everything_expected
        assert isinstance(everything["totals"]["bytes_total"], int)
        large = analytics_service.summarize(conn, _filt(path_exact="/large"), None)
        assert large["totals"]["bytes_total"] == 2**63 - 1
        assert isinstance(large["totals"]["bytes_total"], int)
        big_rows = analytics_service.top_paths(
            conn,
            TopPathsQuery(filt=_filt(path_exact="/big")),
            None,
        )
        assert big_rows["items"][0]["bytes_total"] == 2 * MAX_BYTES
        large_countries = analytics_service.country_breakdown(
            conn, _filt(path_exact="/large"), None
        )
        assert [item["bytes_total"] for item in large_countries["items"]] == [2**63 - 1]
    client, token = _client(db)
    response = client.get(
        "/api/v1/summary",
        params={
            "site_id": "default",
            "from": "2026-10-27T00:00:00+00:00",
            "to": "2026-10-28T00:00:00+00:00",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200, response.text[:300]
    envelope = response.json()
    assert envelope["totals"]["bytes_total"] == everything_expected


def test_comparison_bytes_exact_beyond_int64(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "t5b1-session-secret")
    monkeypatch.setenv("HMAC_KEY", "t5b1-integration-hmac-key")
    root = tmp_path / "logs"
    root.mkdir()
    (root / "bytes.log").write_text(
        "\n".join(
            [
                f'203.0.113.41 [2026-10-27T14:00:00Z] "GET /big HTTP/1.1" 200 {MAX_BYTES}',
                f'203.0.113.42 [2026-10-27T14:01:00Z] "GET /big HTTP/1.1" 200 {MAX_BYTES}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    db = tmp_path / "t5b1c.sqlite3"
    migrate(db)
    spec = load_spec({"format_id": "custom-t5b1", "pattern": PATTERN, "time_format": "iso8601"})
    assert _import(db, root, "bytes.log", spec.format_id, custom_format=spec).status == "completed"
    current = _filt(
        window=TimeWindow(
            time_from=datetime(2026, 10, 27, 14, tzinfo=UTC),
            time_to=datetime(2026, 10, 27, 15, tzinfo=UTC),
        )
    )
    previous = _filt(
        window=TimeWindow(
            time_from=datetime(2026, 10, 27, 13, tzinfo=UTC),
            time_to=datetime(2026, 10, 27, 14, tzinfo=UTC),
        )
    )
    with writer_transaction(db) as conn:
        compared = analytics_service.compare_windows(conn, current, previous, RULES)
    metric = next(item for item in compared["metrics"] if item["name"] == "bytes_total")
    # Exact beyond int64 with an empty baseline: exact change, no ratio.
    assert metric["current"] == 2 * MAX_BYTES
    assert metric["previous"] == 0
    assert metric["absolute_change"] == 2 * MAX_BYTES
    assert metric["ratio_status"] == "zero_baseline"
    # The empty baseline puts every metric on zero_baseline.
    assert (
        next(item for item in compared["metrics"] if item["name"] == "requests")["ratio_status"]
        == "zero_baseline"
    )


def test_fractional_window_roundtrip_keeps_precision(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "t5b1-session-secret")
    monkeypatch.setenv("HMAC_KEY", "t5b1-integration-hmac-key")
    root = tmp_path / "logs"
    root.mkdir()
    (root / "iso.log").write_text(ISO_LOG + "\n", encoding="utf-8")
    db = tmp_path / "t5b1w.sqlite3"
    migrate(db)
    spec = load_spec({"format_id": "custom-t5b1", "pattern": PATTERN, "time_format": "iso8601"})
    assert _import(db, root, "iso.log", spec.format_id, custom_format=spec).status == "completed"
    client, _ = _client(db)
    # A 1us window around the fractional event: unchanged Apply must not
    # floor the bounds to minutes or widen the counts.
    window = (
        "site=default&range=custom&tz=UTC"
        "&from=2026-10-27T13:30:00.000001%2B00:00&to=2026-10-27T13:30:00.000002%2B00:00"
    )
    html = client.get(f"/?{window}").text
    assert (
        'id="f-from" name="from" type="datetime-local" value="2026-10-27T13:30:00.000001"' in html
    )
    assert 'step="0.000001"' in html
    with writer_transaction(db) as conn:
        scoped = analytics_service.summarize(
            conn,
            _filt(
                window=TimeWindow(
                    time_from=datetime(2026, 10, 27, 13, 30, 0, 1, tzinfo=UTC),
                    time_to=datetime(2026, 10, 27, 13, 30, 0, 2, tzinfo=UTC),
                )
            ),
            None,
        )
    assert scoped["totals"]["requests"] == 1


def test_egress_bytes_exact_beyond_int64():
    import json as _json

    huge = 2 * MAX_BYTES
    summary = egress_mod._project_result(
        "get_summary",
        {
            "totals": {"requests": 3, "errors_4xx": 0, "errors_5xx": 0, "bytes_total": huge},
            "status_distribution": [],
        },
        None,
    )
    assert _json.loads(summary)["bytes"] == huge
    countries = egress_mod._project_report(
        "countries",
        {"items": [{"country": "US", "requests": 2, "bytes_total": huge}]},
        {"items": [{"country": "US", "requests": 2, "bytes_total": huge}]},
    )
    assert _json.loads(countries)["top"][0]["bytes"] == huge
