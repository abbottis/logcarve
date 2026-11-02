"""T5b1b corrections (integration): streamed carry ranking and safe rejections.

Synthetic fixtures only. Import files pair one rejected line with one
following valid line to prove continuation, accounting, source
immutability and withheld diagnostics.
"""

from datetime import UTC, datetime
from pathlib import Path

from starlette.testclient import TestClient

from app.analytics.contracts import AnalyticsFilter, TimeWindow, TopPathsQuery
from app.analytics import service as analytics_service
from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user, issue_token
from app.db.database import writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.custom import load_spec
from app.ingestion.sources import SourceConfig
from app.ingestion.stream import collect_records

HMAC_KEY = b"t5b1b-integration-hmac-key"
ROOT = Path(__file__).resolve().parent.parent.parent

PIPE_SIZE = (
    r"^(?P<host>[^|]+)\|(?P<time>[^|]+)\|(?P<request>[^|]+)"
    r"\|(?P<status>[0-9]{3})\|(?P<size>[^|]*)$"
)
PIPE_BYTES = (
    r"^(?P<host>[^|]+)\|(?P<time>[^|]+)\|(?P<request>[^|]+)"
    r"\|(?P<status>[0-9]{3})\|(?P<bytes>[^|]*)$"
)


def _filt(**overrides):
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
    return SourceConfig(source_id="t5b1b", format_id=fmt, allowed_root=root, relative_path=relative)


def _import(db, root, relative, fmt, **kwargs):
    return run_import(
        db,
        source=_source(root, relative, fmt),
        site_id="default",
        site_name="T5b1b",
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
        _, token = issue_token(conn, name="t5b1b", site_id="default")
    client = TestClient(create_app(db_path=db, secure_cookies=False), raise_server_exceptions=False)
    assert (
        client.post(
            "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
        ).status_code
        == 200
    )
    return client, token


def test_carry_ranking_through_import_and_paths_api(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "t5b1b-session-secret")
    monkeypatch.setenv("HMAC_KEY", "t5b1b-integration-hmac-key")
    root = tmp_path / "logs"
    root.mkdir()
    (root / "carry.log").write_text(
        "\n".join(
            [
                '203.0.113.11 [2026-10-27T09:00:00Z] "GET /carry-a HTTP/1.1" 200 4294967296',
                '203.0.113.12 [2026-10-27T09:01:00Z] "GET /carry-b HTTP/1.1" 200 2147483649',
                '203.0.113.13 [2026-10-27T09:02:00Z] "GET /carry-b HTTP/1.1" 200 2147483649',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    pattern = (
        r"^(?P<host>\S+) \[(?P<time>[^\]]+)\] \"(?P<request>[^\"]*)\""
        r" (?P<status>\d{3}) (?P<size>\d+|-)$"
    )
    db = tmp_path / "t5b1b.sqlite3"
    migrate(db)
    spec = load_spec({"format_id": "custom-t5b1x", "pattern": pattern, "time_format": "iso8601"})
    result = _import(db, root, "carry.log", spec.format_id, custom_format=spec)
    assert result.status == "completed", result.error_summary
    assert (result.lines_accepted, result.lines_rejected) == (3, 0)
    with writer_transaction(db) as conn:
        items = analytics_service.top_paths(
            conn, TopPathsQuery(filt=_filt(), sort="bytes_desc"), None
        )["items"]
    assert [item["path"] for item in items[:2]] == ["/carry-b", "/carry-a"]
    assert items[0]["bytes_total"] == 4294967298
    assert items[1]["bytes_total"] == 4294967296
    assert all(item["method"] == "GET" for item in items[:2])
    client, token = _client(db)
    response = client.get(
        "/api/v1/paths",
        params={
            "site_id": "default",
            "from": "2026-10-27T00:00:00+00:00",
            "to": "2026-10-28T00:00:00+00:00",
            "sort": "bytes_desc",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200, response.text[:300]
    body = response.json()
    assert [item["path"] for item in body["items"][:2]] == ["/carry-b", "/carry-a"]
    assert body["items"][0]["bytes_total"] == 4294967298
    assert body["items"][1]["bytes_total"] == 4294967296
    # Full ranking applies before paging: the second page holds /carry-a.
    page2 = client.get(
        "/api/v1/paths",
        params={
            "site_id": "default",
            "from": "2026-10-27T00:00:00+00:00",
            "to": "2026-10-28T00:00:00+00:00",
            "sort": "bytes_desc",
            "limit": 1,
            "offset": 1,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert page2.status_code == 200, page2.text[:300]
    assert page2.json()["items"][0]["path"] == "/carry-a"


def _stream_case(tmp_path, monkeypatch, lines, pattern, time_format="iso8601"):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "case.log"
    target.write_bytes(("\n".join(lines) + "\n").encode())
    before = target.read_bytes()
    spec = load_spec({"format_id": "custom-t5b1y", "pattern": pattern, "time_format": time_format})
    records, report = collect_records(
        target, source_id="s", format_id="custom-t5b1y", hmac_key=HMAC_KEY, custom_format=spec
    )
    return target, before, records, report


def test_iso_extreme_overflow_rejects_and_continues(tmp_path, monkeypatch):
    good = "203.0.113.30|2026-10-27T09:15:32Z|GET /safe HTTP/1.1|200|128"
    for bad in ("0001-01-01T00:00:00+23:59", "9999-12-31T23:59:59-23:59"):
        target, before, records, report = _stream_case(
            tmp_path,
            monkeypatch,
            [f"203.0.113.30|{bad}|GET /safe HTTP/1.1|200|128", good],
            PIPE_SIZE,
        )
        assert [record.line_number for record in records] == [2]
        assert report.accepted == 1 and report.rejected == 1
        assert report.rejected_by_reason == {"invalid_time": 1}
        assert report.diagnostics[0].excerpt == "<withheld>:invalid_time"
        assert target.read_bytes() == before
        assert bad not in report.diagnostics[0].excerpt


def test_iso_bad_offset_rejects_and_continues(tmp_path, monkeypatch):
    good = "203.0.113.30|2026-10-27T09:15:32Z|GET /safe HTTP/1.1|200|128"
    for bad in ("2026-10-27T09:15:32+00:60", "2026-10-27T09:15:32-01:99"):
        target, before, records, report = _stream_case(
            tmp_path,
            monkeypatch,
            [f"203.0.113.30|{bad}|GET /safe HTTP/1.1|200|128", good],
            PIPE_SIZE,
        )
        assert [record.line_number for record in records] == [2]
        assert report.accepted == 1 and report.rejected == 1
        assert report.rejected_by_reason == {"invalid_time": 1}
        assert report.diagnostics[0].excerpt == "<withheld>:invalid_time"
        assert target.read_bytes() == before


def test_empty_bytes_rejects_and_continues_for_both_aliases(tmp_path, monkeypatch):
    good = "203.0.113.30|2026-10-27T09:15:32Z|GET /safe HTTP/1.1|200|128"
    bad = "203.0.113.30|2026-10-27T09:15:32Z|GET /safe HTTP/1.1|200|"
    for pattern in (PIPE_SIZE, PIPE_BYTES):
        target, before, records, report = _stream_case(
            tmp_path, monkeypatch, [bad, good], pattern
        )
        assert [record.line_number for record in records] == [2]
        assert records[0].bytes_sent == 128
        assert report.accepted == 1 and report.rejected == 1
        assert report.rejected_by_reason == {"invalid_bytes": 1}
        assert report.diagnostics[0].excerpt == "<withheld>:invalid_bytes"
        assert target.read_bytes() == before
