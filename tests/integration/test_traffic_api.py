"""Slice A: new analytics endpoints, selector validation and enforcement.

Compact 10-row synthetic fixture with hand-computed breakdowns:
browser 2 (600B), claimed 3 (200B, 1x404), automation 3 (450B, 1x404),
unknown 2 (40B). All rows fall in UTC hour 2026-10-27T09 (1290B, 2 errors).
"""

import pytest
from starlette.testclient import TestClient

from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user, issue_token
from app.db.database import writer_transaction
from app.db.importer import run_import
from app.ingestion.sources import SourceConfig

LINES = [
    '203.0.113.1 - - [27/Oct/2026:10:00:00 +0100] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"',
    '203.0.113.2 - - [27/Oct/2026:10:01:00 +0100] "GET /robots.txt HTTP/1.1" 200 60 "-" "Googlebot/2.1"',
    '203.0.113.3 - - [27/Oct/2026:10:02:00 +0100] "GET /sitemap.xml HTTP/1.1" 200 90 "-" "GPTBot/1.0"',
    '203.0.113.4 - - [27/Oct/2026:10:03:00 +0100] "GET /missing HTTP/1.1" 404 50 "-" "GPTBot/1.0"',
    '203.0.113.5 - - [27/Oct/2026:10:04:00 +0100] "POST /api/events HTTP/1.1" 201 300 "-" "curl/8.0"',
    '203.0.113.6 - - [27/Oct/2026:10:05:00 +0100] "GET / HTTP/1.1" 200 100 "-" "UptimeRobot/2.0"',
    '203.0.113.7 - - [27/Oct/2026:10:06:00 +0100] "GET /.env HTTP/1.1" 404 50 "-" "SomeBot/1.0"',
    '203.0.113.8 - - [27/Oct/2026:10:07:00 +0100] "GET /x HTTP/1.1" 200 10 "-" "test/1.0"',
    '203.0.113.9 - - [27/Oct/2026:10:08:00 +0100] "GET /null HTTP/1.1" 200 30 "-" "-"',
    '203.0.113.10 - - [27/Oct/2026:10:09:00 +0100] "GET /style.css HTTP/1.1" 200 500 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"',
]

WINDOW = {"from": "2026-10-27T09:00:00+00:00", "to": "2026-10-27T10:00:00+00:00"}


@pytest.fixture
def tapi(tmp_path, monkeypatch):
    from app.db.migrations_runner import migrate

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_text("\n".join(LINES) + "\n", encoding="utf-8")
    db = tmp_path / "traffic_api.sqlite3"
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
        hmac_key=b"synthetic-test-hmac-key",
    )
    with writer_transaction(db) as conn:
        _, valid = issue_token(conn, name="valid", site_id="default")
    from app.main import create_app

    client = TestClient(create_app(db_path=db, secure_cookies=False), raise_server_exceptions=False)
    return client, {"valid": valid}


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _params(**overrides):
    base = {"site_id": "default", **WINDOW}
    base.update(overrides)
    return base


def test_breakdown_endpoint_matches_service(tapi):
    client, tokens = tapi
    body = client.get(
        "/api/v1/traffic/breakdown", params=_params(), headers=_auth(tokens["valid"])
    ).json()
    by_bucket = {b["traffic"]: b for b in body["buckets"]}
    assert by_bucket["browser_like"]["requests"] == 2
    assert by_bucket["browser_like"]["bytes_total"] == 600
    assert by_bucket["claimed_bot"]["requests"] == 3
    assert by_bucket["claimed_bot"]["errors_4xx"] == 1
    assert by_bucket["other_automation"]["requests"] == 3
    assert by_bucket["unknown"]["requests"] == 2
    assert sum(b["requests"] for b in body["buckets"]) == 10
    assert body["filters"]["traffic"] == "all"
    assert body["coverage"]["unique_events"] == 10


def test_breakdown_traffic_filter(tapi):
    client, tokens = tapi
    body = client.get(
        "/api/v1/traffic/breakdown",
        params=_params(traffic="claimed_bot"),
        headers=_auth(tokens["valid"]),
    ).json()
    assert body["coverage"]["unique_events"] == 3
    assert body["filters"]["traffic"] == "claimed_bot"


def test_bots_table_and_detail(tapi):
    client, tokens = tapi
    table = client.get("/api/v1/bots", params=_params(), headers=_auth(tokens["valid"])).json()
    assert table["total_rules"] == 5
    by_id = {row["rule_id"]: row for row in table["items"]}
    assert by_id["bot-ai-gpt"]["requests"] == 2
    assert by_id["bot-ai-gpt"]["provider"] == "OpenAI"
    detail = client.get(
        "/api/v1/bots/bot-ai-gpt", params=_params(), headers=_auth(tokens["valid"])
    ).json()
    assert detail["counts"]["requests"] == 2
    assert detail["robots_requests"] == 0
    assert detail["sitemap_requests"] == 1
    assert detail["not_found"] == [{"path": "/missing", "status": 404, "requests": 1}]
    assert detail["filters"]["traffic"] == "all"


def test_bot_detail_route_rejects_conflict_and_unknown(tapi):
    client, tokens = tapi
    conflict = client.get(
        "/api/v1/bots/bot-search-google",
        params=_params(bot="bot-ai-gpt"),
        headers=_auth(tokens["valid"]),
    )
    assert conflict.status_code == 400
    assert conflict.json()["code"] == "invalid_request"
    missing = client.get("/api/v1/bots/bot-nope", params=_params(), headers=_auth(tokens["valid"]))
    assert missing.status_code == 404
    assert missing.json()["code"] == "unknown_bot"


def test_unknown_selectors_rejected(tapi):
    client, tokens = tapi
    for params in (
        _params(bot="bot-nope"),
        _params(provider="No Such Provider"),
        _params(purpose="No Such Purpose"),
        _params(category="search_crawler", bot="bot-ai-gpt", provider="Meta"),
    ):
        response = client.get(
            "/api/v1/traffic/breakdown", params=params, headers=_auth(tokens["valid"])
        )
        assert response.status_code == 400, params
        assert response.json()["code"] == "invalid_request"
    contradiction = client.get(
        "/api/v1/summary",
        params=_params(status=200, status_class="5xx"),
        headers=_auth(tokens["valid"]),
    )
    assert contradiction.status_code == 400


def test_explorer_search_and_sort(tapi):
    client, tokens = tapi
    newest = client.get(
        "/api/v1/requests", params=_params(limit=3), headers=_auth(tokens["valid"])
    ).json()
    assert newest["total_rows"] == 10
    assert [row["path"] for row in newest["items"]] == ["/style.css", "/null", "/x"]
    assert newest["sort"] == "newest"
    oldest = client.get(
        "/api/v1/requests", params=_params(limit=1, sort="oldest"), headers=_auth(tokens["valid"])
    ).json()
    assert oldest["items"][0]["path"] == "/"
    gpt = client.get(
        "/api/v1/requests", params=_params(search="gpt"), headers=_auth(tokens["valid"])
    ).json()
    assert gpt["total_rows"] == 2
    env = client.get(
        "/api/v1/requests", params=_params(search="env"), headers=_auth(tokens["valid"])
    ).json()
    assert env["total_rows"] == 1
    for row in newest["items"]:
        assert "203.0.113" not in "|".join(str(value or "") for value in row.values())
        assert set(row) == {
            "ts_utc",
            "method",
            "path",
            "status",
            "bytes",
            "referer_host",
            "user_agent",
            "client_pseudonym",
            "traffic",
            "rule_id",
        }


def test_timeseries_bots_panels_and_cross_site(tapi):
    client, tokens = tapi
    headers = _auth(tokens["valid"])
    series = client.get(
        "/api/v1/traffic/timeseries", params=_params(bucket="hour"), headers=headers
    ).json()
    assert series["buckets"] == [
        {
            "bucket": "2026-10-27T09:00:00+00:00",
            "requests": 10,
            "errors": 2,
            "bytes_total": 1290,
        }
    ]
    heat = client.get(
        "/api/v1/traffic/heatmap", params=_params(tz="Europe/Berlin"), headers=headers
    ).json()
    assert heat["timezone"] == "Europe/Berlin"
    assert heat["dst_merges"] == 0
    assert sum(sum(week) for week in heat["matrix"]) == 10
    assert heat["utc_buckets"] == 1
    for path in (
        "/api/v1/traffic/resources",
        "/api/v1/traffic/browsers",
        "/api/v1/traffic/clients",
        "/api/v1/bots",
    ):
        assert client.get(path, params=_params(), headers=headers).status_code == 200, path
    denied = client.get(
        "/api/v1/traffic/breakdown",
        params={**_params(), "site_id": "other"},
        headers=headers,
    )
    assert denied.status_code in (401, 403)
    forbidden = client.get(
        "/api/v1/bots/bot-ai-gpt",
        params={**_params(), "site_id": "other"},
        headers=headers,
    )
    assert forbidden.status_code in (401, 403)


def test_heatmap_rejects_bad_timezone(tapi):
    client, tokens = tapi
    response = client.get(
        "/api/v1/traffic/heatmap",
        params=_params(tz="Asia/Kathmandu"),
        headers=_auth(tokens["valid"]),
    )
    assert response.status_code == 400
    unknown = client.get(
        "/api/v1/traffic/heatmap", params=_params(tz="Nope/Zone"), headers=_auth(tokens["valid"])
    )
    assert unknown.status_code == 400
