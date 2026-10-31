"""T5 API tests: auth boundaries, envelopes and analytics agreement.

Every analytic API result is compared against the shared service layer
on the same filter, so the external contract cannot drift from the
deterministic core. Synthetic data only.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from app.analytics import service
from app.analytics.contracts import AnalyticsFilter, TimeWindow
from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user, issue_token, revoke_token
from app.db.database import connect, writer_transaction
from app.db.importer import run_import
from app.ingestion.sources import SourceConfig

NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)
WINDOW = {"from": "2026-10-27T00:00:00+00:00", "to": "2026-10-28T00:00:00+00:00"}
ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG_DIR = ROOT / "config"
HMAC_KEY = b"synthetic-test-hmac-key"


def _seed_db(db, root):
    from app.db.migrations_runner import migrate

    migrate(db)
    (root / "access.log").write_bytes((root / "nginx_combined.txt").read_bytes())
    (root / "other.log").write_bytes((root / "nginx_combined.txt").read_bytes())
    with writer_transaction(db) as conn:
        conn.execute(
            "INSERT INTO sites (id, name, hostname, timezone, created_at) VALUES (?, ?, ?, ?, ?)",
            ("other", "Other site", "other.example.org", "UTC", NOW.isoformat()),
        )
        conn.execute(
            "INSERT INTO log_sources (id, site_id, server_type, format_id, path_alias, enabled)"
            " VALUES ('other-source', 'other', 'nginx', 'nginx_combined', 'access.log', 1)"
        )
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
    run_import(
        db,
        source=SourceConfig(
            source_id="other-source",
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="other.log",
        ),
        site_id="other",
        site_name="o",
        site_hostname="other.example.org",
        server_type="nginx",
        path_alias="other.log",
        hmac_key=b"synthetic-test-hmac-key",
    )
    with writer_transaction(db) as conn:
        _, valid = issue_token(conn, name="valid", site_id="default")
        _, other = issue_token(conn, name="other", site_id="other")
        _, expired = issue_token(
            conn, name="expired", site_id="default", expires_at="2020-01-01T00:00:00+00:00"
        )
        revoked_id, revoked = issue_token(conn, name="revoked", site_id="default")
        _, wrong_scope = issue_token(conn, name="wrong", site_id="default", scopes=("other:scope",))
    with writer_transaction(db) as conn:
        revoke_token(conn, token_id=revoked_id)
    return {
        "valid": valid,
        "other": other,
        "expired": expired,
        "revoked": revoked,
        "wrong_scope": wrong_scope,
    }


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    root = tmp_path / "logs"
    root.mkdir()
    (root / "nginx_combined.txt").write_bytes(open_fixture())
    db = tmp_path / "api.sqlite3"
    tokens = _seed_db(db, root)
    from app.main import create_app

    client = TestClient(create_app(db_path=db, secure_cookies=False), raise_server_exceptions=False)
    return client, tokens, db


def open_fixture():
    from pathlib import Path

    return (
        Path(__file__).resolve().parent.parent.parent
        / "tests"
        / "fixtures"
        / "combined"
        / "nginx_combined.txt"
    ).read_bytes()


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _filt(**overrides):
    base = {
        "site_id": "default",
        "window": TimeWindow(
            time_from=datetime(2026, 10, 27, tzinfo=UTC), time_to=datetime(2026, 10, 28, tzinfo=UTC)
        ),
    }
    base.update(overrides)
    return AnalyticsFilter(**base)


def test_healthz_without_model_key(api):
    client, _, _ = api
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "logcarve", "ai_enabled": False}


def test_missing_and_bad_tokens_rejected(api):
    client, tokens, _ = api
    params = {"site_id": "default", **WINDOW}
    assert client.get("/api/v1/summary", params=params).status_code == 401
    body = client.get("/api/v1/summary", params=params).json()
    assert body["code"] == "missing_token" and "request_id" in body
    for bad in (
        "Bearer nope",
        "Basic abc",
        f"Bearer {tokens['expired']}",
        f"Bearer {tokens['revoked']}",
    ):
        response = client.get("/api/v1/summary", params=params, headers={"Authorization": bad})
        assert response.status_code == 401
        assert response.json()["code"] == "invalid_token"
        assert response.headers["X-Request-ID"] == response.json()["request_id"]


def test_scope_site_and_source_boundaries(api):
    client, tokens, _ = api
    params = {"site_id": "default", **WINDOW}
    assert (
        client.get("/api/v1/summary", params=params, headers=_auth(tokens["wrong_scope"])).json()[
            "code"
        ]
        == "insufficient_scope"
    )
    cross = client.get(
        "/api/v1/summary", params={"site_id": "other", **WINDOW}, headers=_auth(tokens["valid"])
    )
    assert cross.status_code == 403 and cross.json()["code"] == "forbidden_site"
    other_source = client.get(
        "/api/v1/summary",
        params={**params, "source_id": "other-source"},
        headers=_auth(tokens["valid"]),
    )
    assert other_source.status_code == 403 and other_source.json()["code"] == "forbidden_source"
    unknown_source = client.get(
        "/api/v1/summary", params={**params, "source_id": "nope"}, headers=_auth(tokens["valid"])
    )
    assert unknown_source.status_code == 403 and unknown_source.json()["code"] == "forbidden_source"
    ok = client.get(
        "/api/v1/summary", params={"site_id": "other", **WINDOW}, headers=_auth(tokens["other"])
    )
    assert ok.status_code == 200 and ok.json()["totals"]["requests"] == 10


def test_summary_matches_shared_service(api):
    client, tokens, db = api
    params = {"site_id": "default", **WINDOW}
    body = client.get("/api/v1/summary", params=params, headers=_auth(tokens["valid"])).json()
    conn = connect(db, read_only=True)
    try:
        expected = service.summarize(conn, _filt())
    finally:
        conn.close()
    assert body["totals"] == expected["totals"]
    assert body["status_distribution"] == expected["status_distribution"]
    assert (
        body["duration"]
        == expected["duration"]
        == {
            "available": False,
            "measured": 0,
            "reason": "combined_sources_have_no_timing",
        }
    )
    assert body["coverage"]["unique_events"] == 10
    assert body["site_id"] == "default" and body["filters"]["site_id"] == "default"
    assert body["data_quality"]["import_attempts"]["records_replayed"] == 0


def test_crawlers_findings_match_service(api):
    client, tokens, db = api
    params = {"site_id": "default", **WINDOW}
    headers = _auth(tokens["valid"])
    crawlers = client.get("/api/v1/crawlers", params=params, headers=headers).json()
    findings = client.get("/api/v1/security/findings", params=params, headers=headers).json()
    conn = connect(db, read_only=True)
    try:
        from app.analytics.rules import load_rules

        rules = (
            load_rules(CONFIG_DIR / "bot_rules.yaml").rules
            + load_rules(CONFIG_DIR / "security_rules.yaml").rules
        )
        expected_crawlers = service.crawler_claims(conn, _filt(), rules)
        expected_findings = service.security_findings(conn, _filt(), rules)
    finally:
        conn.close()
    assert [i["rule_id"] for i in crawlers["items"]] == [f.rule_id for f in expected_crawlers]
    assert [i["rule_id"] for i in findings["items"]] == [f.rule_id for f in expected_findings]
    assert crawlers["items"] == []
    assert findings["coverage"]["unique_events"] == 10
    for item in findings["items"]:
        assert "meaning" in item and "limitations" in item and item["limitations"]


def test_errors_and_paths_match_service(api):
    client, tokens, db = api
    params = {"site_id": "default", **WINDOW}
    headers = _auth(tokens["valid"])
    errors = client.get("/api/v1/errors", params=params, headers=headers).json()
    assert errors["total_groups"] == 3
    assert errors["items"][0]["path"] == "/api/events"
    paths = client.get("/api/v1/paths", params={**params, "limit": 2}, headers=headers).json()
    assert paths["total_groups"] == 9 and len(paths["items"]) == 2
    conn = connect(db, read_only=True)
    try:
        from app.analytics.contracts import TopPathsQuery

        expected = service.top_paths(conn, TopPathsQuery(filt=_filt(limit=2)))
    finally:
        conn.close()
    assert paths["items"] == expected["items"]


def test_timeseries_and_performance(api):
    client, tokens, _ = api
    params = {"site_id": "default", **WINDOW}
    headers = _auth(tokens["valid"])
    buckets = client.get(
        "/api/v1/traffic/timeseries", params={**params, "bucket": "hour"}, headers=headers
    ).json()
    assert buckets["bucket"] == "hour"
    by_bucket = {b["bucket"]: b for b in buckets["buckets"]}
    assert by_bucket["2026-10-27T11:00:00+00:00"]["requests"] == 6
    assert by_bucket["2026-10-27T00:00:00+00:00"]["requests"] == 0
    perf = client.get("/api/v1/performance", params=params, headers=headers).json()
    assert perf["available"] is False and "average" not in perf and "p50" not in perf


def test_time_limit_boundary_and_invalid_filters(api):
    client, tokens, _ = api
    headers = _auth(tokens["valid"])
    just_over = client.get(
        "/api/v1/summary",
        params={
            "site_id": "default",
            "from": "2026-01-01T00:00:00+00:00",
            "to": "2027-01-03T00:00:00+00:00",
        },
        headers=headers,
    )
    assert just_over.status_code == 400 and just_over.json()["code"] == "invalid_request"
    naive = client.get(
        "/api/v1/summary",
        params={"site_id": "default", "from": "2026-10-27T00:00:00", "to": "2026-10-28T00:00:00"},
        headers=headers,
    )
    assert naive.status_code == 400
    bad_status = client.get(
        "/api/v1/summary", params={"site_id": "default", **WINDOW, "status": "abc"}, headers=headers
    )
    assert bad_status.status_code == 400
    body = bad_status.json()
    assert body["code"] == "invalid_request" and "request_id" in body
    assert "SELECT" not in bad_status.text and ".sqlite" not in bad_status.text
    bad_tz = client.get(
        "/api/v1/summary",
        params={"site_id": "default", **WINDOW, "timezone": "Mars/Olympus"},
        headers=headers,
    )
    assert bad_tz.status_code == 400
    non_utc = client.get(
        "/api/v1/summary",
        params={"site_id": "default", **WINDOW, "timezone": "Europe/Berlin"},
        headers=headers,
    )
    assert non_utc.status_code == 400 and non_utc.json()["code"] == "unsupported_timezone"
    bad_sort = client.get(
        "/api/v1/paths", params={"site_id": "default", **WINDOW, "sort": "hack"}, headers=headers
    )
    assert bad_sort.status_code == 400


def test_admin_login_logout_and_csrf(api):
    client, _, _ = api
    wrong = client.post("/api/v1/admin/login", json={"username": "admin", "password": "wrong"})
    assert wrong.status_code == 401 and wrong.json()["code"] == "invalid_credentials"
    ghost = client.post("/api/v1/admin/login", json={"username": "ghost", "password": "wrong"})
    assert ghost.status_code == 401 and ghost.json()["code"] == "invalid_credentials"
    assert ghost.json()["message"] == wrong.json()["message"]
    ok = client.post("/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"})
    assert ok.status_code == 200 and "csrf_token" in ok.json()
    denied = client.post("/api/v1/admin/tokens", json={"name": "x", "site_id": "default"})
    assert denied.status_code == 403 and denied.json()["code"] == "csrf_required"
    forged = client.post(
        "/api/v1/admin/tokens",
        json={"name": "x", "site_id": "default"},
        headers={"X-CSRF-Token": "wrong"},
    )
    assert forged.status_code == 403
    issued = client.post(
        "/api/v1/admin/tokens",
        json={"name": "x", "site_id": "default"},
        headers={"X-CSRF-Token": ok.json()["csrf_token"]},
    )
    assert issued.status_code == 201 and issued.json()["token"].startswith("lc_")
    listed = client.get("/api/v1/admin/tokens").json()
    assert all("token" not in entry for entry in listed)
    assert (
        client.post(
            "/api/v1/admin/logout", headers={"X-CSRF-Token": ok.json()["csrf_token"]}
        ).status_code
        == 200
    )
    assert client.get("/api/v1/admin/tokens").status_code == 401


def test_token_and_session_do_not_cross_authorize(api):
    client, tokens, _ = api
    params = {"site_id": "default", **WINDOW}
    using_session = client.get("/api/v1/summary", params=params)
    assert using_session.status_code == 401
    login = client.post("/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"})
    csrf = login.json()["csrf_token"]
    as_bearer = client.post(
        "/api/v1/admin/tokens",
        json={"name": "y", "site_id": "default"},
        headers={"Authorization": f"Bearer {tokens['valid']}"},
    )
    assert as_bearer.status_code in (401, 403)
    client.post("/api/v1/admin/logout", headers={"X-CSRF-Token": csrf})


def test_session_expiry_and_readyz(api):
    client, _, db = api
    assert (
        client.post(
            "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
        ).status_code
        == 200
    )
    assert client.get("/readyz").status_code == 200
    assert client.get("/readyz").json()["ready"] is True
    conn = connect(db)
    with conn:
        conn.execute("UPDATE admin_sessions SET expires_at = '2020-01-01T00:00:00+00:00'")
    conn.close()
    assert client.get("/readyz").status_code == 401
    assert client.get("/api/v1/admin/tokens").status_code == 401
    client.cookies.clear()
    assert client.get("/readyz").status_code == 401


def test_login_rate_limit(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    db = tmp_path / "rate.sqlite3"
    from app.db.migrations_runner import migrate

    migrate(db)
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
    from app.main import create_app

    strict = TestClient(
        create_app(db_path=db, secure_cookies=False, login_max_attempts=2, login_window_s=300.0),
        raise_server_exceptions=False,
    )
    assert (
        strict.post(
            "/api/v1/admin/login", json={"username": "admin", "password": "wrong"}
        ).status_code
        == 401
    )
    assert (
        strict.post(
            "/api/v1/admin/login", json={"username": "admin", "password": "wrong"}
        ).status_code
        == 401
    )
    limited = strict.post("/api/v1/admin/login", json={"username": "admin", "password": "wrong"})
    assert limited.status_code == 429 and limited.json()["code"] == "rate_limited"


def test_openapi_protected_and_docs_disabled(api):
    client, tokens, _ = api
    assert client.get("/api/v1/openapi.json").status_code == 401
    assert client.get("/docs").status_code == 404
    schema = client.get("/api/v1/openapi.json", headers=_auth(tokens["valid"])).json()
    assert "/api/v1/summary" in schema["paths"]


def _admin_client(db, **kwargs):
    from app.main import create_app

    return TestClient(
        create_app(db_path=db, secure_cookies=False, **kwargs), raise_server_exceptions=False
    )


def _login(client, username="admin", password="s3cret-pw"):
    response = client.post("/api/v1/admin/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["csrf_token"]


def test_token_expiry_offsets_and_naive_rejected(api):
    client, _, _ = api
    csrf = _login(client)
    headers = {"X-CSRF-Token": csrf}
    offset = client.post(
        "/api/v1/admin/tokens",
        json={"name": "off", "site_id": "default", "expires_at": "2026-11-30T12:00:00+05:00"},
        headers=headers,
    )
    assert offset.status_code == 201
    # Stored normalized to UTC: 12:00+05:00 -> 07:00Z.
    assert offset.json()["expires_at"] == "2026-11-30T07:00:00+00:00"
    naive = client.post(
        "/api/v1/admin/tokens",
        json={"name": "naive", "site_id": "default", "expires_at": "2026-11-30T12:00:00"},
        headers=headers,
    )
    assert naive.status_code == 400 and naive.json()["code"] == "invalid_request"
    malformed = client.post(
        "/api/v1/admin/tokens",
        json={"name": "bad", "site_id": "default", "expires_at": "not-a-time"},
        headers=headers,
    )
    assert malformed.status_code == 400 and malformed.json()["code"] == "invalid_request"


def test_login_missing_store_is_safe_503_without_creating_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    db = tmp_path / "missing-dir" / "auth.sqlite3"
    client = _admin_client(db)
    response = client.post("/api/v1/admin/login", json={"username": "a", "password": "b"})
    assert response.status_code == 503
    body = response.json()
    assert body["code"] == "store_unavailable" and "request_id" in body
    assert response.headers["X-Request-ID"] == body["request_id"]
    assert not db.exists() and not (tmp_path / "missing-dir").exists()


def test_login_corrupt_store_is_safe_503_without_modifying(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    db = tmp_path / "corrupt.sqlite3"
    before = b"this is not a sqlite database"
    db.write_bytes(before)
    client = _admin_client(db)
    response = client.post("/api/v1/admin/login", json={"username": "a", "password": "b"})
    assert response.status_code == 503
    assert response.json()["code"] == "store_unavailable"
    assert db.read_bytes() == before


def test_login_uninitialized_store_is_safe_503(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    db = tmp_path / "empty.sqlite3"
    db.write_bytes(b"")
    client = _admin_client(db)
    response = client.post("/api/v1/admin/login", json={"username": "a", "password": "b"})
    assert response.status_code == 503
    assert response.json()["code"] == "store_unavailable"


def _env_client(db, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    return _admin_client(db)


def _assert_safe_503(response, content=None):
    assert response.status_code == 503
    body = response.json()
    assert body["code"] == "store_unavailable"
    assert body["message"] == "The data store is unavailable."
    assert body.get("request_id")
    assert response.headers["X-Request-ID"] == body["request_id"]
    text = response.text
    assert "SELECT" not in text and "sqlite" not in text.lower()
    assert "Traceback" not in text
    if content is not None:
        path, before = content
        assert path.read_bytes() == before


def test_bearer_auth_unavailable_stores_503(tmp_path, monkeypatch):
    missing = tmp_path / "gone" / "auth.sqlite3"
    corrupt = tmp_path / "corrupt.sqlite3"
    corrupt.write_bytes(b"this is not a sqlite database")
    empty = tmp_path / "empty.sqlite3"
    empty.write_bytes(b"")
    variants = [
        (missing, None),
        (corrupt, (corrupt, corrupt.read_bytes())),
        (empty, (empty, b"")),
    ]
    for db, content in variants:
        client = _env_client(db, tmp_path, monkeypatch)
        response = client.get(
            "/api/v1/summary",
            params={"site_id": "default", **WINDOW},
            headers={"Authorization": "Bearer lc_synthetic"},
        )
        _assert_safe_503(response, content=content)
    # A broken store must not be repairable into existence by reads.
    assert not missing.exists() and not missing.parent.exists()


def test_session_cookie_and_admin_reads_unavailable_store_503(tmp_path, monkeypatch):
    corrupt = tmp_path / "corrupt.sqlite3"
    before = b"this is not a sqlite database"
    corrupt.write_bytes(before)
    client = _env_client(corrupt, tmp_path, monkeypatch)
    cookies = {"lc_admin_session": "a" * 64}
    _assert_safe_503(client.get("/readyz", cookies=cookies))
    _assert_safe_503(client.get("/api/v1/admin/tokens", cookies=cookies))
    assert corrupt.read_bytes() == before


def test_readyz_missing_store_503_without_creating_files(api):
    from app.db.database import connect as _connect

    client, _, db = api
    login = client.post("/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"})
    assert login.status_code == 200
    assert client.get("/readyz").status_code == 200
    gone = db.parent / "gone.sqlite3"
    missing_client = _admin_client(gone)
    # No session: the session gate answers 401 without touching the store.
    assert missing_client.get("/readyz").status_code == 401
    assert not gone.exists()
    # With a session cookie but no store: the session read fails safe.
    cookies = dict(client.cookies)
    _assert_safe_503(missing_client.get("/readyz", cookies=cookies))
    assert not gone.exists()
    # Valid session, then the readiness query itself breaks: not_ready.
    conn = _connect(db)
    try:
        conn.execute("PRAGMA foreign_keys=OFF")
        with conn:
            conn.execute("DROP TABLE sites")
    finally:
        conn.close()
    response = client.get("/readyz")
    assert response.status_code == 503
    body = response.json()
    assert body["code"] == "not_ready" and "request_id" in body
    assert response.headers["X-Request-ID"] == body["request_id"]


def test_query_time_service_failure_503_without_sql_leak(api):
    client, tokens, db = api
    params = {"site_id": "default", **WINDOW}
    headers = _auth(tokens["valid"])
    assert client.get("/api/v1/summary", params=params, headers=headers).status_code == 200
    from app.db.database import connect as _connect

    conn = _connect(db)
    try:
        with conn:
            conn.execute("DROP TABLE requests")
    finally:
        conn.close()
    _assert_safe_503(client.get("/api/v1/summary", params=params, headers=headers))
    _assert_safe_503(
        client.get(
            "/api/v1/summary", params={**params, "source_id": "example-combined"}, headers=headers
        )
    )


def test_source_check_store_failure_503_without_sql_leak(api):
    client, tokens, db = api
    params = {"site_id": "default", **WINDOW}
    headers = _auth(tokens["valid"])
    from app.db.database import connect as _connect

    conn = _connect(db)
    try:
        conn.execute("PRAGMA foreign_keys=OFF")
        with conn:
            conn.execute("DROP TABLE log_sources")
    finally:
        conn.close()
    # Token verification still succeeds (api_tokens intact); the later
    # membership/coverage reads fail safe instead of leaking SQL errors.
    # The source-scoped request fails at the membership check, the
    # unscoped one at coverage: both map to the same safe envelope.
    _assert_safe_503(
        client.get(
            "/api/v1/summary", params={**params, "source_id": "example-combined"}, headers=headers
        )
    )
    _assert_safe_503(client.get("/api/v1/summary", params=params, headers=headers))
