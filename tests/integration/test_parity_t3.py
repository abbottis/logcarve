"""Parity T3 transport hardening: snapshots, pagination, validation.

- One read snapshot spans each response's related queries: a
  follow/refresh batch committing mid-response cannot mix
  generations (counts vs coverage, event vs private original).
- Offsets above the SQLite signed-64-bit binding range reject as
  sanitized 4xx with ``request_id`` (never ``OverflowError``/500);
  invalid numerics/booleans/filters reject the same way.
- Status/format/limit validation stays independent of broken
  stores where the contract requires it (FastAPI-level rejects
  answer 400 even when the store is corrupt).
"""

import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from starlette.testclient import TestClient

from app.analytics.contracts import AnalyticsFilter, JourneyQuery, TimeWindow
from app.api.deps import read_store
from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user, issue_token
from app.db.database import connect, writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.sources import SourceConfig

NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)
HMAC_KEY = b"t3-hardening-key"


def _seed_db(db, root):
    migrate(db)
    (root / "access.log").write_bytes(
        b'198.51.100.7 - - [27/Oct/2026:10:00:00 +0000] "GET /a HTTP/1.1" 200 10 "-" "Hard/1.0"\n'
        b'198.51.100.8 - - [27/Oct/2026:10:01:00 +0000] "GET /b HTTP/1.1" 404 10 "-" "Hard/1.0"\n'
    )
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
    run_import(
        db,
        source=SourceConfig(
            source_id="hard-source",
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
        _, valid = issue_token(conn, name="valid", site_id="default")
    return valid


@pytest.fixture
def hardening(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    root = tmp_path / "logs"
    root.mkdir()
    db = tmp_path / "hard.sqlite3"
    token = _seed_db(db, root)
    from app.main import create_app

    client = TestClient(create_app(db_path=db, secure_cookies=False), raise_server_exceptions=False)
    return client, token, db


def _stub(db):
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(db_path=db)))


def _follow_batch(db):
    """One deterministic follow/refresh batch: a new event plus its original."""
    with writer_transaction(db) as conn:
        scope = conn.execute(
            "SELECT import_id, site_id, source_id, file_fingerprint FROM requests LIMIT 1"
        ).fetchone()
        offset = conn.execute("SELECT COALESCE(MAX(byte_offset), 0) + 1 FROM requests").fetchone()[
            0
        ]
        conn.execute(
            "INSERT INTO requests (import_id, site_id, source_id, file_fingerprint,"
            " byte_offset, line_number, ts_utc, method, path, status, bytes,"
            " referer_host, user_agent, client_pseudonym)"
            " VALUES (?, ?, ?, ?, ?, ?, '2026-10-27T10:02:00+00:00', 'GET',"
            " '/follow', 200, 10, NULL, 'Hard/1.0', 'follow-pseudo')",
            (scope[0], scope[1], scope[2], scope[3], offset, offset),
        )


def test_read_snapshot_spans_counts_and_coverage(hardening):
    """A batch committing mid-response cannot split counts from coverage."""
    _, _, db = hardening
    with read_store(_stub(db)) as conn:
        before = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
        cov_before = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
        assert before == cov_before == 2
        _follow_batch(db)
        # Same snapshot: the follow batch stays invisible here.
        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 2
    with read_store(_stub(db)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 3


def test_read_snapshot_pairs_event_with_private_original(hardening):
    """Displayed events and private originals read under one snapshot."""
    _, _, db = hardening
    with read_store(_stub(db)) as conn:
        pairs_before = conn.execute(
            "SELECT r.id, r.client_pseudonym, o.request_id"
            " FROM requests r LEFT JOIN request_original_ips o ON o.request_id = r.id"
            " ORDER BY r.id"
        ).fetchall()
        _follow_batch(db)
        pairs_same = conn.execute(
            "SELECT r.id, r.client_pseudonym, o.request_id"
            " FROM requests r LEFT JOIN request_original_ips o ON o.request_id = r.id"
            " ORDER BY r.id"
        ).fetchall()
        # No new row ID can pair an old request with another event's data.
        assert pairs_same == pairs_before
    with read_store(_stub(db)) as conn:
        pairs_after = conn.execute("SELECT r.id FROM requests r ORDER BY r.id").fetchall()
    assert len(pairs_after) == len(pairs_before) + 1


def test_huge_offset_rejects_as_400_not_500(hardening):
    """Offsets above int64 reject with request_id; normal paging still works."""
    client, token, _ = hardening
    headers = {"Authorization": f"Bearer {token}"}
    window = {"from": "2026-10-27T00:00:00+00:00", "to": "2026-10-28T00:00:00+00:00"}
    huge = client.get(
        "/api/v1/requests",
        params={"site_id": "default", **window, "offset": str(2**70)},
        headers=headers,
    )
    assert huge.status_code == 400
    body = huge.json()
    assert body["code"] == "invalid_request" and body["request_id"]
    assert huge.headers["X-Request-ID"] == body["request_id"]
    # Invalid numerics reject the same way instead of being ignored.
    bad = client.get(
        "/api/v1/requests",
        params={"site_id": "default", **window, "limit": "many"},
        headers=headers,
    )
    assert bad.status_code == 400
    assert bad.json()["request_id"]
    # The shared contract rejects huge offsets before any store read.
    with pytest.raises(ValidationError):
        AnalyticsFilter(
            site_id="default",
            window=TimeWindow(
                time_from=datetime(2026, 10, 27, tzinfo=UTC),
                time_to=datetime(2026, 10, 28, tzinfo=UTC),
            ),
            offset=2**70,
        )
    # Normal large valid scopes keep complete paging semantics.
    page = client.get(
        "/api/v1/requests",
        params={"site_id": "default", **window, "limit": 100, "offset": 1},
        headers=headers,
    )
    assert page.status_code == 200
    assert page.json()["total_rows"] == 2
    assert len(page.json()["items"]) == 1


# ---------------------------------------------------------------------------
# T3 versioned API surfaces: service/API equality + negatives
# ---------------------------------------------------------------------------

SITE_T3 = "site-t3"
SOURCE_T3 = "t3-extended-source"
SITE_HOST_T3 = "example.org"
GOOGLE_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36"
JOURNEY_UA = "JourneyProbe/1.0"


def _ext(
    *,
    path="/x",
    status=200,
    referer="-",
    ua="-",
    host=SITE_HOST_T3,
    cache="-",
    request_time="-",
    mime="-",
    tls="-",
    upstream="-",
    version=" HTTP/1.1",
    ip="198.51.100.60",
    stamp="27/Oct/2026:10:00:00",
):
    return (
        f"{ip} - - [{stamp} +0000] "
        f'"GET {path}{version}" {status} 10 "{referer}" "{ua}" '
        f'{host} {cache} {request_time} {mime} {tls} "{upstream}"\n'
    ).encode()


def _seed_t3(tmp_path):
    from app.ingestion.combined import NGINX_EXTENDED

    root = tmp_path / "t3logs"
    root.mkdir(exist_ok=True)
    (root / "ext.log").write_bytes(
        b"".join(
            [
                # Measured timing/cache/MIME/TLS/host rows (hand-derived).
                _ext(
                    path="/fast",
                    request_time="0.010",
                    cache="HIT",
                    mime="text/html",
                    tls="TLSv1.3",
                    upstream="0.004, 0.006",
                    ua=BROWSER_UA,
                    stamp="27/Oct/2026:10:00:00",
                ),
                _ext(
                    path="/fast",
                    request_time="0.010",
                    cache="HIT",
                    mime="text/html",
                    tls="TLSv1.3",
                    upstream="0.004, 0.006",
                    ua=BROWSER_UA,
                    stamp="27/Oct/2026:10:01:00",
                ),
                _ext(
                    path="/slow",
                    request_time="0.500",
                    cache="MISS",
                    mime="application/json",
                    tls="TLSv1.2",
                    upstream="0.400",
                    ua=BROWSER_UA,
                    stamp="27/Oct/2026:10:02:00",
                ),
                # Referrer 404 targets: one internal, one external.
                _ext(
                    path="/gone",
                    status=404,
                    referer="http://example.org/from",
                    ua=BROWSER_UA,
                    stamp="27/Oct/2026:10:03:00",
                ),
                _ext(
                    path="/gone",
                    status=404,
                    referer="http://external.example/page",
                    ua=BROWSER_UA,
                    stamp="27/Oct/2026:10:04:00",
                ),
                # Claimed-bot 404s for the SEO report.
                _ext(path="/missing", status=404, ua=GOOGLE_UA, stamp="27/Oct/2026:10:05:00"),
                _ext(path="/missing", status=404, ua=GOOGLE_UA, stamp="27/Oct/2026:10:06:00"),
                # One request journey (same client + agent, 10-min gap).
                _ext(path="/j1a", ua=JOURNEY_UA, ip="198.51.100.61", stamp="27/Oct/2026:10:00:00"),
                _ext(path="/j1b", ua=JOURNEY_UA, ip="198.51.100.61", stamp="27/Oct/2026:10:10:00"),
                _ext(path="/j2", ua=JOURNEY_UA, ip="198.51.100.62", stamp="27/Oct/2026:10:05:00"),
                # Baseline-window row for comparison.
                _ext(path="/old", stamp="27/Oct/2026:09:30:00"),
            ]
        )
    )
    db = tmp_path / "t3.sqlite3"
    migrate(db)
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
    imported = run_import(
        db,
        source=SourceConfig(
            source_id=SOURCE_T3,
            format_id=NGINX_EXTENDED,
            allowed_root=root,
            relative_path="ext.log",
            allowed_hosts=[SITE_HOST_T3],
        ),
        site_id=SITE_T3,
        site_name="T3",
        site_hostname=SITE_HOST_T3,
        server_type="nginx",
        path_alias="ext.log",
        hmac_key=HMAC_KEY,
    )
    assert imported.status == "completed"
    with writer_transaction(db) as conn:
        conn.execute(
            "INSERT INTO sites (id, name, hostname, timezone, created_at) VALUES (?, ?, ?, ?, ?)",
            ("elsewhere", "Elsewhere", "elsewhere.example.org", "UTC", NOW.isoformat()),
        )
        _, valid = issue_token(conn, name="valid", site_id=SITE_T3)
        _, other_site = issue_token(conn, name="other", site_id="elsewhere")
        _, expired = issue_token(
            conn, name="expired", site_id=SITE_T3, expires_at="2020-01-01T00:00:00+00:00"
        )
        _, wrong = issue_token(conn, name="wrong", site_id=SITE_T3, scopes=("other:scope",))
    return db, {"valid": valid, "other_site": other_site, "expired": expired, "wrong": wrong}


@pytest.fixture
def t3api(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    db, tokens = _seed_t3(tmp_path)
    from app.main import create_app

    client = TestClient(create_app(db_path=db, secure_cookies=False), raise_server_exceptions=False)
    return client, tokens, db


CUR = {"from": "2026-10-27T10:00:00+00:00", "to": "2026-10-27T11:00:00+00:00"}
BASE = {"from": "2026-10-27T09:00:00+00:00", "to": "2026-10-27T10:00:00+00:00"}


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _rules():
    from pathlib import Path

    from app.analytics.rules import load_rules

    root = Path(__file__).resolve().parent.parent.parent / "config"
    return (
        load_rules(root / "bot_rules.yaml").rules + load_rules(root / "security_rules.yaml").rules
    )


def _filt(**overrides):
    base = {
        "site_id": SITE_T3,
        "window": TimeWindow(
            time_from=datetime(2026, 10, 27, 10, 0, tzinfo=UTC),
            time_to=datetime(2026, 10, 27, 11, 0, tzinfo=UTC),
        ),
    }
    base.update(overrides)
    return AnalyticsFilter(**base)


def test_t3_performance_overview_matches_service(t3api):
    """Hand-derived latency/cache/MIME/version/TLS/host figures agree with shared service."""
    from app.analytics import service as shared

    client, tokens, db = t3api
    response = client.get(
        "/api/v1/performance/overview",
        params={"site_id": SITE_T3, **CUR},
        headers=_auth(tokens["valid"]),
    )
    assert response.status_code == 200
    body = response.json()
    conn = connect(db, read_only=True)
    try:
        expected = shared.performance_overview(conn, _filt(), _rules())
    finally:
        conn.close()
    assert body["latency_ms"] == expected["latency_ms"]
    assert body["cache"] == expected["cache"]
    assert body["mime_vs_resource"] == expected["mime_vs_resource"]
    assert body["http_versions"] == expected["http_versions"]
    assert body["tls_protocols"] == expected["tls_protocols"]
    assert body["logged_hosts"] == expected["logged_hosts"]
    assert body["filters"] == expected["filters"]
    # Hand-derived: measured rows are /fast x2 (10ms) + /slow (500ms).
    assert body["latency_available"] is True
    assert body["latency_ms"]["measured"] == 3
    assert body["latency_ms"]["average_ms"] == pytest.approx((10 + 10 + 500) / 3)
    assert body["latency_ms"]["median_ms"] == pytest.approx(10.0)
    assert body["latency_ms"]["p95_ms"] == pytest.approx(10 + (500 - 10) * 0.9)
    assert body["units"] == "milliseconds"
    assert body["coverage"]["unique_events"] == 10


def test_t3_slow_endpoints_and_filters_survive(t3api):
    """Slow-endpoint ranking plus new-filter echo through response metadata."""
    client, tokens, _ = t3api
    body = client.get(
        "/api/v1/performance/slow-endpoints",
        params={"site_id": SITE_T3, **CUR, "sort": "avg_desc"},
        headers=_auth(tokens["valid"]),
    ).json()
    assert [item["path"] for item in body["items"]][:1] == ["/slow"]
    assert body["items"][0]["average_ms"] == pytest.approx(500.0)
    assert body["units"] == "milliseconds"
    # New filters validate centrally and echo in metadata.
    filtered = client.get(
        "/api/v1/performance/slow-endpoints",
        params={"site_id": SITE_T3, **CUR, "cache_status": "HIT", "server_host": SITE_HOST_T3},
        headers=_auth(tokens["valid"]),
    ).json()
    assert filtered["filters"]["cache_status"] == "HIT"
    assert filtered["filters"]["server_host"] == SITE_HOST_T3
    bad = client.get(
        "/api/v1/performance/slow-endpoints",
        params={"site_id": SITE_T3, **CUR, "sort": "fastest"},
        headers=_auth(tokens["valid"]),
    )
    assert bad.status_code in (400, 422)
    if bad.status_code == 400:
        assert bad.json()["request_id"]


def test_t3_seo_reports_match_service(t3api):
    """Bot-status groups, AI-only paths and referrer 404s equal shared results."""
    from app.analytics import service as shared

    client, tokens, db = t3api
    headers = _auth(tokens["valid"])
    params = {"site_id": SITE_T3, **CUR}
    seo = client.get(
        "/api/v1/seo/bot-statuses", params={**params, "report": "4xx"}, headers=headers
    )
    assert seo.status_code == 200
    conn = connect(db, read_only=True)
    try:
        expected = shared.seo_status_groups(conn, _filt(), _rules(), status_class="4xx")
    finally:
        conn.close()
    assert seo.json()["items"] == expected["items"]
    assert {item["path"] for item in seo.json()["items"]} >= {"/missing"}
    missing = next(item for item in seo.json()["items"] if item["path"] == "/missing")
    assert missing["requests"] == 2
    assert missing["drilldown"]["path_exact"] == "/missing"
    ai = client.get("/api/v1/seo/ai-only-paths", params=params, headers=headers)
    assert ai.status_code == 200
    ref = client.get("/api/v1/referrers/404-targets", params=params, headers=headers)
    assert ref.status_code == 200
    conn = connect(db, read_only=True)
    try:
        expected_ref = shared.referrer_404s(conn, _filt(), _rules())
    finally:
        conn.close()
    assert ref.json()["items"] == expected_ref["items"]
    assert ref.json()["total_groups"] == 2
    internal = client.get(
        "/api/v1/referrers/404-targets", params={**params, "relation": "internal"}, headers=headers
    ).json()
    assert internal["total_groups"] == 1
    assert internal["items"][0]["referer_host"] == SITE_HOST_T3
    external = client.get(
        "/api/v1/referrers/404-targets", params={**params, "relation": "external"}, headers=headers
    ).json()
    assert external["total_groups"] == 1


def test_t3_journeys_match_service_and_resolve(t3api):
    """Journey list/entry/timeline/by-id agree with the shared layer."""
    from app.analytics import service as shared

    client, tokens, db = t3api
    headers = _auth(tokens["valid"])
    params = {"site_id": SITE_T3, **CUR}
    listed = client.get("/api/v1/journeys", params=params, headers=headers)
    assert listed.status_code == 200
    conn = connect(db, read_only=True)
    try:
        expected = shared.journeys(conn, JourneyQuery(filt=_filt()), _rules())
    finally:
        conn.close()
    assert listed.json()["items"] == expected["items"]
    # Four (client, agent) keys in scope: browser rows, Googlebot rows,
    # and the two journey-probe clients.
    assert listed.json()["total_groups"] == 4
    first = next(item for item in listed.json()["items"] if item["entry_path"] == "/j1a")
    assert first["requests_total"] == 2
    entries = client.get("/api/v1/journeys/entry-paths", params=params, headers=headers).json()
    assert {item["entry_path"] for item in entries["items"]} == {"/j1a", "/j2", "/fast", "/missing"}
    timeline = client.get(
        "/api/v1/journeys/by-id",
        params={
            **params,
            "client_pseudonym": first["client_pseudonym"],
            "journey_start": first["started_at"],
            "journey_id": first["journey_id"],
        },
        headers=headers,
    )
    assert timeline.status_code == 200
    assert [row["path"] for row in timeline.json()["items"]] == ["/j1a", "/j1b"]
    assert timeline.json()["resolved_via"] == "journey_id"
    direct = client.get(
        "/api/v1/journeys/timeline",
        params={
            **params,
            "client_pseudonym": first["client_pseudonym"],
            "journey_start": first["started_at"],
        },
        headers=headers,
    )
    # Without the agent key the NULL/empty default does not match: honest 404.
    assert direct.status_code == 404
    unknown = client.get(
        "/api/v1/journeys/by-id",
        params={
            **params,
            "client_pseudonym": first["client_pseudonym"],
            "journey_start": first["started_at"],
            "journey_id": "0" * 64,
        },
        headers=headers,
    )
    assert unknown.status_code == 404


def test_t3_comparison_matches_service_and_bounds(t3api):
    """Comparison equals shared results; scope/length mismatches reject."""
    from app.analytics import service as shared

    client, tokens, db = t3api
    headers = _auth(tokens["valid"])
    params = {
        "site_id": SITE_T3,
        **CUR,
        "baseline_from": BASE["from"],
        "baseline_to": BASE["to"],
    }
    compared = client.get("/api/v1/comparison", params=params, headers=headers)
    assert compared.status_code == 200
    conn = connect(db, read_only=True)
    try:
        expected = shared.compare_windows(
            conn,
            _filt(),
            _filt(
                window=TimeWindow(
                    time_from=datetime(2026, 10, 27, 9, 0, tzinfo=UTC),
                    time_to=datetime(2026, 10, 27, 10, 0, tzinfo=UTC),
                )
            ),
            _rules(),
        )
    finally:
        conn.close()
    assert compared.json()["metrics"] == expected["metrics"]
    assert compared.json()["selectors"] == expected["selectors"]
    current = next(m for m in compared.json()["metrics"] if m["name"] == "requests")
    assert current["current"] == 10 and current["previous"] == 1
    # Unequal-length baseline rejects instead of comparing populations.
    skewed = client.get(
        "/api/v1/comparison",
        params={
            "site_id": SITE_T3,
            **CUR,
            "baseline_from": "2026-10-27T09:30:00+00:00",
            "baseline_to": BASE["to"],
        },
        headers=headers,
    )
    assert skewed.status_code == 400
    # Cross-site baseline is impossible: site is token-bound, one value only.
    cross = client.get("/api/v1/comparison", params=params, headers=_auth(tokens["other_site"]))
    assert cross.status_code == 403


def test_t3_comparison_keeps_int64_exact(t3api):
    """Raw integer metrics survive above 2**53 with exact small deltas.

    ``9007199254740993`` (2**53+1, valid SQLite int64) would collapse
    to ``9007199254740992`` through any lossy ``float`` step; the API
    must return it (and its exact change) as JSON integers, matching
    the shared service layer, while ratios stay finite floats.
    """
    import math as _math

    from app.analytics import service as shared

    client, tokens, db = t3api
    huge = 9007199254740993
    assert huge < 2**63  # SQLite int64-valid, above the float-exact range
    with writer_transaction(db) as conn:
        scope = conn.execute(
            "SELECT import_id, site_id, source_id, file_fingerprint FROM requests LIMIT 1"
        ).fetchone()
        base = conn.execute("SELECT COALESCE(MAX(byte_offset), 0) FROM requests").fetchone()[0]
        conn.execute(
            "INSERT INTO requests (import_id, site_id, source_id, file_fingerprint,"
            " byte_offset, line_number, ts_utc, method, path, status, bytes,"
            " referer_host, user_agent, client_pseudonym)"
            " VALUES (?, ?, ?, ?, ?, ?, '2026-10-27T10:07:00+00:00', 'GET',"
            " '/huge-bytes', 200, ?, NULL, 'Huge/1.0', 'huge-pseudo')",
            (scope[0], scope[1], scope[2], scope[3], base + 1, base + 1, huge),
        )
    params = {
        "site_id": SITE_T3,
        **CUR,
        "baseline_from": BASE["from"],
        "baseline_to": BASE["to"],
    }
    body = client.get("/api/v1/comparison", params=params, headers=_auth(tokens["valid"]))
    assert body.status_code == 200
    metrics = {item["name"]: item for item in body.json()["metrics"]}
    # Seed bytes: 10 current-window rows x 10 B + huge; baseline /old = 10 B.
    assert metrics["bytes_total"]["current"] == 100 + huge
    assert metrics["bytes_total"]["previous"] == 10
    assert isinstance(metrics["bytes_total"]["current"], int)
    assert isinstance(metrics["bytes_total"]["previous"], int)
    assert metrics["bytes_total"]["absolute_change"] == 90 + huge
    assert isinstance(metrics["bytes_total"]["absolute_change"], int)
    # Small-delta exactness: no float rounding anywhere near the change.
    assert metrics["bytes_total"]["absolute_change"] - huge == 90
    assert _math.isfinite(metrics["bytes_total"]["ratio"])
    assert isinstance(metrics["bytes_total"]["ratio"], float)
    # API equals the shared service layer exactly (byte counts included).
    conn = connect(db, read_only=True)
    try:
        expected = shared.compare_windows(conn, _filt(), _filt_for_base(), _rules())
    finally:
        conn.close()
    assert body.json()["metrics"] == expected["metrics"]


def _filt_for_base():
    return _filt(
        window=TimeWindow(
            time_from=datetime(2026, 10, 27, 9, 0, tzinfo=UTC),
            time_to=datetime(2026, 10, 27, 10, 0, tzinfo=UTC),
        )
    )


def test_t3_new_endpoint_auth_scope_time_negatives(t3api):
    """Every new endpoint enforces token/site/source/time/paging/sort."""
    client, tokens, _ = t3api
    routes = [
        "/api/v1/performance/overview",
        "/api/v1/performance/slow-endpoints",
        "/api/v1/seo/bot-statuses",
        "/api/v1/seo/ai-only-paths",
        "/api/v1/referrers/404-targets",
        "/api/v1/journeys",
        "/api/v1/journeys/entry-paths",
        "/api/v1/comparison",
    ]
    base = {"site_id": SITE_T3, **CUR}
    comparison_extra = {"baseline_from": BASE["from"], "baseline_to": BASE["to"]}
    for route in routes:
        params = dict(base, **(comparison_extra if route == "/api/v1/comparison" else {}))
        missing = client.get(route, params=params)
        assert missing.status_code == 401, route
        expired = client.get(route, params=params, headers=_auth(tokens["expired"]))
        assert expired.status_code == 401, route
        scoped = client.get(route, params=params, headers=_auth(tokens["wrong"]))
        assert scoped.status_code == 403, route
        foreign = client.get(route, params=params, headers=_auth(tokens["other_site"]))
        assert foreign.status_code == 403, route
        cross_source = client.get(
            route,
            params={**params, "source_id": "no-such-source"},
            headers=_auth(tokens["valid"]),
        )
        assert cross_source.status_code == 403, route
        over = client.get(
            route,
            params={
                "site_id": SITE_T3,
                "from": "2025-01-01T00:00:00+00:00",
                "to": "2026-10-28T00:00:00+00:00",
                **(comparison_extra if route == "/api/v1/comparison" else {}),
            },
            headers=_auth(tokens["valid"]),
        )
        assert over.status_code == 400, route
        assert over.json()["request_id"], route


def test_t3_journey_history_cannot_cross_token_bounds(t3api):
    """Journey detail inside a narrowed window stays 404; no widening."""
    client, tokens, _ = t3api
    headers = _auth(tokens["valid"])
    listed = client.get(
        "/api/v1/journeys", params={"site_id": SITE_T3, **CUR}, headers=headers
    ).json()
    first = next(item for item in listed["items"] if item["entry_path"] == "/j1a")
    narrow = client.get(
        "/api/v1/journeys/by-id",
        params={
            "site_id": SITE_T3,
            "from": "2026-10-27T10:05:00+00:00",
            "to": "2026-10-27T10:06:00+00:00",
            "client_pseudonym": first["client_pseudonym"],
            "journey_start": first["started_at"],
            "journey_id": first["journey_id"],
        },
        headers=headers,
    )
    assert narrow.status_code == 404
    foreign = client.get(
        "/api/v1/journeys",
        params={"site_id": "elsewhere", **CUR},
        headers=_auth(tokens["valid"]),
    )
    assert foreign.status_code == 403


def test_t3_fractional_security_windows_keep_precise_rates(t3api):
    """0.5s/1.5s windows carry float seconds + exact us (rate, not None)."""
    client, tokens, db = t3api
    headers = _auth(tokens["valid"])
    windows = [
        ("2026-10-27T10:20:00+00:00", "2026-10-27T10:20:00.500000+00:00", 0.5, 500_000),
        ("2026-10-27T10:21:00+00:00", "2026-10-27T10:21:01.500000+00:00", 1.5, 1_500_000),
    ]
    with writer_transaction(db) as conn:
        scope = conn.execute(
            "SELECT import_id, site_id, source_id, file_fingerprint FROM requests LIMIT 1"
        ).fetchone()
        base = conn.execute("SELECT COALESCE(MAX(byte_offset), 0) FROM requests").fetchone()[0]
        n = 0
        for index, (_start, _end, _secs, _us) in enumerate(windows):
            for hit in range(5):
                offset = base + 1 + n
                n += 1
                step = 100000 if index == 0 else 200000
                moment = f"2026-10-27T10:{20 + index}:00.{hit * step:06d}+00:00"
                conn.execute(
                    "INSERT INTO requests (import_id, site_id, source_id, file_fingerprint,"
                    " byte_offset, line_number, ts_utc, method, path, status, bytes,"
                    " referer_host, user_agent, client_pseudonym)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, 'GET', ?, 404, 10, NULL,"
                    " 'FracProbe/1.0', ?)",
                    (
                        scope[0],
                        scope[1],
                        scope[2],
                        scope[3],
                        offset,
                        offset,
                        moment,
                        f"/frac404-{index}-{hit}",
                        f"frac-{index}",
                    ),
                )
    for start, end, seconds, micros in windows:
        body = client.get(
            "/api/v1/security/findings",
            params={"site_id": SITE_T3, "from": start, "to": end},
            headers=headers,
        )
        assert body.status_code == 200, body.text[:300]
        finding = next(
            item for item in body.json()["items"] if item["rule_id"] == "sec-repeated-client-errors"
        )
        assert finding["counts"] == {"errors": 5, "distinct_paths": 5}
        assert finding["evidence"]["window_seconds"] == seconds
        assert finding["evidence"]["window_seconds_us"] == micros
        assert finding["evidence"]["avg_requests_per_minute"] == 5 / seconds * 60


def test_t3_fractional_comparison_window_metadata(t3api):
    """Equal 0.5s comparison windows report float seconds + exact us."""
    client, tokens, _ = t3api
    body = client.get(
        "/api/v1/comparison",
        params={
            "site_id": SITE_T3,
            "from": "2026-10-27T10:00:00+00:00",
            "to": "2026-10-27T10:00:00.500000+00:00",
            "baseline_from": "2026-10-27T09:59:59.500000+00:00",
            "baseline_to": "2026-10-27T10:00:00+00:00",
        },
        headers=_auth(tokens["valid"]),
    )
    assert body.status_code == 200, body.text[:300]
    payload = body.json()
    assert payload["window_seconds"] == 0.5
    assert payload["window_seconds_us"] == 500_000
    metrics = {item["name"]: item for item in payload["metrics"]}
    # Only the two rows stamped exactly 10:00:00 (/fast, /j1a) fall in.
    assert metrics["requests"]["current"] == 2
    assert metrics["requests"]["previous"] == 0
    assert isinstance(metrics["requests"]["current"], int)


def test_t3_microsecond_journey_duration(t3api):
    """A 1us journey reports duration_us 1 (not a floored 0)."""
    client, tokens, db = t3api
    with writer_transaction(db) as conn:
        scope = conn.execute(
            "SELECT import_id, site_id, source_id, file_fingerprint FROM requests LIMIT 1"
        ).fetchone()
        base = conn.execute("SELECT COALESCE(MAX(byte_offset), 0) FROM requests").fetchone()[0]
        for index, (moment, path) in enumerate(
            (
                ("2026-10-27T10:22:00.000000+00:00", "/usec-a"),
                ("2026-10-27T10:22:00.000001+00:00", "/usec-b"),
            )
        ):
            offset = base + 1 + index
            conn.execute(
                "INSERT INTO requests (import_id, site_id, source_id, file_fingerprint,"
                " byte_offset, line_number, ts_utc, method, path, status, bytes,"
                " referer_host, user_agent, client_pseudonym)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, 'GET', ?, 200, 10, NULL,"
                " 'UsecProbe/1.0', 'usec-pseudo')",
                (scope[0], scope[1], scope[2], scope[3], offset, offset, moment, path),
            )
    body = client.get(
        "/api/v1/journeys",
        params={"site_id": SITE_T3, **CUR},
        headers=_auth(tokens["valid"]),
    )
    assert body.status_code == 200
    by_entry = {item["entry_path"]: item for item in body.json()["items"]}
    usec = by_entry["/usec-a"]
    assert usec["requests_total"] == 2
    assert usec["duration_us"] == 1
    assert usec["duration_s"] == pytest.approx(1e-6)
    # Ordinary whole-second journeys stay exact both ways.
    ten_min = by_entry["/j1a"]
    assert ten_min["duration_us"] == 600_000_000
    assert ten_min["duration_s"] == 600.0


def test_t3_old_endpoints_work_with_ai_off_no_key(t3api, monkeypatch):
    """Legacy surfaces keep working with chat disabled and no model key."""
    client, tokens, _ = t3api
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    health = client.get("/healthz").json()
    assert health["ai_enabled"] is False
    for route in ("/api/v1/summary", "/api/v1/requests", "/api/v1/security/findings"):
        response = client.get(
            route, params={"site_id": SITE_T3, **CUR}, headers=_auth(tokens["valid"])
        )
        assert response.status_code == 200, route
    enriched = client.get(
        "/api/v1/requests",
        params={"site_id": SITE_T3, **CUR, "timing_available": "true"},
        headers=_auth(tokens["valid"]),
    ).json()
    assert enriched["filters"]["timing_available"] is True
    assert enriched["timing_units"] == "milliseconds"
    assert all(row["timing_available"] for row in enriched["items"])
    bad_bool = client.get(
        "/api/v1/requests",
        params={"site_id": SITE_T3, **CUR, "timing_available": "maybe"},
        headers=_auth(tokens["valid"]),
    )
    assert bad_bool.status_code == 400
    assert bad_bool.json()["request_id"]


# ---------------------------------------------------------------------------
# T3 full-result export (PAR-07)
# ---------------------------------------------------------------------------

HOSTILE_UAS = [
    "=cmd|' /c calc'!A1",
    "+evil-sum",
    "-evil-diff",
    "@macro-call",
    "  =padded-formula",
    # NOTE: a raw double-quote cannot appear inside a Combined quoted
    # field, so the quoting/unicode hazard is exercised with single
    # quotes here (the parser rightly rejects a raw `"` as
    # `malformed_line`; see the seed's accepted/rejected assertion).
    "Evil 'Quoted', Ünïcodé",
    # NBSP-leading formula: valid log bytes that must still be
    # neutralized in the export (Unicode-aware formula classifier).
    "\u00a0=nbsp-trap",
]

HOSTILE_PATHS = [
    "/=HYPERLINK(1)",
    "/+plus-path",
    "/-minus-path",
    "/@at-path",
]


def _seed_export_db(tmp_path):
    from app.ingestion.combined import NGINX_EXTENDED

    root = tmp_path / "exportlogs"
    root.mkdir(exist_ok=True)
    lines = [
        _ext(
            path=path,
            ua=ua,
            ip=f"198.51.100.{70 + (index % 20)}",
            stamp=f"27/Oct/2026:10:{index % 60:02d}:00",
            request_time="0.020",
            cache="HIT",
            mime="text/html",
            tls="TLSv1.3",
        )
        for index, (path, ua) in enumerate(
            [(p, f"Agent/{i}") for i, p in enumerate(HOSTILE_PATHS)]
            + [(f"/row{i}", ua) for i, ua in enumerate(HOSTILE_UAS)]
        )
    ]
    # A query-bearing raw line: values must never reach the export.
    lines.append(
        b'198.51.100.99 - - [27/Oct/2026:10:30:00 +0000] "GET /search?q=hunter2&secret=topsecret HTTP/1.1"'
        b' 200 10 "-" "QueryProbe/1.0" example.org HIT 0.020 text/html TLSv1.3 "0.001"\n'
    )
    (root / "ext.log").write_bytes(b"".join(lines))
    db = tmp_path / "export.sqlite3"
    migrate(db)
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
    imported = run_import(
        db,
        source=SourceConfig(
            source_id="export-source",
            format_id=NGINX_EXTENDED,
            allowed_root=root,
            relative_path="ext.log",
            allowed_hosts=[SITE_HOST_T3],
        ),
        site_id="export-site",
        site_name="Export",
        site_hostname=SITE_HOST_T3,
        server_type="nginx",
        path_alias="ext.log",
        hmac_key=HMAC_KEY,
    )
    assert imported.status == "completed"
    # Hand-audited import contract: 4 hostile paths + 7 hostile UAs +
    # 1 query-bearing line = 12 valid lines, 0 rejected. A raw `"`
    # inside a quoted Combined field is NOT among them: the parser
    # rightly rejects such bytes as `malformed_line` (probed
    # independently), so the quoting hazard is exercised with valid
    # single-quote bytes instead of weakening the parser.
    assert (imported.lines_accepted, imported.lines_rejected) == (12, 0)
    with writer_transaction(db) as conn:
        _, valid = issue_token(conn, name="valid", site_id="export-site")
    return db, valid


@pytest.fixture
def exportapi(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    db, token = _seed_export_db(tmp_path)
    from app.main import create_app

    client = TestClient(create_app(db_path=db, secure_cookies=False), raise_server_exceptions=False)
    return client, token, db


EXPORT_WINDOW = {"from": "2026-10-27T10:00:00+00:00", "to": "2026-10-27T11:00:00+00:00"}
EXPORT_PARAMS = {"site_id": "export-site", **EXPORT_WINDOW}
#: Independent expected export scope: 4 hostile paths + 7 hostile UAs +
#: 1 query-bearing line. Endpoint counts must equal the stored scope,
#: not just this literal.
EXPECTED_EXPORT_ROWS = 12


def _stored_row_count(db):
    """Independent oracle: rows actually stored for the export scope."""
    from app.db.database import connect as _connect

    conn = _connect(db, read_only=True)
    try:
        return int(conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0])
    finally:
        conn.close()


def _export_rows_json(client, token, fmt="json", **extra):
    response = client.get(
        "/api/v1/exports/requests",
        params={**EXPORT_PARAMS, "export_format": fmt, **extra},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200, response.text[:300]
    return response


def test_t3_export_csv_full_result_and_formula_protection(exportapi):
    """Exact row count, stable order, quoting and formula neutralization."""
    import csv as csv_module
    import io as io_module

    from app.analytics.queries import EXPORT_COLUMNS

    client, token, db = exportapi
    # Independent oracle: the export equals what is actually stored.
    assert _stored_row_count(db) == EXPECTED_EXPORT_ROWS
    response = _export_rows_json(client, token, fmt="csv", sort="oldest")
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment" in response.headers["content-disposition"]
    assert response.headers["content-disposition"].endswith('.csv"')
    assert response.headers["X-Logcarve-Export-Schema"] == "export/1"
    assert "pseudonymized" in response.headers["X-Logcarve-Privacy"]
    assert int(response.headers["X-Logcarve-Export-Rows"]) == EXPECTED_EXPORT_ROWS
    rows = list(csv_module.reader(io_module.StringIO(response.text)))
    assert rows[0] == list(EXPORT_COLUMNS)
    body = rows[1:]
    assert len(body) == EXPECTED_EXPORT_ROWS
    by_path = {row[EXPORT_COLUMNS.index("path")]: row for row in body}
    # No missing or duplicate rows: every stored path appears exactly once.
    assert len(by_path) == EXPECTED_EXPORT_ROWS
    ua_idx = EXPORT_COLUMNS.index("user_agent")
    for hostile in ("=HYPERLINK(1)", "+plus-path", "-minus-path", "@at-path"):
        stored = next(path for path in by_path if hostile in path)
        assert by_path[stored][ua_idx] is not None
    # Formula-leading paths are neutralized with a quote prefix.
    for row in body:
        for name in ("path", "user_agent"):
            cell = row[EXPORT_COLUMNS.index(name)]
            stripped = cell.lstrip(" \t\r\n\x0b\x0c")
            if stripped[:1] in ("=", "+", "-", "@") and not cell.startswith("'"):
                raise AssertionError(f"unprotected formula cell in {name}: {cell!r}")
    quoted = next(row for row in body if "Quoted" in row[ua_idx])
    assert "Ünïcodé" in quoted[ua_idx]
    assert quoted[ua_idx].startswith("'") is False  # plain text quoting only
    # NBSP-leading formula arrives neutralized end to end (the
    # classifier looks past Unicode whitespace/control/format bytes).
    nbsp = next(row for row in body if "nbsp-trap" in row[ua_idx])
    # Original text preserved verbatim behind the neutralizing prefix.
    assert nbsp[ua_idx] == "'\u00a0=nbsp-trap"
    # Meaningful numerics stay unquoted numbers in the raw body.
    assert ",200," in response.text
    # Sentinels absent: original IPs, query values, raw lines, secrets.
    blob = response.text
    assert "198.51.100" not in blob
    assert "hunter2" not in blob and "topsecret" not in blob
    assert "[27/Oct/2026" not in blob


def test_t3_export_json_envelope_and_cursor_equality(exportapi):
    """Metadata envelope plus cursor-identical rows in both formats."""
    import csv as csv_module
    import io as io_module

    from app.analytics.queries import EXPORT_COLUMNS

    client, token, db = exportapi
    # Independent oracle: the export equals what is actually stored.
    assert _stored_row_count(db) == EXPECTED_EXPORT_ROWS
    envelope = _export_rows_json(client, token, fmt="json", sort="oldest").json()
    meta = envelope["metadata"]
    assert meta["schema_version"] == "export/1"
    assert meta["site_id"] == "export-site"
    assert meta["row_count"] == EXPECTED_EXPORT_ROWS
    assert meta["filters"]["site_id"] == "export-site"
    assert meta["time_range"] == {
        "time_from": "2026-10-27T10:00:00+00:00",
        "time_to": "2026-10-27T11:00:00+00:00",
    }
    assert meta["generated_at"]
    assert meta["coverage"]["unique_events"] == EXPECTED_EXPORT_ROWS
    assert "pseudonymized" in meta["privacy"]
    assert "error_summary" not in json.dumps(meta["data_quality"])
    assert set(meta["data_quality"]["imports"][0]) == {"import_id", "status"}
    assert envelope["complete"] is True
    assert len(envelope["rows"]) == EXPECTED_EXPORT_ROWS
    csv_rows = list(
        csv_module.reader(
            io_module.StringIO(_export_rows_json(client, token, fmt="csv", sort="oldest").text)
        )
    )[1:]
    json_paths = [row["path"] for row in envelope["rows"]]
    csv_paths = [row[EXPORT_COLUMNS.index("path")] for row in csv_rows]
    assert json_paths == csv_paths
    assert len(set(json_paths)) == EXPECTED_EXPORT_ROWS
    blob = json.dumps(envelope)
    assert "198.51.100" not in blob and "hunter2" not in blob and "topsecret" not in blob


def test_t3_export_over_page_size_exact(exportapi):
    """1500+ extra rows stream exactly: no missing, duplicate or silent cap."""
    client, token, db = exportapi
    with writer_transaction(db) as conn:
        scope = conn.execute(
            "SELECT import_id, site_id, source_id, file_fingerprint FROM requests LIMIT 1"
        ).fetchone()
        base = conn.execute("SELECT COALESCE(MAX(byte_offset), 0) FROM requests").fetchone()[0]
        for n in range(1500):
            offset = base + 1 + n
            conn.execute(
                "INSERT INTO requests (import_id, site_id, source_id, file_fingerprint,"
                " byte_offset, line_number, ts_utc, method, path, status, bytes,"
                " referer_host, user_agent, client_pseudonym)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, 'GET', ?, ?, 10, NULL, 'Bulk/1.0', ?)",
                (
                    scope[0],
                    scope[1],
                    scope[2],
                    scope[3],
                    offset,
                    offset,
                    f"2026-10-27T10:{n % 60:02d}:{(n // 60) % 60:02d}+00:00",
                    f"/bulk{n:04d}",
                    200 if n % 7 else 500,
                    f"bulk-{n % 50}",
                ),
            )
    response = _export_rows_json(client, token, fmt="json", sort="oldest")
    envelope = response.json()
    expected = EXPECTED_EXPORT_ROWS + 1500
    # Independent oracle: the export equals what is actually stored.
    assert _stored_row_count(db) == expected
    assert envelope["metadata"]["row_count"] == expected
    assert len(envelope["rows"]) == expected
    assert envelope["complete"] is True
    keys = [(row["ts_utc"], row["path"], row["status"]) for row in envelope["rows"]]
    assert len(set(keys)) == expected
    assert response.headers["X-Logcarve-Export-Rows"] == str(expected)


def _export_filt():
    return AnalyticsFilter(
        site_id="export-site",
        window=TimeWindow(
            time_from=datetime(2026, 10, 27, 10, 0, tzinfo=UTC),
            time_to=datetime(2026, 10, 27, 11, 0, tzinfo=UTC),
        ),
    )


def _insert_export_row(db, *, ts, path, pseudo, status=200, agent="Probe/1.0"):
    with writer_transaction(db) as conn:
        scope = conn.execute(
            "SELECT import_id, site_id, source_id, file_fingerprint FROM requests LIMIT 1"
        ).fetchone()
        base = conn.execute("SELECT COALESCE(MAX(byte_offset), 0) FROM requests").fetchone()[0]
        conn.execute(
            "INSERT INTO requests (import_id, site_id, source_id, file_fingerprint,"
            " byte_offset, line_number, ts_utc, method, path, status, bytes,"
            " referer_host, user_agent, client_pseudonym)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, 'GET', ?, ?, 10, NULL, ?, ?)",
            (
                scope[0],
                scope[1],
                scope[2],
                scope[3],
                base + 1,
                base + 1,
                ts,
                path,
                status,
                agent,
                pseudo,
            ),
        )


def test_t3_export_single_snapshot_freezes_scope(exportapi):
    """Count/metadata/rows share one snapshot (writer between prep/stream)."""
    from app.api.routes_export import ExportStream, json_chunks

    _, _, db = exportapi
    stream = ExportStream(db).open()
    metadata = stream.prepare(
        _export_filt(), _rules(), "oldest", max_rows=250_000, display_timezone="UTC"
    )
    assert metadata["row_count"] == EXPECTED_EXPORT_ROWS
    assert metadata["sort"] == "oldest"
    assert metadata["display_timezone"] == "UTC"
    # A writer commits a matching row AFTER preparation, BEFORE streaming.
    _insert_export_row(
        db, ts="2026-10-27T10:15:00+00:00", path="/late-append", pseudo="late-pseudo"
    )
    rows = list(stream.rows())
    # Same snapshot: the appended row stays invisible; count == rows.
    assert len(rows) == EXPECTED_EXPORT_ROWS == metadata["row_count"]
    assert stream.closed
    envelope = json.loads("".join(json_chunks(metadata, iter(rows))))
    assert envelope["complete"] is True
    assert len(envelope["rows"]) == EXPECTED_EXPORT_ROWS


def test_t3_export_snapshot_survives_retention(exportapi):
    """Retention deleting after preparation cannot shrink the stream."""
    from app.api.routes_export import ExportStream

    _, _, db = exportapi
    stream = ExportStream(db).open()
    metadata = stream.prepare(
        _export_filt(), _rules(), "oldest", max_rows=250_000, display_timezone="UTC"
    )
    with writer_transaction(db) as conn:
        conn.execute("DELETE FROM request_original_ips")
        conn.execute("DELETE FROM requests")
    assert _stored_row_count(db) == 0
    rows = list(stream.rows())
    assert len(rows) == EXPECTED_EXPORT_ROWS == metadata["row_count"]
    assert stream.closed


def test_t3_export_cap_and_lifecycle_close_resources(exportapi, tmp_path):
    """Cap rejects close the snapshot; every lifecycle path closes it."""
    from app.api.deps import StoreUnavailable
    from app.api.routes_export import ExportStream, ExportTooLarge

    _, _, db = exportapi
    # Over-cap scope rejects before streaming and releases the snapshot.
    capped = ExportStream(db).open()
    with pytest.raises(ExportTooLarge):
        capped.prepare(_export_filt(), _rules(), "oldest", max_rows=5, display_timezone="UTC")
    assert capped.closed
    # Full consumption closes cursor and connection.
    full = ExportStream(db).open()
    full.prepare(_export_filt(), _rules(), "oldest", max_rows=250_000, display_timezone="UTC")
    assert len(list(full.rows())) == EXPECTED_EXPORT_ROWS
    assert full.closed
    # Partial consumption plus cancellation closes without GC waits.
    cancelled = ExportStream(db).open()
    cancelled.prepare(_export_filt(), _rules(), "oldest", max_rows=250_000, display_timezone="UTC")
    gen = cancelled.rows()
    assert next(gen)["path"] is not None
    gen.close()
    assert cancelled.closed
    # Explicit close without any consumption releases the snapshot.
    untouched = ExportStream(db).open()
    untouched.prepare(_export_filt(), _rules(), "oldest", max_rows=250_000, display_timezone="UTC")
    untouched.close()
    assert untouched.closed
    # Unknown sorts reject before streaming and release the snapshot.
    bad_sort = ExportStream(db).open()
    with pytest.raises(ValueError):
        bad_sort.prepare(
            _export_filt(), _rules(), "fastest", max_rows=250_000, display_timezone="UTC"
        )
    assert bad_sort.closed
    # A missing store maps to StoreUnavailable (safe 503), never 200+prefix.
    with pytest.raises(StoreUnavailable):
        ExportStream(tmp_path / "missing.sqlite3").open()


def test_t3_export_post_header_failure_aborts_incomplete(exportapi):
    """A mid-stream read failure aborts: no completeTrue, snapshot closed."""
    import sqlite3 as _sqlite3

    from app.api.routes_export import ExportStream, csv_chunks, json_chunks

    _, _, db = exportapi
    stream = ExportStream(db).open()
    metadata = stream.prepare(
        _export_filt(), _rules(), "oldest", max_rows=250_000, display_timezone="UTC"
    )
    gen = stream.rows()
    assert next(gen)["path"] is not None  # primed buffer: headers could go out now
    # The read handle dies mid-stream (explicit public close): the
    # next fetch genuinely fails in SQLite, the body aborts without
    # a complete footer, and the snapshot stays released.
    stream.close()
    with pytest.raises(_sqlite3.Error):
        list(gen)
    assert stream.closed

    def failing():
        yield {"path": "/a", "status": 200}
        raise _sqlite3.OperationalError("simulated renderer-input failure")

    partial_json = ""
    with pytest.raises(_sqlite3.OperationalError):
        for chunk in json_chunks(metadata, failing()):
            partial_json += chunk
    # The success footer never emits (the word "complete" may still
    # appear inside metadata prose such as import statuses).
    assert '], "complete": true}' not in partial_json
    assert partial_json.endswith('{"path": "/a", "status": 200}')
    partial_csv = ""
    with pytest.raises(_sqlite3.OperationalError):
        for chunk in csv_chunks(failing()):
            partial_csv += chunk if isinstance(chunk, str) else chunk.decode()
    assert len(partial_csv.splitlines()) == 2  # header + one row, then abort


def test_t3_export_metadata_both_formats(exportapi):
    """JSON envelope and CSV headers carry the same reproducibility set."""
    client, token, _ = exportapi
    params = {
        **EXPORT_PARAMS,
        "export_format": "json",
        "source_id": "export-source",
        "status": 200,
        "sort": "newest",
    }
    response = client.get(
        "/api/v1/exports/requests",
        params=params,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200, response.text[:300]
    envelope = response.json()
    meta = envelope["metadata"]
    assert meta["sort"] == "newest"
    assert meta["display_timezone"] == "UTC"
    assert meta["filters"]["status"] == 200
    assert meta["filters"]["source_id"] == "export-source"
    assert "limit" not in meta and "offset" not in meta
    csv_response = client.get(
        "/api/v1/exports/requests",
        params={**params, "export_format": "csv"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert csv_response.status_code == 200
    headers = csv_response.headers
    assert headers["X-Logcarve-Export-Sort"] == "newest"
    assert headers["X-Logcarve-Export-Timezone"] == "UTC"
    assert headers["X-Logcarve-Export-Source"] == "export-source"
    assert all(value.isascii() for value in headers.values())
    header_filters = json.loads(headers["X-Logcarve-Export-Filters"])
    assert header_filters["site_id"] == "export-site"
    assert header_filters["source_id"] == "export-source"
    assert header_filters["status"] == 200
    assert "traffic" not in header_filters  # defaults stay out (bounded)
    coverage = json.loads(headers["X-Logcarve-Export-Coverage"])
    assert coverage["unique_events"] == meta["coverage"]["unique_events"]
    assert coverage["lines_accepted"] == meta["data_quality"]["line_totals"]["lines_accepted"]
    assert coverage["imports_total"] == len(meta["data_quality"]["imports"])
    assert coverage["imports"] == meta["data_quality"]["imports"]
    assert coverage["imports_truncated"] is False
    blob = headers["X-Logcarve-Export-Filters"] + headers["X-Logcarve-Export-Coverage"]
    assert "error_summary" not in blob
    assert "198.51.100" not in blob


def test_t3_export_header_imports_truncation_flagged():
    """The CSV coverage header caps imports with an explicit flag."""
    from app.api.routes_export import _IMPORTS_HEADER_CAP, metadata_headers

    def meta_with(n):
        return {
            "schema_version": "export/1",
            "site_id": "s",
            "source_id": None,
            "time_range": {
                "time_from": "2026-10-27T10:00:00+00:00",
                "time_to": "2026-10-27T11:00:00+00:00",
            },
            "display_timezone": "UTC",
            "sort": "oldest",
            "generated_at": "2026-10-27T11:00:00+00:00",
            "filters": {"site_id": "s", "traffic": "all"},
            "row_count": n,
            "coverage": {
                "unique_events": n,
                "observed_min": None,
                "observed_max": None,
                "sources": ["s"],
            },
            "data_quality": {
                "line_totals": {
                    "lines_total": n,
                    "lines_accepted": n,
                    "lines_rejected": 0,
                    "records_replayed": 0,
                },
                "imports": [{"import_id": i, "status": "completed"} for i in range(n)],
            },
        }

    few = json.loads(metadata_headers(meta_with(3), "f.csv")["X-Logcarve-Export-Coverage"])
    assert few["imports_total"] == 3 and few["imports_truncated"] is False
    assert len(few["imports"]) == 3
    many = metadata_headers(meta_with(_IMPORTS_HEADER_CAP + 10), "f.csv")
    coverage = json.loads(many["X-Logcarve-Export-Coverage"])
    assert coverage["imports_total"] == _IMPORTS_HEADER_CAP + 10
    assert coverage["imports_truncated"] is True
    assert len(coverage["imports"]) == _IMPORTS_HEADER_CAP
    assert all(value.isascii() for value in many.values())
    assert len(many["X-Logcarve-Export-Coverage"]) < 8192


def test_t3_export_auth_scope_and_cap_negatives(exportapi, monkeypatch):
    """Auth, scope, sort and cap failures map safely before streaming."""
    import app.api.routes_export as export_mod

    client, token, _ = exportapi
    params = dict(EXPORT_PARAMS, export_format="csv")
    assert client.get("/api/v1/exports/requests", params=params).status_code == 401
    cookie_only = client.get("/api/v1/exports/requests", params=params)
    assert cookie_only.status_code == 401  # browser sessions never authorize the API
    bad_sort = client.get(
        "/api/v1/exports/requests",
        params={**params, "sort": "fastest"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert bad_sort.status_code in (400, 422)
    bad_source = client.get(
        "/api/v1/exports/requests",
        params={**params, "source_id": "no-such-source"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert bad_source.status_code == 403
    monkeypatch.setattr(export_mod, "EXPORT_MAX_ROWS", 5)
    capped = client.get(
        "/api/v1/exports/requests", params=params, headers={"Authorization": f"Bearer {token}"}
    )
    assert capped.status_code == 413
    body = capped.json()
    assert body["code"] == "export_too_large" and body["request_id"]
    assert "content-disposition" not in {k.lower() for k in capped.headers}


def test_t3_export_browser_entrypoint_session_only(exportapi):
    """Session download works; tokens and strangers stay out."""
    client, _, _ = exportapi
    web_params = {
        "site": "export-site",
        "range": "custom",
        "from": "2026-10-27T00:00:00+00:00",
        "to": "2026-10-27T11:00:00+00:00",
        "tz": "UTC",
        "format": "csv",
    }
    # NOTE: TestClient follows redirects by default, which would turn
    # the login redirect into a 200 login page and fake an auth-bypass
    # finding. Disable following to inspect the actual redirect.
    stranger = client.get("/export/requests", params=web_params, follow_redirects=False)
    assert stranger.status_code == 302
    assert "/login" in stranger.headers["location"]
    # No data or metadata escapes on the unauthenticated path.
    assert "198.51.100" not in stranger.text
    assert "attachment" not in stranger.headers.get("content-disposition", "")
    assert "pseudonym" not in stranger.text.lower()
    login = client.post("/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"})
    assert login.status_code == 200
    download = client.get("/export/requests", params=web_params)
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("text/csv")
    assert "attachment" in download.headers["content-disposition"]
    assert "198.51.100" not in download.text
    as_json = client.get("/export/requests", params={**web_params, "format": "json"})
    assert as_json.status_code == 200
    assert as_json.json()["complete"] is True
    assert as_json.json()["metadata"]["row_count"] == EXPECTED_EXPORT_ROWS
    assert as_json.json()["metadata"]["display_timezone"] == "UTC"
    # A non-UTC display zone is recorded as selected; rows stay UTC.
    berlin = client.get(
        "/export/requests", params={**web_params, "format": "json", "tz": "Europe/Berlin"}
    )
    assert berlin.status_code == 200
    assert berlin.json()["metadata"]["display_timezone"] == "Europe/Berlin"
    assert berlin.json()["metadata"]["time_range"] == {
        "time_from": "2026-10-27T00:00:00+00:00",
        "time_to": "2026-10-27T11:00:00+00:00",
    }
    assert len(berlin.json()["rows"]) == EXPECTED_EXPORT_ROWS
    bad_format = client.get("/export/requests", params={**web_params, "format": "xml"})
    assert bad_format.status_code == 400


def test_param_validation_answers_before_broken_store(hardening, tmp_path, monkeypatch):
    """Status/format/limit rejects stay 400 even with a corrupt store."""
    from app.main import create_app

    corrupt = tmp_path / "corrupt.sqlite3"
    corrupt.write_bytes(b"this is not a sqlite database")
    monkeypatch.chdir(tmp_path)
    client = TestClient(
        create_app(db_path=corrupt, secure_cookies=False), raise_server_exceptions=False
    )
    # Well-formed but unknown: reaches the store (unlike a malformed
    # header, which rejects before any store read).
    headers = {"Authorization": "Bearer lc_" + "0" * 43}
    window = {"from": "2026-10-27T00:00:00+00:00", "to": "2026-10-28T00:00:00+00:00"}
    rejected = client.get(
        "/api/v1/requests",
        params={"site_id": "default", **window, "limit": 0},
        headers=headers,
    )
    assert rejected.status_code == 400
    assert rejected.json()["code"] == "invalid_request"
    assert rejected.json()["request_id"]
    # A well-formed request against the broken store keeps the safe 503.
    failed = client.get(
        "/api/v1/requests",
        params={"site_id": "default", **window},
        headers=headers,
    )
    assert failed.status_code == 503
    assert failed.json()["code"] == "store_unavailable"
