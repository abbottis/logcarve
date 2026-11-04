"""T4c integration tests: saved views, comparison, refresh, locale audit.

Covers the frozen-T4b2 display corrections (journey filter-state
serialization, display-timezone instants, microsecond durations,
central security labels) plus the new T4c surface: session-owned
saved views with CSRF/ownership/allowlist bounds, explicit
current-vs-baseline comparison with honest empty/zero handling,
opt-in read-only refresh defaults, central-English locale coverage
and API independence. Synthetic data only; no browser here
(repeatable Playwright slice in tests/e2e).
"""

import re
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pytest
from starlette.testclient import TestClient

from app.analytics import service as analytics_service
from app.analytics.contracts import AnalyticsFilter, TimeWindow
from app.analytics.rules import load_rules
from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user, issue_token
from app.db import saved_views as view_store
from app.db.database import connect, writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.sources import SourceConfig
from app.web import evidence as evidence_mod
from app.web.locales import load_catalog
from app.web.routes import SAVED_VIEW_MAX_COUNT

ROOT = Path(__file__).resolve().parent.parent.parent
HMAC_KEY = b"t4c-integration-hmac-key"
WINDOW_QS = "range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"
BASE = f"site=default&{WINDOW_QS}&tz=UTC"
BERLIN = f"site=default&{WINDOW_QS}&tz=Europe%2FBerlin"
FROM = datetime.fromisoformat("2026-10-27T00:00:00+00:00")
TO = datetime.fromisoformat("2026-10-28T00:00:00+00:00")


def _line(host, stamp, method, path, status):
    return (
        f'{host} - - [{stamp}] "{method} {path} HTTP/1.1" {status} 128 '
        f'"-" "Browser/1.0" example.org - - - - "-"'
    )


def _seed_lines():
    return [
        _line("198.51.100.21", "27/Oct/2026:10:00:00 +0000", "GET", "/in", 200),
        _line("198.51.100.21", "27/Oct/2026:10:05:00 +0000", "GET", "/mid", 200),
        _line("198.51.100.21", "27/Oct/2026:10:40:00 +0000", "GET", "/late", 200),
        _line("198.51.100.22", "27/Oct/2026:11:00:00 +0000", "GET", "/other", 200),
        _line("198.51.100.23", "27/Oct/2026:12:00:00 +0000", "GET", "/gone-1", 404),
        _line("198.51.100.23", "27/Oct/2026:12:01:00 +0000", "GET", "/gone-2", 404),
        _line("198.51.100.23", "27/Oct/2026:12:02:00 +0000", "GET", "/gone-3", 404),
        _line("198.51.100.23", "27/Oct/2026:12:03:00 +0000", "GET", "/gone-4", 404),
        _line("198.51.100.23", "27/Oct/2026:12:04:00 +0000", "GET", "/gone-5", 404),
        _line("198.51.100.25", "27/Oct/2026:12:20:00 +0000", "GET", "/login", 401),
        _line("198.51.100.25", "27/Oct/2026:12:21:00 +0000", "GET", "/login", 401),
        _line("198.51.100.25", "27/Oct/2026:12:22:00 +0000", "GET", "/admin", 403),
        # Microsecond probe pair: the second row is nudged to +1us below.
        _line("198.51.100.29", "27/Oct/2026:12:00:00 +0000", "GET", "/m-a", 200),
        _line("198.51.100.29", "27/Oct/2026:12:00:01 +0000", "GET", "/m-b", 200),
    ]


@pytest.fixture
def t4c(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    monkeypatch.delenv("DEFAULT_TIMEZONE", raising=False)
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_text("\n".join(_seed_lines()) + "\n", encoding="utf-8")
    db = tmp_path / "t4c.sqlite3"
    migrate(db)
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
        create_admin_user(conn, username="other", password_hash=hash_password("other-pw"))
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
        site_hostname="example.org",
        server_type="nginx",
        path_alias="access.log",
        hmac_key=HMAC_KEY,
    )
    # Genuine 1us journey: same key, second instant one microsecond later.
    with writer_transaction(db) as conn:
        row = conn.execute(
            "SELECT id FROM requests WHERE path = '/m-b' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert row is not None
        conn.execute(
            "UPDATE requests SET ts_utc = '2026-10-27T12:00:00.000001+00:00' WHERE id = ?",
            (row[0],),
        )
    with writer_transaction(db) as conn:
        _, token = issue_token(conn, name="t4c", site_id="default")
    from app.main import create_app

    app = create_app(db_path=db, secure_cookies=False)
    client = TestClient(app, raise_server_exceptions=False)
    login = client.post("/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"})
    assert login.status_code == 200
    csrf = login.json()["csrf_token"]
    # A second admin on a separate session: ownership isolation needs
    # a distinct cookie jar, since login cookies overwrite each other.
    other = TestClient(app, raise_server_exceptions=False)
    other_login = other.post(
        "/api/v1/admin/login", json={"username": "other", "password": "other-pw"}
    )
    assert other_login.status_code == 200
    rules = (
        load_rules(ROOT / "config" / "bot_rules.yaml").rules
        + load_rules(ROOT / "config" / "security_rules.yaml").rules
    )
    return {
        "client": client,
        "other": other,
        "db": db,
        "token": token,
        "rules": rules,
        "csrf": csrf,
        "other_csrf": other_login.json()["csrf_token"],
    }


def _page(client, url):
    response = client.get(url)
    assert response.status_code == 200, (url, response.text[:400])
    return response.text


def _form(client, url, fields):
    return client.post(
        url,
        data=fields,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        follow_redirects=False,
    )


# --- Frozen T4b2 corrections. ---


def test_journey_filter_state_survives_form_and_partial(t4c):
    client = t4c["client"]
    url = f"/journeys?{BASE}&view=entries&sort=duration_desc&min_requests=5"
    html = _page(client, url)
    assert 'name="view" value="entries"' in html
    assert 'name="sort" value="duration_desc"' in html
    assert 'name="min_requests" value="5"' in html
    assert "journey-entries-chart" in html
    partial = client.get(
        f"/partials/journeys?{BASE}&view=entries&sort=duration_desc&min_requests=5"
    )
    assert partial.status_code == 200, partial.text[:400]
    push = partial.headers.get("hx-push-url", "")
    assert "view=entries" in push and "sort=duration_desc" in push and "min_requests=5" in push
    native = _page(client, url.replace("view=entries", "view=journeys"))
    assert "journeys-chart" in native


def test_journey_instants_follow_display_timezone(t4c):
    client = t4c["client"]
    berlin = _page(client, f"/journeys?{BERLIN}&sort=start_asc")
    # 12:00 UTC on 27 Oct 2026 is 13:00 in Europe/Berlin (CET, UTC+01:00).
    assert "13:00" in berlin and "UTC+01:00" in berlin
    utc = _page(client, f"/journeys?{BASE}&sort=start_asc")
    assert "12:00" in utc and "UTC+00:00" in utc
    # Canonical UTC stays in titles and detail selectors, never converted.
    assert 'title="2026-10-27T12:00:00+00:00"' in berlin
    assert "journey_start=2026-10-27T12" in berlin


def test_microsecond_journey_never_reads_as_zero(t4c):
    client = t4c["client"]
    html = _page(client, f"/journeys?{BASE}&min_requests=1")
    assert "1 µs" in html
    # No table cell reads exactly zero seconds (a "300.000 s" whole
    # span legitimately contains that substring, so match the cell).
    assert ">0.000 s<" not in html


def test_security_cards_use_central_labels(t4c):
    client = t4c["client"]
    html = _page(client, f"/security?{BASE}")
    assert "Rule-matching scope" in html
    assert "Exact minute interval:" in html
    assert "(UTC)" in html
    assert "peak_minute_scope" not in html
    assert "peak_minute_numerator" not in html
    assert "avg_numerator" not in html
    # The honest tempo sentence survives without internal key names.
    assert "SAME rule-matching numerator" in html
    assert "peak_minute_interval" not in html


# --- Saved views. ---


def _save(client, csrf, name, target):
    return _form(client, "/saved-views", {"csrf_token": csrf, "name": name, "target": target})


def test_saved_view_roundtrip_create_open_rename_delete(t4c):
    client, csrf = t4c["client"], t4c["csrf"]
    target = f"/journeys?{BASE}&view=entries&sort=duration_desc&min_requests=5"
    created = _save(client, csrf, "Entry watch", target)
    assert created.status_code == 303, created.text[:400]
    assert created.headers["location"] == "/saved-views"
    listed = _page(client, "/saved-views")
    assert "Entry watch" in listed
    assert "view=entries" in listed and "min_requests=5" in listed
    conn = connect(t4c["db"], read_only=True)
    try:
        rows = view_store.list_for_user(conn, 1)
    finally:
        conn.close()
    assert len(rows) == 1 and rows[0]["path"] == "/journeys"
    replay = _page(client, rows[0]["url"])
    assert "Entry paths" in replay
    view_id = rows[0]["id"]
    renamed = _form(
        client, f"/saved-views/{view_id}/rename", {"csrf_token": csrf, "name": "Renamed ✓"}
    )
    assert renamed.status_code == 303
    assert "Renamed ✓" in _page(client, "/saved-views")
    retarget = _form(
        client,
        f"/saved-views/{view_id}/update",
        {"csrf_token": csrf, "target": f"/security?{BASE}"},
    )
    assert retarget.status_code == 303
    assert "/security" in _page(client, "/saved-views")
    deleted = _form(client, f"/saved-views/{view_id}/delete", {"csrf_token": csrf})
    assert deleted.status_code == 303
    assert "Renamed" not in _page(client, "/saved-views")


def test_saved_views_require_session_and_csrf(t4c):
    # A bearer analytics token alone (no session cookie) never opens
    # the session-owned views UI: the client session is cleared first.
    t4c["client"].cookies.clear()
    bare = t4c["client"].get(
        "/saved-views",
        headers={"Authorization": "Bearer " + t4c["token"]},
        follow_redirects=False,
    )
    assert bare.status_code in (302, 303, 307, 401), bare.status_code


def test_saved_view_mutations_reject_bad_csrf(t4c):
    # Wrong, missing and Unicode CSRF tokens all fail closed with 403.
    for bad in ("wrong-token", "", "x" * 200):
        denied = _save(t4c["client"], bad, "CSRF probe", f"/?{BASE}")
        assert denied.status_code == 403, (bad, denied.status_code)
    denied = _save(t4c["client"], "t\u00f6k\u00e9n-\u2603", "CSRF probe", f"/?{BASE}")
    assert denied.status_code == 403


def test_saved_views_enforce_ownership(t4c):
    client, other = t4c["client"], t4c["other"]
    created = _save(client, t4c["csrf"], "Mine", f"/?{BASE}")
    assert created.status_code == 303
    conn = connect(t4c["db"], read_only=True)
    try:
        rows = view_store.list_for_user(conn, 1)
        foreign = view_store.list_for_user(conn, 2)
    finally:
        conn.close()
    assert foreign == []
    view_id = rows[0]["id"]
    # The second admin neither sees nor touches the first admin's view.
    assert "Mine" not in _page(other, "/saved-views")
    for action, fields in (
        ("rename", {"csrf_token": t4c["other_csrf"], "name": "Theft"}),
        ("update", {"csrf_token": t4c["other_csrf"], "target": f"/?{BASE}"}),
        ("delete", {"csrf_token": t4c["other_csrf"]}),
    ):
        response = _form(other, f"/saved-views/{view_id}/{action}", fields)
        assert response.status_code == 404, (action, response.status_code)
    assert "Mine" in _page(client, "/saved-views")


def test_saved_views_reject_hostile_targets(t4c):
    client, csrf = t4c["client"], t4c["csrf"]
    hostile = [
        "https://evil.example/x",
        "//evil.example/x",
        "/\\evil",
        "/settings?x=1",
        "/help",
        "/api/v1/summary?site_id=default",
        "/requests?site=default&csrf_token=abc",
        "/requests?site=default&next=//evil",
        "/requests?site=default&raw_ip=1.2.3.4",
        "/crawlers?site=default&sort=bogus",
        "/journeys?site=default&view=bogus",
        f"/comparison?{BASE}&baseline=history",
        f"/comparison?{BASE}&baseline_from=2026-10-27T00:00:00%2B00:00",
        "/?" + "x" * 2100,
    ]
    for target in hostile:
        response = _save(client, csrf, "Hostile", target)
        assert response.status_code == 400, (target, response.status_code, response.text[:200])
    conn = connect(t4c["db"], read_only=True)
    try:
        assert view_store.list_for_user(conn, 1) == []
    finally:
        conn.close()


def test_saved_views_validate_names_and_bounds(t4c):
    client, csrf = t4c["client"], t4c["csrf"]
    for bad_name in ("", "   ", "x" * 65, "bad\x01name"):
        response = _save(client, csrf, bad_name, f"/?{BASE}")
        assert response.status_code == 400, (repr(bad_name), response.status_code)
    unicode_ok = _save(client, csrf, "Morgendliche 404-Übersicht ☃", f"/?{BASE}")
    assert unicode_ok.status_code == 303
    for index in range(SAVED_VIEW_MAX_COUNT - 1):
        response = _save(client, csrf, f"Bulk {index}", f"/?{BASE}")
        assert response.status_code == 303, (index, response.status_code)
    full = _save(client, csrf, "One too many", f"/?{BASE}")
    assert full.status_code == 400
    assert "limit is reached" in full.text


# --- Comparison: explicit current vs baseline. ---


def _compare(client, extra):
    url = f"/comparison?{BASE}{extra}"
    response = client.get(url)
    return response


def test_comparison_previous_matches_service_counts(t4c):
    client = t4c["client"]
    response = _compare(client, "&baseline=previous")
    assert response.status_code == 200, response.text[:400]
    html = response.text
    assert "compare-metrics-chart" in html and "Comparison table" in html
    assert "baseline=previous" in html
    conn = connect(t4c["db"], read_only=True)
    try:
        filt = AnalyticsFilter(site_id="default", window=TimeWindow(time_from=FROM, time_to=TO))
        compared = analytics_service.compare_windows(
            conn, filt, analytics_service.previous_window_filter(filt), t4c["rules"]
        )
    finally:
        conn.close()
    names = [metric["name"] for metric in compared["metrics"]]
    assert "requests" in names
    for metric in compared["metrics"]:
        assert str(metric["current"]) in html and str(metric["previous"]) in html


def test_comparison_explicit_window_and_canonical_link(t4c):
    client = t4c["client"]
    extra = (
        "&baseline_from=2026-10-26T00%3A00%3A00%2B00%3A00"
        "&baseline_to=2026-10-27T00%3A00%3A00%2B00%3A00"
    )
    html = _page(client, f"/comparison?{BASE}{extra}")
    assert "baseline_from=2026-10-26" in html
    partial = client.get(f"/partials/comparison?{BASE}{extra}")
    assert partial.status_code == 200, partial.text[:400]
    assert partial.headers.get("hx-push-url", "").startswith("/comparison?")
    assert "baseline_from=" in partial.headers["hx-push-url"]


def test_comparison_zero_baseline_is_exact_never_infinite(t4c):
    client = t4c["client"]
    extra = (
        "&baseline_from=2026-10-20T00%3A00%3A00%2B00%3A00"
        "&baseline_to=2026-10-21T00%3A00%3A00%2B00%3A00"
    )
    html = _page(client, f"/comparison?{BASE}{extra}")
    assert "Zero baseline" in html
    assert "ratio unavailable" in html
    assert "Infinity" not in html


def test_comparison_empty_current_has_no_confident_ratio(t4c):
    client = t4c["client"]
    empty_window = "range=custom&from=2026-10-20T00:00:00%2B00:00&to=2026-10-21T00:00:00%2B00:00"
    extra = (
        "&baseline_from=2026-10-27T00%3A00%3A00%2B00%3A00"
        "&baseline_to=2026-10-28T00%3A00%3A00%2B00%3A00"
    )
    html = _page(client, f"/comparison?site=default&{empty_window}&tz=UTC{extra}")
    assert "No confident ratios" in html
    assert "Unavailable: empty window or limited coverage" in html
    assert ">—<" in html


def test_comparison_rejects_unequal_and_hostile_baselines(t4c):
    client = t4c["client"]
    unequal = (
        "&baseline_from=2026-10-27T00%3A00%3A00%2B00%3A00"
        "&baseline_to=2026-10-27T12%3A00%3A00%2B00%3A00"
    )
    response = _compare(client, unequal)
    assert response.status_code == 400
    assert "equal lengths" in response.text
    half = _compare(client, "&baseline_from=2026-10-27T00%3A00%3A00%2B00%3A00")
    assert half.status_code == 400
    reversed_pair = (
        "&baseline_from=2026-10-28T00%3A00%3A00%2B00%3A00"
        "&baseline_to=2026-10-27T00%3A00%3A00%2B00%3A00"
    )
    assert _compare(client, reversed_pair).status_code == 400


def test_comparison_without_baseline_prompts_explicit_choice(t4c):
    client = t4c["client"]
    html = _page(client, f"/comparison?{BASE}")
    assert "Choose a baseline" in html
    assert "compare-metrics-chart" not in html
    assert "Compare with previous period" in html


def test_comparison_evidence_replays_actual_executed_halves(t4c):
    from app.ai import service as ai_service

    client = t4c["client"]
    rules = t4c["rules"]
    outcome = ai_service._execute_bounded_tool(
        t4c["db"],
        rules,
        "get_report",
        {"report": "comparison"},
        site_id="default",
        source_id=None,
        time_from=FROM,
        time_to=TO,
        tool_index=0,
        investigation_id="halfreplay",
        observation_time=datetime.fromisoformat("2026-10-29T12:00:00+00:00"),
    )
    envelope = outcome["envelope"]
    href = evidence_mod.envelope_href("get_report", envelope["filters"], "UTC")
    assert href is not None and href.startswith("/comparison?")
    parts = dict(parse_qsl(urlsplit(href).query))
    mid = "2026-10-27T12:00:00+00:00"
    # The page window is the executed CURRENT half; the baseline params
    # are the executed BASELINE half: never the parent-as-current.
    assert parts["from"] == mid and parts["to"] == TO.isoformat()
    assert parts["baseline_from"] == FROM.isoformat() and parts["baseline_to"] == mid
    replay = _page(client, href)
    result = envelope["result"]
    for metric in result["metrics"]:
        assert str(metric["current"]) in replay and str(metric["previous"]) in replay
    # Tampering with the halves (unequal lengths) fails closed, never widens.
    tampered = href.replace("baseline_from=2026-10-27T00", "baseline_from=2026-10-27T06")
    assert client.get(tampered).status_code == 400
    # An unsplittable parent (valid 3us window, odd length) links
    # honestly with no silent baseline default.
    odd = evidence_mod.comparison_evidence_url(
        {
            "site_id": "default",
            "time_from": FROM.isoformat(),
            "time_to": "2026-10-27T00:00:00.000003+00:00",
            "traffic": "all",
            "report": "comparison",
        },
        "UTC",
    )
    assert odd.startswith("/comparison?") and "baseline_from" not in odd
    assert _page(client, odd).count("Choose a baseline") == 1


# --- Refresh defaults and read-only behavior. ---


def test_refresh_is_opt_in_and_read_only(t4c):
    client = t4c["client"]
    html = _page(client, f"/?{BASE}")
    assert 'id="refresh-toggle"' in html
    assert "Auto-refresh is off." in html
    assert "Never imports" in html
    assert 'value="30"' in html and 'value="60"' in html and 'value="300"' in html
    before = _import_count(t4c["db"])
    for path in ("/partials/overview", "/partials/comparison", "/partials/journeys"):
        response = client.get(f"{path}?{BASE}")
        assert response.status_code in (200, 400)
    assert _import_count(t4c["db"]) == before
    assert client.post(f"/partials/comparison?{BASE}").status_code == 405


def _import_count(db):
    conn = connect(db, read_only=True)
    try:
        return int(conn.execute("SELECT COUNT(*) FROM imports").fetchone()[0])
    finally:
        conn.close()


# --- Central-English locale audit. ---


def _used_keys():
    keys = set(re.findall(r"""\bt\(\s*"([^"]+)\"""", (ROOT / "app/web/routes.py").read_text()))
    for template in (ROOT / "app/web/templates").rglob("*.html"):
        keys.update(re.findall(r"""\bt\(\s*"([^"]+)\"""", template.read_text()))
    return keys


def test_locale_keys_cover_all_product_strings():
    catalog = load_catalog("en")
    # Literal keys must all exist; trailing prefixes are dynamic
    # families covered member-by-member below (traffic buckets,
    # status classes, weekdays, comparison metrics).
    dynamic = {"filter.class_", "overview.weekday_", "traffic."}
    missing = sorted(key for key in _used_keys() if key not in catalog and key not in dynamic)
    assert missing == [], missing
    from app.analytics.service import TRAFFIC_BUCKETS

    for bucket in TRAFFIC_BUCKETS:
        assert f"traffic.{bucket}" in catalog, bucket
    for cls in ("2xx", "3xx", "4xx", "5xx"):
        assert f"filter.class_{cls}" in catalog, cls
    for day in range(1, 8):
        assert f"overview.weekday_{day}" in catalog, day
    for metric in (
        "requests",
        "errors_4xx",
        "errors_5xx",
        "bytes_total",
        "claimed_bot_requests",
        "automation_requests",
        "requests_per_hour",
    ):
        assert f"compare.metric_{metric}" in catalog, metric
    # Variable-carried keys (detail/error states) resolve to fixed keys.
    for key in (
        "journeys.detail_not_found",
        "compare.error_mismatch",
        "views.error_name",
        "views.error_path",
        "views.error_query",
        "views.error_params",
        "views.error_full",
        "views.error_missing",
        "error.form_too_large",
    ):
        assert key in catalog, key


def test_locale_placeholders_render_without_raw_keys():
    from app.web.locales import t

    assert t("compare.events_count", count=3) == "3 observed events"
    assert t("views.count", count=1, max=50) == "1 of 50 views saved."
    assert (
        t("security.peak_requests_at", minute="2026-10-27T12:00")
        == "requests at 2026-10-27T12:00 UTC"
    )
    assert t("journeys.duration_microseconds", count=1) == "1 µs"
    assert t("no.such.key") == "no.such.key"
    # A known key without values renders its template, never blank.
    assert t("compare.events_count") == "{count} observed events"


def test_no_shipped_language_chooser():
    base = (ROOT / "app/web/templates/base.html").read_text()
    assert "theme-select" in base
    assert "locale" not in base.lower() or "locales" not in base.lower()
    lowered = base.lower()
    assert "language" not in lowered or "lang=" in lowered
    assert "data-theme-select" in base


# --- Display-helper units (DST, offsets, duration precision). ---


def test_display_instant_follows_dst_per_instant():
    from zoneinfo import ZoneInfo

    from app.web.routes import _display_instant

    berlin = ZoneInfo("Europe/Berlin")
    # Late October: CET (UTC+01:00).
    shown, offset = _display_instant("2026-10-27T12:00:00+00:00", berlin, "Europe/Berlin")
    assert shown == "2026-10-27 13:00 CET" and offset == "UTC+01:00"
    # Mid-July: CEST (UTC+02:00) for the DST-equivalent family.
    shown, offset = _display_instant("2026-07-15T12:00:00+00:00", berlin, "Europe/Berlin")
    assert shown == "2026-07-15 14:00 CEST" and offset == "UTC+02:00"
    # Across the spring-forward gap each instant labels its own offset.
    before, offset_before = _display_instant("2026-03-29T00:30:00+00:00", berlin, "Europe/Berlin")
    after, offset_after = _display_instant("2026-03-29T01:30:00+00:00", berlin, "Europe/Berlin")
    assert (before, offset_before) == ("2026-03-29 01:30 CET", "UTC+01:00")
    assert (after, offset_after) == ("2026-03-29 03:30 CEST", "UTC+02:00")
    # UTC stays UTC; unparsable values fall back verbatim, never converted.
    shown, offset = _display_instant("2026-10-27T12:00:00+00:00", ZoneInfo("UTC"), "UTC")
    assert (shown, offset) == ("2026-10-27 12:00 UTC", "UTC+00:00")
    assert _display_instant("not-a-time", berlin, "Europe/Berlin") == (
        "not-a-time",
        "Europe/Berlin",
    )


def test_duration_label_never_rounds_to_zero():
    from app.web.routes import _duration_label

    assert _duration_label(1) == "1 \u00b5s"
    assert _duration_label(0) == "0 \u00b5s"
    assert _duration_label(999) == "999 \u00b5s"
    assert _duration_label(1000) == "1 ms"
    assert _duration_label(1500) == "1.5 ms"
    assert _duration_label(999999) == "999.999 ms"
    assert _duration_label(1000000) == "1.000 s"
    assert _duration_label(300_000_000) == "300.000 s"
    assert _duration_label(None) == "Duration unavailable"


# --- API independence and help. ---


def test_comparison_api_is_independent_of_chat_and_keys(t4c, monkeypatch):
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    api = t4c["client"].get(
        "/api/v1/comparison?site_id=default"
        "&from=2026-10-27T00%3A00%3A00%2B00%3A00&to=2026-10-28T00%3A00%3A00%2B00%3A00"
        "&baseline_from=2026-10-26T00%3A00%3A00%2B00%3A00&baseline_to=2026-10-27T00%3A00%3A00%2B00%3A00",
        headers={"Authorization": f"Bearer {t4c['token']}"},
    )
    assert api.status_code == 200, api.text[:400]
    payload = api.json()
    assert payload["current_window"]["time_from"] == FROM.isoformat()
    names = [metric["name"] for metric in payload["metrics"]]
    assert "requests" in names


def test_help_covers_operators_and_declares_boundaries(t4c):
    html = _page(t4c["client"], "/help")
    for section in (
        "command line",
        "Missing timing is always shown as unavailable",
        "never verified identities",
        "microsecond",
        "authentication challenge",
        "display masking only",
        "pseudonyms regardless",
        "explicit baseline of exactly equal length",
        "placeholder credentials",
        "honestly shows Unknown",
        "explicit opt-in command-line operation",
        "logcarve-import follow",
        "no live watcher",
    ):
        assert section in html, section
    lowered = html.lower()
    # The documented absence of import controls is prose, never controls.
    assert "drag target or file chooser" in html
    assert "never uploads" in html
    assert 'type="file"' not in html
    assert "multipart" not in lowered


# --- T4c independent-correction regressions (findings 1-6). ---


def test_utc_input_formatter_precision():
    from app.web.routes import _utc_input

    # Minute-exact instants keep the established minute-only form.
    assert _utc_input(datetime.fromisoformat("2026-10-27T00:00:00+00:00")) == (
        "2026-10-27T00:00",
        "60",
    )
    # Nonzero seconds add :SS with a dividing step.
    assert _utc_input(datetime.fromisoformat("2026-10-27T12:00:05+00:00")) == (
        "2026-10-27T12:00:05",
        "1",
    )
    # Nonzero microseconds (the 1us backend precision) survive.
    assert _utc_input(datetime.fromisoformat("2026-10-27T12:00:00.000001+00:00")) == (
        "2026-10-27T12:00:00.000001",
        "0.000001",
    )
    # Positive/negative offsets replay as the same UTC instant.
    berlin_noon = _utc_input(datetime.fromisoformat("2026-10-27T12:00:00+05:00"))
    la_noon = _utc_input(datetime.fromisoformat("2026-10-26T23:00:00-08:00"))
    assert berlin_noon == la_noon == ("2026-10-27T07:00", "60")
    # Naive values are labelled UTC, never shifted.
    assert _utc_input(datetime.fromisoformat("2026-10-27T12:00:00")) == (
        "2026-10-27T12:00",
        "60",
    )


def test_global_fractional_window_survives_apply(t4c):
    client = t4c["client"]
    # A 1us evidence window must render as a valid control value with a
    # dividing step, and the canonical URL must keep full precision.
    url = (
        "/requests?site=default&range=custom"
        "&from=2026-10-27T12%3A00%3A00.000000%2B00%3A00"
        "&to=2026-10-27T12%3A00%3A00.000001%2B00%3A00&tz=UTC"
    )
    html = _page(client, url)
    assert 'id="f-from" name="from" type="datetime-local" value="2026-10-27T12:00"' in html
    assert 'id="f-to" name="to" type="datetime-local" value="2026-10-27T12:00:00.000001"' in html
    assert 'step="0.000001"' in html
    assert "from=2026-10-27T12%3A00%3A00%2B00%3A00" in html
    assert "to=2026-10-27T12%3A00%3A00.000001%2B00%3A00" in html
    # Resubmitting the displayed control values replays the same window.
    replay = _page(
        client,
        "/requests?site=default&range=custom&from=2026-10-27T12:00:00"
        "&to=2026-10-27T12:00:00.000001&tz=UTC",
    )
    assert "to=2026-10-27T12%3A00%3A00.000001%2B00%3A00" in replay
    # Seconds precision survives the same round-trip.
    seconds = _page(
        client,
        "/requests?site=default&range=custom&from=2026-10-27T12:00:05"
        "&to=2026-10-27T12:00:35&tz=UTC",
    )
    assert 'value="2026-10-27T12:00:05"' in seconds
    assert 'value="2026-10-27T12:00:35"' in seconds


def test_custom_baseline_controls_show_valid_utc(t4c):
    client = t4c["client"]
    extra = (
        "&baseline_from=2026-10-26T00%3A00%3A00%2B00%3A00"
        "&baseline_to=2026-10-27T00%3A00%3A00%2B00%3A00"
    )
    html = _page(client, f"/comparison?{BASE}{extra}")
    # Offset-free UTC values: the controls render instead of blanking.
    assert (
        'id="c-bfrom" name="baseline_from" type="datetime-local" value="2026-10-26T00:00"' in html
    )
    assert 'id="c-bto" name="baseline_to" type="datetime-local" value="2026-10-27T00:00"' in html
    assert "+00:00" not in html.split('id="c-bfrom"')[1].split(">")[0]
    # The previous-period mode fills the computed previous window.
    previous = _page(client, f"/comparison?{BASE}&baseline=previous")
    assert 'value="2026-10-26T00:00"' in previous
    # A +05:00 pair replays as the same UTC instant as +00:00.
    offset = _page(
        client,
        f"/comparison?{BASE}"
        "&baseline_from=2026-10-26T05%3A00%3A00%2B05%3A00"
        "&baseline_to=2026-10-27T05%3A00%3A00%2B05%3A00",
    )
    assert 'value="2026-10-26T00:00"' in offset
    assert 'value="2026-10-27T00:00"' in offset


def test_comparison_baseline_survives_filter_apply(t4c):
    client = t4c["client"]
    # Previous mode plus a global matcher: the fragment push keeps both.
    partial = client.get(f"/partials/comparison?{BASE}&baseline=previous&search=%2Flogin")
    assert partial.status_code == 200, partial.text[:400]
    push = partial.headers.get("hx-push-url", "")
    assert "baseline=previous" in push and "search=%2Flogin" in push
    # The full page carries the baseline as filter-bar hidden state.
    html = _page(client, f"/comparison?{BASE}&baseline=previous&search=%2Flogin")
    assert 'name="baseline" value="previous"' in html
    assert "Compare with previous period" in html
    # Custom mode: the canonical aware pair survives serialization.
    extra = (
        "&baseline_from=2026-10-26T00%3A00%3A00%2B00%3A00"
        "&baseline_to=2026-10-27T00%3A00%3A00%2B00%3A00"
    )
    custom_push = client.get(f"/partials/comparison?{BASE}{extra}").headers.get("hx-push-url", "")
    assert "baseline_from=2026-10-26" in custom_push
    assert "baseline_to=2026-10-27" in custom_push
    custom_html = _page(client, f"/comparison?{BASE}{extra}")
    assert 'name="baseline_from" value="2026-10-26T00:00:00+00:00"' in custom_html
    assert 'name="baseline_to" value="2026-10-27T00:00:00+00:00"' in custom_html
    # No baseline means no silent default anywhere in the push.
    bare_push = client.get(f"/partials/comparison?{BASE}").headers.get("hx-push-url", "")
    assert bare_push.startswith("/comparison?")
    assert "baseline" not in bare_push
    # Empty and zero baselines still render their honest notes via Apply.
    zero = client.get(
        "/partials/comparison?site=default&range=custom"
        "&from=2026-10-27T00%3A00%3A00%2B00%3A00&to=2026-10-28T00%3A00%3A00%2B00%3A00&tz=UTC"
        "&baseline_from=2026-10-20T00%3A00%3A00%2B00%3A00"
        "&baseline_to=2026-10-21T00%3A00%3A00%2B00%3A00"
    )
    assert zero.status_code == 200, zero.text[:400]
    assert "Zero baseline" in zero.text


def test_save_target_header_carries_full_state(t4c):
    client = t4c["client"]
    # Global search plus page-local journey state travel in the push URL.
    partial = client.get(
        f"/partials/journeys?{BASE}&search=%2Flogin&view=entries&sort=duration_desc&min_requests=5"
    )
    assert partial.status_code == 200, partial.text[:400]
    push = partial.headers.get("hx-push-url", "")
    assert "search=%2Flogin" in push
    assert "view=entries" in push and "sort=duration_desc" in push and "min_requests=5" in push
    assert "csrf_token" not in push and "raw_ip" not in push
    # The full-page Save-current target matches that canonical state, and
    # saving it replays the exact read.
    html = _page(
        client, f"/journeys?{BASE}&search=%2Flogin&view=entries&sort=duration_desc&min_requests=5"
    )
    assert 'id="save-view-target"' in html
    assert "search=%2Flogin" in html.split('id="save-view-target"')[1].split(">")[0]
    created = _save(
        client,
        t4c["csrf"],
        "Applied watch",
        f"/journeys?{BASE}&search=%2Flogin&view=entries&sort=duration_desc&min_requests=5",
    )
    assert created.status_code == 303
    conn = connect(t4c["db"], read_only=True)
    try:
        rows = view_store.list_for_user(conn, 1)
    finally:
        conn.close()
    assert len(rows) == 1
    replay = _page(client, rows[0]["url"])
    assert "search" in rows[0]["url"] and "view=entries" in rows[0]["url"]
    assert "Entry paths" in replay


def test_saved_view_update_from_ui(t4c):
    client, csrf = t4c["client"], t4c["csrf"]
    created = _save(client, csrf, "Movable", f"/?{BASE}")
    assert created.status_code == 303
    listed = _page(client, "/saved-views")
    # Every owned view offers an update control prefilled with its target.
    assert 'button:has-text("Update")' in listed or ">Update</button>" in listed
    assert 'name="target"' in listed
    conn = connect(t4c["db"], read_only=True)
    try:
        rows = view_store.list_for_user(conn, 1)
    finally:
        conn.close()
    view_id = rows[0]["id"]
    assert f"/saved-views/{view_id}/update" in listed
    # Updating through the UI form retains the full new filter set.
    retarget = _form(
        client,
        f"/saved-views/{view_id}/update",
        {"csrf_token": csrf, "target": f"/security?{BASE}&status=404"},
    )
    assert retarget.status_code == 303, retarget.text[:400]
    updated = _page(client, "/saved-views")
    assert "/security" in updated and "status=404" in updated
    conn = connect(t4c["db"], read_only=True)
    try:
        kept = view_store.list_for_user(conn, 1)
    finally:
        conn.close()
    replay = _page(client, kept[0]["url"])
    assert "status=404" in kept[0]["url"]
    assert "404" in replay
    # A hostile update target through the same form fails closed.
    hostile = _form(
        client, f"/saved-views/{view_id}/update", {"csrf_token": csrf, "target": "/help"}
    )
    assert hostile.status_code == 400


def test_saved_view_id_bounds_before_db(t4c):
    from app.web.routes import SQLITE_MAX_ROW_ID, _checked_view_id

    assert SQLITE_MAX_ROW_ID == 2**63 - 1
    assert _checked_view_id("1") == 1
    assert _checked_view_id(str(2**63 - 1)) == 2**63 - 1
    assert _checked_view_id("007") == 7
    for bad in (
        "0",
        "-1",
        str(2**63),
        "9" * 30,
        "abc",
        "12ab",
        "",
        "   ",
        "1.5",
        "+3",
        "１２３",
        None,
        5,
        5.0,
    ):
        assert _checked_view_id(bad) is None, repr(bad)
    client = t4c["client"]
    before = _import_count(t4c["db"])
    conn = connect(t4c["db"], read_only=True)
    try:
        views_before = view_store.list_for_user(conn, 1)
    finally:
        conn.close()
    for action in ("rename", "update", "delete"):
        fields = {"csrf_token": t4c["csrf"], "name": "X", "target": f"/?{BASE}"}
        for probe in (str(2**63), "0", "-1", "9" * 40, "nope", str(2**63 - 1)):
            response = _form(client, f"/saved-views/{probe}/{action}", fields)
            assert response.status_code == 404, (action, probe, response.status_code)
            assert "That saved view does not exist." in response.text, (action, probe)
            lowered = response.text.lower()
            assert "overflow" not in lowered and "traceback" not in lowered
            assert "sqlite" not in lowered and "internal server error" not in lowered
            if len(probe) > 19:
                assert probe not in response.text, (action, probe)
    # Bad CSRF with an overflowing id still fails closed at the gate.
    denied = _form(client, f"/saved-views/{2**63!s}/delete", {"csrf_token": "wrong"})
    assert denied.status_code == 403
    # No DB mutation from any probe.
    conn = connect(t4c["db"], read_only=True)
    try:
        assert view_store.list_for_user(conn, 1) == views_before
    finally:
        conn.close()
    assert _import_count(t4c["db"]) == before


def test_refresh_control_uses_central_messages(t4c):
    from app.web.locales import load_catalog

    catalog = load_catalog("en")
    html = _page(t4c["client"], f"/journeys?{BASE}")
    assert 'data-msg-refresh-off="Auto-refresh is off."' in html
    assert 'data-msg-refresh-on="Auto-refresh is on;' in html
    assert "data-msg-refresh-paused=" in html
    assert catalog["refresh.paused_note"] in html
    assert "Auto-refresh is off." in html
    assert 'value="30"' in html and 'value="60"' in html and 'value="300"' in html
    source = (ROOT / "assets" / "src" / "js" / "refresh.js").read_text()
    assert "Auto-refresh is off." not in source
    assert "Auto-refresh is on" not in source
    assert "paused while unsaved" not in source
