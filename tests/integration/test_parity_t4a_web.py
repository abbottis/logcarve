"""T4a integration tests: private admin IP view, settings, exact-IP search.

Session-gated original-IP display over temporary synthetic databases:
CSRF/session/Bearer denial, full/masked/pseudonym rendering with the
masked suffix absent, missing/wrong/tampered keys and unenriched rows
as fixed Unavailable with recovery guidance, corrupt preferences
failing closed, per-row id binding for duplicate events, POST-only
exact-IP search that never echoes the address, shared enrichment
filter propagation into web params/canonical/nav/paging, API/export
remaining address-free, concurrent-delete tolerance, and
history/cache privacy markers. Synthetic data only; no browser here
(the repeatable Playwright slice lives in tests/e2e).
"""

import base64
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user, issue_token
from app.db.database import writer_transaction
from app.db.importer import run_import
from app.ingestion.combined import pseudonymize_client
from app.ingestion.sources import SourceConfig

ROOT = Path(__file__).resolve().parent.parent.parent
HMAC_KEY = b"t4a-integration-hmac-key"
HMAC_ENV = "t4a-integration-hmac-key"
V4 = "203.0.113.20"
V6_SHORT = "2001:db8::25"
V6_LONG = "2001:0db8:0000:0000:0000:0000:0000:0025"
WINDOW_QS = "range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"

EXT_FMT = "nginx_extended"
PLAIN_FMT = "nginx_combined"


def _ext_line(
    host,
    stamp,
    method,
    path,
    status,
    size,
    referer,
    ua,
    vhost="example.org",
    cache="MISS",
    timing="0.123",
    mime="text/html",
    tls="TLSv1.3",
    upstream='"0.100, 0.020"',
):
    return (
        f'{host} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} '
        f'"{referer}" "{ua}" {vhost} {cache} {timing} {mime} {tls} {upstream}'
    )


def _seed_lines():
    return [
        _ext_line(
            V4,
            "27/Oct/2026:10:15:32 +0100",
            "GET",
            "/shop/item",
            200,
            153,
            "https://example.org/old",
            "Mozilla/5.0",
        ),
        _ext_line(
            V4,
            "27/Oct/2026:10:15:33 +0100",
            "GET",
            "/shop/item",
            200,
            153,
            "https://example.org/old",
            "Mozilla/5.0",
        ),
        _ext_line(
            V6_SHORT,
            "27/Oct/2026:11:02:03 +0100",
            "GET",
            "/style.css",
            200,
            2314,
            "-",
            "curl/8.0",
            cache="HIT",
            timing="0.002",
            mime="text/css",
            tls="TLSv1.2",
            upstream='"-"',
        ),
        _ext_line(
            V6_LONG,
            "27/Oct/2026:11:03:04 +0100",
            "GET",
            "/expanded",
            200,
            100,
            "-",
            "curl/8.0",
            cache="HIT",
            timing="0.002",
            mime="text/css",
            tls="TLSv1.2",
            upstream='"-"',
        ),
    ]


PLAIN_LINE = (
    '198.51.100.7 - - [27/Oct/2026:12:15:44 +0100] "GET /legacy HTTP/1.1"'
    ' 200 128 "-" "TestAgent/1.0"'
)


def _key_bytes(seed: int = 7) -> bytes:
    return bytes((seed * 31 + i) % 256 for i in range(32))


@pytest.fixture
def t4a(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "t4a-session-secret")
    monkeypatch.setenv("HMAC_KEY", HMAC_ENV)
    key = _key_bytes()
    monkeypatch.setenv("ORIGINAL_IP_KEY", base64.b64encode(key).decode())
    root = tmp_path / "logs"
    root.mkdir()
    (root / "ext.log").write_text("\n".join(_seed_lines()) + "\n", encoding="utf-8")
    (root / "plain.log").write_text(PLAIN_LINE + "\n", encoding="utf-8")
    db = tmp_path / "t4a.sqlite3"
    run_import(
        db,
        source=SourceConfig(
            source_id="t4a-ext", format_id=EXT_FMT, allowed_root=root, relative_path="ext.log"
        ),
        site_id="default",
        site_name="T4a",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="ext.log",
        hmac_key=HMAC_KEY,
        capture_originals=True,
    )
    run_import(
        db,
        source=SourceConfig(
            source_id="t4a-plain", format_id=PLAIN_FMT, allowed_root=root, relative_path="plain.log"
        ),
        site_id="default",
        site_name="T4a",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="plain.log",
        hmac_key=HMAC_KEY,
        capture_originals=False,
    )
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
        _, token = issue_token(conn, name="t4a", site_id="default")
    from app.main import create_app

    client = TestClient(create_app(db_path=db, secure_cookies=False), raise_server_exceptions=False)
    login = client.post("/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"})
    assert login.status_code == 200
    csrf = login.json()["csrf_token"]
    return {"client": client, "db": db, "csrf": csrf, "token": token, "key": key}


def _requests(client, extra=""):
    return client.get(f"/requests?site=default&{WINDOW_QS}&tz=UTC{extra}")


def _pseudo(address: str) -> str:
    return pseudonymize_client(address, HMAC_KEY)


# --- Auth: sessions authorize, Bearer [REDACTED] do not, CSRF is enforced ---


def test_requests_requires_session(t4a):
    client = t4a["client"]
    fresh = TestClient(client.app, raise_server_exceptions=False)
    response = fresh.get(f"/requests?site=default&{WINDOW_QS}&tz=UTC", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["location"]


def test_bearer_token_cannot_open_requests_or_post(t4a):
    from starlette.testclient import TestClient as TC

    bearer = TC(
        t4a["client"].app,
        raise_server_exceptions=False,
        headers={"Authorization": f"Bearer {t4a['token']}"},
    )
    assert bearer.get(
        f"/requests?site=default&{WINDOW_QS}&tz=UTC", follow_redirects=False
    ).status_code in (302, 401)
    denied = bearer.post(
        "/settings/ip-display",
        data={
            "ip_mode": "pseudonym_only",
            "ip_v4_hidden": "1",
            "ip_v6_hidden": "4",
            "csrf_token": t4a["csrf"],
        },
    )
    assert denied.status_code in (401, 302)
    denied_search = bearer.post("/requests/ip-search", data={"ip": V4, "csrf_token": "x"})
    assert denied_search.status_code == 401


def test_settings_post_requires_csrf_and_leaves_state(t4a):
    client = t4a["client"]
    forged = client.post(
        "/settings/ip-display",
        data={
            "ip_mode": "pseudonym_only",
            "ip_v4_hidden": "1",
            "ip_v6_hidden": "4",
            "csrf_token": "wrong",
        },
    )
    assert forged.status_code == 403
    page = _requests(client).text
    # Full default survived the forged mutation: originals still shown.
    assert V4 in page
    unicode_csrf = client.post(
        "/settings/ip-display",
        data={
            "ip_mode": "pseudonym_only",
            "ip_v4_hidden": "1",
            "ip_v6_hidden": "4",
            "csrf_token": "tökén-☃",
        },
    )
    assert unicode_csrf.status_code == 403
    assert "session check" in unicode_csrf.text


def test_settings_post_without_session_is_denied(t4a):
    from starlette.testclient import TestClient as TC

    anon = TC(t4a["client"].app, raise_server_exceptions=False)
    response = anon.post(
        "/settings/ip-display", data={"ip_mode": "full", "ip_v4_hidden": "1", "ip_v6_hidden": "4"}
    )
    assert response.status_code == 401


def _set_mode(client, csrf, mode, v4="1", v6="4", headers=None):
    return client.post(
        "/settings/ip-display",
        data={"ip_mode": mode, "ip_v4_hidden": v4, "ip_v6_hidden": v6, "csrf_token": csrf},
        headers=headers or {},
        follow_redirects=False,
    )


def test_settings_post_persists_mode_and_redirects(t4a):
    client, csrf = t4a["client"], t4a["csrf"]
    response = _set_mode(client, csrf, "suffix_mask", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 303
    assert response.headers["location"].startswith("/settings")
    page = _requests(client).text
    assert "203.0.113.*" in page
    assert V4 not in page


def test_settings_post_rejects_bad_values_without_echo(t4a):
    client, csrf = t4a["client"], t4a["csrf"]
    for body in (
        {"ip_mode": "everyone", "ip_v4_hidden": "1", "ip_v6_hidden": "4"},
        {"ip_mode": "full", "ip_v4_hidden": "0", "ip_v6_hidden": "4"},
        {"ip_mode": "full", "ip_v4_hidden": "1", "ip_v6_hidden": "99"},
    ):
        response = client.post("/settings/ip-display", data={**body, "csrf_token": csrf})
        assert response.status_code == 400
    # Failed mutations left the default full mode intact.
    assert V4 in _requests(client).text


# --- Display modes: full default, masked suffix absent, pseudonym ---


def test_full_default_shows_exact_spellings_and_stable_counts(t4a):
    client, csrf = t4a["client"], t4a["csrf"]
    full = _requests(client).text
    assert V4 in full
    assert V6_SHORT in full
    assert V6_LONG in full
    assert _pseudo(V4) in full
    _set_mode(client, csrf, "pseudonym_only")
    pseudo_page = _requests(client).text
    assert V4 not in pseudo_page
    assert V6_SHORT not in pseudo_page
    assert V6_LONG not in pseudo_page
    assert _pseudo(V4) in pseudo_page
    # Pseudonyms, counts and filters are stable across display modes.
    assert "unique events" in full and "unique events" in pseudo_page
    assert "Showing 1–5 of 5" in full
    assert "Showing 1–5 of 5" in pseudo_page


def test_suffix_mask_hides_suffix_everywhere(t4a):
    client, csrf = t4a["client"], t4a["csrf"]
    _set_mode(client, csrf, "suffix_mask")
    page = _requests(client).text
    assert "203.0.113.*" in page
    assert "2001:0db8:0000:0000:*" in page
    assert V4 not in page
    assert "203.0.113.20" not in page
    assert V6_SHORT not in page
    assert V6_LONG not in page
    # Masked full page (list + details + title attrs) carries no suffix.
    assert "masking is not anonymity" in page or "absent from the page" in page


def test_hidden_counts_maxhide(t4a):
    client, csrf = t4a["client"], t4a["csrf"]
    assert _set_mode(client, csrf, "suffix_mask", v4="4", v6="8").status_code == 303
    page = _requests(client).text
    assert "*.*.*.*" in page
    assert "203.0.113" not in page


def test_corrupt_stored_mode_fails_closed_with_notice(t4a):
    client, csrf = t4a["client"], t4a["csrf"]
    with writer_transaction(t4a["db"]) as conn:
        conn.execute(
            "INSERT INTO admin_settings (key, value, updated_at) VALUES (?, ?, ?)"
            " ON CONFLICT (key) DO UPDATE SET value = excluded.value,"
            " updated_at = excluded.updated_at",
            ("ip_display_mode", "everyone", "2026-11-01T00:00:00+00:00"),
        )
    page = _requests(client).text
    assert V4 not in page
    assert "safely ignored" in page
    assert _set_mode(client, csrf, "full").status_code == 303
    assert V4 in _requests(client).text


def test_missing_key_renders_unavailable_with_guidance(t4a, monkeypatch):
    monkeypatch.delenv("ORIGINAL_IP_KEY", raising=True)
    page = _requests(t4a["client"]).text
    assert "Unavailable" in page
    assert "no decryption key" in page
    assert V4 not in page
    # Deterministic analytics keep working without a key.
    assert "unique events" in page


def test_wrong_key_renders_decrypt_failed(t4a, monkeypatch):
    monkeypatch.setenv("ORIGINAL_IP_KEY", base64.b64encode(bytes(32)).decode())
    page = _requests(t4a["client"]).text
    assert "Unavailable" in page
    assert "decryption failed" in page
    assert V4 not in page


def test_tampered_ciphertext_fails_closed(t4a):
    with writer_transaction(t4a["db"]) as conn:
        rows = conn.execute("SELECT request_id FROM request_original_ips").fetchall()
        assert rows
        conn.execute("UPDATE request_original_ips SET ciphertext = ?", (b"tampered-bytes",))
    page = _requests(t4a["client"]).text
    assert "decryption failed" in page
    assert V4 not in page
    assert "tampered-bytes" not in page


def test_legacy_unenriched_row_is_unavailable(t4a):
    page = _requests(t4a["client"]).text
    # The plain-combined legacy row has no encrypted original.
    assert "/legacy" in page
    assert "never was enriched" in page or "was never enriched" in page


def test_duplicate_events_bind_distinct_originals(t4a):
    page = _requests(t4a["client"]).text
    # Two identical /shop/item rows from distinct offsets each show the
    # same full original exactly (duplicate binding, no cross-pairing).
    assert page.count("/shop/item") >= 2
    assert page.count(V4) >= 2
    # Five rows (four enriched + one legacy) each carry a detail panel.
    assert page.count('class="req-detail"') == 5


# --- Exact-IP search: POST-only, transient, pseudonym redirect ---


def _ip_search(client, csrf, ip, extra_headers=None):
    # Mirror the real form action: the current filter/window state rides
    # the POST query string and must survive into the safe redirect.
    return client.post(
        f"/requests/ip-search?site=default&{WINDOW_QS}&tz=UTC",
        data={"ip": ip, "csrf_token": csrf},
        headers=extra_headers or {},
        follow_redirects=False,
    )


def test_exact_ip_search_translates_to_safe_pseudonym(t4a):
    client, csrf = t4a["client"], t4a["csrf"]
    response = _ip_search(client, csrf, V4, {"X-CSRF-Token": csrf})
    assert response.status_code == 303
    location = response.headers["location"]
    assert V4 not in location
    expected = _pseudo(V4)
    assert f"search={expected}" in location
    assert "site=default" in location and "tz=UTC" in location
    followed = client.get(location).text
    assert "/shop/item" in followed
    assert "/style.css" not in followed


def test_exact_ip_search_keeps_legacy_spelling_identity(t4a):
    client, csrf = t4a["client"], t4a["csrf"]
    short = _ip_search(client, csrf, V6_SHORT)
    long = _ip_search(client, csrf, V6_LONG)
    assert short.status_code == 303 and long.status_code == 303
    # Equivalent spellings hash distinctly (legacy byte identity): the
    # compressed search must not match the expanded row and vice versa.
    assert _pseudo(V6_SHORT) != _pseudo(V6_LONG)
    assert f"search={_pseudo(V6_SHORT)}" in short.headers["location"]
    assert f"search={_pseudo(V6_LONG)}" in long.headers["location"]
    assert "/style.css" in client.get(short.headers["location"]).text
    assert "/style.css" not in client.get(long.headers["location"]).text


def test_exact_ip_search_rejects_invalid_without_echo(t4a):
    client, csrf = t4a["client"], t4a["csrf"]
    for bad in ("not-an-ip", "999.1.1.1", "", "x" * 2000, "203.0.113.20/24", "  "):
        response = _ip_search(client, csrf, bad)
        assert response.status_code == 400
        assert "single valid IPv4 or IPv6" in response.text
        if bad.strip():
            assert bad.strip()[:32] not in response.text
    assert "location" not in response.headers


def test_exact_ip_search_scoped_form_never_leaks_zone(t4a):
    # Scoped IPv6 is ingestion-valid (ipaddress accepts it), so the
    # search translates it like any stored spelling; the zone id must
    # never appear in the redirect, URL, history or rendered page, and
    # the row renders the fixed scoped-unavailable notice instead.
    client, csrf = t4a["client"], t4a["csrf"]
    response = _ip_search(client, csrf, "fe80::1%eth0")
    assert response.status_code == 303
    location = response.headers["location"]
    assert "eth0" not in location and "fe80" not in location
    assert f"search={_pseudo('fe80::1%eth0')}" in location
    followed = client.get(location).text
    assert "eth0" not in followed


def test_exact_ip_search_requires_session_and_csrf(t4a):
    from starlette.testclient import TestClient as TC

    anon = TC(t4a["client"].app, raise_server_exceptions=False)
    assert anon.post("/requests/ip-search", data={"ip": V4, "csrf_token": "x"}).status_code == 401
    denied = t4a["client"].post("/requests/ip-search", data={"ip": V4, "csrf_token": "wrong"})
    assert denied.status_code == 403
    assert t4a["client"].get("/requests/ip-search").status_code == 405


# --- Shared enrichment filters in web params/state/nav/paging ---


def test_enrichment_filters_propagate_and_narrow(t4a):
    client = t4a["client"]
    base = f"/requests?site=default&{WINDOW_QS}&tz=UTC"
    page = client.get(
        base + "&server_host=example.org&http_version=HTTP%2F1.1"
        "&mime_type=text%2Fhtml&cache_status=MISS&tls_protocol=TLSv1.3"
        "&timing_available=yes&timing_min_ms=100&timing_max_ms=200"
    ).text
    assert "/shop/item" in page
    assert "/style.css" not in page
    assert "/legacy" not in page
    # Current values survive in the filter form and canonical scope.
    for needle in (
        'value="example.org"',
        'value="HTTP/1.1"',
        'value="text/html"',
        'value="MISS"',
        'value="TLSv1.3"',
        'value="100"',
        'value="200"',
    ):
        assert needle in page
    # Safe navigation keeps the scope: side-nav links carry the matchers.
    assert "server_host=example.org" in page
    assert "timing_available=yes" in page
    assert "timing_min_ms=100" in page


def test_path_exact_and_timing_absence_filters(t4a):
    client = t4a["client"]
    base = f"/requests?site=default&{WINDOW_QS}&tz=UTC"
    exact = client.get(base + "&path_exact=%2Flegacy").text
    assert "/legacy" in exact and "/shop/item" not in exact
    missing = client.get(base + "&timing_available=no").text
    assert "/legacy" in missing and "/shop/item" not in missing
    upstream = client.get(base + "&upstream_available=yes").text
    assert "/shop/item" in upstream and "/style.css" not in upstream


def test_enrichment_filters_reject_invalid(t4a):
    client = t4a["client"]
    base = f"/requests?site=default&{WINDOW_QS}&tz=UTC"
    for bad in (
        "&http_version=bogus",
        "&timing_available=maybe",
        "&timing_min_ms=abc",
        "&timing_min_ms=500&timing_max_ms=100",
        "&tls_protocol=has+space",
        "&mime_type=not-a-mime",
        "&path_exact=no-leading-slash",
        "&timing_max_ms=infinity",
    ):
        assert client.get(base + bad).status_code == 400


def test_paging_preserves_new_filters(t4a):
    client = t4a["client"]
    page = client.get(
        f"/requests?site=default&{WINDOW_QS}&tz=UTC&limit=2&offset=0"
        "&server_host=example.org&cache_status=HIT"
    ).text
    assert "server_host=example.org" in page
    assert "cache_status=HIT" in page
    assert "Showing 1–2 of 2" in page


# --- API and exports stay address-free; downloads carry privacy note ---


def test_api_and_export_never_carry_originals(t4a):
    client, token = t4a["client"], t4a["token"]
    headers = {"Authorization": f"Bearer {token}"}
    params = {
        "site_id": "default",
        "from": "2026-10-27T00:00:00+00:00",
        "to": "2026-10-28T00:00:00+00:00",
    }
    api = client.get("/api/v1/requests", params=params, headers=headers)
    assert api.status_code == 200
    assert V4 not in api.text and V6_SHORT not in api.text
    for fmt in ("csv", "json"):
        export = client.get(
            "/api/v1/exports/requests", params={**params, "format": fmt}, headers=headers
        )
        assert export.status_code == 200
        assert V4 not in export.text and V6_SHORT not in export.text
        assert V6_LONG not in export.text


def test_session_downloads_stream_pseudonyms_with_note(t4a):
    client, csrf = t4a["client"], t4a["csrf"]
    page = _requests(client).text
    assert "Full-result downloads" in page
    assert "pseudonyms only" in page
    assert "export_csv_url" not in page
    assert "format=csv" in page and "format=json" in page
    for mode in ("full", "suffix_mask", "pseudonym_only"):
        _set_mode(client, csrf, mode)
        mode_page = _requests(client).text
        assert "pseudonyms only" in mode_page
        assert V4 not in mode_page or mode == "full"
    _set_mode(client, csrf, "full")
    # Follow the reviewed session export directly with the same scope.
    csv = client.get(f"/export/requests?site=default&{WINDOW_QS}&tz=UTC&format=csv&sort=newest")
    assert csv.status_code == 200
    assert V4 not in csv.text and V6_SHORT not in csv.text
    assert _pseudo(V4) in csv.text
    json_export = client.get(
        f"/export/requests?site=default&{WINDOW_QS}&tz=UTC&format=json&sort=newest"
    )
    assert json_export.status_code == 200
    assert V4 not in json_export.text and _pseudo(V4) in json_export.text


# --- Rendering details: referrer links, sort truth, locale, history ---


def test_detail_inspector_links_and_units(t4a):
    page = _requests(t4a["client"]).text
    assert 'href="https://example.org/old"' in page
    assert 'rel="noopener noreferrer nofollow"' in page
    assert "123.0 ms" in page
    assert "Response-time data unavailable" in page
    assert "never by original address" in page
    assert "HTTP/1.1" in page and "TLSv1.3" in page and "text/html" in page


def test_new_locale_keys_render_without_raw_fallback(t4a):
    client, csrf = t4a["client"], t4a["csrf"]
    for mode in ("full", "suffix_mask", "pseudonym_only"):
        _set_mode(client, csrf, mode)
        page = _requests(client).text
        for raw in (
            "privacy.ip_search_title",
            "privacy.export_note",
            "requests.client_sort_note",
            "requests.downloads_title",
            "filter.more",
            "filter.path_exact",
            "filter.logged_host",
            "filter.timing_with",
            "privacy.ip_unavailable_short",
        ):
            assert raw not in page
    settings = client.get("/settings").text
    assert "privacy.ip_title" not in settings
    assert "Original client addresses" in settings
    assert "privacy.ip_mode_full" not in settings


def test_history_and_cache_privacy_markers(t4a):
    client = t4a["client"]
    response = _requests(client)
    assert response.headers.get("Cache-Control") == "no-store"
    base = (ROOT / "app" / "web" / "templates" / "base.html").read_text(encoding="utf-8")
    assert '"historyCacheSize": 0' in base
    assert '"refreshOnHistoryMiss": true' in base
    assert "hx-history" not in base or "false" in base
    headers_src = (ROOT / "app" / "web" / "headers.py").read_text(encoding="utf-8")
    assert "no-store" in headers_src
    full_page = response.text
    assert "data-private-stale-reload" in full_page
    _set_mode(client, t4a["csrf"], "pseudonym_only")
    assert "data-private-stale-reload" not in _requests(client).text
    # Served dashboard JS refreshes stale private views on BFCache
    # restore and never persists addresses in web storage.
    served = client.get("/static/js/requests.js").text
    assert "pageshow" in served and "persisted" in served
    assert "localStorage" not in served and "sessionStorage" not in served
    assert "203.0.113" not in served
    assert "reload" in served


def test_concurrent_delete_keeps_rendering(t4a):
    client = t4a["client"]
    with writer_transaction(t4a["db"]) as conn:
        target = conn.execute("SELECT id FROM requests WHERE path = '/legacy'").fetchone()
        assert target is not None
        conn.execute("DELETE FROM requests WHERE id = ?", (target[0],))
    page = _requests(client).text
    assert "/legacy" not in page
    assert "/shop/item" in page
    assert V4 in page
