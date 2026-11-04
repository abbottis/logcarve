"""T4a correction regressions: exact client, body bound, locale, timing, state.

Owner-authorized parity scope (T4a only). Synthetic fixtures only.
Frozen-tree probes reproduced each defect first: the exact-IP POST
returned 303 but matched 3 rows instead of 1 (another client's
User-Agent and a third client's path both contained the target HMAC),
the selected explorer sort was dropped, the requests banner printed
the raw ``private_unavailable:no_key`` code, an upstream-only row hid
its measured value, oversized chunked bodies streamed unbounded, and
Ask serialized only the old selector allowlist.
"""

import base64
from datetime import UTC, datetime
from pathlib import Path

import pytest
from starlette.requests import Request
from starlette.testclient import TestClient

from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user
from app.db.database import writer_transaction
from app.db.importer import run_import
from app.ingestion.combined import pseudonymize_client
from app.ingestion.sources import SourceConfig

ROOT = Path(__file__).resolve().parent.parent.parent
HMAC_KEY = b"t4a-corrections-hmac-key"
HMAC_ENV = "t4a-corrections-hmac-key"

V4 = "203.0.113.20"
OTHER_IP = "198.51.100.9"
PATH_IP = "198.51.100.10"
UP_IP = "192.0.2.55"
ZERO_IP = "192.0.2.66"

WINDOW_QS = "range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"
FROM = datetime(2026, 10, 27, tzinfo=UTC)
TO = datetime(2026, 10, 28, tzinfo=UTC)


def _ext_line(host, stamp, method, path, status, size, referer, ua, **kw):
    vhost = kw.get("vhost", "example.org")
    cache = kw.get("cache", "MISS")
    timing = kw.get("timing", "0.050")
    mime = kw.get("mime", "text/html")
    tls = kw.get("tls", "TLSv1.3")
    upstream = kw.get("upstream", '"-"')
    return (
        f'{host} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} '
        f'"{referer}" "{ua}" {vhost} {cache} {timing} {mime} {tls} {upstream}'
    )


def _seed_lines(hmac_target):
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
            timing="0.123",
            upstream='"0.100, 0.020"',
        ),
        _ext_line(
            V4,
            "27/Oct/2026:10:16:32 +0100",
            "GET",
            "/other-page",
            200,
            64,
            "-",
            "Other/1.0",
        ),
        # Adversarial neighbours: the target HMAC embedded in another
        # client's User-Agent and in a third client's path. A general
        # text search matches these; the exact client selector must not.
        _ext_line(
            OTHER_IP,
            "27/Oct/2026:10:17:32 +0100",
            "GET",
            "/other",
            200,
            10,
            "-",
            f"probe-{hmac_target}-bot",
        ),
        _ext_line(
            PATH_IP,
            "27/Oct/2026:10:18:32 +0100",
            "GET",
            f"/{hmac_target}",
            200,
            10,
            "-",
            "Mozilla/5.0",
        ),
        # Upstream-only row: no request duration, measured upstream 12.5ms.
        _ext_line(
            UP_IP,
            "27/Oct/2026:11:02:03 +0100",
            "GET",
            "/upstream-only",
            200,
            128,
            "-",
            "Mozilla/5.0",
            timing="-",
            upstream='"0.0125"',
        ),
        # Zero row: measured 0ms request and upstream durations stay 0.
        _ext_line(
            ZERO_IP,
            "27/Oct/2026:11:03:03 +0100",
            "GET",
            "/zero",
            200,
            128,
            "-",
            "Mozilla/5.0",
            timing="0.000",
            upstream='"0.000"',
        ),
        # Both-missing row: neither duration measured; only the
        # unavailable note may render, never a faked zero.
        _ext_line(
            "192.0.2.77",
            "27/Oct/2026:11:04:03 +0100",
            "GET",
            "/no-timing",
            200,
            128,
            "-",
            "TestAgent/1.0",
            timing="-",
            upstream='"-"',
        ),
    ]


@pytest.fixture
def cx(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "t4a-corrections-session")
    monkeypatch.setenv("HMAC_KEY", HMAC_ENV)
    key = bytes((7 * 31 + i) % 256 for i in range(32))
    monkeypatch.setenv("ORIGINAL_IP_KEY", base64.b64encode(key).decode())
    hmac_target = pseudonymize_client(V4, HMAC_KEY)
    root = tmp_path / "logs"
    root.mkdir()
    (root / "ext.log").write_text("\n".join(_seed_lines(hmac_target)) + "\n", encoding="utf-8")
    db = tmp_path / "corr.sqlite3"
    run_import(
        db,
        source=SourceConfig(
            source_id="cx-ext",
            format_id="nginx_extended",
            allowed_root=root,
            relative_path="ext.log",
        ),
        site_id="default",
        site_name="Cx",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="ext.log",
        hmac_key=HMAC_KEY,
        capture_originals=True,
    )
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
        _, token = __import__("app.auth.tokens", fromlist=["issue_token"]).issue_token(
            conn, name="cx", site_id="default"
        )
    from app.main import create_app

    app = create_app(db_path=db, secure_cookies=False)
    client = TestClient(app, raise_server_exceptions=False)
    login = client.post("/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"})
    assert login.status_code == 200
    return {
        "app": app,
        "client": client,
        "db": db,
        "csrf": login.json()["csrf_token"],
        "token": token,
        "target": hmac_target,
    }


def _auth(cx):
    return {"Authorization": f"Bearer {cx['token']}"}


def _api(cx, path, **params):
    base = {"site_id": "default", "from": FROM.isoformat(), "to": TO.isoformat()}
    base.update(params)
    return cx["client"].get(path, params=base, headers=_auth(cx))


# --- 1. Exact client scope: equality, not general search ---


def test_exact_client_ignores_adversarial_ua_and_path(cx):
    target = cx["target"]
    exact = _api(cx, "/api/v1/requests", client=target)
    assert exact.status_code == 200, exact.text
    rows = exact.json()["items"]
    assert len(rows) == 2
    assert {row["client_pseudonym"] for row in rows} == {target}
    summary = _api(cx, "/api/v1/summary", client=target)
    assert summary.json()["totals"]["requests"] == 2
    assert summary.json()["filters"]["client"] == target
    # The general text search intentionally still matches the
    # adversarial neighbours: that breadth is the documented
    # difference, not a regression.
    broad = _api(cx, "/api/v1/requests", search=target)
    assert broad.json()["total_rows"] == 4


def test_exact_client_unknown_yields_empty_not_fuzzy(cx):
    unknown = "0" * 64
    assert unknown != cx["target"]
    response = _api(cx, "/api/v1/summary", client=unknown)
    assert response.status_code == 200
    assert response.json()["totals"]["requests"] == 0
    assert _api(cx, "/api/v1/requests", client=unknown).json()["items"] == []


def test_exact_client_rejects_malformed_pseudonym(cx):
    for bad in ("xyz", "0" * 63, "0" * 65, "G" * 64, "0" * 64 + " "):
        assert _api(cx, "/api/v1/summary", client=bad).status_code == 400


def test_exact_client_intersects_with_text_search(cx):
    # Only the /other-page row is both the target client AND the text hit.
    response = _api(cx, "/api/v1/requests", client=cx["target"], search="other-page")
    assert response.status_code == 200
    rows = response.json()["items"]
    assert len(rows) == 1
    assert rows[0]["path"] == "/other-page"


def _ip_search(cx, ip, action_extra="", headers=None):
    return cx["client"].post(
        f"/requests/ip-search?site=default&{WINDOW_QS}&tz=UTC{action_extra}",
        data={"ip": ip, "csrf_token": cx["csrf"]},
        headers=headers or {},
        follow_redirects=False,
    )


def test_ip_search_sets_client_preserves_scope_and_sort(cx):
    target = cx["target"]
    response = _ip_search(
        cx,
        V4,
        "&search=other-page&sort=oldest&limit=10&offset=40",
        headers={"X-CSRF-Token": cx["csrf"]},
    )
    assert response.status_code == 303, response.text
    location = response.headers["location"]
    assert V4 not in location
    assert f"client={target}" in location
    # Independent text search and the allowlisted sort survive; the
    # offset resets deliberately for the new search.
    assert "search=other-page" in location
    assert "sort=oldest" in location
    assert "offset=0" in location
    assert "limit=10" in location
    followed = cx["client"].get(location)
    assert followed.status_code == 200
    page = followed.text
    assert "/other-page" in page
    assert "/shop/item" not in page  # text filter still applies
    assert "req-client" in page


def test_consumers_agree_on_exact_client(cx):
    import sqlite3

    from app.ai.tools.definitions import execute_tool
    from app.analytics import service as analytics_service
    from app.analytics.contracts import AnalyticsFilter, TimeWindow
    from app.analytics.rules import load_rules

    target = cx["target"]
    rules = (
        load_rules(ROOT / "config" / "bot_rules.yaml").rules
        + load_rules(ROOT / "config" / "security_rules.yaml").rules
    )
    filt = AnalyticsFilter(
        site_id="default",
        window=TimeWindow(time_from=FROM, time_to=TO),
        client=target,
        limit=100,
        offset=0,
    )
    conn = sqlite3.connect(cx["db"])
    try:
        expected = analytics_service.summarize(conn, filt, rules)["totals"]["requests"]
        envelope = execute_tool(
            conn,
            rules,
            name="get_summary",
            arguments={
                "site_id": "default",
                "time_from": FROM.isoformat(),
                "time_to": TO.isoformat(),
                "client": target,
            },
            tool_call_id="tc1",
        )
    finally:
        conn.close()
    assert expected == 2
    assert envelope["filters"]["client"] == target
    assert envelope["result"]["totals"]["requests"] == expected
    api = _api(cx, "/api/v1/summary", client=target).json()
    assert api["totals"]["requests"] == expected
    # Session export streams the same two pseudonym rows in both formats.
    import json as _json

    for fmt in ("csv", "json"):
        export = cx["client"].get(
            f"/export/requests?site=default&{WINDOW_QS}&tz=UTC&client={target}"
            f"&format={fmt}&sort=oldest"
        )
        assert export.status_code == 200, (fmt, export.text[:200])
        assert V4 not in export.text
        if fmt == "csv":
            # Metadata travels in headers; the body is header row + rows.
            data_lines = [line for line in export.text.splitlines() if line]
            assert len(data_lines) - 1 == expected
            assert all(target in line for line in data_lines[1:])
        else:
            payload = _json.loads(export.text)
            assert len(payload["rows"]) == expected
            assert payload["metadata"]["filters"]["client"] == target
            assert '"complete": true' in export.text


def test_comparison_carries_exact_client(cx):
    response = _api(
        cx,
        "/api/v1/comparison",
        client=cx["target"],
        baseline_from=datetime(2026, 10, 26, tzinfo=UTC).isoformat(),
        baseline_to=datetime(2026, 10, 27, tzinfo=UTC).isoformat(),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["filters"]["current"]["client"] == cx["target"]
    assert body["filters"]["previous"]["client"] == cx["target"]
    assert body["selectors"]["client"] == cx["target"]


# --- 2. Ask scope: every selector reaches the trusted browser POST ---


def _chat_body(cx, **overrides):
    body = {
        "question": "How many requests carry the exact client?",
        "site_id": "default",
        "time_from": FROM.isoformat(),
        "time_to": TO.isoformat(),
    }
    body.update(overrides)
    return body


def test_ask_page_serializes_full_trusted_scope(cx):
    page = cx["client"].get(
        f"/ask?site=default&{WINDOW_QS}&tz=UTC&client={cx['target']}"
        "&timing_available=no&timing_min_ms=0&server_host=example.org"
        "&http_version=HTTP%2F1.1&mime_type=text%2Fhtml&cache_status=MISS"
        "&tls_protocol=TLSv1.3&path_exact=%2Fshop%2Fitem&upstream_available=yes"
    )
    assert page.status_code == 200, page.text[:300]
    html = page.text
    assert f'data-client="{cx["target"]}"' in html
    assert 'data-timing-available="no"' in html
    assert 'data-timing-min-ms="0.0"' in html
    assert 'data-upstream-available="yes"' in html
    assert 'data-server-host="example.org"' in html
    assert 'data-path-exact="/shop/item"' in html
    assert 'data-mime-type="text/html"' in html
    assert 'data-cache-status="MISS"' in html
    assert 'data-tls-protocol="TLSv1.3"' in html


def test_chat_post_carries_full_scope_and_model_cannot_widen_client(cx, monkeypatch):
    from app.ai.providers.base import ProviderResponse, ToolCall
    from app.ai.providers.fake import FakeProvider

    other = "f" * 64
    fake = FakeProvider(
        script=[
            ProviderResponse(
                text="",
                input_tokens=10,
                output_tokens=5,
                tool_calls=(ToolCall(name="get_summary", arguments={"client": other}),),
            ),
            ProviderResponse(text="Two requests.", input_tokens=10, output_tokens=5),
        ]
    )
    monkeypatch.setenv("AI_ENABLED", "true")
    monkeypatch.setenv("MODEL_DATA_POLICY_VERIFIED", "true")
    monkeypatch.setenv("MODEL_ALLOW_REAL_DATA", "true")
    monkeypatch.setenv("LLM_DAILY_LIMIT_USD", "50")
    monkeypatch.setattr("app.ai.service.select_provider", lambda settings: fake)
    response = cx["client"].post(
        "/api/v1/chat/ask",
        json=_chat_body(
            cx,
            client=cx["target"],
            path_exact="/shop/item",
            server_host="example.org",
            http_version="HTTP/1.1",
            mime_type="text/html",
            cache_status="MISS",
            tls_protocol="TLSv1.3",
            timing_available=False,
            upstream_available=True,
            timing_min_ms=0,
            timing_max_ms=200,
        ),
        headers={"X-CSRF-Token": cx["csrf"]},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["evidence"], "scoped tool call must leave evidence"
    filters = body["evidence"][0]["filters"]
    # The trusted scope wins over the model's attempted override.
    assert filters["client"] == cx["target"]
    assert filters["timing_available"] is False
    assert filters["timing_min_ms"] == 0
    assert filters["path_exact"] == "/shop/item"
    # The served evidence link reproduces the same scope for the browser.
    href = body["evidence"][0]["href"]
    assert f"client={cx['target']}" in href
    assert "timing_available=no" in href
    assert "timing_min_ms=0" in href


def test_trusted_scope_rejects_malformed_client(cx, monkeypatch):
    from app.ai.providers.base import ProviderResponse
    from app.ai.providers.fake import FakeProvider

    fake = FakeProvider(script=[ProviderResponse(text="x", input_tokens=1, output_tokens=1)])
    monkeypatch.setenv("AI_ENABLED", "true")
    monkeypatch.setenv("MODEL_DATA_POLICY_VERIFIED", "true")
    monkeypatch.setenv("MODEL_ALLOW_REAL_DATA", "true")
    monkeypatch.setenv("LLM_DAILY_LIMIT_USD", "50")
    monkeypatch.setattr("app.ai.service.select_provider", lambda settings: fake)
    response = cx["client"].post(
        "/api/v1/chat/ask",
        json=_chat_body(cx, client="not-a-pseudonym"),
        headers={"X-CSRF-Token": cx["csrf"]},
    )
    assert response.status_code == 400
    assert fake.outgoing == []


# --- 3. Real form body bound: stream cap, field policy, auth order ---


def test_settings_oversized_body_rejects_413_without_reflection(cx):
    padding = "x" * (20 * 1024)
    response = cx["client"].post(
        "/settings/ip-display",
        data={
            "ip_mode": "full",
            "ip_v4_hidden": "1",
            "ip_v6_hidden": "4",
            "csrf_token": cx["csrf"],
            "pad": padding,
        },
        headers={"X-CSRF-Token": cx["csrf"]},
        follow_redirects=False,
    )
    assert response.status_code == 413
    assert "too large" in response.text
    assert padding[:64] not in response.text


def test_ip_search_oversized_body_rejects_413_without_echo(cx):
    padding = V4 + "y" * (20 * 1024)
    response = cx["client"].post(
        f"/requests/ip-search?site=default&{WINDOW_QS}&tz=UTC",
        data={"ip": padding, "csrf_token": cx["csrf"]},
        headers={"X-CSRF-Token": cx["csrf"]},
        follow_redirects=False,
    )
    assert response.status_code == 413
    assert "too large" in response.text
    # The oversized field value is never echoed (the stored V4 row may
    # still render in full display mode; the padding run must not).
    assert "y" * 64 not in response.text


def test_bounded_reader_stops_consuming_oversized_chunks():
    import asyncio

    from app.web.routes import FORM_BODY_MAX_BYTES, _read_bounded_form

    consumed = {"n": 0}
    total_chunks = 41
    chunk = b"a=1&" * (16 * 1024)  # 64KiB per chunk, ~2.6MiB total
    assert len(chunk) * total_chunks > 2 * 1024 * 1024

    async def receive():
        consumed["n"] += 1
        if consumed["n"] <= total_chunks:
            return {
                "type": "http.request",
                "body": chunk,
                "more_body": consumed["n"] < total_chunks,
            }
        raise AssertionError("reader consumed past the available stream")

    async def _send(message):
        raise AssertionError("reader must never send")

    scope = {
        "type": "http",
        "method": "POST",
        "headers": [(b"content-type", b"application/x-www-form-urlencoded")],
    }
    fields, status = asyncio.run(_read_bounded_form(Request(scope, receive, _send)))
    assert status == "too_large"
    assert fields == {}
    # The oversized remainder is never consumed into the app buffer.
    assert consumed["n"] < total_chunks
    assert consumed["n"] * len(chunk) <= FORM_BODY_MAX_BYTES + len(chunk)


def test_lying_content_length_and_chunked_still_bounded(cx):
    import asyncio

    cookie = "; ".join(f"{k}={v}" for k, v in cx["client"].cookies.items())
    body_chunks = [b"ip=203.0.113.20&pad=" + b"z" * 8000] + [b"z" * 8000] * 10
    consumed = {"n": 0}

    async def receive():
        consumed["n"] += 1
        if body_chunks:
            return {
                "type": "http.request",
                "body": body_chunks.pop(0),
                "more_body": bool(body_chunks),
            }
        return {"type": "http.request", "body": b"", "more_body": False}

    messages = []

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/requests/ip-search",
        "query_string": f"site=default&{WINDOW_QS}&tz=UTC".encode(),
        "headers": [
            (b"cookie", cookie.encode()),
            (b"x-csrf-token", cx["csrf"].encode()),
            (b"content-type", b"application/x-www-form-urlencoded"),
            # Lying small length with a large chunked-style body.
            (b"content-length", b"32"),
        ],
        "server": ("testserver", 80),
        "client": ("testclient", 50000),
    }
    asyncio.run(cx["app"](scope, receive, send))
    start = next(m for m in messages if m["type"] == "http.response.start")
    assert start["status"] == 413
    # The lying length is ignored and the tail is never consumed:
    # 8021 + 8000 bytes fit under the cap, the third chunk trips it,
    # and the remaining eight chunks are never read.
    assert consumed["n"] == 3
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    assert b"z" * 64 not in raw


def test_form_field_policy_rejects_duplicates_and_malformed(cx):
    base = "/settings/ip-display"
    good = {"ip_mode": "full", "ip_v4_hidden": "1", "ip_v6_hidden": "4", "csrf_token": cx["csrf"]}
    headers = {"X-CSRF-Token": cx["csrf"]}
    # Ambiguous duplicates reject instead of keeping first or last.
    dup_body = (
        f"ip_mode=full&ip_mode=pseudonym_only&ip_v4_hidden=1&ip_v6_hidden=4&csrf_token={cx['csrf']}"
    )
    dup = cx["client"].post(
        base,
        content=dup_body,
        headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert dup.status_code == 400
    # Malformed percent escapes reject with a fixed 400.
    bad = cx["client"].post(
        base,
        content=f"ip_mode=%zz&csrf_token={cx['csrf']}",
        headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert bad.status_code == 400
    assert "203.0" not in bad.text
    # Oversized values within an undersized body still reject.
    big_value = cx["client"].post(base, data={**good, "ip_mode": "x" * 5000}, headers=headers)
    assert big_value.status_code == 400
    # The valid progressive form still works with the header token.
    ok = cx["client"].post(
        base,
        data={k: v for k, v in good.items() if k != "csrf_token"},
        headers=headers,
        follow_redirects=False,
    )
    assert ok.status_code == 303


def test_invalid_unicode_csrf_stays_safe_403(cx):
    response = cx["client"].post(
        "/settings/ip-display",
        content=b"ip_mode=full&csrf_token=\xff\xfe",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 403


# --- 4. UI accuracy: banner guidance and independent timing ---


def test_banner_key_maps_every_store_code_to_guidance():
    from app.web.private_ip import banner_key

    assert banner_key(None) == "privacy.ip_unavailable_not_stored"
    assert banner_key("private_unavailable:no_key") == "privacy.ip_unavailable_no_key"
    assert banner_key("private_unavailable:invalid_key") == "privacy.ip_unavailable_invalid_key"
    assert (
        banner_key("private_unavailable:decrypt_failed") == "privacy.ip_unavailable_decrypt_failed"
    )
    assert banner_key("private_unavailable:not_stored") == "privacy.ip_unavailable_not_stored"
    assert banner_key("private_unavailable:anything-else") == "privacy.ip_unavailable_not_stored"


def test_missing_key_banner_shows_guidance_not_raw_code(cx, monkeypatch):
    from app.web import private_ip

    monkeypatch.setattr(private_ip, "key_status", lambda conn: (None, "private_unavailable:no_key"))
    page = cx["client"].get(f"/requests?site=default&{WINDOW_QS}&tz=UTC")
    assert page.status_code == 200
    assert "private_unavailable" not in page.text
    assert "no decryption key is configured" in page.text


def test_upstream_only_row_renders_measured_value(cx):
    page = cx["client"].get(f"/requests?site=default&{WINDOW_QS}&tz=UTC&sort=oldest&limit=100").text
    # Upstream-only 12.5ms renders even though the request duration is
    # unavailable; zero stays zero, never hidden or faked.
    assert "12.5 ms" in page
    assert "0 ms" in page or "0.0 ms" in page


def test_both_missing_stays_unavailable_not_zero(cx):
    page = cx["client"].get(f"/requests?site=default&{WINDOW_QS}&tz=UTC&sort=oldest&limit=100").text
    # Exactly one fixture row lacks both measurements, so the honest
    # unavailable note renders exactly once; the upstream-only row
    # (12.5 ms above) never carries it.
    assert page.count("Response-time data unavailable") == 1


# --- 5. Safe state: canonical redirects preserve scope, reject junk ---


def test_settings_redirect_keeps_scope_drops_unknown(cx):
    response = cx["client"].post(
        f"/settings/ip-display?site=default&{WINDOW_QS}&tz=UTC&search=shop&evil=1",
        data={
            "ip_mode": "full",
            "ip_v4_hidden": "1",
            "ip_v6_hidden": "4",
            "csrf_token": cx["csrf"],
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("/settings?")
    assert "evil" not in location
    assert "search=shop" in location
    assert "tz=UTC" in location


def test_settings_malformed_state_rejects_before_write(cx):
    before = cx["client"].get(f"/requests?site=default&{WINDOW_QS}&tz=UTC").text
    assert V4 in before  # full mode shows originals
    response = cx["client"].post(
        "/settings/ip-display?range=bogus",
        data={
            "ip_mode": "pseudonym_only",
            "ip_v4_hidden": "1",
            "ip_v6_hidden": "4",
            "csrf_token": cx["csrf"],
        },
        follow_redirects=False,
    )
    assert response.status_code == 400
    after = cx["client"].get(f"/requests?site=default&{WINDOW_QS}&tz=UTC").text
    assert V4 in after  # the rejected change never wrote


def test_evidence_url_round_trips_bools_and_client():
    from app.web.evidence import evidence_url

    url = evidence_url(
        "/",
        {
            "site_id": "default",
            "time_from": FROM.isoformat(),
            "time_to": TO.isoformat(),
            "client": "0" * 64,
            "timing_available": False,
            "upstream_available": True,
            "timing_min_ms": 0,
            "limit": 20,
            "offset": 0,
        },
    )
    assert "timing_available=no" in url
    assert "upstream_available=yes" in url
    assert "timing_min_ms=0" in url
    assert ("client=" + "0" * 64) in url
    assert "True" not in url and "False" not in url
