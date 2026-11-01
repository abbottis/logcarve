"""Slice B web tests: rich overview panels, bot sorting, request explorer.

Early-review regression cases live here: robots/sitemap cards stay
conjunctive with an active path_prefix, ``traffic=error`` is rejected as
an illegal bucket, and every data page passes the versioned rules under
an active named/bot filter. Synthetic data only.
"""

from fastapi.testclient import TestClient

WINDOW_QS = "range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"


def _login(client):
    response = client.post(
        "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
    )
    assert response.status_code == 200


def _robot_db(tmp_path, monkeypatch):
    """Self-contained DB with a bot /robots.txt hit plus other rows."""
    from app.auth.passwords import hash_password
    from app.auth.tokens import create_admin_user
    from app.db.database import writer_transaction
    from app.db.importer import run_import
    from app.db.migrations_runner import migrate
    from app.ingestion.sources import SourceConfig

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    root = tmp_path / "robot-logs"
    root.mkdir()
    (root / "access.log").write_bytes(
        b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0000] "GET /robots.txt HTTP/1.1"'
        b' 200 100 "-" "Googlebot/2.1"\n'
        b'203.0.113.20 - - [27/Oct/2026:11:15:44 +0000] "GET /docs/guide HTTP/1.1"'
        b' 200 50 "-" "Googlebot/2.1"\n'
        b'198.51.100.7 - - [27/Oct/2026:11:20:00 +0000] "GET / HTTP/1.1"'
        b' 200 10 "-" "curl/8.0"\n'
    )
    db = tmp_path / "robot.sqlite3"
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
    return db


def _robot_client(tmp_path, monkeypatch):
    from app.main import create_app

    db = _robot_db(tmp_path, monkeypatch)
    return TestClient(create_app(db_path=db, secure_cookies=False), raise_server_exceptions=False)


def _card_count(html, label):
    import re

    match = re.search(re.escape(label) + r"</dt><dd class=\"tech text-lg\">(\d+)</dd>", html)
    assert match is not None, label
    return int(match.group(1))


def test_robots_sitemap_cards_keep_active_path_prefix(tmp_path, monkeypatch):
    client = _robot_client(tmp_path, monkeypatch)
    _login(client)
    base = f"site=default&{WINDOW_QS}&tz=UTC"
    plain = client.get(f"/crawlers?{base}").text
    assert _card_count(plain, "robots.txt requests") == 1
    # An active global path_prefix narrows the cards conjunctively; the
    # /robots.txt hit outside /docs/ must not leak into the scoped card.
    narrowed = client.get(f"/crawlers?{base}&path_prefix=/docs/").text
    assert _card_count(narrowed, "robots.txt requests") == 0
    assert _card_count(narrowed, "sitemap.xml requests") == 0
    empty = client.get(f"/crawlers?{base}&path_prefix=/no-match").text
    assert _card_count(empty, "robots.txt requests") == 0
    assert _card_count(empty, "sitemap.xml requests") == 0


def test_traffic_error_bucket_rejected_on_errors_page(web):
    client, _ = web
    _login(client)
    base = f"site=default&{WINDOW_QS}&tz=UTC"
    assert client.get(f"/errors?{base}").status_code == 200
    bad = client.get(f"/errors?{base}&traffic=error")
    assert bad.status_code == 400


def test_every_data_page_reads_rules_under_bot_filter(web):
    client, _ = web
    _login(client)
    base = f"site=default&{WINDOW_QS}&tz=UTC&traffic=claimed_bot"
    for path in ("/", "/security", "/crawlers", "/errors", "/requests", "/ask"):
        response = client.get(f"{path}?{base}")
        assert response.status_code == 200, path
    bot_base = f"site=default&{WINDOW_QS}&tz=UTC&bot=bot-auto-curl"
    for path in ("/", "/crawlers", "/requests"):
        response = client.get(f"{path}?{bot_base}")
        assert response.status_code == 200, path
    unknown = client.get(f"/crawlers?{base}&bot=no-such-bot")
    assert unknown.status_code == 400


def test_overview_renders_new_panels_and_filter_controls(web):
    client, _ = web
    _login(client)
    html = client.get(f"/?site=default&{WINDOW_QS}&tz=UTC").text
    for caption in (
        "Traffic by type",
        "Requests by resource kind",
        "Claimed browsers",
        "Requests by weekday and hour",
        "Most active clients",
    ):
        assert caption in html
    for control in (
        'name="traffic"',
        'name="bot"',
        'name="category"',
        'name="provider"',
        'name="purpose"',
        'name="status_class"',
        'name="search"',
        'name="path_prefix"',
    ):
        assert control in html
    assert "bot-auto-curl" in html


def test_crawlers_sort_links_reject_unknown_sort(web):
    client, _ = web
    _login(client)
    base = f"site=default&{WINDOW_QS}&tz=UTC"
    assert client.get(f"/crawlers?{base}&sort=name_asc").status_code == 200
    assert client.get(f"/crawlers?{base}&sort=bogus").status_code == 400
    assert client.get(f"/partials/crawlers?{base}&sort=bogus").status_code == 400


def test_requests_explorer_renders_sanitized_rows(web):
    client, _ = web
    _login(client)
    base = f"site=default&{WINDOW_QS}&tz=UTC"
    html = client.get(f"/requests?{base}").text
    assert "Sanitized request rows" in html
    assert client.get(f"/requests?{base}&sort=oldest").status_code == 200
    assert client.get(f"/requests?{base}&sort=bogus").status_code == 400
    assert "/requests" in html  # nav entry present
