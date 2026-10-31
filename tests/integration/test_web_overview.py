"""T9-A web tests: shell, login, Overview data and output safety.

The dashboard reads through the shared analytics services, so every
rendered total is checked against independently expected fixture values
(10 requests, 4xx=2, 5xx=1 for the Nginx Combined fixture) and against
the shared service on the same filter. Synthetic data only.
"""

from app.analytics import service
from app.analytics.contracts import AnalyticsFilter, TimeWindow
from app.db.database import connect, writer_transaction

WINDOW = "/?range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"


def _login(client):
    response = client.post(
        "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
    )
    assert response.status_code == 200
    return response.json()["csrf_token"]


def test_login_page_is_public_with_csp(web):
    client, _ = web
    response = client.get("/login")
    assert response.status_code == 200
    assert "data-login-form" in response.text
    assert 'name="password"' in response.text
    csp = response.headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp


def test_overview_requires_session(web):
    client, _ = web
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"].startswith("/login?next=")


def test_bearer_token_does_not_open_dashboard(web):
    client, db = web
    with writer_transaction(db) as conn:
        from app.auth.tokens import issue_token

        _, token = issue_token(conn, name="web", site_id="default")
    response = client.get("/", headers={"Authorization": f"Bearer {token}"}, follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"].startswith("/login")


def test_overview_totals_and_notices(web):
    client, _ = web
    _login(client)
    response = client.get(WINDOW)
    assert response.status_code == 200
    html = response.text
    # Independently expected fixture totals: 10 fixture lines plus the
    # attack line (a 404), so 4xx rises from 2 to 3 while 5xx stays 1.
    assert "Total requests" in html
    assert ">11<" in html
    assert "3 / 1" in html
    # Attack path is escaped, never raw executable markup.
    assert "&lt;script&gt;" in html
    assert "<script>alert" not in html
    # Combined sources carry no timing: unavailable, never zero.
    assert "Response-time data unavailable for this log source" in html
    # Explicit display timezone and observation window.
    assert "Times shown in UTC" in html
    # Referrer and development summaries come from the shared layer.
    assert "example.org" in html
    assert "/identical" in html
    # Every script, stylesheet and image is served locally.
    assert 'src="http' not in html and 'href="http' not in html


def test_overview_matches_shared_service(web):
    client, db = web
    _login(client)
    html = client.get(WINDOW).text
    conn = connect(db, read_only=True)
    try:
        filt = AnalyticsFilter(
            site_id="default",
            window=TimeWindow(
                time_from="2026-10-27T00:00:00+00:00",
                time_to="2026-10-28T00:00:00+00:00",
            ),
        )
        summary = service.summarize(conn, filt)
    finally:
        conn.close()
    totals = summary["totals"]
    assert totals == {
        "requests": 11,
        "errors_4xx": 3,
        "errors_5xx": 1,
        "bytes_total": 3334,
        "bytes_measured": 10,
    }
    assert f">{totals['requests']}<" in html
    assert f"{totals['errors_4xx']} / {totals['errors_5xx']}" in html


def test_empty_window_shows_no_data(web):
    client, _ = web
    _login(client)
    response = client.get(
        "/?range=custom&from=2020-01-01T00:00:00%2B00:00&to=2020-01-02T00:00:00%2B00:00"
    )
    assert response.status_code == 200
    assert "No data is available for the selected filters." in response.text


def test_invalid_params_and_unknown_site(web):
    client, _ = web
    _login(client)
    bad = client.get("/?range=custom&from=not-a-date&to=2026-10-28T00:00:00%2B00:00")
    assert bad.status_code == 400
    unknown = client.get(
        "/?range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00&site=ghost"
    )
    assert unknown.status_code == 404


def test_fragment_auth_and_content(web):
    client, _ = web
    denied = client.get("/partials/overview")
    assert denied.status_code == 401
    _login(client)
    response = client.get(
        "/partials/overview?range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"
    )
    assert response.status_code == 200
    assert "Total requests" in response.text
    # Fragments carry no layout shell and no executable scripts (chart
    # data travels in non-executable application/json blocks only).
    assert "<html" not in response.text
    assert "<script src" not in response.text
    assert 'type="application/json"' in response.text


def test_logout_locks_dashboard(web):
    client, _ = web
    csrf = _login(client)
    assert client.get("/").status_code == 200
    logout = client.post("/api/v1/admin/logout", headers={"X-CSRF-Token": csrf})
    assert logout.status_code == 200
    locked = client.get("/", follow_redirects=False)
    assert locked.status_code == 302
    assert locked.headers["location"].startswith("/login")
