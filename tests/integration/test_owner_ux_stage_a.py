"""Stage A owner-review integration checks: dropdowns, labels, Help,
starter, quick views and filter state.

All pages render from the seeded synthetic fixture through the real
router; machine IDs, submitted values and API contracts stay exact
while labels, offsets and controls read human-friendly. Synthetic
data only.
"""

import html
import re
from urllib.parse import parse_qs, urlsplit

WINDOW_QS = "range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"


def _login(client):
    response = client.post(
        "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
    )
    assert response.status_code == 200


def _params(url):
    return parse_qs(urlsplit(html.unescape(url)).query)


def test_method_status_are_native_dropdowns_with_all_and_phrases(web):
    client, _ = web
    _login(client)
    page = client.get(f"/?site=default&{WINDOW_QS}&tz=UTC").text
    method = re.search(r'<select id="f-method".*?</select>', page, re.DOTALL).group(0)
    status = re.search(r'<select id="f-status".*?</select>', page, re.DOTALL).group(0)
    assert '<option value="" selected>All</option>' in method
    assert '<option value="" selected>All</option>' in status
    for code in ("200", "404", "500"):
        assert f'value="{code}"' in status, f"standard status {code} missing"
    assert "404 · Not Found" in status
    assert "500 · Internal Server Error" in status
    for method_name in ("GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"):
        assert f">{method_name}</option>" in method, method_name
    assert 'name="method" type=' not in page, "no raw text input for method"
    assert 'name="status" type=' not in page, "no raw text input for status"


def test_current_selection_retained_and_applied(web):
    client, _ = web
    _login(client)
    page = client.get(f"/?site=default&{WINDOW_QS}&tz=UTC&method=GET&status=404").text
    assert '<option value="GET" selected>' in page
    assert '<option value="404" selected>' in page


def test_unobserved_valid_selection_retained(web):
    client, _ = web
    _login(client)
    # PROPFIND/599 are valid but absent from the fixture: retained, not dropped.
    page = client.get(f"/?site=default&{WINDOW_QS}&tz=UTC&method=PROPFIND&status=599").text
    assert '<option value="PROPFIND" selected>' in page
    assert '<option value="599" selected>' in page
    assert "Status 599 (unregistered)" in page


def test_named_bot_dropdown_drops_claimed_prefix(web):
    client, _ = web
    _login(client)
    page = client.get(f"/crawlers?site=default&{WINDOW_QS}&tz=UTC").text
    select = re.search(r'<select id="f-bot".*?</select>', page, re.DOTALL).group(0)
    assert "Claimed " not in select, "dropdown must not repeat the claim prefix"
    assert "curl" in select and "generic bot/crawler signal" in select
    assert "identified from User-Agent; identity not verified" in page


def test_crawlers_groups_stacked_readable_no_midword_breaks(web):
    client, _ = web
    _login(client)
    page = client.get(f"/crawlers?site=default&{WINDOW_QS}&tz=UTC").text
    assert "lg:grid-cols-3" not in page, "side-by-side triple crunch must be gone"
    assert 'class="bot-name"' in page
    # Ordinary names render whole; raw snake categories never show as text.
    assert "Automation tools" in page
    assert "Suspected automation" in page
    assert ">automation_tool<" not in page
    assert ">suspected_automation<" not in page
    assert "Unspecified" in page, "empty provider/purpose reads as Unspecified"
    assert "Claimed curl" not in page and "Claimed generic" not in page
    names = re.findall(r'<td class="bot-name">(.*?)</td>', page)
    assert names, "group name cells must render"
    for name in names:
        assert "wbr" not in name and "­" not in name


def test_offset_notice_carries_window_start_offset(web):
    client, _ = web
    _login(client)
    page = client.get(f"/?site=default&{WINDOW_QS}&tz=Europe%2FBerlin").text
    assert "Times shown in Europe/Berlin (UTC+01:00;" in page
    assert "Offsets are for the window start (2026-10-27)" in page
    summer = "range=custom&from=2026-07-27T00:00:00%2B00:00&to=2026-07-28T00:00:00%2B00:00"
    summer_page = client.get(f"/?site=default&{summer}&tz=Europe%2FBerlin").text
    assert "Times shown in Europe/Berlin (UTC+02:00;" in summer_page


def test_help_session_gated_with_safe_examples(web):
    client, _ = web
    denied = client.get("/help", follow_redirects=False)
    assert denied.status_code == 302, "Help must require a session"
    assert denied.headers["location"].startswith("/login"), "session gate redirects to login"
    _login(client)
    page = client.get(f"/help?site=default&{WINDOW_QS}&tz=UTC").text
    for section in (
        "Filters and time window",
        "UTC storage and display offsets",
        "Bot identity limits",
        "Privacy and pseudonyms",
        "External API and sessions",
    ):
        assert section in page, section
    assert "&lt;YOUR_TOKEN&gt;" in page, "examples use placeholders only"
    assert "s3cret" not in page and "SESSION_SECRET" not in page
    assert "verify-google-requests" in page, "optional verification reference linked"
    assert "Data Sources" in page, "sidebar navigation present"


def test_help_bearer_token_cannot_open_ui(web):
    from app.auth.tokens import issue_token
    from app.db.database import writer_transaction

    client, db = web
    _login(client)
    with writer_transaction(db) as conn:
        _, token = issue_token(conn, name="help-probe", site_id="default")
    client.cookies.clear()
    denied = client.get(
        "/help", headers={"Authorization": f"Bearer {token}"}, follow_redirects=False
    )
    assert denied.status_code in (302, 401), "bearer tokens must not open browser UI"


def test_help_keeps_active_filter_navigation(web):
    client, _ = web
    _login(client)
    page = client.get(f"/help?site=default&{WINDOW_QS}&tz=UTC&traffic=claimed_bot").text
    assert "traffic=claimed_bot" in page, "Help sidebar must keep active filters"


def test_firewall_starter_populates_without_sending(web):
    client, _ = web
    _login(client)
    page = client.get(f"/ask?site=default&{WINDOW_QS}&tz=UTC").text
    assert "Help me create firewall rules" in page
    match = re.search(r'data-starter-prompt="([^"]*firewall[^"]*)"', page, re.IGNORECASE)
    assert match, "firewall starter must populate the input"
    prompt = html.unescape(match.group(1))
    assert "MANUAL REVIEW" in prompt
    assert "never" in prompt.lower() and "apply" in prompt.lower()
    assert "original IP" in prompt


def test_quick_views_preserve_scope_and_replace_explicitly(web):
    client, _ = web
    _login(client)
    page = client.get(f"/?site=default&{WINDOW_QS}&tz=UTC").text
    assert "Quick views" in page
    links = {
        label: url
        for url, label in re.findall(
            r'<a class="btn btn-outline btn-xs" href="([^"]+)">([^<]+)</a>', page
        )
    }
    assert set(links) >= {
        "404 issues",
        "Server errors (5xx)",
        "Bot traffic",
        "Potential user traffic",
        "Largest responses",
    }
    params_404 = _params(links["404 issues"])
    assert params_404["status"] == ["404"] and "status_class" not in params_404
    assert params_404["site"] == ["default"] and params_404["tz"] == ["UTC"]
    assert params_404["offset"] == ["0"], "quick views reset paging"
    params_5xx = _params(links["Server errors (5xx)"])
    assert params_5xx["status_class"] == ["5xx"] and "status" not in params_5xx
    params_bots = _params(links["Bot traffic"])
    assert params_bots["traffic"] == ["claimed_bot"]
    params_humans = _params(links["Potential user traffic"])
    assert params_humans["traffic"] == ["browser_like"]
    for label in ("404 issues", "Server errors (5xx)", "Bot traffic", "Potential user traffic"):
        followed = client.get(html.unescape(links[label]))
        assert followed.status_code == 200, label


def test_quick_view_links_follow_to_matching_data(web):
    client, _ = web
    _login(client)
    overview = client.get(f"/?site=default&{WINDOW_QS}&tz=UTC").text
    links = {
        label: url
        for url, label in re.findall(
            r'<a class="btn btn-outline btn-xs" href="([^"]+)">([^<]+)</a>', overview
        )
    }
    errors_404 = client.get(html.unescape(links["404 issues"])).text
    assert "404 · Not Found" in errors_404
    humans = client.get(html.unescape(links["Potential user traffic"])).text
    assert "traffic=Browser-like" in humans
