"""Shared-window navigation roundtrips (T10): Settings/Data Sources keep state.

Regression tests for the confirmed state loss: data pages threaded the
shared site/source/window/tz state through the side nav, but Settings and
Data Sources rendered no ``nav_query``, so returning to a data view
discarded the selected window. Every assertion replays real HTTP reads
through the TestClient; the Playwright click-through twin lives in
``tests/e2e/test_nav_roundtrip.py`` for coordinator execution.
Synthetic data only.
"""

import html
import re
from urllib.parse import parse_qs, urlsplit

WINDOW = (
    "site=default&range=custom&from=2026-10-27T00:00:00%2B00:00"
    "&to=2026-10-28T00:00:00%2B00:00&tz=Europe%2FBerlin&source=example-combined"
)


def _login(client):
    response = client.post(
        "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
    )
    assert response.status_code == 200
    return response.json()["csrf_token"]


def _hrefs(html, prefix):
    """All href targets starting with prefix, in document order."""
    return [m for m in re.findall(r'href="([^"]+)"', html) if m == prefix or m.startswith(prefix)]


def _params(url):
    return parse_qs(urlsplit(html.unescape(url)).query)


def _get(client, href):
    return client.get(html.unescape(href))


def test_settings_roundtrip_preserves_shared_window(web):
    client, _ = web
    _login(client)
    overview = client.get(f"/?{WINDOW}")
    assert overview.status_code == 200
    settings_hrefs = _hrefs(overview.text, "/settings")
    assert settings_hrefs, "side nav must link to Settings"
    assert _params(settings_hrefs[0])["source"] == ["example-combined"]
    assert _params(settings_hrefs[0])["tz"] == ["Europe/Berlin"]
    assert _params(settings_hrefs[0])["range"] == ["custom"]

    settings = _get(client, settings_hrefs[0])
    assert settings.status_code == 200
    back_hrefs = [h for h in _hrefs(settings.text, "/") if h == "/" or h.startswith("/?")]
    assert back_hrefs, "Settings must link back to Overview with state"
    back = _params(back_hrefs[0])
    assert back["source"] == ["example-combined"]
    assert back["tz"] == ["Europe/Berlin"]
    assert back["range"] == ["custom"]
    assert back["from"] == ["2026-10-27T00:00:00+00:00"]
    assert back["to"] == ["2026-10-28T00:00:00+00:00"]

    again = _get(client, back_hrefs[0])
    assert again.status_code == 200
    assert "example-combined" in again.text


def test_data_sources_roundtrip_preserves_shared_window(web):
    client, _ = web
    _login(client)
    overview = client.get(f"/?{WINDOW}")
    assert overview.status_code == 200
    sources_hrefs = _hrefs(overview.text, "/data-sources")
    assert sources_hrefs, "side nav must link to Data Sources"
    assert _params(sources_hrefs[0])["source"] == ["example-combined"]

    sources = _get(client, sources_hrefs[0])
    assert sources.status_code == 200
    assert "example-combined" in sources.text
    back_hrefs = [h for h in _hrefs(sources.text, "/") if h == "/" or h.startswith("/?")]
    assert back_hrefs, "Data Sources must link back to Overview with state"
    back = _params(back_hrefs[0])
    assert back["source"] == ["example-combined"]
    assert back["tz"] == ["Europe/Berlin"]
    assert back["range"] == ["custom"]

    again = _get(client, back_hrefs[0])
    assert again.status_code == 200


def test_settings_direct_visit_has_no_state_and_stays_200(web):
    client, _ = web
    _login(client)
    for path in ("/settings", "/data-sources"):
        response = client.get(path)
        assert response.status_code == 200
        # No stale or partial state leaks into the side nav.
        assert "example-combined" not in response.text or path == "/data-sources"


def test_settings_malformed_params_never_400(web):
    client, _ = web
    _login(client)
    for path in ("/settings", "/data-sources"):
        response = client.get(f"{path}?range=bogus&tz=Mars%2FOlympus")
        assert response.status_code == 200


def test_matchers_stay_page_local_while_source_is_shared(web):
    client, _ = web
    _login(client)
    errors = client.get(f"/errors?{WINDOW}&status=404")
    assert errors.status_code == 200
    overview_hrefs = [h for h in _hrefs(errors.text, "/") if h == "/" or h.startswith("/?")]
    assert overview_hrefs, "side nav must link to Overview"
    shared = _params(overview_hrefs[0])
    assert shared["source"] == ["example-combined"]
    assert "status" not in shared, "page-local matchers must not leak into shared nav state"
