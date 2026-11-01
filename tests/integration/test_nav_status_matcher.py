"""Sidebar global-matcher preservation (accepted Slice B behavior).

``status`` is a global event matcher (``MATCHER_KEYS`` in
``app/web/routes.py``), so every dashboard navigation link — including the
sidebar Security link on the Errors page — preserves it. This is the
server-side proof behind the updated
``test_errors_apply_preserves_matchers_source_and_nav`` browser expectation:
the old baseline asserting ``status=404`` disappears on navigation is
outdated. Synthetic data only.
"""

import html
import re
from urllib.parse import parse_qs, urlparse

W1 = "range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"


def _login(client):
    response = client.post(
        "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
    )
    assert response.status_code == 200


def _params(href):
    return parse_qs(urlparse(html.unescape(href)).query)


def test_errors_sidebar_security_link_preserves_status_matcher(web):
    client, _ = web
    _login(client)
    page = client.get(f"/errors?site=default&{W1}&tz=UTC&status=404&source=example-combined")
    assert page.status_code == 200
    security_hrefs = [
        m for m in re.findall(r'href="([^"]+)"', page.text) if m.startswith("/security")
    ]
    assert security_hrefs, "side nav must link to Security findings"
    params = _params(security_hrefs[0])
    assert params["status"] == ["404"]
    assert params["source"] == ["example-combined"]
    assert params["site"] == ["default"]
    assert params["from"] == ["2026-10-27T00:00:00+00:00"]
    assert params["to"] == ["2026-10-28T00:00:00+00:00"]
    followed = client.get(html.unescape(security_hrefs[0]))
    assert followed.status_code == 200
    assert "Security findings" in followed.text
